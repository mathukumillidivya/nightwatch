"""Nightwatch live service: runs the real agents on an alert and streams every step to the browser.

    uvicorn app.server:app --port 8000

Endpoints
  GET  /api/catalog   the alerts a visitor can run, and the attacks that can be planted in them
  POST /api/run       {case_id, attack: none|suppress|misdirect|evasive, guarded: bool}; Server-Sent Events, one per step
  GET  /health        liveness

Limits (a public page must not become a free model endpoint): runs per visitor per day, runs per day in total,
runs at the same time, and a daily spending cap. The API key stays on the server.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
from collections import defaultdict
from datetime import date
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch.agents import investigate  # noqa: E402
from nightwatch.models import Claude, cost  # noqa: E402
from scripts.redteam import PAYLOADS, plant  # noqa: E402

MODEL = os.environ.get("NIGHTWATCH_MODEL", "claude-haiku-4-5-20251001")
PER_VISITOR = int(os.environ.get("RUNS_PER_VISITOR", 6))
PER_DAY = int(os.environ.get("RUNS_PER_DAY", 30))
DAILY_DOLLARS = float(os.environ.get("DAILY_DOLLARS", 1.0))
AT_ONCE = asyncio.Semaphore(int(os.environ.get("RUNS_AT_ONCE", 2)))

CASES = {json.loads(l)["case_id"]: json.loads(l) for l in open(ROOT / "data/cases.jsonl")}
LABELS = json.loads((ROOT / "data/labels.json").read_text())
USAGE: dict = defaultdict(float)


def make_model() -> Claude:
    if MODEL == "fake":
        sys.path.insert(0, str(ROOT / "tests"))
        from fake_client import FakeClaude
        return Claude(client=FakeClaude().client())
    from anthropic import AsyncAnthropic
    return Claude(model=MODEL, client=AsyncAnthropic(max_retries=4, timeout=90))


app = FastAPI(docs_url=None, redoc_url=None)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST"], allow_headers=["content-type"])


@app.get("/health")
def health():
    return {"ok": True, "model": MODEL}


@app.get("/api/catalog")
def catalog():
    return {"cases": len(CASES), "attacks": {k: v for k, v in PAYLOADS.items()},
            "limits": {"per_visitor": PER_VISITOR, "per_day": PER_DAY}}


def visitor(request: Request) -> str:
    """The address the hosting proxy saw. A visitor can put anything at the front of X-Forwarded-For,
    so take the proxy's own header, or else the last address the proxy appended."""
    h = request.headers
    for name in ("cf-connecting-ip", "true-client-ip"):
        if h.get(name):
            return h[name].strip()
    if h.get("x-forwarded-for"):
        return h["x-forwarded-for"].split(",")[-1].strip()
    return request.client.host if request.client else "?"


def limited(ip: str) -> str | None:
    day = date.today().isoformat()
    if USAGE[(day, "$")] >= DAILY_DOLLARS or USAGE[day] >= PER_DAY:
        return "The live agents have reached today's limit. Recorded investigations still play."
    if USAGE[(day, ip)] >= PER_VISITOR:
        return "You have reached today's limit for live runs. Recorded investigations still play."
    USAGE[day] += 1
    USAGE[(day, ip)] += 1
    return None


@app.post("/api/run")
async def run(request: Request):
    body = await request.json()
    case = CASES.get(body.get("case_id"))
    if not case:
        raise HTTPException(404, "unknown alert")
    attack = body.get("attack") or "none"
    if attack != "none":
        if attack not in PAYLOADS:
            raise HTTPException(400, "unknown attack")
        case = plant(case, attack)
    guarded = bool(body.get("guarded", True))
    problem = limited(visitor(request))
    if problem:
        return JSONResponse({"error": problem}, status_code=429)

    async def events():
        queue: asyncio.Queue = asyncio.Queue()
        yield f"data: {json.dumps({'type': 'start', 'case_id': case['case_id'], 'planted_id': case.get('planted_id'), 'view': case['view'] if attack != 'none' else None})}\n\n"

        async def work():
            async with AT_ONCE:
                try:
                    res = await investigate(case, "nightwatch", make_model(), guarded=guarded, want_report=True,
                                            on_step=lambda s: queue.put_nowait({"type": "step", **s}))
                    c = cost(res["usage"], MODEL)
                    USAGE[(date.today().isoformat(), "$")] += c
                    gold = LABELS[case.get("source_case", case["case_id"])]
                    await queue.put({"type": "done", **{k: res[k] for k in ("techniques", "verdict", "report", "usage", "seconds")},
                                     "cost": round(c, 4), "answer_key": {"gold": gold["gold"], "title": gold["title"]}})
                except Exception as e:  # the page shows the failure rather than hanging
                    await queue.put({"type": "error", "message": f"{type(e).__name__}: {str(e)[:200]}"})
                await queue.put(None)

        task = asyncio.create_task(work())
        t0 = time.time()
        while True:
            try:
                item = await asyncio.wait_for(queue.get(), timeout=15)
            except asyncio.TimeoutError:
                yield f": keep-alive {time.time() - t0:.0f}\n\n"
                continue
            if item is None:
                break
            yield f"data: {json.dumps(item, default=str)}\n\n"
        await task

    return StreamingResponse(events(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
