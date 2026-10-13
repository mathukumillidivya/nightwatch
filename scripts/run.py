"""Run Nightwatch (or the single-call baseline) over a split and save every result.

Usage:
  python scripts/run.py --system nightwatch  --split dev --run-id dev-v1 [--limit 10]
  python scripts/run.py --system single_call --split test --run-id test-single
  python scripts/run.py --system nightwatch --cases data/redteam.jsonl --unguarded --run-id rt-nightwatch-open

Spending is capped twice: --budget stops this run when its own cost reaches it, and results/spend.json (the ledger
of every run, committed with the results) refuses to start a run once the project total reaches --project-cap.
Writes results/runs/<run-id>/results.jsonl and config.json.
"""
import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch.agents import investigate  # noqa: E402
from nightwatch.models import Claude, cost  # noqa: E402

LEDGER = ROOT / "results/spend.json"


def make_model(name: str) -> Claude:
    if name == "fake":
        sys.path.insert(0, str(ROOT / "tests"))
        from fake_client import FakeClaude
        return Claude(client=FakeClaude().client())
    from anthropic import AsyncAnthropic
    return Claude(model=name, client=AsyncAnthropic(max_retries=6, timeout=120))


def spent() -> float:
    return json.loads(LEDGER.read_text())["total"] if LEDGER.exists() else 0.0


def record(run_id: str, model: str, amount: float, cases: int):
    led = json.loads(LEDGER.read_text()) if LEDGER.exists() else {"total": 0.0, "runs": []}
    led["runs"].append({"run_id": run_id, "model": model, "cost": round(amount, 4), "cases": cases})
    led["total"] = round(sum(r["cost"] for r in led["runs"]), 4)
    LEDGER.parent.mkdir(parents=True, exist_ok=True)
    LEDGER.write_text(json.dumps(led, indent=1))


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--system", choices=["nightwatch", "single_call"], default="nightwatch")
    ap.add_argument("--split", choices=["dev", "test", "test_variants", "all"], default="dev")
    ap.add_argument("--cases", default="data/cases.jsonl")
    ap.add_argument("--ids", default="", help="comma-separated case ids to run instead of a split")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--concurrency", type=int, default=4)
    ap.add_argument("--model", default="claude-haiku-4-5-20251001")
    ap.add_argument("--unguarded", action="store_true", help="switch off the prompt-injection guardrails (red team)")
    ap.add_argument("--report", action="store_true", help="also write the incident report")
    ap.add_argument("--budget", type=float, default=1.5, help="stop this run at this cost (US$)")
    ap.add_argument("--project-cap", type=float, default=5.0, help="refuse to run once all runs together cost this")
    ap.add_argument("--run-id", required=True)
    args = ap.parse_args()

    if args.model != "fake" and spent() >= args.project_cap:
        sys.exit(f"Project spending cap reached: ${spent():.2f} of ${args.project_cap:.2f}. Nothing was run.")
    budget = min(args.budget, args.project_cap - spent()) if args.model != "fake" else float("inf")

    cases = {json.loads(l)["case_id"]: json.loads(l) for l in open(ROOT / args.cases)}
    labels = json.loads((ROOT / "data/labels.json").read_text())
    if args.ids:
        ids = args.ids.split(",")
    elif args.split == "all" or args.cases != "data/cases.jsonl":
        ids = list(cases)
    else:
        ids = json.loads((ROOT / "data/split.json").read_text())[args.split]
    todo = [cases[c] for c in ids if c in cases][: args.limit or None]
    out = ROOT / "results/runs" / args.run_id
    out.mkdir(parents=True, exist_ok=True)
    model = make_model(args.model)
    sem = asyncio.Semaphore(args.concurrency)
    total = {"cost": 0.0, "stopped": False}

    async def one(case):
        async with sem:
            if total["cost"] >= budget:
                total["stopped"] = True
                return None
            t0 = time.time()
            try:
                res = await investigate(case, args.system, model, guarded=not args.unguarded, want_report=args.report)
                err = None
            except Exception as e:  # keep going; a failed case is an error, not an answer
                res, err = {"usage": getattr(e, "usage", {}), "trace": getattr(e, "trace", [])}, f"{type(e).__name__}: {e}"[:500]
                if "credit balance" in str(e).lower():
                    total["stopped"] = True
                    total["cost"] = float("inf")
            c = cost(res.get("usage") or {}, args.model)
            if total["cost"] != float("inf"):
                total["cost"] += c
            lab = labels.get(case.get("source_case", case["case_id"]), {})
            return {"case_id": case["case_id"], "gold": lab.get("gold"), "dataset": case["dataset"], **res,
                    "cost": round(c, 5), "seconds": round(time.time() - t0, 1), "error": err,
                    "attack": case.get("attack")}

    results, t0 = [], time.time()
    with open(out / "results.jsonl", "w") as f:
        for i, coro in enumerate(asyncio.as_completed([one(c) for c in todo])):
            r = await coro
            if r is None:
                continue
            results.append(r)
            f.write(json.dumps(r, default=str) + "\n")
            f.flush()
            if (i + 1) % 10 == 0 or i + 1 == len(todo):
                top1 = sum(bool(x.get("techniques")) and x["techniques"][0] in (x["gold"] or []) for x in results)
                print(f"{len(results)}/{len(todo)}  top-1 so far {top1}  errors {sum(1 for x in results if x['error'])}  "
                      f"cost ${sum(x['cost'] for x in results):.3f}  {time.time() - t0:.0f}s", flush=True)
    run_cost = sum(r["cost"] for r in results)
    if args.model != "fake":
        record(args.run_id, args.model, run_cost, len(results))
    (out / "config.json").write_text(json.dumps({**vars(args), "cases": len(todo), "completed": len(results),
                                                 "stopped_at_budget": total["stopped"], "cost": round(run_cost, 4)}, indent=2))
    print(f"done: {len(results)} cases, ${run_cost:.3f}" + ("  (stopped: budget reached)" if total["stopped"] else ""))


if __name__ == "__main__":
    asyncio.run(main())
