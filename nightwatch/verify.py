"""Code checks on everything an agent claims. No model is involved here.

A finding survives only if:
  - its technique id is a current ATT&CK Enterprise technique (revoked ids are followed to their replacement);
  - at least one piece of evidence holds: the cited event exists in this recording, and the quoted text appears
    in that event's fields (whitespace and case aside).
"""
from __future__ import annotations

import re

from . import attack

TID = re.compile(r"^T\d{4}(\.\d{3})?$")


def norm(s: str) -> str:
    return re.sub(r"\s+", " ", str(s)).strip().lower().replace('"', "").replace("…", "").strip()


def events_by_id(case: dict) -> dict[str, dict]:
    return {r["id"]: r for r in case["view"] + case["index"]} | {r["id"]: r for r in case.get("planted", [])}


def check_evidence(case: dict, evidence: list[dict], events: dict | None = None) -> list[dict]:
    """Annotate each evidence item with ok / why."""
    events = events or events_by_id(case)
    out = []
    for ev in evidence or []:
        eid = str(ev.get("event_id", "")).strip().strip("[]")
        q = norm(ev.get("quote", ""))
        r = events.get(eid)
        item = {"event_id": eid, "field": ev.get("field"), "quote": ev.get("quote", ""), "ok": False}
        if not r:
            item["why"] = f"there is no event {eid}"
        elif len(q) < 3:
            item["why"] = "the quote is empty"
        else:
            fields = {k: norm(v) for k, v in r["fields"].items()}
            hit = [k for k, v in fields.items() if q in v]
            if hit:
                item["ok"] = True
                item["field"] = ev.get("field") if ev.get("field") in hit else hit[0]
            else:
                item["why"] = f"\"{ev.get('quote', '')[:60]}\" does not appear in event {eid}"
        out.append(item)
    return out


def check_technique(tid: str) -> tuple[str | None, str | None]:
    t = str(tid or "").strip().upper()
    if t in ("NONE", ""):
        return None, "none"
    if not TID.match(t):
        return None, f"{tid} is not a technique id"
    if not attack.get(t):
        return None, f"{t} is not a current ATT&CK Enterprise technique"
    return attack.current(t), None


def check_mapping(case: dict, mapping: dict, events: dict | None = None) -> dict:
    tid, problem = check_technique(mapping.get("technique_id"))
    evidence = check_evidence(case, mapping.get("evidence") or [], events)
    ok_ev = [e for e in evidence if e["ok"]]
    problems = []
    if problem and problem != "none":
        problems.append(problem)
    if tid and not ok_ev:
        problems.append("none of the evidence could be found in the logs: " + "; ".join(e.get("why", "") for e in evidence[:3])
                        if evidence else "no evidence was cited")
    return {"technique_id": tid, "declined": problem == "none", "evidence": evidence, "verified": bool(tid and ok_ev),
            "problems": problems}
