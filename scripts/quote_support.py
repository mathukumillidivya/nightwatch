"""Does each quote actually support the technique it is cited for?

The evaluation already checks that every quote exists word for word in the event it names. A quote can exist
and still prove nothing: "powershell.exe" is in the log of almost every Windows machine. This script asks a
second model to read each finding next to the full events it cites and the ATT&CK description of the technique,
and say whether the evidence shows that technique:

  supports          the cited events show the technique's behaviour on their own
  partial           consistent with it, but they would fit ordinary activity or a different technique just as well
  does_not_support  the events do not show this technique

Findings are then split by whether the technique is right (the recording's label or its parent technique), so
the result shows whether "verified" evidence on wrong answers is any different from evidence on right ones.

The judge is Claude Haiku 4.5, the same model the systems use, at temperature 0, one call per alert. A model
can share the blind spots of the model it judges, so treat this as a screen, not ground truth.

Usage:
  python scripts/quote_support.py --run nightwatch=results/runs/test-nightwatch --run single_call=results/runs/test-single \
      --budget 0.6 --out results/quote_support.json        # needs ANTHROPIC_API_KEY
  ... --provider mock --limit 3                            # offline check of the plumbing
Per-finding judgments go to <run>/quote_support.jsonl. The cost is added to results/spend.json.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch import attack  # noqa: E402

MODEL = "claude-haiku-4-5-20251001"
PRICE = {"input": 1.0 / 1e6, "output": 5.0 / 1e6, "cache_read": 0.1 / 1e6, "cache_write": 1.25 / 1e6}
LEDGER = ROOT / "results/spend.json"

INSTRUCTIONS = """You review findings from an AI security analyst before a human acts on them. Each finding names \
a MITRE ATT&CK technique and cites events from Windows logs (Sysmon and Security) as evidence. Every quote has \
already been checked to exist in the event it names. Your job is different: decide whether the cited events, \
read in full, actually show the technique.

For each finding answer:
- supports: the cited events by themselves show behaviour specific to this technique (for example a process \
opening LSASS with full access and writing a dump file, for LSASS Memory).
- partial: the events are consistent with the technique but would fit ordinary administration, normal Windows \
activity, or a different technique just as well (for example "powershell.exe started" cited for a specific \
PowerShell attack technique, or a registry write that matches the technique's location but not its purpose).
- does_not_support: the events do not show this technique, or show something else.

Judge only from the events and the technique description given. Do not assume activity that is not in the events. \
Say in one sentence what the cited events do show.

Submit with the submit_review tool, one entry per finding, in the same order."""

TOOL = {"name": "submit_review", "description": "Submit one judgment per finding.", "input_schema": {
    "type": "object", "required": ["findings"], "properties": {"findings": {"type": "array", "items": {
        "type": "object", "required": ["index", "support", "events_show"], "properties": {
            "index": {"type": "integer"},
            "support": {"type": "string", "enum": ["supports", "partial", "does_not_support"]},
            "events_show": {"type": "string", "description": "One sentence: what the cited events actually show."}}}}}}}


def cost(u: dict) -> float:
    return sum(u.get(k, 0) * PRICE[k] for k in PRICE)


def right(tid: str, gold: list[str]) -> bool:
    fam = {attack.parent(g) for g in gold}
    t = attack.current(tid)
    return t in gold or attack.parent(t) in fam


def prompt(findings: list[dict], events: dict) -> str:
    parts = []
    for i, f in enumerate(findings):
        ids = sorted({e["event_id"] for e in f.get("evidence", [])})
        evs = "\n".join(f"  {k}: " + json.dumps({x: events[k][x] for x in ("host", "channel", "event_id", "label", "fields") if x in events[k]},
                                                  ensure_ascii=False) for k in ids if k in events)
        quotes = "\n".join(f"  - {e['event_id']} {e.get('field')}: \"{e['quote']}\"" for e in f.get("evidence", []))
        parts.append(f"FINDING {i}\nTechnique: {attack.card(f['technique_id'], chars=600, det_chars=0).split(chr(10) + 'How ATT&CK')[0]}\n"
                     f"Analyst's claim: {f.get('behavior', '')}\nQuotes cited:\n{quotes}\nThe cited events in full:\n{evs or '  (none)'}")
    return "\n\n".join(parts)


class Judge:
    def __init__(self, provider: str):
        self.provider = provider
        if provider == "anthropic":
            import anthropic
            self.client = anthropic.Anthropic(max_retries=5)

    def review(self, text: str, n: int) -> tuple[list[dict], dict]:
        if self.provider == "mock":
            return [{"index": i, "support": "supports", "events_show": "mock"} for i in range(n)], {}
        r = self.client.messages.create(
            model=MODEL, max_tokens=300 + 160 * n,
            system=[{"type": "text", "text": INSTRUCTIONS, "cache_control": {"type": "ephemeral"}}],
            tools=[TOOL], tool_choice={"type": "tool", "name": "submit_review"},
            messages=[{"role": "user", "content": text}], extra_body={"temperature": 0})
        u = r.usage
        out = next(b.input for b in r.content if b.type == "tool_use")["findings"]
        return out, {"input": u.input_tokens, "output": u.output_tokens,
                     "cache_read": getattr(u, "cache_read_input_tokens", 0) or 0, "cache_write": getattr(u, "cache_creation_input_tokens", 0) or 0}


def rate(k: int, n: int) -> dict:
    return {"count": k, "of": n, "rate": round(k / n, 4) if n else None}


def summarise(rows: list[dict]) -> dict:
    def block(rs):
        c = Counter(r["support"] for r in rs)
        return {"findings": len(rs), **{k: rate(c[k], len(rs)) for k in ("supports", "partial", "does_not_support")},
                "all_quotes_verified": rate(sum(r["quotes_verified"] for r in rs), len(rs))}
    return {"all": block(rows), "right_technique": block([r for r in rows if r["right"]]),
            "wrong_technique": block([r for r in rows if not r["right"]]),
            "first_finding": block([r for r in rows if r["slot"] == 0])}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", nargs="+", required=True, help="name=results/runs/<run>")
    ap.add_argument("--cases", default="data/cases.jsonl")
    ap.add_argument("--provider", default="anthropic", choices=["anthropic", "mock"])
    ap.add_argument("--budget", type=float, default=0.6)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--out", default="results/quote_support.json")
    args = ap.parse_args()
    cases = {json.loads(l)["case_id"]: json.loads(l) for l in open(ROOT / args.cases)}
    judge, spent, report = Judge(args.provider), 0.0, {"judge_model": MODEL, "systems": {}}
    for spec in args.run:
        name, run = spec.split("=", 1)
        run = Path(run)
        out_path = run / "quote_support.jsonl"
        done = {}
        if out_path.exists():
            for l in open(out_path):
                x = json.loads(l)
                done.setdefault(x["case_id"], []).append(x)
        rows, n_cases = [], 0
        for line in open(run / "results.jsonl"):
            r = json.loads(line)
            findings = (r.get("verdict") or {}).get("findings") or []
            if not findings or r["case_id"] not in cases:
                continue
            if args.limit and n_cases >= args.limit:
                break
            n_cases += 1
            if r["case_id"] in done:
                rows += done[r["case_id"]]
                continue
            if spent >= args.budget:
                print(f"budget reached; {name}: {n_cases - 1} alerts judged")
                break
            events = {e["id"]: e for e in cases[r["case_id"]]["view"]}
            for attempt in range(3):
                try:
                    judged, usage = judge.review(prompt(findings, events), len(findings))
                    break
                except Exception as e:  # noqa: BLE001 - retried, then the alert is skipped
                    print("retry", r["case_id"], type(e).__name__, str(e)[:120])
                    time.sleep(5 * (attempt + 1))
            else:
                continue
            spent += cost(usage)
            by_i = {j.get("index"): j for j in judged}
            new = []
            for i, f in enumerate(findings):
                j = by_i.get(i) or {"support": "missing", "events_show": ""}
                new.append({"case_id": r["case_id"], "slot": i, "technique": f["technique_id"], "right": right(f["technique_id"], r["gold"]),
                            "quotes_verified": bool(f.get("evidence")) and all(e.get("ok") for e in f["evidence"]),
                            "support": j["support"], "events_show": j.get("events_show", ""), "usage": usage if i == 0 else {}})
            with open(out_path, "a") as fh:
                for x in new:
                    fh.write(json.dumps(x) + "\n")
            rows += new
        report["systems"][name] = {**summarise(rows), "alerts": len({r["case_id"] for r in rows}),
                                   "cost_usd": round(sum(cost(r["usage"]) for r in rows), 4),
                                   "examples_wrong_but_verified": [{k: r[k] for k in ("case_id", "technique", "support", "events_show")}
                                                                   for r in rows if not r["right"] and r["quotes_verified"] and r["support"] != "supports"][:8]}
    report["note"] = ("Every quote here already exists word for word in its event. 'supports' means a second model "
                      "(the same family as the systems) found the cited events show the technique; treat it as a screen.")
    Path(args.out).write_text(json.dumps(report, indent=2))
    if args.provider == "anthropic" and spent > 0:
        led = json.loads(LEDGER.read_text())
        led["runs"].append({"run_id": "quote-support-judge", "model": MODEL, "cost": round(spent, 4),
                            "cases": sum(s["alerts"] for s in report["systems"].values())})
        led["total"] = round(sum(x["cost"] for x in led["runs"]), 4)
        LEDGER.write_text(json.dumps(led, indent=1))
    print(json.dumps({k: {kk: v[kk] for kk in ("all", "right_technique", "wrong_technique")} for k, v in report["systems"].items()}, indent=1))
    print(f"spent ${spent:.4f}")


if __name__ == "__main__":
    main()
