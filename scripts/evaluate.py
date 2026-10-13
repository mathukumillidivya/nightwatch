"""Score runs against the ATT&CK labels, and compare two systems with a paired bootstrap.

Usage:
  python scripts/evaluate.py results/runs/<run>                        one run
  python scripts/evaluate.py results/runs/<a> results/runs/<b> --out results/test-comparison.json

Metrics (a recording's label can hold more than one technique; a hit on any counts):
  top1         the first technique named is a labelled technique (exact, sub-technique included)
  top1_family  the first technique is in the right family (T1003.001 vs T1003.006 counts)
  top3         any of the techniques named (at most three) is labelled
  tactic       the first technique shares a tactic with the label
  by_dataset   top1 with each dataset weighted once (some datasets have several recordings)
  invented     share of named technique ids that are not current ATT&CK techniques (baseline only; Nightwatch
               cannot return one, code drops it)
  grounded     share of returned techniques backed by at least one quote code found in the logs
"""
import argparse
import json
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch import attack  # noqa: E402


def load(run: str) -> list[dict]:
    return [json.loads(l) for l in open(Path(run) / "results.jsonl")]


def hits(r: dict, key: str = "techniques") -> dict:
    gold = set(r.get("gold") or [])
    pred = [attack.current(t) for t in (r.get(key) or [])][:3]
    fam = {attack.parent(g) for g in gold}
    gtac = {t for g in gold for t in (attack.get(g) or {}).get("tactics", [])}
    first = pred[0] if pred else None
    return {"top1": bool(first and first in gold), "top1_family": bool(first and attack.parent(first) in fam),
            "top3": any(p in gold for p in pred),
            "tactic": bool(first and set((attack.get(first) or {}).get("tactics", [])) & gtac), "answered": bool(first)}


def score(rows: list[dict], key: str = "techniques") -> dict:
    rows = [r for r in rows if r.get("gold")]
    n = len(rows)
    per = [hits(r, key) for r in rows]
    out = {"cases": n, "errors": sum(1 for r in rows if r.get("error"))}
    for k in ("top1", "top1_family", "top3", "tactic", "answered"):
        out[k] = round(sum(p[k] for p in per) / n, 4) if n else 0
    by_ds = defaultdict(list)
    for r, p in zip(rows, per):
        by_ds[r["dataset"]].append(p["top1"])
    out["by_dataset"] = round(statistics.mean(statistics.mean(v) for v in by_ds.values()), 4) if by_ds else 0
    if any("checked" in r for r in rows):  # baseline: how often it named ids that do not exist, or cited nothing real
        named = [f for r in rows for f in r.get("checked") or []]
        out["invented"] = round(sum(not f["valid_id"] for f in named) / max(len(named), 1), 4)
        out["grounded"] = round(sum(f["verified"] for f in named) / max(len(named), 1), 4)
    else:
        found = [f for r in rows for f in (r.get("verdict") or {}).get("findings", [])]
        dropped = [u for r in rows for u in (r.get("verdict") or {}).get("unverified", [])]
        out["invented"] = 0.0
        out["grounded"] = 1.0 if found else 0.0
        out["dropped_by_code"] = len(dropped)
        out["sent_back"] = sum(len((r.get("verdict") or {}).get("retried") or []) for r in rows)
    costs = [r.get("cost", 0) for r in rows]
    secs = [r.get("seconds", 0) for r in rows]
    out["cost_per_case"] = round(statistics.mean(costs), 5) if costs else 0
    out["cost_total"] = round(sum(costs), 4)
    out["median_seconds"] = round(statistics.median(secs), 1) if secs else 0
    calls = [sum(u.get("calls", 0) for u in (r.get("usage") or {}).values()) for r in rows]
    out["model_calls_per_case"] = round(statistics.mean(calls), 2) if calls else 0
    return out


def paired(a: list[dict], b: list[dict], metric: str = "top1", key_a: str = "techniques", key_b: str = "techniques",
           n: int = 10000) -> dict:
    A = {r["case_id"]: hits(r, key_a)[metric] for r in a if r.get("gold")}
    B = {r["case_id"]: hits(r, key_b)[metric] for r in b if r.get("gold")}
    ids = sorted(set(A) & set(B))
    d = [B[i] - A[i] for i in ids]
    rng = random.Random(0)
    boots = sorted(sum(rng.choice(d) for _ in d) / len(d) for _ in range(n))
    return {"metric": metric, "cases": len(ids), "a": round(sum(A[i] for i in ids) / len(ids), 4),
            "b": round(sum(B[i] for i in ids) / len(ids), 4), "diff": round(sum(d) / len(d), 4),
            "ci95": [round(boots[int(0.025 * n)], 4), round(boots[int(0.975 * n)], 4)],
            "b_only": sum(1 for x in d if x > 0), "a_only": sum(1 for x in d if x < 0)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("runs", nargs="+")
    ap.add_argument("--out")
    args = ap.parse_args()
    report = {}
    for run in args.runs:
        rows = load(run)
        name = Path(run).name
        report[name] = score(rows)
        if any("techniques_verified" in r for r in rows):
            report[name + "+verify"] = score(rows, "techniques_verified")
    if len(args.runs) == 2:
        a, b = load(args.runs[0]), load(args.runs[1])
        report["paired"] = {m: paired(a, b, m) for m in ("top1", "top1_family", "top3")}
    print(json.dumps(report, indent=1))
    if args.out:
        Path(args.out).write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    main()
