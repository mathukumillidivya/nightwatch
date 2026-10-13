"""Score runs on the benign and mixed alerts (data/benign.jsonl).

  benign  a false alarm is any ATT&CK technique reported on a window of ordinary activity
  mixed   right if the first technique is the attack's label, as on the clean recording; "kept" counts the
          attacks the same system got right on the clean recording and still gets right with the noise around it

Usage: python scripts/score_benign.py --run nightwatch=results/runs/benign-nightwatch --clean nightwatch=results/runs/test-nightwatch \
           --run single_call=results/runs/benign-single --clean single_call=results/runs/test-single [--out results/benign.json]
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(run):
    return {r["case_id"]: r for r in (json.loads(l) for l in open(Path(run) / "results.jsonl"))}


def pairs(items):
    return dict(x.split("=", 1) for x in items)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", nargs="+", required=True)
    ap.add_argument("--clean", nargs="+", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    runs, cleans = pairs(a.run), pairs(a.clean)
    meta = json.loads((ROOT / "data/benign_meta.json").read_text())
    out = {}
    for name, run in runs.items():
        rows, clean = load(run), load(cleans[name])
        ben = [r for c, r in rows.items() if meta.get(c, {}).get("kind") == "benign"]
        mix = [r for c, r in rows.items() if meta.get(c, {}).get("kind") == "mixed"]
        ok_b = [r for r in ben if not r.get("error")]
        alarms = [r for r in ok_b if r.get("techniques")]
        ok_m = [r for r in mix if not r.get("error")]
        right = [r for r in ok_m if r.get("techniques") and r["techniques"][0] in (r.get("gold") or [])]
        eligible = [r for r in ok_m if (lambda c: c and c.get("techniques") and c["techniques"][0] in (c.get("gold") or []))(clean.get(meta[r["case_id"]]["attack"]))]
        kept = [r for r in eligible if r in right]
        out[name] = {
            "benign_alerts": len(ben), "benign_errors": len(ben) - len(ok_b),
            "false_alarms": len(alarms), "false_alarm_rate": round(len(alarms) / max(len(ok_b), 1), 3),
            "techniques_per_false_alarm": round(sum(len(r["techniques"]) for r in alarms) / max(len(alarms), 1), 2),
            "false_alarm_examples": [{"case": r["case_id"], "techniques": r["techniques"][:3]} for r in alarms][:6],
            "mixed_alerts": len(mix), "mixed_errors": len(mix) - len(ok_m), "mixed_right": len(right),
            "mixed_right_on_clean": len(eligible), "mixed_kept": len(kept),
            "mixed_cases": [{"case": r["case_id"], "attack": meta[r["case_id"]]["attack"], "gold": r.get("gold"),
                             "first": (r.get("techniques") or [None])[0]} for r in ok_m],
            "cost": round(sum(r.get("cost", 0) for r in rows.values()), 4)}
    print(json.dumps(out, indent=1))
    if a.out:
        Path(a.out).write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
