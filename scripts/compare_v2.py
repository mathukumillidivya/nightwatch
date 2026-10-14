"""Nightwatch v2 against v1: false alarms on fresh ordinary activity, attacks in noise, held-out attacks, quote support.

v2 (nightwatch/agents.py, system "nightwatch_v2") was designed after the false-alarm test on the original 12
ordinary windows, so those windows are not used to judge it. The comparison uses:

  fresh ordinary   10 new windows from two machines not used before (evtx-baseline win11-client, win2022-evtx),
                   non-overlapping; both v1 and v2 run on them
  mixed            the same 8 attacks-in-ordinary-activity alerts as before (v1 from results/runs/benign-nightwatch)
  attacks          24 held-out attack recordings drawn at random (data/v2_attack_sample.txt); v1 from the frozen
                   test run, v2 run once
  quote support    the second-model check of scripts/quote_support.py on v2's findings for those 24, against v1's
                   judgments on the same 24

Output: results/nightwatch_v2.json
"""
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch import attack  # noqa: E402

R = ROOT / "results/runs"


def load(run):
    f = R / run / "results.jsonl"
    return {json.loads(l)["case_id"]: json.loads(l) for l in open(f)} if f.exists() else {}


def first_right(r):
    t = r.get("techniques") or []
    return bool(t and t[0] in (r.get("gold") or []))


def family_right(r):
    t = r.get("techniques") or []
    return bool(t and attack.parent(attack.current(t[0])) in {attack.parent(g) for g in r.get("gold") or []})


def rate(k, n):
    return {"count": k, "of": n, "rate": round(k / n, 3) if n else None}


def benign_block(rows):
    ok = [r for r in rows.values() if not r.get("error")]
    out = Counter(((r.get("verdict") or {}).get("outcome") or "adversary_activity") for r in ok)
    return {"windows": len(rows), "errors": len(rows) - len(ok), "false_alarms": rate(sum(bool(r.get("techniques")) for r in ok), len(ok)),
            "outcomes": dict(out), "leads_only": sum(1 for r in ok if not r.get("techniques") and (r.get("verdict") or {}).get("leads"))}


def quote_block(run, ids):
    f = R / run / "quote_support.jsonl"
    if not f.exists():
        return None
    rows = [json.loads(l) for l in open(f) if json.loads(l)["case_id"] in ids]
    c = Counter(r["support"] for r in rows)
    return {"findings": len(rows), "supports": rate(c["supports"], len(rows)), "partial": rate(c["partial"], len(rows)),
            "does_not_support": rate(c["does_not_support"], len(rows))}


def main():
    ids = set((ROOT / "data/v2_attack_sample.txt").read_text().strip().split(","))
    mixed_ids = [f"MX-{i:02d}" for i in range(1, 9)]
    v1_mixed, v2_mixed = load("benign-nightwatch"), load("mixed-nightwatch_v2")
    v1_test = {k: v for k, v in load("test-nightwatch").items() if k in ids}
    v2_test = load("test24-nightwatch_v2")
    out = {
        "fresh_ordinary": {"v1": benign_block(load("benign-fresh-nightwatch")), "v2": benign_block(load("benign-fresh-nightwatch_v2"))},
        "original_ordinary_v1": benign_block({k: v for k, v in load("benign-nightwatch").items() if k.startswith("BN")}),
        "mixed": {name: {"alerts": sum(1 for m in mixed_ids if m in rows), "attack_named_first": rate(sum(first_right(rows[m]) for m in mixed_ids if m in rows),
                                                                                                        sum(1 for m in mixed_ids if m in rows)),
                         "nothing_reported": sum(1 for m in mixed_ids if m in rows and not rows[m].get("techniques"))}
                  for name, rows in (("v1", v1_mixed), ("v2", v2_mixed))},
        "attacks": {name: {"recordings": len(rows), "errors": sum(bool(r.get("error")) for r in rows.values()),
                           "first_technique_right": rate(sum(first_right(r) for r in rows.values()), len(rows)),
                           "right_family": rate(sum(family_right(r) for r in rows.values()), len(rows)),
                           "nothing_reported": sum(1 for r in rows.values() if not r.get("techniques") and not r.get("error")),
                           "cost": round(sum(r.get("cost") or 0 for r in rows.values()), 4)}
                    for name, rows in (("v1", v1_test), ("v2", v2_test))},
        "quote_support": {"v1": quote_block("test-nightwatch", ids), "v2": quote_block("test24-nightwatch_v2", ids)},
        "v2_misses_that_v1_got": sorted(k for k in v2_test if k in v1_test and first_right(v1_test[k]) and not first_right(v2_test[k])),
        "v2_gains": sorted(k for k in v2_test if k in v1_test and first_right(v2_test[k]) and not first_right(v1_test[k])),
    }
    v21 = {"fresh_ordinary": benign_block(load("benign-fresh-nightwatch_v21")) if load("benign-fresh-nightwatch_v21") else None}
    m21 = load("mixed-nightwatch_v21")
    if m21:
        v21["mixed"] = {"alerts": len(m21), "attack_named_first": rate(sum(first_right(r) for r in m21.values()), len(m21))}
    n86 = load("nw086-nightwatch_v21").get("NW-086")
    if n86:
        v21["NW-086"] = {"techniques": n86.get("techniques"), "first_right": first_right(n86),
                         "outcome": (n86.get("verdict") or {}).get("outcome"),
                         "rechecked": any(s.get("kind") == "authorization_check" for s in n86.get("trace") or [])}
    sup = {**load("rt-suppress-nightwatch_v21"), **load("rt-wide-suppress-nightwatch_v21")}
    if sup:
        ok = [r for r in sup.values() if not r.get("error")]
        v21["report_nothing_injection"] = {"planted": len(sup), "errors": len(sup) - len(ok),
                                           "attacker_success": rate(sum(not r.get("techniques") for r in ok), len(ok)),
                                           "right_first": rate(sum(first_right(r) for r in ok), len(ok)),
                                           "rechecked": sum(any(s.get("kind") == "authorization_check" for s in r.get("trace") or []) for r in ok)}
    rechecks = sum(any(s.get("kind") == "authorization_check" for s in r.get("trace") or [])
                   for run in ("benign-fresh-nightwatch_v21", "mixed-nightwatch_v21") for r in load(run).values())
    v21["authorization_rechecks_on_ordinary_and_mixed"] = rechecks
    if any(v for k, v in v21.items() if k != "authorization_rechecks_on_ordinary_and_mixed"):
        out["v2_1"] = v21
    # A second, unplanned run of v1 and v2 (a workflow condition matched "v21" as "v2"); kept as a replication.
    rr = {"fresh_v1": load("benign-fresh-nightwatch-rerun2"), "fresh_v2": load("benign-fresh-nightwatch_v2-rerun2"),
          "mixed_v2": load("mixed-nightwatch_v2-rerun2"), "attacks_v2": load("test24-nightwatch_v2-rerun2")}
    if all(rr.values()):
        out["v2_second_run"] = {"fresh_ordinary_v1": benign_block(rr["fresh_v1"]), "fresh_ordinary_v2": benign_block(rr["fresh_v2"]),
                                "mixed_v2_attack_named_first": rate(sum(first_right(r) for r in rr["mixed_v2"].values()), len(rr["mixed_v2"])),
                                "attacks_v2": {"first_technique_right": rate(sum(first_right(r) for r in rr["attacks_v2"].values()), len(rr["attacks_v2"])),
                                               "right_family": rate(sum(family_right(r) for r in rr["attacks_v2"].values()), len(rr["attacks_v2"])),
                                               "nothing_reported": sum(1 for r in rr["attacks_v2"].values() if not r.get("techniques"))}}
    (ROOT / "results/nightwatch_v2.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
