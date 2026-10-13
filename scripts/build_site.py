"""Build the Nightwatch console (app/site) from the template, the cases and every recorded run.

Usage: python scripts/build_site.py [--api https://<live service>]

Writes
  app/site/index.html             the console, with the alert queue, results and ATT&CK names inlined
  app/site/data/<case id>.json    one file per alert: the triage view, both systems' recorded runs, the answer key
"""
import argparse
import json
import shutil
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch import attack, enrich, guard, logs  # noqa: E402
from scripts.redteam import PAYLOADS  # noqa: E402

RUNS = {"nightwatch": ["results/runs/test-nightwatch", "results/runs/dev-r1-nightwatch", "results/runs/dev-probe4-nightwatch"],
        "single_call": ["results/runs/test-single", "results/runs/dev-probe4-single"]}
FEATURED = ["NW-002", "NW-003", "NW-043", "NW-026", "NW-034", "NW-011"]


def load_runs(paths):
    out = {}
    for p in paths:
        f = ROOT / p / "results.jsonl"
        if f.exists():
            for l in open(f):
                r = json.loads(l)
                out.setdefault(r["case_id"], r)
    return out


def row(r: dict) -> dict:
    ann = enrich.annotate(r["channel"], r["event_id"], r["fields"])
    return {k: r[k] for k in ("id", "t", "host", "channel", "event_id", "label", "fields", "count", "fleet")} | (
        {"decoded": ann} if ann else {}) | ({"flag": guard.scan_event(r["fields"])} if guard.scan_event(r["fields"]) else {})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="")
    args = ap.parse_args()
    cases = {json.loads(l)["case_id"]: json.loads(l) for l in open(ROOT / "data/cases.jsonl")}
    labels = json.loads((ROOT / "data/labels.json").read_text())
    split = json.loads((ROOT / "data/split.json").read_text())
    where = {c: s for s, ids in split.items() for c in ids}
    runs = {s: load_runs(p) for s, p in RUNS.items()}

    out_dir = ROOT / "app/site/data"
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)
    queue, used = [], set()
    for cid, c in cases.items():
        lab = labels[cid]
        nw, sc = runs["nightwatch"].get(cid), runs["single_call"].get(cid)
        for r in (nw, sc):
            used.update((r or {}).get("techniques") or [])
        used.update(lab["gold"])
        queue.append({"id": cid, "split": where.get(cid, "dev"), "hosts": sorted(c["hosts"], key=lambda h: -c["hosts"][h]),
                      "events": c["events"], "templates": c["templates"], "gold": lab["gold"], "title": lab["title"],
                      "nw": (nw or {}).get("techniques"), "sc": (sc or {}).get("techniques"), "sc_err": bool((sc or {}).get("error")),
                      "nw_cost": (nw or {}).get("cost"), "nw_sec": (nw or {}).get("seconds"), "nw_err": bool((nw or {}).get("error")),
                      "first": min((r["t"] for r in c["view"]), default=0), "last": max((r["t"] for r in c["view"]), default=0)})
        doc = {"id": cid, "hosts": c["hosts"], "events": c["events"], "templates": c["templates"], "index_size": len(c["index"]),
               "view": [row(r) for r in c["view"]], "split": where.get(cid, "dev"),
               "answer_key": {"gold": lab["gold"], "title": lab["title"], "description": lab["description"],
                              "dataset": lab["dataset"], "recording": lab["recording"]},
               "nightwatch": nw and {k: nw.get(k) for k in ("techniques", "verdict", "trace", "usage", "cost", "seconds", "error")},
               "single_call": sc and {k: sc.get(k) for k in ("techniques", "techniques_verified", "answer", "checked", "usage", "cost",
                                                              "seconds", "error")}}
        # the cited index events (X####) the agents searched for, so the page can show them too
        cited = {e["event_id"] for f in ((nw or {}).get("verdict") or {}).get("findings", []) for e in f["evidence"]}
        cited |= {x for h in ((nw or {}).get("verdict") or {}).get("hypotheses", []) for x in h.get("event_ids", [])}
        doc["extra"] = [row(r) for r in c["index"] if r["id"] in cited]
        (out_dir / f"{cid}.json").write_text(json.dumps(doc, separators=(",", ":"), default=str))

    techniques = {}
    for t in sorted(used | {"T1082"}):
        x = attack.get(t)
        if x:
            techniques[t] = {"name": x["name"], "parent": x.get("parent_name"), "tactics": x["tactics"]}
    results = {}
    for name in ("test-comparison.json", "dev-comparison.json", "redteam.json"):
        f = ROOT / "results" / name
        if f.exists():
            results[name.split(".")[0]] = json.loads(f.read_text())
    spend = json.loads((ROOT / "results/spend.json").read_text()) if (ROOT / "results/spend.json").exists() else {}
    data = {"api": args.api, "queue": sorted(queue, key=lambda q: q["id"]), "featured": FEATURED, "techniques": techniques,
            "results": results, "attacks": PAYLOADS, "spend": spend.get("total"), "attack_version": attack.kb()["version"],
            "tactics": [v["name"] for v in sorted(attack.kb()["tactics"].values(), key=lambda v: v["id"])]}
    html = (ROOT / "app/template.html").read_text().replace("/*DATA*/null", json.dumps(data, separators=(",", ":")).replace("</", "<\\/"))
    out = ROOT / "app/site/index.html"
    out.write_text(html)
    size = sum(f.stat().st_size for f in out_dir.iterdir())
    print(f"{out}: {out.stat().st_size / 1e3:.0f} kB; {len(queue)} alert files, {size / 1e6:.1f} MB; results: {list(results)}")


if __name__ == "__main__":
    main()
