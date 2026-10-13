"""Build the cases from the OTRF Security-Datasets Windows host recordings.

Usage: python scripts/build_cases.py --raw <folder with <dataset id>/<recording>.json> --meta <meta.json>

Writes
  data/cases.jsonl   one case per recording: the triage view and the searchable index (no labels)
  data/labels.json   the answer key: ATT&CK technique ids and tactics from the dataset metadata
  data/split.json    development / test split, by dataset so variants of one attack never straddle it; the test
                     split takes one recording per dataset, the other variants are kept apart in test_variants
"""
import argparse
import json
import pickle
import random
import sys
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch import attack, logs  # noqa: E402


def parse_one(path: str):
    p = logs.parse(Path(path))
    for g in p["groups"].values():
        g["hosts"] = sorted(g["hosts"])
    return path, p


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--raw", required=True)
    ap.add_argument("--meta", required=True)
    ap.add_argument("--cache", default="")
    ap.add_argument("--dev", type=int, default=30)
    args = ap.parse_args()
    meta = {d["id"]: d for d in json.load(open(args.meta))}
    files = sorted(str(f) for f in Path(args.raw).glob("*/*.json"))
    cache = Path(args.cache) if args.cache else None
    if cache and cache.exists():
        parsed = pickle.loads(cache.read_bytes())
    else:
        with Pool(2) as pool:
            parsed = dict(pool.imap_unordered(parse_one, files))
        if cache:
            cache.write_bytes(pickle.dumps(parsed))
    df = logs.build_df(parsed)
    n = len(parsed)

    cases, labels = [], {}
    for path in sorted(parsed):
        ds = Path(path).parent.name
        m = meta[ds]
        gold = sorted({attack.current(t) for t in m["techniques"] if attack.get(t)})
        if not gold:  # e.g. a dataset labelled T0000 (no technique)
            print("skipped, no ATT&CK label:", ds, m["title"])
            continue
        c = logs.condense(parsed[path], df, n)
        cid = f"NW-{len(cases) + 1:03d}"
        cases.append({"case_id": cid, "dataset": ds, **c})
        labels[cid] = {"dataset": ds, "recording": Path(path).stem, "title": m["title"], "techniques": m["techniques"],
                       "gold": gold, "gold_tactics": sorted({t for g in gold for t in attack.get(g)["tactics"]}),
                       "description": m["desc"]}
    out = ROOT / "data"
    out.mkdir(exist_ok=True)
    with open(out / "cases.jsonl", "w") as f:
        for c in cases:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
    (out / "labels.json").write_text(json.dumps(labels, indent=1))

    datasets = sorted({c["dataset"] for c in cases})
    random.Random(7).shuffle(datasets)
    dev_ds, picked = set(), 0
    for d in datasets:  # whole datasets into development until it holds about --dev recordings
        if picked >= args.dev:
            break
        dev_ds.add(d)
        picked += sum(1 for c in cases if c["dataset"] == d)
    first = {}
    for c in cases:  # one recording per dataset: several datasets hold near-identical variants of one attack
        first.setdefault(c["dataset"], c["case_id"])
    split = {"dev": [c["case_id"] for c in cases if c["dataset"] in dev_ds],
             "test": [c["case_id"] for c in cases if c["dataset"] not in dev_ds and first[c["dataset"]] == c["case_id"]],
             "test_variants": [c["case_id"] for c in cases if c["dataset"] not in dev_ds and first[c["dataset"]] != c["case_id"]]}
    (out / "split.json").write_text(json.dumps(split, indent=1))
    view_chars = [sum(len(logs.line(r)) for r in c["view"]) for c in cases]
    print(f"{len(cases)} cases, {len(split['dev'])} dev / {len(split['test'])} test (+{len(split['test_variants'])} variants); "
          f"view about {sum(view_chars) / len(view_chars) / 4:.0f} tokens on average (max {max(view_chars) / 4:.0f}); "
          f"index {sum(len(c['index']) for c in cases) / len(cases):.0f} rows on average")


if __name__ == "__main__":
    main()
