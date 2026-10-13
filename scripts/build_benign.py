"""Build benign and mixed alerts, to measure false alarms.

Every OTRF recording contains an attack, so attack-only accuracy says nothing about how often Nightwatch
raises an alarm on ordinary activity. This adds two kinds of alert:

  benign (BN-*)  windows of ordinary Windows activity from NextronSystems/evtx-baseline (Apache-2.0): clean
                 Windows installations with software installs and everyday use, logged with a Sysmon config
                 forked from the same OTRF one. The right answer is "nothing to report".
  mixed  (MX-*)  one held-out attack recording that Nightwatch got right, merged into a benign window with its
                 timestamps shifted into it. The right answer is the attack's label, now with more noise around it.

Each window is reduced exactly like the OTRF recordings: same templates, same fleet rarity table (the 105
attack recordings plus the excluded T0000 one), same 50-event view.

Usage
  python scripts/build_benign.py --prepare --parsed <parsed.pkl>   # once, locally: fleet table and the attacks to mix in
  python scripts/build_benign.py --evtx <folder of .evtx files>    # in CI: builds data/benign.jsonl
"""
import argparse
import gzip
import json
import pickle
import random
from collections import Counter
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nightwatch import logs  # noqa: E402

FLEET = ROOT / "data/fleet_templates.json.gz"
SOURCES = ROOT / "data/benign_mix_sources.json.gz"
# held-out attacks Nightwatch got right on the clean recording, one per behaviour family, none used in the red team
MIX = ["NW-057", "NW-069", "NW-088", "NW-059", "NW-009", "NW-037", "NW-075", "NW-005"]
WINDOW = 4000          # events per benign window; the OTRF recordings have a median of about 3,700
PER_IMAGE = 6


def prepare(parsed_path: str):
    parsed = pickle.loads(Path(parsed_path).read_bytes())
    df = logs.build_df(parsed)
    FLEET.write_bytes(gzip.compress(json.dumps({"recordings": len(parsed), "templates": df}).encode()))
    labels = json.loads((ROOT / "data/labels.json").read_text())
    by_file = {Path(p).parent.name + "/" + Path(p).stem: v for p, v in parsed.items()}
    src = {}
    for cid in MIX:
        lab = labels[cid]
        p = by_file[f"{lab['dataset']}/{lab['recording']}"]
        src[cid] = {"events": p["events"], "hosts": p["hosts"],
                    "groups": {k: {**g, "hosts": sorted(g["hosts"])} for k, g in p["groups"].items()}}
    SOURCES.write_bytes(gzip.compress(json.dumps(src).encode()))
    print(f"fleet table: {len(df)} templates from {len(parsed)} recordings; {len(src)} attacks kept for mixing")


def flatten(rec: dict) -> dict:
    """An evtx JSON record to the flat field layout the OTRF recordings use."""
    ev = rec.get("Event", rec)
    sysd = ev.get("System", {})
    eid = sysd.get("EventID")
    if isinstance(eid, dict):
        eid = eid.get("#text")
    tc = sysd.get("TimeCreated", {})
    ts = tc.get("#attributes", {}).get("SystemTime") if isinstance(tc, dict) else None
    out = {"EventID": eid, "Channel": sysd.get("Channel"), "Hostname": sysd.get("Computer"), "@timestamp": ts}
    data = ev.get("EventData") or {}
    if isinstance(data, dict):
        for k, v in data.items():
            if k == "#attributes":
                continue
            out[k] = v if not isinstance(v, (dict, list)) else json.dumps(v)
    ud = ev.get("UserData")
    if isinstance(ud, dict):
        for inner in ud.values():
            if isinstance(inner, dict):
                for k, v in inner.items():
                    if k != "#attributes" and not isinstance(v, (dict, list)):
                        out.setdefault(k, v)
    return out


def read_evtx(folder: str) -> dict[str, list[dict]]:
    from evtx import PyEvtxParser
    images = {}
    for f in sorted(Path(folder).rglob("*.evtx")):
        image = f.relative_to(folder).parts[0]
        rows = images.setdefault(image, [])
        try:
            for r in PyEvtxParser(str(f)).records_json():
                e = flatten(json.loads(r["data"]))
                if e.get("@timestamp") and logs.channel(e):
                    rows.append(e)
        except Exception as ex:  # noqa: BLE001 - a corrupt file is skipped, not fatal
            print("skipped", f, ex)
    for rows in images.values():
        rows.sort(key=lambda e: e["@timestamp"])
    return images


def parse_events(events: list[dict]) -> dict:
    tmp = ROOT / "data/.window.json"
    tmp.write_text(json.dumps(events))
    try:
        return logs.parse(tmp)
    finally:
        tmp.unlink()


def merge(benign: dict, attack: dict) -> dict:
    """Put the attack's events into the benign window, shifted to start 30% of the way into it."""
    starts = [g["first"] for g in benign["groups"].values() if g["first"] is not None]
    ends = [g["last"] for g in benign["groups"].values() if g["last"] is not None]
    a_starts = [g["first"] for g in attack["groups"].values() if g["first"] is not None]
    shift = (min(starts) + 0.3 * (max(ends) - min(starts))) - min(a_starts)
    groups = {k: {**g, "hosts": set(g["hosts"])} for k, g in benign["groups"].items()}
    for k, g in attack["groups"].items():
        g = {**g, "hosts": set(g["hosts"]),
             "first": g["first"] + shift if g["first"] is not None else None, "last": g["last"] + shift if g["last"] is not None else None}
        if k in groups:
            h = groups[k]
            h["count"] += g["count"]
            h["hosts"] |= g["hosts"]
            h["first"] = min(x for x in (h["first"], g["first"]) if x is not None)
            h["last"] = max(x for x in (h["last"], g["last"]) if x is not None)
        else:
            groups[k] = g
    hosts = dict(benign["hosts"])
    for h, n in attack["hosts"].items():
        hosts[h] = hosts.get(h, 0) + n
    return {"events": benign["events"] + attack["events"], "groups": groups, "hosts": hosts}


def build(folder: str, per_image: int = PER_IMAGE, prefix: str = "BN", out: str = "data/benign.jsonl",
          meta_out: str = "data/benign_meta.json", mix: bool = True, seed: int = 11):
    fleet = json.loads(gzip.decompress(FLEET.read_bytes()))
    df, n = Counter(fleet["templates"]), fleet["recordings"]
    sources = json.loads(gzip.decompress(SOURCES.read_bytes()))
    images = read_evtx(folder)
    rnd = random.Random(seed)
    windows = []
    for image, events in sorted(images.items()):
        if len(events) < WINDOW:
            continue
        # the original set (prefix BN) sampled any start, so two pairs of windows overlap; later sets use a grid
        step = 1 if prefix == "BN" else WINDOW
        starts = sorted(rnd.sample(range(0, len(events) - WINDOW, step), per_image))
        for s in starts:
            windows.append((image, s, parse_events(events[s:s + WINDOW])))
        print(f"{image}: {len(events)} events, {per_image} windows")
    cases, meta = [], {}
    for i, (image, s, p) in enumerate(windows, 1):
        cid = f"{prefix}-{i:02d}"
        cases.append({"case_id": cid, "dataset": f"benign:{image}", **logs.condense(p, df, n)})
        meta[cid] = {"kind": "benign", "image": image, "first_event": s}
    for i, cid in enumerate(MIX if mix else []):
        image, s, p = windows[i % len(windows)]
        mixed = merge(p, sources[cid])
        mid = f"MX-{i + 1:02d}"
        cases.append({"case_id": mid, "dataset": f"mixed:{image}", "source_case": cid, **logs.condense(mixed, df, n)})
        meta[mid] = {"kind": "mixed", "image": image, "first_event": s, "attack": cid}
    with open(ROOT / out, "w") as f:
        for c in cases:
            f.write(json.dumps(c, separators=(",", ":"), default=sorted) + "\n")
    (ROOT / meta_out).write_text(json.dumps(meta, indent=1))
    print(f"{sum(1 for c in cases if c['case_id'].startswith(prefix))} benign and {len(MIX) if mix else 0} mixed alerts -> {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--prepare", action="store_true")
    ap.add_argument("--parsed", default="")
    ap.add_argument("--evtx", default="")
    ap.add_argument("--per-image", type=int, default=PER_IMAGE)
    ap.add_argument("--prefix", default="BN")
    ap.add_argument("--out", default="data/benign.jsonl")
    ap.add_argument("--meta", default="data/benign_meta.json")
    ap.add_argument("--no-mix", action="store_true")
    ap.add_argument("--seed", type=int, default=11)
    a = ap.parse_args()
    prepare(a.parsed) if a.prepare else build(a.evtx, a.per_image, a.prefix, a.out, a.meta, not a.no_mix, a.seed)
