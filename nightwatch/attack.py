"""The MITRE ATT&CK knowledge base: every current Enterprise technique, searchable with BM25.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

`scripts/build_attack.py` extracts data/attack.json from the official STIX bundle (ATT&CK v19). Each technique
document is its name, its parent's name, its description and the descriptions and log sources of the analytics
ATT&CK publishes to detect it (for example "WinEventLog:Security EventCode=4662").
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from rank_bm25 import BM25Okapi

ROOT = Path(__file__).resolve().parent.parent
STOP = set("""a an the of to and or in on for by with from as is are be been was were may can could this that these those
it its into via use used using adversaries adversary such other also which their they than not if when will within
any all e g i e""".split())


def tokens(text: str) -> list[str]:
    out = []
    for t in re.findall(r"[a-z0-9_.$-]+", text.lower()):
        t = t.strip(".-")
        if len(t) < 2 or t in STOP:
            continue
        out.append(t)
        if "." in t or "-" in t:  # lsass.exe -> lsass, exe as well
            out += [p for p in re.split(r"[.-]", t) if len(p) > 1 and p not in STOP]
    return out


@lru_cache(maxsize=1)
def kb() -> dict:
    data = json.loads((ROOT / "data/attack.json").read_text())
    techs = data["techniques"]
    ids = sorted(techs)
    docs = []
    for t in ids:
        x = techs[t]
        name = f"{x['name']} {x.get('parent_name') or ''}"
        docs.append(tokens(" ".join([name] * 3 + [x["description"], " ".join(x["detection"]), " ".join(x["log_sources"])])))
    return {"ids": ids, "techniques": techs, "tactics": data["tactics"], "revoked": data["revoked"], "bm25": BM25Okapi(docs),
            "version": data["version"]}


def current(tid: str) -> str:
    """Follow ATT&CK's revoked-by links (v19 moved, for example, T1562.002 to T1685.001)."""
    seen = set()
    rev = kb()["revoked"]
    while tid in rev and tid not in seen:
        seen.add(tid)
        tid = rev[tid]
    return tid


def parent(tid: str) -> str:
    return tid.split(".")[0]


def get(tid: str) -> dict | None:
    return kb()["techniques"].get(current(tid))


def search(query: str, k: int = 8, platform: str | None = "Windows") -> list[dict]:
    K = kb()
    scores = K["bm25"].get_scores(tokens(query))
    order = sorted(range(len(scores)), key=lambda i: -scores[i])
    out = []
    for i in order:
        if scores[i] <= 0 or len(out) >= k:
            break
        t = K["ids"][i]
        x = K["techniques"][t]
        if platform and platform not in x["platforms"]:
            continue
        out.append({"id": t, "name": x["name"] if not x.get("parent_name") else f"{x['parent_name']}: {x['name']}",
                    "tactics": x["tactics"], "score": round(float(scores[i]), 2)})
    return out


def card(tid: str, chars: int = 900, det_chars: int = 500) -> str:
    """A short reference card for one technique, as the mapper agent reads it."""
    x = get(tid)
    if not x:
        return f"{tid}: not an ATT&CK Enterprise technique"
    name = x["name"] if not x.get("parent_name") else f"{x['parent_name']}: {x['name']}"
    desc = re.sub(r"\(Citation:[^)]*\)", "", x["description"])
    desc = re.sub(r"\s+", " ", desc).strip()
    det = " ".join(x["detection"])[:det_chars]
    return (f"{current(tid)} {name} [{', '.join(x['tactics'])}]\n{desc[:chars]}{' …' if len(desc) > chars else ''}\n"
            f"How ATT&CK detects it: {det}{' …' if len(' '.join(x['detection'])) > det_chars else ''}")
