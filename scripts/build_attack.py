"""Extract the ATT&CK Enterprise knowledge base from the official STIX bundle.

Usage: python scripts/build_attack.py <enterprise-attack.json>

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def ext(x):
    for r in x.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")


def main():
    bundle = json.loads(Path(sys.argv[1]).read_text())
    objs = bundle["objects"]
    by = {o["id"]: o for o in objs}
    version = next(o.get("x_mitre_version") for o in objs if o["type"] == "x-mitre-collection")
    tactics = {o["x_mitre_shortname"]: {"id": ext(o), "name": o["name"]} for o in objs if o["type"] == "x-mitre-tactic"}
    live = {o["id"]: o for o in objs if o["type"] == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    parents, detections, revoked = {}, {}, {}
    for r in objs:
        if r["type"] != "relationship":
            continue
        s, t = by.get(r["source_ref"]), by.get(r["target_ref"])
        if not s or not t:
            continue
        if r["relationship_type"] == "subtechnique-of":
            parents[s["id"]] = t
        elif r["relationship_type"] == "detects" and t["id"] in live:
            detections.setdefault(t["id"], []).append(s)
        elif r["relationship_type"] == "revoked-by" and s["type"] == "attack-pattern":
            revoked[ext(s)] = ext(t)
    techniques = {}
    for oid, o in live.items():
        det, sources = [], set()
        for strat in detections.get(oid, []):
            det.append(strat["name"] + ".")
            for a in strat.get("x_mitre_analytic_refs", []):
                an = by.get(a)
                if not an or "Windows" not in an.get("x_mitre_platforms", []):
                    continue
                det.append(an.get("description", ""))
                for ls in an.get("x_mitre_log_source_references", []):
                    sources.add(f"{ls.get('name')} {ls.get('channel')}")
        p = parents.get(oid)
        techniques[ext(o)] = {
            "name": o["name"], "parent_name": p["name"] if p else None, "description": o.get("description", ""),
            "tactics": [tactics[k["phase_name"]]["name"] for k in o.get("kill_chain_phases", []) if k["phase_name"] in tactics],
            "platforms": o.get("x_mitre_platforms", []), "detection": det, "log_sources": sorted(sources)}
    out = {"version": version, "notice": "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission "
           "of The MITRE Corporation.", "tactics": tactics, "techniques": techniques, "revoked": revoked}
    (ROOT / "data/attack.json").write_text(json.dumps(out, separators=(",", ":")))
    print(f"ATT&CK v{version}: {len(techniques)} techniques, {len(revoked)} revoked ids mapped")


if __name__ == "__main__":
    main()
