"""Offline tests: no API key, no cost. The model is the scripted FakeClaude."""
import asyncio
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fake_client import FakeClaude  # noqa: E402
from nightwatch import attack, guard, logs, verify  # noqa: E402
from nightwatch.agents import case_message, investigate  # noqa: E402
from nightwatch.models import Claude, cost  # noqa: E402
from scripts.redteam import PAYLOADS, plant  # noqa: E402

CASES = {json.loads(l)["case_id"]: json.loads(l) for l in open(ROOT / "data/cases.jsonl")}
LABELS = json.loads((ROOT / "data/labels.json").read_text())


def run(coro):
    return asyncio.run(coro)


# --- triage


def test_templates_mask_variable_parts():
    a = logs.template("Sysmon", 1, [("CommandLine", "rundll32 {4F2B1C3E-1111-2222-3333-444455556666} 0x1f3a pid 4412 tmp_a8f3k2")])
    b = logs.template("Sysmon", 1, [("CommandLine", "rundll32 {9A9A9A9A-0000-1111-2222-333344445555} 0x0001 pid 9031 tmp_77zq1x")])
    assert a == b


def test_every_case_has_a_view_and_no_labels():
    for c in CASES.values():
        assert 10 <= len(c["view"]) <= 60
        text = json.dumps(c)
        assert "techniques" not in text and "T1003" not in c.get("dataset", "")
    assert set(CASES) == set(LABELS)


def test_split_keeps_datasets_together():
    split = json.loads((ROOT / "data/split.json").read_text())
    dev = {LABELS[c]["dataset"] for c in split["dev"]}
    test = {LABELS[c]["dataset"] for c in split["test"]}
    assert not dev & test


# --- ATT&CK


def test_attack_search_and_revocations():
    assert attack.search("DsGetNCChanges replication 1131f6aa directory 4662 mimikatz", 3)[0]["id"] == "T1003.006"
    assert attack.current("T1562.002") == "T1685.001"  # moved in ATT&CK v19
    assert attack.get("T9999") is None


# --- verification


def test_quotes_must_be_in_the_cited_event():
    case = CASES["NW-002"]
    r = case["view"][0]
    field, value = next(iter(r["fields"].items()))
    ok = verify.check_mapping(case, {"technique_id": "T1003.006", "evidence": [{"event_id": r["id"], "field": field, "quote": value[:25]}]})
    assert ok["verified"] and not ok["problems"]
    bad = verify.check_mapping(case, {"technique_id": "T1003.006", "evidence": [{"event_id": r["id"], "field": field, "quote": "mimikatz sekurlsa"}]})
    assert not bad["verified"] and "does not appear" in bad["problems"][0]
    fake_id = verify.check_mapping(case, {"technique_id": "T1999.999", "evidence": [{"event_id": r["id"], "field": field, "quote": value[:25]}]})
    assert not fake_id["verified"]


# --- guardrails


def test_scanner_flags_planted_text_but_not_real_logs():
    assert guard.scan(PAYLOADS["suppress"]) and guard.scan(PAYLOADS["misdirect"])
    assert not guard.scan(PAYLOADS["evasive"])  # by design: the other defences have to hold
    flagged = [r for c in CASES.values() for r in c["view"] + c["index"] if guard.scan_event(r["fields"])]
    assert flagged == []


def test_unguarded_message_has_no_fence():
    c = plant(CASES["NW-002"], "suppress")
    assert guard.FENCE_OPEN in case_message(c) and "[!injection" in case_message(c)
    assert guard.FENCE_OPEN not in case_message(c, guarded=False)


# --- the pipeline, offline


def test_pipeline_end_to_end():
    fake = FakeClaude()
    r = run(investigate(CASES["NW-002"], "nightwatch", Claude(client=fake.client()), want_report=True))
    kinds = [s["kind"] for s in r["trace"]]
    assert "retrieval" in kinds and "verify" in kinds and "verdict" in kinds
    assert "reverify" in kinds  # the fake misquotes once; code sends it back to a fresh mapper
    assert r["techniques"] == ["T1003.001", "T1053.005"]
    assert all(e["ok"] for f in r["verdict"]["findings"] for e in f["evidence"])
    assert r["report"]["severity"] == "high"
    agents = set(r["usage"])
    assert {"hunter", "mapper", "reporter"} <= agents and cost(r["usage"]) > 0
    hunter_calls = [q for q in fake.requests if "threat hunter" in json.dumps(q.get("system"))]
    assert len(hunter_calls) == 2 and guard.RULE in json.dumps(hunter_calls[0]["system"])


def test_baseline_invented_ids_are_caught():
    r = run(investigate(CASES["NW-002"], "single_call", Claude(client=FakeClaude().client())))
    assert r["techniques"] == ["T1003.001"]  # T9999 is not a technique; it is dropped and counted
    assert any(not f["valid_id"] for f in r["checked"])


def test_unguarded_prompts_drop_the_rule():
    fake = FakeClaude()
    run(investigate(plant(CASES["NW-002"], "suppress"), "nightwatch", Claude(client=fake.client()), guarded=False))
    assert all(guard.RULE not in json.dumps(q.get("system")) for q in fake.requests)


def test_code_owns_the_verdict():
    """A hunter that obeys an injection and returns nothing yields no findings, never a prose 'benign' verdict."""
    r = run(investigate(plant(CASES["NW-002"], "suppress"), "nightwatch", Claude(client=FakeClaude(obey_injection=True).client())))
    assert r["techniques"] == [] and r["verdict"]["findings"] == []


@pytest.mark.parametrize("cid", ["NW-002", "NW-050"])
def test_search_tool_budget(cid):
    from nightwatch.agents import CASES as LIVE, HUNTER_SEARCHES, search_events

    class Ctx:
        def __init__(self):
            self.state = {"case_id": cid}
    LIVE[cid] = CASES[cid]
    ctx = Ctx()
    out = [search_events("powershell", ctx) for _ in range(HUNTER_SEARCHES + 1)]
    assert "events" in out[0] and "error" in out[-1]
