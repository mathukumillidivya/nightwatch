"""Nightwatch: a team of agents that investigates a Windows host recording and maps it to MITRE ATT&CK.

Built as a Google Agent Development Kit (ADK 2) Workflow graph:

  START ─▶ hunter ─▶ retrieval ─▶ mapper ×N ─▶ verify ─▶ report
           LLM+tool   code (BM25)   LLM, parallel   code      LLM, optional
                                    worker per      └─ failed mappings go back once to a fresh mapper (dynamic node)
                                    hypothesis

- Triage (before the graph): `logs.py` has reduced thousands of events to a view of about 60 unusual ones and an
  index of about 600 more.
- Hunter: reads the view, can search the index, returns up to three ranked hypotheses, each citing events.
- Retrieval: code searches the ATT&CK knowledge base (BM25) with each hypothesis and writes each mapper's brief.
- Mappers: one per hypothesis, in parallel. Each picks one technique, from the candidates or through its own lookup
  tool, and quotes the log fields that prove it.
- Verify: code checks every technique id and every quote; a failure is sent back once with the reason; code ranks
  the verified findings. Unverified claims never reach the result.
- Report: writes the incident ticket from verified findings only (on demand); code checks its event ids.

`single_call` is the baseline: one model call with the same view and the same instructions.
"""
from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from typing import AsyncGenerator, Literal

from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.agents.context_cache_config import ContextCacheConfig
from google.adk.agents.readonly_context import ReadonlyContext
from google.adk.apps import App
from google.adk.events import Event, EventActions
from google.adk.workflow import START, FunctionNode, Workflow
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.tools.tool_context import ToolContext
from google.genai import types
from pydantic import BaseModel, Field

from . import attack, guard, logs, verify
from .models import Claude, add_usage, usage_of

MAX_HYPOTHESES = 3
HUNTER_SEARCHES = 3
MAPPER_LOOKUPS = 1

# ----------------------------------------------------------------------------------------------- what agents return


class Hypothesis(BaseModel):
    behavior: str = Field(description="What the adversary did, concretely: which process or account did what to what.")
    event_ids: list[str] = Field(description="2 to 6 event ids (E### or X####) that show it.")
    keywords: list[str] = Field(description="3 to 8 terms to look the behavior up in ATT&CK: tools, commands, APIs, concepts.")


class Hunt(BaseModel):
    assessment: str = Field(description="One or two sentences: what happened on these hosts.")
    hypotheses: list[Hypothesis] = Field(description="1 to 3 distinct adversary behaviors, most important first.")


class Evidence(BaseModel):
    event_id: str = Field(description="The event id, e.g. E014 or X0213.")
    field: str = Field(description="The field name, e.g. CommandLine.")
    quote: str = Field(description="Text copied exactly from that field, long enough to be specific.")


class Mapping(BaseModel):
    technique_id: str = Field(description="ATT&CK technique id such as T1003.006, or 'none' if this is not adversary behavior.")
    reasoning: str = Field(description="Two or three sentences: why this technique, and why not the nearest alternative.")
    evidence: list[Evidence] = Field(description="1 to 4 quotes from the logs that prove it.")


class BaselineFinding(BaseModel):
    technique_id: str = Field(description="ATT&CK technique id such as T1003.006.")
    behavior: str = Field(description="What the adversary did.")
    evidence: list[Evidence] = Field(description="1 to 4 quotes from the logs that prove it.")


class BaselineAnswer(BaseModel):
    assessment: str = Field(description="One or two sentences: what happened on these hosts.")
    findings: list[BaselineFinding] = Field(description="1 to 3 techniques, most important first.")


class TimelineEntry(BaseModel):
    event_id: str
    what: str


class Report(BaseModel):
    headline: str = Field(description="One line for the incident queue.")
    severity: Literal["critical", "high", "medium", "low"]
    summary: str = Field(description="Three to five sentences for the incident ticket.")
    timeline: list[TimelineEntry] = Field(description="The key events in order, each tied to an event id.")
    response: list[str] = Field(description="Two to five concrete containment or follow-up actions.")


# ------------------------------------------------------------------------------------------------------- prompts

TASK = """You are working a Security Operations Center alert. Each recording captures Windows hosts in a small
lab domain while an operator ran one adversary action (sometimes a short sequence). The surrounding events are
normal background: Windows services, updates, telemetry, logons.

Rank by the operator's objective, not the means. Encoded PowerShell launchers, C2 agents beaconing, stagers and
in-memory loading of a tool (for example mimikatz or PowerView) are how the operator acts; the technique under
investigation is what that tool or command was used to do: whose credentials were taken and how, which object or
setting was changed, what was enumerated, where the operator moved, what was made to persist. Delivery and
execution belong first only when nothing else happened."""

HUNTER = f"""{TASK}

You are the threat hunter. You get a triage view: the most unusual event templates in the recording, rare across
the fleet, each collapsed with a count. Each event has an id (E###). A wider index of several hundred more
templates (ids X####) can be searched with the search_events tool, up to {HUNTER_SEARCHES} times. Search when the
view hints at something you cannot see in full: the command that started a process, what a suspicious process
did next, activity on the domain controller.

Return up to {MAX_HYPOTHESES} hypotheses, each a distinct adversary behavior, most important first. Keep each
behavior to one sentence naming the process or account, the action and the target. Cite at most five events.
Background noise is not a hypothesis. Give a few ATT&CK-style keywords for each so it can be looked up."""

MAPPER = f"""{TASK}

You are the ATT&CK mapper. The hunter has proposed one adversary behavior. Map it to the single best MITRE
ATT&CK Enterprise technique (v19). Prefer the most specific sub-technique the evidence supports. Candidates
retrieved from ATT&CK are listed in the brief; you may call technique_lookup once if none fits. If the behavior
is not adversary activity after all, answer "none".

Give one or two sentences of reasoning. Cite one to three pieces of evidence as short exact quotes (under 80
characters) copied from the log fields shown. Code checks every quote against the logs and rejects anything that
is not there."""

BASELINE = f"""{TASK}

Read the triage view: the most unusual event templates in the recording, rare across the fleet, each collapsed
with a count. Identify up to {MAX_HYPOTHESES} adversary techniques as MITRE ATT&CK Enterprise technique ids
(ATT&CK v19), most important first. Prefer the most specific sub-technique the evidence supports. Keep each
behavior to one sentence. For each, cite one to three short exact quotes (under 80 characters) copied from the
log fields shown."""

REPORTER = """You are the incident responder writing the ticket for this alert. Use only the verified findings and
the events below; every timeline entry must name one of these event ids. Be specific and brief. Severity: critical
for domain-wide credential theft or domain controller compromise, high for credential access, lateral movement or
persistence, medium for defense evasion or execution, low for discovery alone."""

# --------------------------------------------------------------------------------------------- rendering the logs

def mark(r: dict) -> str:
    flagged = guard.scan_event(r["fields"])
    return logs.line(r) + (f"  [!injection: {', '.join(flagged)}]" if flagged else "")


def render(rows: list[dict], guarded: bool = True) -> str:
    lines = [mark(r) if guarded else logs.line(r) for r in rows]
    body = "\n".join(lines)
    return f"{guard.FENCE_OPEN}\n{body}\n{guard.FENCE_CLOSE}" if guarded else body


def case_message(case: dict, guarded: bool = True) -> str:
    view = sorted(case["view"] + case.get("planted", []), key=lambda r: r["t"])
    hosts = ", ".join(f"{h} ({n:,} events)" for h, n in sorted(case["hosts"].items(), key=lambda x: -x[1]))
    return (f"Alert {case['case_id']}. The recording holds {case['events']:,} events from: {hosts}. They collapse into "
            f"{case['templates']:,} templates; these {len(view)} are the most unusual.\n\n{render(view, guarded)}")


# ---------------------------------------------------------------------------------------------------- tools

CASES: dict[str, dict] = {}


def _case(tool_context: ToolContext) -> dict:
    return CASES[tool_context.state["case_id"]]


def search_events(query: str, tool_context: ToolContext) -> dict:
    """Search all events in this recording (the triage view and the wider index) for words or a phrase.

    Args:
        query: Words to look for, e.g. "lsass", "schtasks /create", "4662", "HKLM\\SYSTEM\\CurrentControlSet\\Services".
    """
    used = tool_context.state.get("searches", 0)
    if used >= HUNTER_SEARCHES:
        return {"error": "Search budget used up. Give your answer now."}
    tool_context.state["searches"] = used + 1
    case = _case(tool_context)
    terms = [t for t in re.split(r"\s+", query.lower().strip()) if t]
    phrase = query.lower().strip()
    scored = []
    for r in case["view"] + case["index"] + case.get("planted", []):
        text = logs.line(r).lower()
        s = (5 if phrase in text else 0) + sum(1 for t in terms if t in text)
        if s:
            scored.append((s, -r["score"], r))
    scored.sort(key=lambda x: (-x[0], x[1]))
    hits = [r for _, _, r in scored[:8]]
    guarded = tool_context.state.get("guarded", True)
    return {"matches": len(scored), "events": render(sorted(hits, key=lambda r: r["t"]), guarded) if hits else "no matches"}


def technique_lookup(query: str, tool_context: ToolContext) -> dict:
    """Search the MITRE ATT&CK Enterprise knowledge base.

    Args:
        query: What the adversary did, or a technique name or id, e.g. "dump credentials from lsass memory".
    """
    used = tool_context.state.get("lookups", 0)  # shared by the parallel mappers
    if used >= MAPPER_LOOKUPS * MAX_HYPOTHESES:
        return {"error": "Lookup budget used up. Give your answer now."}
    tool_context.state["lookups"] = used + 1
    q = query.strip()
    hits = [attack.get(q)] if re.fullmatch(r"T\d{4}(\.\d{3})?", q.upper()) and attack.get(q) else None
    found = [{"id": attack.current(q.upper())}] if hits else attack.search(q, 6)
    return {"techniques": [attack.card(h["id"], 300, 200) for h in found[:4]]}


# ------------------------------------------------------------------------------------------- the workflow


def _usage_callback(callback_context, llm_response):
    """Each model call's usage under its own key, so parallel workers never overwrite each other."""
    u = usage_of(llm_response)
    if u:
        callback_context.state[f"usage:{callback_context.agent_name}:{uuid.uuid4().hex[:10]}"] = u
    return None


def _with_rule(text: str):
    """The untrusted-data rule is part of every prompt unless the guardrails are switched off (red-team ablation)."""
    def build(ctx: ReadonlyContext) -> str:
        return f"{text}\n\n{guard.RULE}" if ctx.state.get("guarded", True) else text
    return build


def _agents(model: Claude) -> dict[str, LlmAgent]:
    def common(max_tokens: int, cache: bool = False):
        return dict(model=model.variant(max_tokens=max_tokens, cache=cache), after_model_callback=_usage_callback,
                    generate_content_config=types.GenerateContentConfig(temperature=0))
    return {
        "hunter": LlmAgent(name="hunter", instruction=_with_rule(HUNTER), tools=[search_events], output_schema=Hunt,
                           **common(1200, cache=True)),
        "mapper": LlmAgent(name="mapper", instruction=_with_rule(MAPPER), tools=[technique_lookup], output_schema=Mapping,
                           parallel_worker=True, **common(700)),
        "fixer": LlmAgent(name="mapper_retry", instruction=_with_rule(MAPPER), tools=[technique_lookup], output_schema=Mapping,
                          **common(700)),
        "reporter": LlmAgent(name="reporter", instruction=_with_rule(REPORTER), output_schema=Report, **common(1200)),
        "single_call": LlmAgent(name="single_call", instruction=_with_rule(BASELINE), output_schema=BaselineAnswer,
                                **common(1500)),
    }


def step(kind: str, **data) -> Event:
    """A code step, recorded in the event stream like an agent turn (no model call)."""
    return Event(actions=EventActions(state_delta={"_step": {"kind": kind, **data}}))


def _plan(ctx: Context, node_input: Hunt) -> list[str]:
    """Retrieval (code): look each hypothesis up in ATT&CK and write the mapper's brief."""
    case = CASES[ctx.state["case_id"]]
    guarded = ctx.state.get("guarded", True)
    events = verify.events_by_id(case)
    hyps = [h.model_dump() for h in node_input.hypotheses[:MAX_HYPOTHESES]]
    tasks, cands = [], []
    for i, h in enumerate(hyps):
        cited = [events[x] for x in h["event_ids"] if x in events][:6]
        found = [c["id"] for c in attack.search(" ".join([h["behavior"]] + h["keywords"] * 2), 5)]
        cands.append(found)
        tasks.append(f"Hypothesis {i + 1} from the hunter: {h['behavior']}\n\nEvents it cites:\n"
                     f"{render(cited, guarded) if cited else '(none of the cited ids exist)'}\n\n"
                     "Candidate techniques from ATT&CK:\n\n" + "\n\n".join(attack.card(c, 400, 250) for c in found))
    ctx.state["hunt"] = {"assessment": node_input.assessment, "hypotheses": hyps}
    ctx.state["tasks"] = tasks
    ctx.state["_step"] = {"kind": "retrieval", "candidates": cands}
    return tasks


def _make_check(fixer: LlmAgent):
    async def check(ctx: Context, node_input: list) -> dict:
        """Verify (code) every mapping; send each failure back once; rank what survives."""
        case = CASES[ctx.state["case_id"]]
        events = verify.events_by_id(case)
        hyps = ctx.state["hunt"]["hypotheses"]
        tasks = ctx.state["tasks"]
        results = []
        for i, m in enumerate(node_input):
            m = m if isinstance(m, dict) else (m.model_dump() if hasattr(m, "model_dump") else {})
            results.append({"mapping": m, "check": verify.check_mapping(case, m, events), "attempts": 1})
        retry = [i for i, r in enumerate(results) if r["check"]["problems"]]
        yield step("verify", results=[r["check"] for r in results], retry=retry)
        for i in retry:
            brief = (tasks[i] + "\n\nYour previous answer was rejected by the code check:\n- " + "\n- ".join(results[i]["check"]["problems"])
                     + f"\nYour previous answer: {json.dumps(results[i]['mapping'])[:800]}\nFix it: copy quotes exactly from the "
                     "event fields shown, and use a current ATT&CK technique id.")
            again = await ctx.run_node(fixer, brief)
            m = again if isinstance(again, dict) else (again.model_dump() if hasattr(again, "model_dump") else {})
            results[i] = {"mapping": m, "check": verify.check_mapping(case, m, events), "attempts": 2}
            yield step("reverify", slot=i, result=results[i]["check"])
        findings, seen = [], set()
        for i in verify.rank_slots([r["check"]["technique_id"] for r in results]):  # verified findings only
            r = results[i]
            c = r["check"]
            if c["verified"] and c["technique_id"] not in seen:
                seen.add(c["technique_id"])
                t = attack.get(c["technique_id"])
                findings.append({"technique_id": c["technique_id"], "name": t["name"], "parent": t.get("parent_name"),
                                 "tactics": t["tactics"], "behavior": hyps[i]["behavior"], "slot": i,
                                 "reasoning": r["mapping"].get("reasoning"), "evidence": [e for e in c["evidence"] if e["ok"]],
                                 "attempts": r["attempts"]})
        unverified = [{"slot": i, "technique_id": r["mapping"].get("technique_id"), "problems": r["check"]["problems"]}
                      for i, r in enumerate(results) if not r["check"]["verified"] and not r["check"]["declined"]]
        verdict = {"assessment": ctx.state["hunt"]["assessment"], "findings": findings, "unverified": unverified,
                   "declined": [i for i, r in enumerate(results) if r["check"]["declined"]], "hypotheses": hyps,
                   "retried": retry}
        ctx.state["verdict"] = verdict
        yield step("verdict", techniques=[f["technique_id"] for f in findings], unverified=len(unverified))
        yield verdict
    return check


def _make_report(reporter: LlmAgent):
    async def report(ctx: Context, node_input: dict) -> dict:
        """Reporter (optional): the ticket, written from verified findings only; code checks its event ids."""
        findings = node_input.get("findings") or []
        if not ctx.state.get("want_report") or not findings:
            yield node_input
            return
        case = CASES[ctx.state["case_id"]]
        events = verify.events_by_id(case)
        ids = sorted({e["event_id"] for f in findings for e in f["evidence"]}
                     | {x for h in node_input["hypotheses"] for x in h["event_ids"] if x in events})
        rows = sorted((events[x] for x in ids if x in events), key=lambda r: r["t"])
        brief = ("Verified findings:\n" + "\n".join(f"- {f['technique_id']} {f['name']} ({', '.join(f['tactics'])}): {f['behavior']}"
                                                     for f in findings)
                 + f"\n\nHunter's assessment: {node_input['assessment']}\n\nEvents:\n{render(rows, ctx.state.get('guarded', True))}")
        rep = await ctx.run_node(reporter, brief)
        rep = rep if isinstance(rep, dict) else (rep.model_dump() if hasattr(rep, "model_dump") else {})
        rep["unknown_event_ids"] = [t.get("event_id") for t in rep.get("timeline") or [] if t.get("event_id") not in events]
        ctx.state["report"] = rep
        yield step("report_check", unknown_event_ids=rep["unknown_event_ids"])
        yield node_input
    return report


def build(system: str, model: Claude):
    """The ADK root: a Workflow graph for Nightwatch, a single LlmAgent for the baseline."""
    a = _agents(model)
    if system == "single_call":
        return a["single_call"]
    plan = FunctionNode(func=_plan, name="retrieval")
    check = FunctionNode(func=_make_check(a["fixer"]), name="verify", rerun_on_resume=True)
    report = FunctionNode(func=_make_report(a["reporter"]), name="report", rerun_on_resume=True)
    return Workflow(name="nightwatch", edges=[(START, a["hunter"]), (a["hunter"], plan), (plan, a["mapper"]),
                                              (a["mapper"], check), (check, report)])


# ----------------------------------------------------------------------------------------------- running a case


def summarize_event(e: Event, t0: float) -> dict | None:
    """One trace step per ADK event, for the run record and the live page."""
    t = round(time.time() - t0, 2)
    step = (e.actions.state_delta or {}).get("_step") if e.actions else None
    if step:
        return {"t": t, "agent": "code", **step}
    if not e.content or not e.content.parts:
        return None
    out = {"t": t, "agent": e.author}
    for p in e.content.parts:
        if p.function_call:
            return {**out, "kind": "tool_call", "tool": p.function_call.name, "args": dict(p.function_call.args or {})}
        if p.function_response:
            resp = p.function_response.response or {}
            return {**out, "kind": "tool_result", "tool": p.function_response.name,
                    "result": {k: (v[:3000] if isinstance(v, str) else v) for k, v in resp.items()}}
        if p.text and e.author in AGENT_NAMES:
            try:
                return {**out, "kind": "output", "output": json.loads(p.text)}
            except json.JSONDecodeError:
                return {**out, "kind": "text", "text": p.text[:2000]} if p.text.strip() else None
    return None


AGENT_NAMES = {"hunter", "mapper", "mapper_retry", "reporter", "single_call"}


def total_usage(state: dict) -> dict:
    out = {}
    for k, v in state.items():
        if k.startswith("usage:"):
            add_usage(out, k.split(":")[1].replace("_retry", ""), v)
    return out


async def investigate(case: dict, system: str, model: Claude, guarded: bool = True, want_report: bool = False,
                      on_step=None) -> dict:
    CASES[case["case_id"]] = case
    root = build(system, model)
    app = App(name="nightwatch", root_agent=root,
              context_cache_config=ContextCacheConfig(min_tokens=1024, ttl_seconds=300, cache_intervals=20))
    sessions = InMemorySessionService()
    runner = Runner(app=app, session_service=sessions)
    sid = uuid.uuid4().hex
    await sessions.create_session(app_name=app.name, user_id="soc", session_id=sid,
                                  state={"case_id": case["case_id"], "guarded": guarded, "want_report": want_report})
    msg = types.Content(role="user", parts=[types.Part(text=case_message(case, guarded))])
    t0 = time.time()
    trace = []
    async for e in runner.run_async(user_id="soc", session_id=sid, new_message=msg):
        s = summarize_event(e, t0)
        if s:
            trace.append(s)
            if on_step:
                r = on_step(s)
                if asyncio.iscoroutine(r):
                    await r
    state = (await sessions.get_session(app_name=app.name, user_id="soc", session_id=sid)).state
    seconds = round(time.time() - t0, 1)
    usage = total_usage(state)
    if system == "nightwatch":
        verdict = state.get("verdict") or {"findings": [], "unverified": []}
        return {"techniques": [f["technique_id"] for f in verdict["findings"]], "verdict": verdict,
                "report": state.get("report"), "trace": trace, "usage": usage, "seconds": seconds}
    answer = next((s["output"] for s in reversed(trace) if s.get("agent") == "single_call" and s.get("kind") == "output"),
                  {"findings": []})
    events = verify.events_by_id(case)
    checked = []
    for f in answer.get("findings") or []:
        tid, _ = verify.check_technique(f.get("technique_id"))
        ev = verify.check_evidence(case, f.get("evidence") or [], events)
        checked.append({"technique_id": tid or f.get("technique_id"), "valid_id": bool(tid), "behavior": f.get("behavior"),
                        "evidence": ev, "verified": bool(tid and any(e["ok"] for e in ev))})
    ranked, ranked_verified = [], []
    for f in checked:  # as answered: valid ids, in order
        if f["valid_id"] and f["technique_id"] not in ranked:
            ranked.append(f["technique_id"])
    for i in verify.rank_slots([f["technique_id"] if f["verified"] else None for f in checked]):
        f = checked[i]  # with Nightwatch's code layer applied: evidence check and the same ranking policy
        if f["verified"] and f["technique_id"] not in ranked_verified:
            ranked_verified.append(f["technique_id"])
    return {"techniques": ranked, "techniques_verified": ranked_verified, "answer": answer, "checked": checked, "trace": trace,
            "usage": usage, "seconds": seconds}
