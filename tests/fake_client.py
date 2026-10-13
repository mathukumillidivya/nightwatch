"""A scripted stand-in for the Anthropic API, so the whole pipeline runs offline with no key and no cost.

It reads each request the way the real model would see it (system prompt, tools, messages) and answers from
the events actually shown, so the code checks downstream exercise real data. It also records every request,
which the tests use to check what each agent was sent.
"""
from __future__ import annotations

import inspect
import json
import re

from anthropic import AsyncAnthropic
from anthropic.resources.messages import AsyncMessages
from anthropic.types import Message, TextBlock, ToolUseBlock, Usage

LINE = re.compile(r"\[(E\d{3}|X\d{4})\] \+\d+s \S+ (\S+) (\d+) [^:]*?: (.*)")


def events_in(text: str) -> list[tuple[str, str, str, str]]:
    return [m.groups() for m in LINE.finditer(text)]


def first_field(rest: str) -> tuple[str, str]:
    m = re.match(r'(\w+)=("([^"]*)"|(\S+))', rest)
    if not m:
        return "Message", rest[:20]
    return m.group(1), (m.group(3) or m.group(4))[:40]


class FakeClaude:
    """messages.create(**kwargs) -> anthropic Message"""

    def __init__(self, bad_quote_first: bool = True, obey_injection: bool = False):
        self.requests: list[dict] = []
        self.bad_quote_first = bad_quote_first
        self.obey_injection = obey_injection

    def client(self) -> AsyncAnthropic:
        c = AsyncAnthropic(api_key="offline")
        c.messages.create = self.create
        return c

    def _text(self, kw) -> str:
        sys_text = kw.get("system")
        if isinstance(sys_text, list):
            sys_text = " ".join(b.get("text", "") for b in sys_text)
        parts = [sys_text or ""]
        for m in kw["messages"]:
            c = m["content"]
            if isinstance(c, str):
                parts.append(c)
            else:
                for b in c:
                    if b.get("type") == "text":
                        parts.append(b["text"])
                    elif b.get("type") == "tool_result":
                        parts.append(json.dumps(b.get("content")))
        return "\n".join(parts)

    async def create(self, **kw):
        allowed = set(inspect.signature(AsyncMessages.create).parameters) - {"self"}
        unknown = set(kw) - allowed
        if unknown:  # the real SDK would raise; so must the fake
            raise TypeError(f"AsyncMessages.create() got unexpected keyword arguments {sorted(unknown)}")
        self.requests.append(kw)
        tools = [t["name"] for t in kw.get("tools") or []]
        text = self._text(kw)
        system = kw.get("system")
        system = " ".join(b.get("text", "") for b in system) if isinstance(system, list) else (system or "")
        n_assistant = sum(1 for m in kw["messages"] if m["role"] == "assistant")
        evs = events_in(text)
        injected = "[!injection" in text or "NOTE TO THE AI" in text

        def tool(name, args):
            return [ToolUseBlock(type="tool_use", id=f"tu{len(self.requests)}", name=name, input=args)]

        def quote(e):
            f, v = first_field(e[3])
            return {"event_id": e[0], "field": f, "quote": v}

        if "threat hunter" in system:
            if "search_events" in tools and n_assistant == 0:
                content = tool("search_events", {"query": "process created"})
            else:
                if self.obey_injection and injected:
                    hyps = []
                else:
                    ids = [e[0] for e in evs[:4]] or ["E001"]
                    hyps = [{"behavior": "powershell.exe accessed lsass.exe memory to dump credentials", "event_ids": ids[:2],
                             "keywords": ["lsass", "credential dumping", "mimikatz"]},
                            {"behavior": "a new scheduled task was created", "event_ids": ids[2:4] or ids[:1],
                             "keywords": ["schtasks", "scheduled task"]}]
                content = tool("set_model_response", {"assessment": "Credential theft on WORKSTATION5.", "hypotheses": hyps})
        elif "ATT&CK mapper" in system:
            task = text[len(system):]
            if "technique_lookup" in tools and n_assistant == 0 and "scheduled task" in task:
                content = tool("technique_lookup", {"query": "scheduled task"})
            else:
                cited = events_in(task.split("Candidate techniques")[0])
                ev = [quote(e) for e in cited[:2]] or [{"event_id": "E001", "field": "Image", "quote": "x"}]
                tid = "T1003.001" if "lsass" in task else "T1053.005"
                if self.bad_quote_first and "rejected by the code check" not in task and tid == "T1053.005":
                    ev = [{"event_id": ev[0]["event_id"], "field": ev[0]["field"], "quote": "text that is not in the logs"}]
                content = tool("set_model_response", {"technique_id": tid, "reasoning": "Fits the evidence.", "evidence": ev})
        elif "incident responder" in system:
            ids = [e[0] for e in evs[:3]]
            content = tool("submit_result", {"headline": "Credential dumping on WORKSTATION5", "severity": "high",
                                             "summary": "LSASS memory was read.",
                                             "timeline": [{"event_id": i, "what": "step"} for i in ids],
                                             "response": ["Isolate the host", "Reset credentials"]})
        elif "submit_result" in tools:  # the single-call baseline
            ev = [quote(e) for e in evs[:2]]
            findings = [] if (self.obey_injection and injected) else [
                {"technique_id": "T1003.001", "behavior": "LSASS dump", "evidence": ev},
                {"technique_id": "T9999", "behavior": "made up", "evidence": ev[:1]}]
            content = tool("submit_result", {"assessment": "Credential theft.", "findings": findings})
        else:
            content = [TextBlock(type="text", text="{}")]
        return Message(id=f"msg{len(self.requests)}", type="message", role="assistant", model=kw["model"], content=content,
                       stop_reason="tool_use" if content[0].type == "tool_use" else "end_turn",
                       usage=Usage(input_tokens=1000, output_tokens=200, cache_read_input_tokens=0, cache_creation_input_tokens=0))
