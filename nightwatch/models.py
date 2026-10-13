"""The model behind every agent: Claude through Google ADK's native Anthropic adapter, plus two additions.

1. Structured output without tools. ADK's Claude adapter only enforces an agent's output schema when the agent also
   has tools (through ADK's set_model_response tool). For a tool-less agent this adapter offers Claude one tool whose
   input schema is the output schema and forces Claude to call it, so the reply is always schema-valid JSON.
2. Cost accounting. Every response's token usage is recorded per agent, split into fresh input, cache writes, cache
   reads and output, and priced.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, AsyncGenerator

from anthropic import NOT_GIVEN
from google.adk.models.anthropic_llm import AnthropicLlm
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import ValidationError

MODEL = os.environ.get("NIGHTWATCH_MODEL", "claude-haiku-4-5-20251001")
SUBMIT = "submit_result"

# US$ per million tokens: fresh input, cache write, cache read, output
PRICES = {
    "claude-haiku-4-5": (1.0, 1.25, 0.10, 5.0),
    "claude-sonnet-4-5": (3.0, 3.75, 0.30, 15.0),
    "claude-sonnet-4-6": (3.0, 3.75, 0.30, 15.0),
    "claude-3-5-haiku": (0.8, 1.0, 0.08, 4.0),
    "claude-3-haiku": (0.25, 0.30, 0.03, 1.25),
}


def price(model: str) -> tuple[float, float, float, float]:
    for k, v in PRICES.items():
        if model.startswith(k):
            return v
    return PRICES["claude-haiku-4-5"]


def cost(usage: dict, model: str = MODEL) -> float:
    p = price(model)
    return sum(u.get("input", 0) * p[0] + u.get("cache_write", 0) * p[1] + u.get("cache_read", 0) * p[2]
               + u.get("output", 0) * p[3] for u in usage.values()) / 1e6


def _schema(llm_request: LlmRequest) -> dict | None:
    cfg = llm_request.config
    if not cfg:
        return None
    s = getattr(cfg, "response_json_schema", None) or getattr(cfg, "response_schema", None)
    if s is None:
        return None
    if isinstance(s, type) and hasattr(s, "model_json_schema"):
        return s.model_json_schema()
    if isinstance(s, dict):
        return s
    if hasattr(s, "model_dump"):
        return s.model_dump(exclude_none=True)
    return None


def unstring(args: dict) -> dict:
    """Claude occasionally sends a nested list or object as a JSON string; decode those before validation."""
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and v.strip()[:1] in ("[", "{"):
            for text in (v, re.sub(r'\\(?![\\/"bfnrtu])', r"\\\\", v)):  # Windows paths often arrive with bare backslashes
                try:
                    v = json.loads(text, strict=False)
                    break
                except json.JSONDecodeError:
                    continue
        out[k] = v
    return out


class Claude(AnthropicLlm):
    """Claude with schema-forced output for tool-less agents."""

    model: str = MODEL
    max_tokens: int = 2048
    cache: bool = True  # prompt caching pays only for agents that call the model several times on one prefix

    def _build_anthropic_kwargs(self, llm_request, messages, tools, tool_choice, thinking) -> dict[str, Any]:
        kwargs = super()._build_anthropic_kwargs(llm_request, messages, tools, tool_choice, thinking)
        schema = _schema(llm_request)
        if schema is not None and kwargs.get("tools") in (None, NOT_GIVEN):
            kwargs["tools"] = [{"name": SUBMIT, "description": "Return your result in this exact structure.",
                                "input_schema": schema}]
            kwargs["tool_choice"] = {"type": "tool", "name": SUBMIT}
        kwargs["max_tokens"] = self.max_tokens
        # The current SDK no longer takes sampling settings as arguments; the API still honours them for this model.
        sampling = {k: kwargs.pop(k) for k in ("temperature", "top_p", "top_k") if k in kwargs}
        if sampling:
            kwargs["extra_body"] = {**(kwargs.get("extra_body") or {}), **sampling}
        return kwargs

    def variant(self, **changes) -> "Claude":
        """The same model and client with different settings (max_tokens, cache) for one agent."""
        return self.model_copy(update=changes)

    async def generate_content_async(self, llm_request: LlmRequest, stream: bool = False) -> AsyncGenerator[LlmResponse, None]:
        if not self.cache:
            llm_request.cache_config = None
        cfg = llm_request.config
        model_cls = getattr(cfg, "response_schema", None) if cfg else None
        model_cls = model_cls if isinstance(model_cls, type) and hasattr(model_cls, "model_validate_json") else None
        spent = None
        for attempt in range(2):
            response = None
            async for response in super().generate_content_async(llm_request, stream=False):
                pass
            problem = None
            parts = (response.content.parts if response and response.content else None) or []
            for i, part in enumerate(parts):
                if part.function_call and part.function_call.name == SUBMIT:
                    text = json.dumps(unstring(part.function_call.args or {}))
                    parts[i] = types.Part(text=text)
                    if model_cls:
                        try:
                            model_cls.model_validate_json(text)
                        except ValidationError as e:
                            problem = "; ".join(f"{'.'.join(map(str, x['loc']))}: {x['msg']}" for x in e.errors()[:3])
            spent = _add_meta(spent, response.usage_metadata if response else None)
            if not problem or attempt == 1:
                if response is not None:
                    response.usage_metadata = spent
                    yield response
                return
            # one validation retry, as structured-output libraries do: say what was wrong and ask again
            llm_request.contents = list(llm_request.contents or []) + [types.Content(role="user", parts=[types.Part(
                text=f"Your answer did not match the required structure ({problem}). Answer again with the {SUBMIT} "
                     "tool, giving every field, with lists as real JSON lists.")])]


def _add_meta(a, b):
    """Sum two usage records, so a validation retry is still billed in the ledger."""
    if a is None or b is None:
        return b if a is None else a
    out = a.model_copy()
    for k in ("prompt_token_count", "candidates_token_count", "total_token_count", "cached_content_token_count",
              "thoughts_token_count"):
        setattr(out, k, (getattr(a, k) or 0) + (getattr(b, k) or 0))
    object.__setattr__(out, "cache_creation_input_tokens",
                       (getattr(a, "cache_creation_input_tokens", 0) or 0) + (getattr(b, "cache_creation_input_tokens", 0) or 0))
    return out


def usage_of(llm_response: LlmResponse) -> dict:
    u = llm_response.usage_metadata
    if not u:
        return {}
    read = u.cached_content_token_count or 0
    write = getattr(u, "cache_creation_input_tokens", None) or 0
    prompt = u.prompt_token_count or 0
    return {"input": max(prompt - read - write, 0), "cache_read": read, "cache_write": write,
            "output": (u.candidates_token_count or 0) + (u.thoughts_token_count or 0), "calls": 1}


def add_usage(total: dict, agent: str, u: dict) -> None:
    t = total.setdefault(agent, {})
    for k, v in u.items():
        t[k] = t.get(k, 0) + v
