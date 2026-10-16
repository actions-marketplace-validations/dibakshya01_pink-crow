"""Thin, duck-typed wrapper for an OpenAI-style chat client (build-plan FR-20).

Mirrors the Preflight -> Input -> Output staging of a guardrailed client with a tripwire:
scan the outgoing messages, call the wrapped client, then scan the completion text. The ``openai`` package
is NOT a dependency — any object exposing ``chat.completions.create(...)`` works, which keeps the core
dependency-free and makes testing trivial.

    from openai import OpenAI
    from pink_crow.integrations.openai import GuardedOpenAI

    client = GuardedOpenAI(OpenAI(), session_id="user-42")
    resp = client.chat.completions.create(model="gpt-4o", messages=[...])   # raises on injection/egress
"""

from __future__ import annotations

from typing import Any

from ..engine import Engine
from ..models import ScanResult
from .guard import PinkCrowTripwire, _default_engine


def _last_user_text(messages: list[dict]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user":
            content = m.get("content", "")
            if isinstance(content, str):
                return content
            if isinstance(content, list):  # content-parts form
                return " ".join(p.get("text", "") for p in content if isinstance(p, dict))
    return ""


def _completion_text(resp: Any) -> str:
    try:
        choices = resp.choices if hasattr(resp, "choices") else resp["choices"]
        first = choices[0]
        msg = first.message if hasattr(first, "message") else first["message"]
        content = msg.content if hasattr(msg, "content") else msg["content"]
        return content or ""
    except (AttributeError, KeyError, IndexError, TypeError):
        return ""


class _Completions:
    def __init__(self, parent: GuardedOpenAI) -> None:
        self._p = parent

    def create(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        eng, sid = self._p._engine, self._p._session_id
        # input stage
        in_res = eng.scan_input(_last_user_text(messages), session_id=sid)
        if self._p._enforce and in_res.blocked:
            raise PinkCrowTripwire(in_res)
        # model call
        resp = self._p._client.chat.completions.create(*args, **kwargs)
        # output stage
        out_res = eng.scan_output(_completion_text(resp), session_id=sid)
        if self._p._enforce and out_res.blocked:
            raise PinkCrowTripwire(out_res)
        self._p.last_input_result = in_res
        self._p.last_output_result = out_res
        return resp


class _Chat:
    def __init__(self, parent: GuardedOpenAI) -> None:
        self.completions = _Completions(parent)


class GuardedOpenAI:
    """Wraps any client exposing ``chat.completions.create``; scans input + output with a tripwire."""

    def __init__(
        self,
        client: Any,
        *,
        session_id: str | None = None,
        engine: Engine | None = None,
        enforce: bool = True,
    ) -> None:
        self._client = client
        self._session_id = session_id
        self._engine = engine or _default_engine()
        self._enforce = enforce
        self.last_input_result: ScanResult | None = None
        self.last_output_result: ScanResult | None = None
        self.chat = _Chat(self)

    def __getattr__(self, name: str) -> Any:
        # delegate everything else (embeddings, models, ...) to the wrapped client
        return getattr(self._client, name)
