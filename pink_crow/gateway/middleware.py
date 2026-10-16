"""Pure-ASGI middleware (build-plan FR-19).

Deliberately NOT Starlette's ``BaseHTTPMiddleware`` — that buffers the whole response and breaks SSE /
streaming. This implements the raw ASGI ``__call__(scope, receive, send)`` contract: it buffers only the
*request* body, scans a configured JSON field, appends the ``X-PinkCrow-Risk`` header to the response, and
(optionally) short-circuits with 403 when the disposition blocks — all while leaving the response body
streaming untouched.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, Callable

from ..engine import Engine
from ..riskheader import HEADER_NAME


class PinkCrowMiddleware:
    def __init__(
        self,
        app: Callable,
        engine: Engine | None = None,
        *,
        field: str | tuple[str, ...] = "message",
        session_field: str = "session_id",
        enforce: bool = False,
        paths: tuple[str, ...] | None = None,
    ) -> None:
        self.app = app
        self.engine = engine or Engine()
        self.fields = (field,) if isinstance(field, str) else tuple(field)
        self.session_field = session_field
        self.enforce = enforce
        self.paths = paths  # if set, only scan (and enforce on) these path prefixes

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] != "http" or (self.paths and not scope["path"].startswith(self.paths)):
            await self.app(scope, receive, send)
            return

        body = await _read_body(receive)
        header_value = ""
        blocked = False
        text = _extract_any(body, self.fields)
        if text is not None:
            sid = _extract_any(body, (self.session_field,))
            # run the (synchronous) scan off the event loop so one request can't stall all connections
            res = await asyncio.get_event_loop().run_in_executor(
                None, lambda: self.engine.scan_input(text, session_id=sid if isinstance(sid, str) else None)
            )
            header_value = res.risk_header
            blocked = res.blocked
        elif self.enforce:
            # fail-closed: on a matched path we could not find anything to scan (non-JSON, missing field,
            # empty body) — refuse rather than silently passing an unscannable request through.
            await _respond_403(send, "v=1; action=block; reason=unscannable-body")
            return

        if blocked and self.enforce:
            await _respond_403(send, header_value)
            return

        # re-emit the buffered body once, then delegate to the real receive (so the downstream app's
        # disconnect listener sees http.disconnect instead of looping forever on a replayed body).
        delivered = False

        async def receive_again() -> dict:
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        async def send_wrapper(message: dict) -> None:
            if message["type"] == "http.response.start" and header_value:
                headers = list(message.get("headers", []))
                headers.append((HEADER_NAME.encode("latin-1"), header_value.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive_again, send_wrapper)


async def _read_body(receive: Callable) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            break
    return b"".join(chunks)


def _extract_any(body: bytes, fields: tuple[str, ...]) -> Any:
    """Return the first present string among ``fields`` of a JSON object body, else None."""
    if not body:
        return None
    try:
        data = json.loads(body)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    for f in fields:
        v = data.get(f)
        if v is not None:
            return v
    return None


async def _respond_403(send: Callable, header_value: str) -> None:
    payload = json.dumps({"error": "blocked_by_pink_crow", "risk": header_value}).encode()
    headers = [(b"content-type", b"application/json")]
    if header_value:
        headers.append((HEADER_NAME.encode("latin-1"), header_value.encode("latin-1")))
    await send({"type": "http.response.start", "status": 403, "headers": headers})
    await send({"type": "http.response.body", "body": payload, "more_body": False})
