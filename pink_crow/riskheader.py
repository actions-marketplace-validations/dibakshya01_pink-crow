"""The ``X-PinkCrow-Risk`` header — a compact, single-line summary appended to every scanned
input/output so the risk score can travel with the chat message.

Format (header-safe, no newlines):
    ``v=1; score=73.0; event=73.0; action=block; acs=ask; ewma=73.0; codes=LLM01:2026,LLM08:2026``
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import ScanResult

HEADER_NAME = "X-PinkCrow-Risk"


def build_header(result: ScanResult) -> str:
    codes = ",".join(result.disposition.reason_codes)
    parts = [
        "v=1",
        f"score={result.session_score:.1f}",
        f"event={result.event_score:.1f}",
        f"action={result.disposition.action.value}",
        f"acs={result.disposition.acs_decision.value}",
        f"ewma={result.ewma:.1f}",
    ]
    if codes:
        parts.append(f"codes={codes}")
    return "; ".join(parts)


def parse_header(value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in value.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            out[k.strip()] = v.strip()
    return out
