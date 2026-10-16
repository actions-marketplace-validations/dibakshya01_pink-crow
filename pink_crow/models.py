"""Core data models shared across pink-crow.

Everything here is a plain dataclass / enum with ``to_dict`` for JSON — no third-party deps, fully
inspectable. A :class:`Finding` is one detected signal mapped to OWASP IDs; a :class:`ScanResult` is the
outcome of scanning one chat event (input or output), carrying the event score, the cumulative session
score, the findings, and the resulting :class:`Disposition`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Per-severity base contribution to an event score (0–100 scale), before confidence weighting.
SEVERITY_SCORE: dict[Severity, float] = {
    Severity.INFO: 2.0,
    Severity.LOW: 8.0,
    Severity.MEDIUM: 22.0,
    Severity.HIGH: 48.0,
    Severity.CRITICAL: 90.0,
}


class Action(str, Enum):
    """What pink-crow's policy engine decides to do (build-plan FR-14).

    ``COOLDOWN`` is the user-facing "session time-out"; it is named distinctly from ACS's approver
    timeout to avoid the overloaded term.
    """

    ALLOW = "allow"
    FLAG = "flag"
    REDACT = "redact"
    BLOCK = "block"
    COOLDOWN = "cooldown"


class ACSDecision(str, Enum):
    """Agent Control Standard v0.1.0 dispositions (the ``decision`` field)."""

    ALLOW = "allow"
    DENY = "deny"
    MODIFY = "modify"
    ASK = "ask"
    DEFER = "defer"


@dataclass
class Finding:
    """One detected signal. ``score`` is this finding's 0–100 contribution; if left at 0 it is derived
    from ``severity`` × ``confidence``. ``owasp_ids`` dual-emits both edition IDs where a crosswalk
    exists (e.g. ``["LLM06:2026", "LLM10:2025"]``)."""

    rule_id: str
    owasp_ids: list[str]
    category: str
    severity: Severity
    message: str
    score: float = 0.0
    span: tuple[int, int] | None = None
    evidence: str = ""
    confidence: float = 1.0

    def __post_init__(self) -> None:
        if not isinstance(self.severity, Severity):
            self.severity = Severity(self.severity)
        if self.score <= 0.0:
            self.score = round(SEVERITY_SCORE[self.severity] * self.confidence, 2)
        self.score = max(0.0, min(100.0, self.score))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "owasp_ids": list(self.owasp_ids),
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "score": self.score,
            "span": list(self.span) if self.span else None,
            "evidence": self.evidence,
            "confidence": self.confidence,
        }


@dataclass
class RedactionSpan:
    """Location (in the *original* text) and label of a redaction. The mask length may differ from the
    original, so offsets are reported against the original, not preserved in the masked string."""

    start: int
    end: int
    label: str

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "label": self.label}


@dataclass
class Disposition:
    action: Action
    acs_decision: ACSDecision
    reason_codes: list[str] = field(default_factory=list)
    reasoning: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "acs_decision": self.acs_decision.value,
            "reason_codes": list(self.reason_codes),
            "reasoning": self.reasoning,
        }


@dataclass
class ScanResult:
    """Outcome of scanning one chat event."""

    session_id: str | None
    direction: str  # "input" | "output"
    event_score: float
    session_score: float
    ewma: float
    findings: list[Finding]
    disposition: Disposition
    redacted_text: str
    redactions: list[RedactionSpan] = field(default_factory=list)
    occurred_at: float = 0.0

    @property
    def blocked(self) -> bool:
        return self.disposition.action in (Action.BLOCK, Action.COOLDOWN)

    @property
    def risk_header(self) -> str:
        """The ``X-PinkCrow-Risk`` header value for this result."""
        from .riskheader import build_header

        return build_header(self)

    def to_acs(self) -> dict[str, Any]:
        """Emit an ACS v0.1.0 response-envelope dict (see :mod:`pink_crow.acs`)."""
        from .acs import to_envelope

        return to_envelope(self)

    def explain(self) -> str:
        lines = [
            f"pink-crow {self.direction} scan"
            + (f" (session {self.session_id})" if self.session_id else ""),
            f"  event score   : {self.event_score:.1f}/100",
            f"  session score : {self.session_score:.1f}/100  (ewma {self.ewma:.1f})",
            f"  disposition   : {self.disposition.action.value}"
            f"  ->  ACS:{self.disposition.acs_decision.value}",
        ]
        if self.disposition.reasoning:
            lines.append(f"  reasoning     : {self.disposition.reasoning}")
        if self.findings:
            lines.append(f"  findings ({len(self.findings)}):")
            for f in sorted(self.findings, key=lambda x: x.score, reverse=True):
                ids = ",".join(f.owasp_ids)
                lines.append(
                    f"    - [{f.severity.value:<8}] {f.score:5.1f}  {f.rule_id}  ({ids})  {f.message}"
                )
        else:
            lines.append("  findings      : none")
        if self.redactions:
            lines.append(f"  redactions    : {len(self.redactions)}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "direction": self.direction,
            "event_score": self.event_score,
            "session_score": self.session_score,
            "ewma": self.ewma,
            "findings": [f.to_dict() for f in self.findings],
            "disposition": self.disposition.to_dict(),
            "redacted_text": self.redacted_text,
            "redactions": [r.to_dict() for r in self.redactions],
            "occurred_at": self.occurred_at,
        }
