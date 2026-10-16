"""Agent Control Standard (ACS) v0.1.0 emission.

Turns a :class:`~pink_crow.models.ScanResult` into an ACS-shaped ``response-envelope`` dict whose
``decision`` is one of ``allow``/``deny``/``modify``/``ask``/``defer``. ``reasoning`` is always included on
a non-allow decision (ACS requires it). pink-crow is deliberately **fail-closed**, so ``ask``/``defer``
carry a ``deny`` timeout — unlike ACS's own fail-open default.

Reference: https://github.com/GenAI-Security-Project/agent-control-standard (v0.1.0).
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any

from .models import ACSDecision

if TYPE_CHECKING:
    from .models import ScanResult

ACS_VERSION = "0.1.0"


def to_envelope(result: ScanResult) -> dict[str, Any]:
    d = result.disposition
    decision = d.acs_decision.value
    env: dict[str, Any] = {
        "acs_version": ACS_VERSION,
        "request_id": str(uuid.uuid4()),      # replay protection
        "timestamp": result.occurred_at,
        "decision": decision,
        "reason_codes": list(d.reason_codes),
        "policy_data": {
            "source": "pink-crow",
            "direction": result.direction,
            "event_score": result.event_score,
            "session_score": result.session_score,
            "action": d.action.value,
        },
    }
    # reasoning: REQUIRED on deny/modify/ask/defer, recommended on allow
    if decision != ACSDecision.ALLOW.value or d.reasoning:
        env["reasoning"] = d.reasoning or "pink-crow risk assessment"

    if decision == ACSDecision.MODIFY.value:
        env["modifications"] = {
            "parameter_overrides": {},
            "redactions": [r.to_dict() for r in result.redactions],
            "redacted_text": result.redacted_text,
        }
    elif decision == ACSDecision.ASK.value:
        env["ask_details"] = {
            "approvers": [],
            "prompt": d.reasoning or "pink-crow flagged elevated session risk; approve to proceed.",
            "timeout_disposition": "deny",   # fail-closed
        }
    elif decision == ACSDecision.DEFER.value:
        env["defer_details"] = {
            "timeout_decision": "deny",       # fail-closed
            "resolve_when": ["scorer_available"],
        }
    return env
