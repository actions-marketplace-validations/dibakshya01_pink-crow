"""Policy engine — maps a session score (+ window state + findings) to a :class:`Disposition`
(action + ACS decision), per the canonical table in build-plan FR-14/FR-15.

The only ways a session *enters* cooldown are a Critical-band block or a window-cap block whose cause is
in ``policy.cooldown_on`` (default ``{critical, window_cap}``) — never a lone High-band block.
"""

from __future__ import annotations

from .config import Policy
from .models import ACSDecision, Action, Disposition, Finding, RedactionSpan
from .scoring import SessionState, window_event_count, window_score_sum


def _reason_codes(findings: list[Finding]) -> list[str]:
    return sorted({oid for f in findings for oid in f.owasp_ids})


def _arm_cooldown(policy: Policy, state: SessionState | None, now: float, cause: str) -> None:
    if state is not None and cause in policy.cooldown_on and policy.cooldown_window > 0:
        state.cooldown_until = now + policy.cooldown_window


def evaluate(
    policy: Policy,
    session_score: float,
    state: SessionState | None,
    findings: list[Finding],
    redactions: list[RedactionSpan],
    now: float,
) -> Disposition:
    codes = _reason_codes(findings)

    # already in cooldown -> refuse without re-scoring
    if state is not None and state.cooldown_until > now:
        return Disposition(
            Action.COOLDOWN, ACSDecision.DENY, codes,
            f"session in cooldown for {state.cooldown_until - now:.0f}s more",
        )

    # sliding-window hard override (flood/burst)
    if state is not None:
        ws = policy.scoring.window_seconds
        # count only RISKY events (score > 0) toward the flood cap, so a benign chat burst is not blocked
        if policy.window_event_cap and window_event_count(state, now, ws, min_score=0.0) > policy.window_event_cap:
            _arm_cooldown(policy, state, now, "window_cap")
            return Disposition(Action.BLOCK, ACSDecision.DENY, codes, "risky-event window cap exceeded")
        if policy.window_score_cap and window_score_sum(state, now, ws) > policy.window_score_cap:
            _arm_cooldown(policy, state, now, "window_cap")
            return Disposition(Action.BLOCK, ACSDecision.DENY, codes, "risk-rate window cap exceeded")

    # score bands
    if session_score >= policy.critical_at:
        _arm_cooldown(policy, state, now, "critical")
        return Disposition(Action.BLOCK, ACSDecision.DENY, codes, f"critical risk score {session_score:.0f}")
    if session_score >= policy.block_at:
        _arm_cooldown(policy, state, now, "high")  # armed only if 'high' in cooldown_on (not by default)
        return Disposition(Action.BLOCK, ACSDecision.ASK, codes, f"high risk score {session_score:.0f}")
    if session_score >= policy.flag_at:
        if redactions:
            return Disposition(Action.REDACT, ACSDecision.MODIFY, codes, "elevated; sensitive content redacted")
        return Disposition(Action.FLAG, ACSDecision.ALLOW, codes, f"elevated risk score {session_score:.0f}")

    # low band
    if redactions:
        return Disposition(Action.REDACT, ACSDecision.MODIFY, codes, "sensitive content redacted")
    if findings:
        return Disposition(Action.FLAG, ACSDecision.ALLOW, codes, "low-severity signal(s) present")
    return Disposition(Action.ALLOW, ACSDecision.ALLOW, [], "")


def fail_closed(policy: Policy, reason: str) -> Disposition:
    """FR-16: on a scan/store error, never silently allow (unless explicitly configured fail-open)."""
    if policy.fail_mode == "open":
        return Disposition(Action.ALLOW, ACSDecision.ALLOW, ["pink-crow:fail-open"],
                           f"scan error, fail-open: {reason}")
    return Disposition(Action.BLOCK, ACSDecision.DENY, ["pink-crow:fail-closed"],
                       f"scan error, fail-closed: {reason}")
