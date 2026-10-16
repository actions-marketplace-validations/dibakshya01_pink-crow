"""Lethal-trifecta session correlation (cross-event signal).

A single prompt or response is rarely the whole story. The real danger in an agentic session is the
*co-occurrence* of three capabilities inside one trust context — what Simon Willison named the
**lethal trifecta** (and Meta's "Rule of Two" inverts):

  1. exposure to **untrusted** content (the indirect-injection surface),
  2. access to **sensitive** data (secrets / PII / hidden context), and
  3. an **external** communication channel (an exfiltration path).

Any one leg alone is usually benign; all three together is the pattern behind real-world agent data
exfiltration. A per-prompt classifier cannot see this — the legs light up on *different* turns. A
*session* scorer can. pink-crow records which legs a session has lit (each with a last-seen timestamp,
so a leg decays out of a quiet session within ``trifecta_window``) and emits a correlation finding when
two or three are active at once: CRITICAL when the full trifecta is assembled, MEDIUM at two legs.

This operationalizes the defensible conclusion from the prompt-injection research program: injection's
*integrity* consequences can be contained, but its *confidentiality* consequences must be **managed** by
never letting the trifecta assemble in one context — so the most useful thing a runtime monitor can do is
notice, and score, the moment it does.
"""

from __future__ import annotations

from .models import Finding, Severity
from .scoring import SessionState

# Leg identifiers (stable; surfaced in the finding message and stored on the session).
LEG_UNTRUSTED = "untrusted-input"
LEG_SENSITIVE = "sensitive-data"
LEG_EXTERNAL = "external-channel"

# A finding in one of these categories lights the SENSITIVE leg (secrets / PII / system-prompt exposure).
_SENSITIVE_CATEGORIES = frozenset({"secret-egress", "pii-egress", "context-exposure"})
# These rule ids are genuine external egress channels (not every "improper-output" is one — e.g. a shell
# or SQL construct is dangerous but not itself a network channel).
_EXTERNAL_RULES = frozenset({"pc.out.exfil_link", "pc.out.exfil_query", "pc.out.exfil_punycode"})

RULE_ID = "pc.ses.trifecta"


def legs_for_event(direction: str, provenance: str, findings: list[Finding]) -> set[str]:
    """Which trifecta legs this single event lights.

    UNTRUSTED: an input turn carrying retrieved/tool content (the indirect-injection surface), or any
    turn that produced a prompt-injection finding. SENSITIVE: any secret/PII/context-exposure finding.
    EXTERNAL: any output exfiltration-channel finding.
    """
    legs: set[str] = set()
    if direction == "input" and provenance in ("retrieved", "tool"):
        legs.add(LEG_UNTRUSTED)
    for f in findings:
        if f.category == "prompt-injection":
            legs.add(LEG_UNTRUSTED)
        if f.category in _SENSITIVE_CATEGORIES:
            legs.add(LEG_SENSITIVE)
        if f.rule_id in _EXTERNAL_RULES:
            legs.add(LEG_EXTERNAL)
    return legs


def correlate(
    state: SessionState,
    direction: str,
    provenance: str,
    findings: list[Finding],
    now: float,
    window: float,
    *,
    enabled: bool = True,
) -> Finding | None:
    """Update ``state.trifecta_legs`` from this event and return a correlation :class:`Finding` when two
    or more legs are active within ``window`` seconds, else ``None``.

    Mutates ``state`` (lights this event's legs, prunes expired ones). A ``window <= 0`` makes legs
    permanent for the life of the session. Only meaningful for session scans (the caller passes a real
    ``SessionState``); stateless scans never correlate.
    """
    if not enabled:
        return None

    for leg in legs_for_event(direction, provenance, findings):
        state.trifecta_legs[leg] = now

    active = {
        leg: ts
        for leg, ts in state.trifecta_legs.items()
        if window <= 0 or (now - ts) <= window
    }
    state.trifecta_legs = active  # drop expired legs so a quiet session relaxes

    n = len(active)
    if n < 2:
        return None

    names = " + ".join(sorted(active))
    if n >= 3:
        return Finding(
            rule_id=RULE_ID,
            owasp_ids=["LLM01:2026", "LLM02:2026", "LLM10:2026", "ASI01"],
            category="lethal-trifecta",
            severity=Severity.CRITICAL,
            message=(
                "lethal trifecta assembled in session: untrusted input + sensitive data + external "
                f"channel all active ({names})"
            ),
            confidence=0.9,
        )
    return Finding(
        rule_id=RULE_ID,
        owasp_ids=["LLM01:2026", "LLM02:2026"],
        category="lethal-trifecta",
        severity=Severity.MEDIUM,
        message=f"two lethal-trifecta legs active in session ({names}); one more assembles an exfil path",
        confidence=0.6,
    )
