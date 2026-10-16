"""LLM01:2026 Prompt Injection detector (with ASI01/ASI06 edges).

Runs the injection rule table across every normalized variant of the text (so an obfuscated payload still
matches), flags invisible/bidi/tag-block smuggling as signals in their own right, and does a bounded
*second-order* scan of decoded base64/hex payloads. Provenance-aware: the same phrasing in retrieved or
tool content is scored higher than in a user turn, because its prior of malice is higher.
"""

from __future__ import annotations

from ..models import SEVERITY_SCORE, Finding, Severity
from .base import ScanContext
from .rules_data import INJECTION_RULES, Rule

_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
_PROVENANCE_SCALE = 1.35  # non-user channels: scale the score up (and bump severity)


def _bump(sev: Severity, steps: int = 1) -> Severity:
    i = min(len(_ORDER) - 1, _ORDER.index(sev) + steps)
    return _ORDER[i]


def _provenance_steps(provenance: str) -> int:
    # Indirect injection: non-user channels carry a higher prior of malice.
    return 1 if provenance in ("retrieved", "tool") else 0


def _find_span(text: str, rule: Rule) -> tuple[int, int] | None:
    m = rule.pattern.search(text)
    return m.span() if m else None


class InjectionDetector:
    name = "injection"
    direction = "input"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        steps = _provenance_steps(ctx.provenance)

        # 1. rule table across all normalized variants (dedupe by rule)
        for rule in INJECTION_RULES:
            if not ctx.rule_enabled(rule.rule_id):
                continue
            if any(rule.pattern.search(v) for v in ctx.variants):
                base = rule.score if rule.score > 0 else round(SEVERITY_SCORE[rule.severity] * rule.confidence, 2)
                if steps:
                    sev = _bump(rule.severity, steps)
                    score = min(100.0, base * _PROVENANCE_SCALE)
                else:
                    sev = rule.severity
                    score = base
                span = _find_span(ctx.scan_text, rule)
                msg = rule.message + (f" (in {ctx.provenance} content)" if steps else "")
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        owasp_ids=rule.owasp_ids,
                        category=rule.category,
                        severity=sev,
                        message=msg,
                        span=span,
                        score=score,
                        confidence=rule.confidence,
                    )
                )

        # 2. invisible / bidi / tag-block smuggling as signals in their own right
        if ctx.invisible_count and ctx.rule_enabled("pc.inj.invisible"):
            if "tag-block" in ctx.invisible_kinds:
                sev, conf = Severity.HIGH, 0.95
                why = "invisible Unicode tag-block characters (high-signal smuggling)"
            elif "bidi" in ctx.invisible_kinds:
                sev, conf = Severity.HIGH, 0.8
                why = "bidirectional override characters (Trojan-Source style)"
            elif "zero-width" in ctx.invisible_kinds:
                sev, conf = Severity.MEDIUM, 0.7
                why = "zero-width / invisible characters"
            else:
                sev, conf = Severity.LOW, 0.5
                why = "variation-selector characters"
            findings.append(
                Finding(
                    rule_id="pc.inj.invisible",
                    owasp_ids=["LLM01:2026", "LLM01:2025"],
                    category="prompt-injection",
                    severity=_bump(sev, steps) if steps else sev,
                    message=f"{why} x{ctx.invisible_count} ({', '.join(ctx.invisible_kinds)})",
                    confidence=conf,
                )
            )

        # 3. second-order: scan decoded base64/hex payloads (re-normalized, and one layer deeper) for
        #    the same injection rules — catches base64-of-obfuscated and double-encoded payloads.
        if ctx.rule_enabled("pc.inj.encoded"):
            encoded = _scan_decoded(ctx.decoded, depth=2)
            if encoded is not None:
                kind, msg, span = encoded
                findings.append(
                    Finding(
                        rule_id="pc.inj.encoded",
                        owasp_ids=["LLM01:2026", "ASI06", "LLM01:2025"],
                        category="prompt-injection",
                        severity=Severity.HIGH,
                        message=f"injection payload hidden in {kind} encoding ({msg})",
                        span=span,
                        confidence=0.9,
                    )
                )

        return findings


def _scan_decoded(decoded, depth: int):
    """Return (kind, rule_message, span) if any decoded payload (re-normalized) matches an injection
    rule, peeling up to ``depth`` encoding layers. Bounded by the decoder's own candidate/size caps."""
    from ..signals import decode_candidates, normalized_variants

    for dec in decoded:
        for variant in normalized_variants(dec.text):
            hit = next((r for r in INJECTION_RULES if r.pattern.search(variant)), None)
            if hit is not None:
                return dec.kind, hit.message, dec.span
        if depth > 1:
            inner = _scan_decoded(decode_candidates(dec.text), depth - 1)
            if inner is not None:
                return f"{dec.kind}+{inner[0]}", inner[1], dec.span
    return None
