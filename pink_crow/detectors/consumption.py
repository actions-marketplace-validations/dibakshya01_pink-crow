"""LLM06:2026 Unbounded Consumption detector.

Metric-based (length / token estimate / repetition / compression ratio / char-run) plus a "repeat
forever / N times" phrasing rule. Metrics are computed on a bounded sample so the detector itself can't
be turned into a DoS. OWASP sets no numeric thresholds — these come from the policy's :class:`ScanConfig`.
"""

from __future__ import annotations

from ..models import Finding, Severity
from ..signals import estimate_tokens, max_char_run, repetition_ratio, zlib_ratio
from .base import ScanContext
from .rules_data import REPEAT_ABUSE_RE

_METRIC_SAMPLE = 200_000  # cap the sample fed to O(n) metrics
_IDS_2026 = ["LLM06:2026"]
_IDS_2025 = ["LLM10:2025"]


def _f(rule_id: str, sev: Severity, msg: str, conf: float = 1.0) -> Finding:
    return Finding(
        rule_id=rule_id,
        owasp_ids=_IDS_2026 + _IDS_2025,
        category="unbounded-consumption",
        severity=sev,
        message=msg,
        confidence=conf,
    )


class ConsumptionDetector:
    name = "consumption"
    direction = "input"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        cfg = ctx.config
        findings: list[Finding] = []
        n = ctx.full_len
        sample = ctx.text[:_METRIC_SAMPLE]

        if cfg.max_input_chars and n > cfg.max_input_chars and ctx.rule_enabled("pc.con.oversize"):
            sev = Severity.HIGH if n > 2 * cfg.max_input_chars else Severity.MEDIUM
            findings.append(_f("pc.con.oversize", sev, f"oversized input: {n} chars (cap {cfg.max_input_chars})"))

        tokens = estimate_tokens(sample)
        if cfg.max_tokens and tokens > cfg.max_tokens and ctx.rule_enabled("pc.con.tokens"):
            sev = Severity.HIGH if tokens > 2 * cfg.max_tokens else Severity.MEDIUM
            findings.append(_f("pc.con.tokens", sev, f"token flood: ~{tokens} tokens (cap {cfg.max_tokens})"))

        if n >= 200 and ctx.rule_enabled("pc.con.repetition"):
            rr = repetition_ratio(sample)
            if rr < cfg.min_repetition_ratio:
                findings.append(
                    _f("pc.con.repetition", Severity.MEDIUM, f"low lexical diversity (unique-word ratio {rr:.2f})", 0.8)
                )

        if n >= 256 and ctx.rule_enabled("pc.con.amplification"):
            zr = zlib_ratio(sample)
            if zr < cfg.min_zlib_ratio:
                sev = Severity.HIGH if zr < cfg.min_zlib_ratio / 2 else Severity.MEDIUM
                findings.append(_f("pc.con.amplification", sev, f"compression-bomb-like input (zlib ratio {zr:.3f})", 0.85))

        if ctx.rule_enabled("pc.con.charrun"):
            run = max_char_run(sample)
            if run >= 2000:
                findings.append(_f("pc.con.charrun", Severity.MEDIUM, f"single character repeated {run}x", 0.8))

        if ctx.rule_enabled("pc.con.repeat_abuse") and REPEAT_ABUSE_RE.search(ctx.scan_text):
            m = REPEAT_ABUSE_RE.search(ctx.scan_text)
            findings.append(
                Finding(
                    rule_id="pc.con.repeat_abuse",
                    owasp_ids=_IDS_2026 + _IDS_2025,
                    category="unbounded-consumption",
                    severity=Severity.HIGH,
                    message="'repeat forever / N times' amplification request",
                    span=m.span() if m else None,
                )
            )

        return findings
