"""A catalog of every bundled rule with its OWASP IDs — powers ``pink-crow rules`` and the docs mapping.

Table-driven rules are pulled from :mod:`pink_crow.detectors.rules_data`; the handful of rules emitted
programmatically by the detectors are listed explicitly here so the catalog is complete.
"""

from __future__ import annotations

from typing import Any

from .detectors.rules_data import DANGEROUS_OUTPUT_RULES, INJECTION_RULES, SECRET_RULES

_PROGRAMMATIC: list[dict[str, Any]] = [
    {"rule_id": "pc.inj.invisible", "owasp_ids": ["LLM01:2026", "LLM01:2025"], "category": "prompt-injection",
     "description": "invisible / bidi / Unicode tag-block smuggling"},
    {"rule_id": "pc.inj.encoded", "owasp_ids": ["LLM01:2026", "ASI06", "LLM01:2025"], "category": "prompt-injection",
     "description": "injection payload hidden in base64/hex (second-order)"},
    {"rule_id": "pc.con.oversize", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "oversized input vs char cap"},
    {"rule_id": "pc.con.tokens", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "token-estimate flood vs token cap"},
    {"rule_id": "pc.con.repetition", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "low lexical diversity (repetition)"},
    {"rule_id": "pc.con.amplification", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "compression-bomb-like input (low zlib ratio)"},
    {"rule_id": "pc.con.charrun", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "single character repeated at length"},
    {"rule_id": "pc.con.repeat_abuse", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "'repeat forever / N times' amplification request"},
    {"rule_id": "pc.out.oversize", "owasp_ids": ["LLM06:2026", "LLM10:2025"], "category": "unbounded-consumption",
     "description": "model output too large to fully scan (egress cap exceeded)"},
    {"rule_id": "pc.sec.generic", "owasp_ids": ["LLM02:2026", "DSGAI01", "LLM02:2025"], "category": "secret-egress",
     "description": "entropy-gated generic key=value credential"},
    {"rule_id": "pc.pii.email", "owasp_ids": ["LLM02:2026", "DSGAI01", "LLM02:2025"], "category": "pii-egress",
     "description": "email address in output"},
    {"rule_id": "pc.pii.ssn", "owasp_ids": ["LLM02:2026", "DSGAI01", "LLM02:2025"], "category": "pii-egress",
     "description": "US SSN pattern in output"},
    {"rule_id": "pc.pii.card", "owasp_ids": ["LLM02:2026", "DSGAI01", "LLM02:2025"], "category": "pii-egress",
     "description": "Luhn-valid payment card in output"},
    {"rule_id": "pc.out.exfil_link", "owasp_ids": ["LLM10:2026", "DSGAI01", "LLM05:2025"], "category": "improper-output",
     "description": "markdown/autolink to a non-allowlisted host (exfil channel)"},
    {"rule_id": "pc.out.exfil_query", "owasp_ids": ["LLM10:2026", "DSGAI01", "LLM02:2026"], "category": "improper-output",
     "description": "data-in-URL exfil: high-entropy blob in a non-allowlisted URL's query/fragment (zero-click)"},
    {"rule_id": "pc.out.exfil_punycode", "owasp_ids": ["LLM10:2026", "DSGAI01"], "category": "improper-output",
     "description": "output link to an IDN/punycode homoglyph-lookalike host"},
    {"rule_id": "pc.ses.trifecta", "owasp_ids": ["LLM01:2026", "LLM02:2026", "LLM10:2026", "ASI01"], "category": "lethal-trifecta",
     "description": "lethal trifecta correlated across a session (untrusted input + sensitive data + external channel)"},
    {"rule_id": "pc.leak.canary", "owasp_ids": ["LLM08:2026", "LLM07:2025"], "category": "context-exposure",
     "description": "system-prompt canary token leaked in output"},
    {"rule_id": "pc.leak.phrase", "owasp_ids": ["LLM08:2026", "LLM07:2025"], "category": "context-exposure",
     "description": "system-prompt-leakage phrasing in output"},
    {"rule_id": "pc.leak.overlap", "owasp_ids": ["LLM08:2026", "LLM07:2025"], "category": "context-exposure",
     "description": "output overlaps the known system prompt (n-gram)"},
]


def catalog() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for rule in INJECTION_RULES + DANGEROUS_OUTPUT_RULES + SECRET_RULES:
        rows.append(
            {
                "rule_id": rule.rule_id,
                "owasp_ids": rule.owasp_ids,
                "category": rule.category,
                "description": rule.message,
                "severity": rule.severity.value,
            }
        )
    rows.extend(_PROGRAMMATIC)
    return sorted(rows, key=lambda r: r["rule_id"])
