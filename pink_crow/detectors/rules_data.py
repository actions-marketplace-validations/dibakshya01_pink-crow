"""Pattern tables, each mapped to OWASP IDs (dual-emit 2026 + 2025 per the finding.md crosswalk).

Every regex uses **bounded** quantifiers (no nested unbounded quantifiers) so it cannot backtrack
catastrophically; the Engine additionally caps input length and enforces a per-scan time budget (FR-24).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from re import Pattern

from ..models import Severity


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: Pattern
    severity: Severity
    owasp_2026: tuple[str, ...]
    owasp_2025: tuple[str, ...]
    category: str
    message: str
    confidence: float = 1.0
    score: float = 0.0  # explicit 0–100 weight; 0 => derive from severity × confidence

    @property
    def owasp_ids(self) -> list[str]:
        return list(self.owasp_2026) + list(self.owasp_2025)


# --- LLM01 Prompt Injection ----------------------------------------------------------------------

INJECTION_RULES: list[Rule] = [
    Rule(
        "pc.inj.override",
        re.compile(
            r"(?ix)\b(?:ignore|disregard|forget|override|bypass|skip|nullify|neglect|"
            r"set\s+aside|pay\s+no\s+attention\s+to|do\s+not\s+(?:follow|obey|heed))\b"
            r"[^.\n]{0,40}?\b(?:previous|prior|earlier|above|preceding|initial|original|system|all|any|your|its)\b"
            r"[^.\n]{0,25}?\b(?:instruction|instructions|prompt|prompts|rule|rules|context|message|"
            r"messages|direction|directions|command|commands|guardrail|guardrails)\b"
        ),
        Severity.HIGH,
        ("LLM01:2026", "ASI01"),
        ("LLM01:2025",),
        "prompt-injection",
        "instruction-override phrasing",
        # explicit weight: a lone, unambiguous instruction-override crosses the block band on its own
        # (adversarial-review round 1) — HIGH severity keeps it below the secret/canary CRITICAL tier.
        score=66.0,
    ),
    Rule(
        "pc.inj.safety_bypass",
        re.compile(
            r"(?ix)\b(?:ignore|bypass|disable|turn\s+off|remove|skip|drop|without|evade|disregard|forget)\b"
            r"[^.\n]{0,30}?\b(?:safety|guardrail|guardrails|filter|filters|restriction|restrictions|"
            r"content\s+policy|moderation|censorship|protections?)\b"
        ),
        Severity.HIGH,
        ("LLM01:2026",),
        ("LLM01:2025",),
        "prompt-injection",
        "safety/guardrail-bypass phrasing",
        score=66.0,  # unambiguous: a lone safety-bypass should block at defaults (adversarial-review round 2)
    ),
    Rule(
        "pc.inj.persona",
        re.compile(
            r"(?i)\b(?:do\s+anything\s+now|DAN|AIM|STAN|DUDE|developer\s+mode|debug\s+mode|sudo\s+mode|"
            r"god\s+mode|jailbreak(?:ing|ed|en)?|unfiltered|no\s+(?:restrictions|limits|rules|filter)|"
            r"opposite\s+day|grandma\s+exploit)\b"
        ),
        Severity.HIGH,
        ("LLM01:2026",),
        ("LLM01:2025",),
        "prompt-injection",
        "known jailbreak persona / mode",
        score=66.0,  # unambiguous jailbreak persona -> block alone (adversarial-review round 2)
    ),
    Rule(
        "pc.inj.chat_template",
        re.compile(
            r"(?i)<\|(?:im_start|im_end|endoftext|system|user|assistant)\|>|\[/?INST\]|<<\s*SYS\s*>>|</?s>"
        ),
        Severity.HIGH,
        ("LLM01:2026",),
        ("LLM01:2025",),
        "prompt-injection",
        "leaked chat-template / role token",
        0.9,
    ),
    Rule(
        "pc.inj.prompt_extraction",
        re.compile(
            r"(?ix)\b(?:reveal|print|show|repeat|output|tell\s+me|give\s+me|display|reproduce|echo|"
            r"what\s+(?:are|were))\b"
            r"[^.\n]{0,30}?\b(?:your|the|initial|original|above|exact)\b"
            r"[^.\n]{0,20}?\b(?:system\s+prompt|instructions?|prompt|rules|guidelines|directives?|"
            r"configuration|preamble)\b"
        ),
        Severity.HIGH,
        ("LLM01:2026", "LLM08:2026"),
        ("LLM01:2025", "LLM07:2025"),
        "prompt-injection",
        "system-prompt extraction probe",
        score=66.0,  # explicit extraction probe -> block alone (adversarial-review round 2)
    ),
    Rule(
        "pc.inj.role_confusion",
        re.compile(r"(?im)^[ \t]*(?:system|assistant|developer|tool|function)[ \t]*[:：]"),
        Severity.MEDIUM,
        ("LLM01:2026",),
        ("LLM01:2025",),
        "prompt-injection",
        "fake conversation-role turn",
        0.5,
    ),
    Rule(
        "pc.inj.role_reassign",
        re.compile(
            r"(?i)\b(?:you\s+are\s+now|from\s+now\s+on\s+you(?:'re|\s+are)|act\s+as\s+(?:if|though)|"
            r"pretend\s+to\s+be|pretend\s+you(?:'re|\s+are)|roleplay\s+as|respond\s+only\s+as)\b"
        ),
        Severity.MEDIUM,
        ("LLM01:2026",),
        ("LLM01:2025",),
        "prompt-injection",
        "role-reassignment phrasing",
        0.5,
    ),
    Rule(
        "pc.inj.override_soft",
        re.compile(
            r"(?ix)\b(?:ignore|disregard|forget)\s+(?:the\s+|everything\s+|all\s+(?:of\s+)?(?:the\s+)?)?"
            r"(?:above|previous|prior|earlier|preceding|foregoing|aforementioned)\b"
        ),
        Severity.MEDIUM,
        ("LLM01:2026",),
        ("LLM01:2025",),
        "prompt-injection",
        "disregard-preceding-context phrasing",
        0.8,
    ),
]


# --- LLM06 Unbounded Consumption -----------------------------------------------------------------

# "repeat forever / N times" amplification phrasing (metric-based checks live in consumption.py).
REPEAT_ABUSE_RE = re.compile(
    r"(?ix)\b(?:repeat|say|print|output|write|generate|produce)\b"
    r"[^.\n]{0,40}?\b(?:forever|indefinitely|endlessly|infinite(?:ly)?|"
    r"\d{3,15}\s+times|(?:a|one|\d{1,15})\s+(?:thousand|million|billion|trillion)\s+times|"
    r"until\s+you\s+(?:run\s+out|stop|crash))\b"
)

# --- LLM10 Improper Output Handling (dangerous / exfil-prone output) ------------------------------

DANGEROUS_OUTPUT_RULES: list[Rule] = [
    Rule(
        "pc.out.shell",
        re.compile(
            r"(?i)(?:\brm\s+-rf\b|\bsudo\s+\w|curl\s+[^\n|]{0,100}\|\s*(?:sh|bash)\b|"
            r"\bwget\s+[^\n]{0,80}\|\s*(?:sh|bash)\b|\beval\(|\bexec\(|\bos\.system\(|\bsubprocess\.(?:call|run|Popen)\()"
        ),
        Severity.HIGH,
        ("LLM10:2026", "ASI05"),
        ("LLM05:2025",),
        "improper-output",
        "dangerous shell/exec construct in output",
    ),
    Rule(
        "pc.out.sql",
        re.compile(
            r"(?i)\b(?:drop\s+table|delete\s+from|truncate\s+table|insert\s+into|"
            r"update\s+\w+\s+set|union\s+select|or\s+1\s*=\s*1)\b"
        ),
        Severity.MEDIUM,
        ("LLM10:2026",),
        ("LLM05:2025",),
        "improper-output",
        "SQL construct in output",
        0.7,
    ),
    Rule(
        "pc.out.xss",
        re.compile(r"(?i)<script\b|javascript:|\bon(?:error|load|click)\s*=|<iframe\b|<img[^>]{1,2048}onerror"),
        Severity.HIGH,
        ("LLM10:2026",),
        ("LLM05:2025",),
        "improper-output",
        "HTML/JS (XSS) construct in output",
    ),
    Rule(
        "pc.out.ansi",
        re.compile("\x1b\\[|\x1b\\]|\x07"),  # CSI / OSC / BEL terminal control sequences
        Severity.MEDIUM,
        ("LLM10:2026",),
        ("LLM05:2025",),
        "improper-output",
        "ANSI/OSC terminal control characters in output",
        0.8,
    ),
]

# Link/exfil detection captures only the HOST (naturally bounded ≤253 chars, stops at the first
# path/query/delimiter), which is all the allowlist check needs. Capturing the host — rather than a greedy
# URL class followed by a *required* trailing delimiter — makes these structurally ReDoS-free: there is no
# long greedy class that must later backtrack. The label class is also bounded (adversarial-review 3–4).
_HOST = r"([^/:?#\s>)\"']{1,253})"
MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]\n]{0,256}\]\(https?://" + _HOST)
AUTOLINK_RE = re.compile(r"<https?://" + _HOST)
# HTML auto-loading exfil: <img src>, <image href>, srcset, background — the model's output may be
# rendered as HTML, so an auto-fetched external resource is an exfil channel.
HTML_SRC_RE = re.compile(r"(?i)(?:src|href|srcset|data-src|background)\s*=\s*[\"']?https?://" + _HOST)
# Full URL + query/fragment capture for "zero-click" data-in-URL exfil (the recipient's own client
# auto-fetches the URL, carrying a secret in its query string). group(1)=host, group(2)=query/fragment.
# Bounded quantifiers throughout => ReDoS-free, same discipline as the host regexes above.
URL_QUERY_RE = re.compile(
    r"(?i)https?://" + _HOST + r"(?::\d{1,5})?(?:/[^\s?#]{0,2048})?[?#]([^\s\"'<>]{1,2048})"
)

# --- LLM08 Hidden Context Exposure (system-prompt leakage phrasing) -------------------------------

SYSTEMPROMPT_LEAK_RE = re.compile(
    r"(?i)(?:you\s+are\s+(?:a|an)\s+(?:helpful|harmless|honest|AI)\s+(?:assistant|AI)|"
    r"my\s+(?:system\s+)?(?:prompt|instructions)\s+(?:are|is|say|state)|"
    r"as\s+an\s+AI\s+language\s+model|the\s+following\s+(?:are|is)\s+my\s+(?:instructions|rules)|"
    r"i\s+(?:was|am)\s+(?:instructed|told|configured|programmed)\s+to|"
    r"my\s+(?:guidelines|rules|directives)\s+(?:state|say|are))"
)

# --- LLM02 / DSGAI01 Sensitive Information Disclosure (secrets) ------------------------------------

SECRET_RULES: list[Rule] = [
    Rule(
        "pc.sec.aws_key",
        re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "AWS access key id",
    ),
    Rule(
        "pc.sec.openai",
        re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,200}\b"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "OpenAI-style API key",
    ),
    Rule(
        "pc.sec.github",
        re.compile(r"\b(?:ghp|gho|ghs|ghu|ghr)_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,200}\b"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "GitHub token",
    ),
    Rule(
        "pc.sec.google",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "Google API key",
    ),
    Rule(
        "pc.sec.slack",
        re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,200}\b"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "Slack token",
    ),
    Rule(
        "pc.sec.stripe",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{10,200}\b"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "Stripe secret key",
    ),
    Rule(
        "pc.sec.jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,2048}\.eyJ[A-Za-z0-9_-]{10,2048}\.[A-Za-z0-9_-]{10,2048}\b"),
        Severity.HIGH,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "JSON Web Token",
    ),
    Rule(
        "pc.sec.pem",
        re.compile(r"-----BEGIN (?:[A-Z0-9 ]{0,40})?PRIVATE KEY(?: BLOCK)?-----"),
        Severity.CRITICAL,
        ("LLM02:2026", "DSGAI01"),
        ("LLM02:2025",),
        "secret-egress",
        "PEM private key block",
    ),
]

# Generic "key = <value>" rule; the captured value is entropy-gated in egress.py to cut false positives.
GENERIC_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key|client[_-]?secret|auth)\b"
    r"\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=]{12,100})[\"']?"
)
