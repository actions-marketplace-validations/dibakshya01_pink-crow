"""Output-side egress detector.

Covers the tight egress triad LLM02:2026 (sensitive-info / secrets, with ``DSGAI01``) ·
LLM08:2026 (system-prompt / hidden-context leakage) · LLM10:2026 (dangerous / exfil-prone output), plus
PII. Secret/PII matches produce **redactions** (reported as spans against the original text, FR-12); the
generic key rule is entropy-gated to cut false positives; credit cards must pass Luhn.
"""

from __future__ import annotations

import re

from ..models import Finding, RedactionSpan, Severity
from ..signals import luhn_ok, shannon_entropy
from .base import ScanContext
from .rules_data import (
    AUTOLINK_RE,
    DANGEROUS_OUTPUT_RULES,
    GENERIC_SECRET_RE,
    HTML_SRC_RE,
    MARKDOWN_LINK_RE,
    SECRET_RULES,
    SYSTEMPROMPT_LEAK_RE,
    URL_QUERY_RE,
)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b")
_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)\d{3}[-.\s](?!00)\d{2}[-.\s](?!0000)\d{4}\b")
_CC_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]?){13,19}\b")
_GENERIC_ENTROPY_MIN = 3.5

# data-in-URL exfil (pc.out.exfil_query): a query/fragment token this long AND this random is smuggled
# data, not an ordinary key=value param. Conservative thresholds keep benign tracking/signed params out.
_EXFIL_QUERY_MIN_LEN = 24
_EXFIL_QUERY_MIN_ENTROPY = 3.6
_QUERY_SPLIT_RE = re.compile(r"[&=;,/#+]")


def _is_lookalike_host(host: str) -> bool:
    """True for an IDN/punycode (``xn--``) label or any non-ASCII in the host — the homoglyph-lookalike
    class (an attacker host that renders like a trusted one)."""
    if not host:
        return False
    if any(ord(ch) > 127 for ch in host):
        return True
    return any(label.startswith("xn--") for label in host.split("."))


def _data_bearing_query(query: str) -> bool:
    """True if a URL query/fragment carries a long, high-entropy token (smuggled data). Linear split +
    per-token entropy — no backtracking."""
    for tok in _QUERY_SPLIT_RE.split(query):
        if len(tok) >= _EXFIL_QUERY_MIN_LEN and shannon_entropy(tok) >= _EXFIL_QUERY_MIN_ENTROPY:
            return True
    return False


def _label(rule_id: str) -> str:
    return rule_id.split(".")[-1].upper()


class EgressDetector:
    name = "egress"
    direction = "output"

    def detect(self, ctx: ScanContext) -> list[Finding]:
        cfg = ctx.config
        findings: list[Finding] = []
        redacts: list[tuple[int, int, str]] = []  # (start, end, label)

        # Bound the scanned region so a huge model output can't turn egress into a (linear-regex +
        # formerly quadratic-redaction) self-DoS. We scan the first `max_output_chars` and keep the
        # untouched tail verbatim in redacted_text; an oversized output is itself flagged below so it
        # is never silently passed. Offsets within `text` map directly to the original (prefix slice).
        full = ctx.text
        limit = cfg.max_output_chars
        truncated = bool(limit) and len(full) > limit
        text = full[:limit] if truncated else full
        if truncated:
            findings.append(
                Finding(
                    "pc.out.oversize",
                    ["LLM06:2026", "LLM10:2025"],
                    "unbounded-consumption",
                    Severity.MEDIUM,
                    f"output too large to fully scan ({len(full)} chars > {limit}); scanned first {limit}",
                    confidence=0.8,
                )
            )

        # 1. known secrets -> finding + redaction
        for rule in SECRET_RULES:
            if not ctx.rule_enabled(rule.rule_id):
                continue
            spans = [m.span() for m in rule.pattern.finditer(text)]
            if spans:
                label = _label(rule.rule_id)
                for s, e in spans:
                    redacts.append((s, e, label))
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        owasp_ids=rule.owasp_ids,
                        category=rule.category,
                        severity=rule.severity,
                        message=f"{rule.message} in output (x{len(spans)})",
                        span=spans[0],
                        confidence=rule.confidence,
                    )
                )

        # 2. generic key=value, entropy-gated
        if ctx.rule_enabled("pc.sec.generic"):
            gspans = []
            for m in GENERIC_SECRET_RE.finditer(text):
                val = m.group(1)
                if shannon_entropy(val) >= _GENERIC_ENTROPY_MIN:
                    gspans.append(m.span(1))
            if gspans:
                for s, e in gspans:
                    redacts.append((s, e, "SECRET"))
                findings.append(
                    Finding("pc.sec.generic", ["LLM02:2026", "DSGAI01", "LLM02:2025"], "secret-egress",
                            Severity.HIGH, f"high-entropy credential-like value in output (x{len(gspans)})",
                            span=gspans[0], confidence=0.7)
                )

        # 3. PII
        if ctx.rule_enabled("pc.pii.email"):
            em = [m.span() for m in _EMAIL_RE.finditer(text)]
            if em:
                for s, e in em:
                    redacts.append((s, e, "EMAIL"))
                findings.append(Finding("pc.pii.email", ["LLM02:2026", "DSGAI01", "LLM02:2025"], "pii-egress",
                                        Severity.MEDIUM, f"email address in output (x{len(em)})", span=em[0], confidence=0.6))
        if ctx.rule_enabled("pc.pii.ssn"):
            ssn = [m.span() for m in _SSN_RE.finditer(text)]
            if ssn:
                for s, e in ssn:
                    redacts.append((s, e, "SSN"))
                findings.append(Finding("pc.pii.ssn", ["LLM02:2026", "DSGAI01", "LLM02:2025"], "pii-egress",
                                        Severity.HIGH, f"US SSN pattern in output (x{len(ssn)})", span=ssn[0]))
        if ctx.rule_enabled("pc.pii.card"):
            cards = []
            for m in _CC_CANDIDATE_RE.finditer(text):
                digits = re.sub(r"\D", "", m.group())
                if luhn_ok(digits):
                    s, e = m.span()
                    while e > s and not text[e - 1].isdigit():  # don't eat a trailing separator
                        e -= 1
                    cards.append((s, e))
            if cards:
                for s, e in cards:
                    redacts.append((s, e, "CARD"))
                findings.append(Finding("pc.pii.card", ["LLM02:2026", "DSGAI01", "LLM02:2025"], "pii-egress",
                                        Severity.HIGH, f"Luhn-valid payment card number in output (x{len(cards)})", span=cards[0]))

        # 4. dangerous / exfil-prone output (LLM10)
        for rule in DANGEROUS_OUTPUT_RULES:
            if not ctx.rule_enabled(rule.rule_id):
                continue
            dm = rule.pattern.search(text)
            if dm:
                findings.append(Finding(rule.rule_id, rule.owasp_ids, rule.category, rule.severity,
                                        rule.message, span=dm.span(), confidence=rule.confidence))

        # 4b. output links/images -> external-channel (exfil) detection. Three graded rules share one
        #     ReDoS-free parse of the output: a link to a non-allowlisted host (exfil_link); an
        #     IDN/punycode homoglyph-lookalike host (exfil_punycode); and — highest-signal — a URL whose
        #     query/fragment carries a high-entropy blob, i.e. data smuggled out in the URL itself
        #     (exfil_query, the "zero-click" class: the recipient's client auto-fetches it).
        want_link = ctx.rule_enabled("pc.out.exfil_link")
        want_puny = ctx.rule_enabled("pc.out.exfil_punycode")
        want_query = ctx.rule_enabled("pc.out.exfil_query")
        if want_link or want_puny or want_query:
            # the regexes capture the HOST directly (ReDoS-free). cheap pre-filter skips the bracket regex
            # unless a "](http" link literal is present. compare hosts to the allowlist (case-insensitive).
            hosts = [m.group(1).lower() for m in MARKDOWN_LINK_RE.finditer(text)] if "](http" in text.lower() else []
            hosts += [m.group(1).lower() for m in AUTOLINK_RE.finditer(text)]
            hosts += [m.group(1).lower() for m in HTML_SRC_RE.finditer(text)]
            allowed = {h.lower() for h in cfg.allowed_hosts}
            external = [h for h in hosts if h and h not in allowed]

            if want_link and external:
                findings.append(Finding("pc.out.exfil_link", ["LLM10:2026", "DSGAI01", "LLM05:2025"],
                                        "improper-output", Severity.HIGH,
                                        f"output links/images to non-allowlisted host(s): {external[0]}",
                                        confidence=0.75))

            # IDN/punycode homoglyph lookalike (only when not explicitly allowlisted by the operator)
            if want_puny:
                puny = [h for h in hosts if h and h not in allowed and _is_lookalike_host(h)]
                if puny:
                    findings.append(Finding("pc.out.exfil_punycode", ["LLM10:2026", "DSGAI01"],
                                            "improper-output", Severity.HIGH,
                                            f"output link to IDN/punycode homoglyph-lookalike host(s): {puny[0]}",
                                            confidence=0.7))

            # data-in-URL exfil: a non-allowlisted URL whose query/fragment smuggles a high-entropy blob
            if want_query and ("?" in text or "#" in text):
                exfil_q = []
                for m in URL_QUERY_RE.finditer(text):
                    host = m.group(1).lower()
                    if host and host not in allowed and _data_bearing_query(m.group(2)):
                        exfil_q.append(host)
                if exfil_q:
                    findings.append(Finding("pc.out.exfil_query", ["LLM10:2026", "DSGAI01", "LLM02:2026"],
                                            "improper-output", Severity.HIGH,
                                            "output URL smuggles a high-entropy blob in its query/fragment "
                                            f"(data-in-URL exfil) to: {exfil_q[0]}",
                                            confidence=0.7))

        # 5. system-prompt / hidden-context leakage (LLM08)
        if cfg.canary and ctx.rule_enabled("pc.leak.canary") and cfg.canary in text:
            idx = text.find(cfg.canary)
            redacts.append((idx, idx + len(cfg.canary), "CANARY"))
            findings.append(Finding("pc.leak.canary", ["LLM08:2026", "LLM07:2025"], "context-exposure",
                                    Severity.CRITICAL, "system-prompt canary token leaked in output",
                                    span=(idx, idx + len(cfg.canary))))
        leak_m = SYSTEMPROMPT_LEAK_RE.search(text) if ctx.rule_enabled("pc.leak.phrase") else None
        if leak_m:
            findings.append(Finding("pc.leak.phrase", ["LLM08:2026", "LLM07:2025"], "context-exposure",
                                    Severity.MEDIUM, "system-prompt-leakage phrasing in output",
                                    span=leak_m.span(), confidence=0.6))
        if cfg.system_prompt and ctx.rule_enabled("pc.leak.overlap"):
            overlap = _shingle_overlap(cfg.system_prompt, text)
            if overlap > 0.3:
                findings.append(Finding("pc.leak.overlap", ["LLM08:2026", "LLM07:2025"], "context-exposure",
                                        Severity.HIGH, f"output overlaps the known system prompt ({overlap:.0%})",
                                        confidence=0.8))

        # apply redactions in a SINGLE pass (O(text + redactions), not O(text × redactions)); keep the
        # unscanned tail of an oversized output verbatim afterwards.
        if redacts:
            merged = _merge_spans(redacts)
            pieces: list[str] = []
            prev = 0
            for s, e, label in merged:
                pieces.append(text[prev:s])
                pieces.append(f"‹PINKCROW:{label}›")
                prev = e
            pieces.append(text[prev:])
            ctx.redacted_text = "".join(pieces) + (full[limit:] if truncated else "")
            ctx.redactions = [RedactionSpan(s, e, label) for (s, e, label) in merged]
        elif truncated:
            ctx.redacted_text = full  # nothing to redact, but preserve the full output

        return findings


def _merge_spans(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """Merge overlapping redaction spans (keep the first label)."""
    merged: list[tuple[int, int, str]] = []
    for s, e, label in sorted(spans, key=lambda r: r[0]):
        if merged and s <= merged[-1][1]:
            ps, pe, pl = merged[-1]
            merged[-1] = (ps, max(pe, e), pl)
        else:
            merged.append((s, e, label))
    return merged


def _shingle_overlap(system_prompt: str, text: str, n: int = 6) -> float:
    sw = system_prompt.lower().split()
    tw = text.lower().split()
    if len(sw) < n:
        return 1.0 if system_prompt.strip().lower() in text.lower() else 0.0
    sys_sh = {tuple(sw[i : i + n]) for i in range(len(sw) - n + 1)}
    txt_sh = {tuple(tw[i : i + n]) for i in range(len(tw) - n + 1)} if len(tw) >= n else set()
    return (len(sys_sh & txt_sh) / len(sys_sh)) if sys_sh else 0.0
