"""Round 5: the email ReDoS fix + a COMPREHENSIVE guard against the whole unbounded-quantifier class.

Rounds 3/4/5 each found a new ReDoS in a different regex (markdown, URL, email). Rather than keep
patching instances, these tests (a) time a battery of pathological shapes through BOTH scan directions,
and (b) statically assert that NO bundled regex contains an open-ended `{n,}` quantifier — so a future
unbounded pattern fails CI immediately.
"""

from __future__ import annotations

import re
import time

import pytest

from pink_crow.clock import FixedClock
from pink_crow.engine import Engine

# pathological shapes: the key is an in-class separator / delimiter that creates many backtrack starts
_PAYLOADS = {
    "email-dot": "a." * 32768,
    "email-dash": "a-" * 32768,
    "email-underscore": "a_" * 32768,
    "email-at": ("x@" + "a." * 20000),
    "img-run": "<img " * 13000,
    "jwt-run": "eyJa." * 13000,
    "bracket-bomb": "[" * 65000 + "](http" + "a" * 100,
    "autolink-run": "<http://a" * 7000,
    "mdurl-run": "[](http://a" * 5900,
    "digit-run": "repeat " + "9" * 65000 + " times",
    "spaced-run": "a " * 32768,
    "dotsep-run": "a.b.c." * 10000,
    "base64-run": "QUJD" * 16000,
    "hex-run": "abcd" * 16000,
}


@pytest.mark.parametrize("name", list(_PAYLOADS))
def test_redos_sweep_input_and_output(name):
    payload = _PAYLOADS[name]
    eng = Engine(clock=FixedClock(0.0))
    for direction in ("input", "output"):
        t = time.perf_counter()
        (eng.scan_input if direction == "input" else eng.scan_output)(payload)
        elapsed = time.perf_counter() - t
        assert elapsed < 0.3, f"{name} ({direction}) took {elapsed * 1000:.0f}ms — unbounded regex?"


def test_email_regex_fixed_specifically():
    eng = Engine(clock=FixedClock(0.0))
    t = time.perf_counter()
    eng.scan_output("a." * 32768)  # round-5 🔴 repro (was ~3050ms)
    assert time.perf_counter() - t < 0.1
    # and a real email is still redacted
    r = eng.scan_output("reach me at john.doe%tag@mail.example.co.uk anytime")
    assert any(f.rule_id == "pc.pii.email" for f in r.findings)


def test_no_open_ended_quantifiers_in_any_bundled_regex():
    """Static guard: no bundled regex may contain an open-ended `{n,}` (every quantifier bounded)."""
    from pink_crow.detectors import egress, rules_data
    from pink_crow.signals import codecs, normalize

    open_ended = re.compile(r"\{\d+,\}")
    patterns: list[tuple[str, str]] = []
    for mod in (rules_data, egress, codecs, normalize):
        for name, val in vars(mod).items():
            if isinstance(val, re.Pattern):
                patterns.append((f"{mod.__name__}.{name}", val.pattern))
    for rule in rules_data.INJECTION_RULES + rules_data.DANGEROUS_OUTPUT_RULES + rules_data.SECRET_RULES:
        patterns.append((rule.rule_id, rule.pattern.pattern))

    offenders = [n for n, p in patterns if open_ended.search(p)]
    assert not offenders, f"open-ended {{n,}} quantifier(s) found (ReDoS risk): {offenders}"
    assert len(patterns) >= 15  # sanity: we actually collected the patterns
