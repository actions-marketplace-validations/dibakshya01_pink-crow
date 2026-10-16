"""M7 — self-scan (FR-23): pink-crow must not raise a CRITICAL finding on its own prose docs.

CRITICAL findings are secrets / canary / Luhn cards — none should appear in prose. (HIGH injection
findings on README/CONTRIBUTING are expected: those files deliberately quote example attack strings, so
they are true positives, not false positives — hence the bar is 'no CRITICAL', per the spec.)
"""

from __future__ import annotations

import pathlib

from pink_crow.engine import Engine
from pink_crow.models import Severity

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = [
    "README.md",
    "ARCHITECTURE.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
    "CODE_OF_CONDUCT.md",
    "docs/LIMITS.md",
    "docs/OWASP-MAPPING.md",
    "finding.md",
    "build-plan.md",
]


def test_no_critical_findings_in_own_docs():
    eng = Engine()
    offenders = []
    for rel in DOCS:
        path = ROOT / rel
        if not path.exists():
            continue
        text = path.read_text()
        for res in (eng.scan_input(text), eng.scan_output(text)):
            for f in res.findings:
                if f.severity == Severity.CRITICAL:
                    offenders.append((rel, f.rule_id, f.message))
    assert not offenders, f"pink-crow raised CRITICAL findings on its own docs: {offenders}"
