"""SARIF 2.1.0 emitter (build-plan FR-17/FR-21).

Turns findings into a Static Analysis Results Interchange Format document that GitHub code-scanning
ingests. Uses ``partialFingerprints`` so GitHub can dedupe/track findings across commits.
"""

from __future__ import annotations

import hashlib
from typing import Any

from . import __version__
from .models import Finding, ScanResult, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def _fingerprint(uri: str, finding: Finding, line: int) -> str:
    h = hashlib.sha256(f"{uri}|{finding.rule_id}|{line}|{finding.message}".encode())
    return h.hexdigest()[:16]


def to_sarif(items: list[tuple[str, str, ScanResult]]) -> dict[str, Any]:
    """``items`` = list of (uri, source_text, ScanResult)."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for uri, text, res in items:
        for f in res.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_id.replace(".", "_"),
                    "shortDescription": {"text": f.message[:120]},
                    "defaultConfiguration": {"level": _LEVEL[f.severity]},
                    "properties": {"owasp": f.owasp_ids, "category": f.category},
                }
            line = _line_of(text, f.span[0]) if f.span else 1
            results.append(
                {
                    "ruleId": f.rule_id,
                    "level": _LEVEL[f.severity],
                    "message": {"text": f"{f.message} (OWASP {', '.join(f.owasp_ids)}; score {f.score:.0f})"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": line},
                            }
                        }
                    ],
                    "partialFingerprints": {"primaryLocationLineHash": _fingerprint(uri, f, line)},
                    "properties": {
                        "owasp_ids": f.owasp_ids,
                        "severity": f.severity.value,
                        "event_score": res.event_score,
                        "session_score": res.session_score,
                    },
                }
            )

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pink-crow",
                        "informationUri": "https://github.com/dibakshya01/pink-crow",
                        "version": __version__,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
