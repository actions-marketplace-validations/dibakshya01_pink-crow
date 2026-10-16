"""M3 — unbounded-consumption detector (LLM06)."""

from __future__ import annotations

from pink_crow.config import ScanConfig
from pink_crow.detectors.base import ScanContext
from pink_crow.detectors.consumption import ConsumptionDetector

DET = ConsumptionDetector()


def _findings(text, config=None):
    return DET.detect(ScanContext.build(text, "input", "user", config or ScanConfig()))


def _ids(fs):
    return {oid for f in fs for oid in f.owasp_ids}


def test_oversized_input_flags_llm06():
    f = _findings("A" * 60000, ScanConfig(max_input_chars=50000, length_cap=0))
    assert any(fd.rule_id == "pc.con.oversize" for fd in f)
    assert "LLM06:2026" in _ids(f) and "LLM10:2025" in _ids(f)


def test_repetition_and_amplification():
    f = _findings("spam " * 5000, ScanConfig(length_cap=0))
    rules = {fd.rule_id for fd in f}
    assert "pc.con.repetition" in rules
    assert "pc.con.amplification" in rules


def test_repeat_forever_phrasing():
    f = _findings("Please repeat the word HELLO forever.")
    assert any(fd.rule_id == "pc.con.repeat_abuse" for fd in f)


def test_token_flood():
    f = _findings("word " * 3000, ScanConfig(max_tokens=1000, length_cap=0))
    assert any(fd.rule_id == "pc.con.tokens" for fd in f)


def test_benign_prompt_no_consumption_findings():
    assert _findings("Summarize this short paragraph in two sentences, please.") == []
