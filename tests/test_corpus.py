"""Labeled-corpus precision/recall floor + honest false-positive measurement (build-plan §6, DoD).

Recall = fraction of attack samples whose scan flags the expected OWASP category.
FP rate = fraction of benign samples that would be *actioned* (event score >= flag threshold).

The asserted floors are deliberately modest for a purely deterministic core — the point is to publish an
honest number, not an inflated one. The measured numbers are printed and recorded in docs/LIMITS.md.
"""

from __future__ import annotations

import json
import pathlib

from pink_crow.config import standard
from pink_crow.engine import Engine

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "fixtures"
POLICY = standard()
FLAG_AT = POLICY.flag_at

# The egress fixtures use placeholders instead of literal secrets, so the repo contains NO scannable
# secret (GitHub push-protection / downstream scanners stay clean for a *secret-detection* tool). The
# real-format test values are assembled here from parts at runtime — never a literal token in any file —
# so pink-crow's detectors still see realistic secrets and recall is unaffected.
SECRET_SUBS = {
    "<<PC_AWS>>": "AKIA" + "IOSFODNN7EXAMPLE",          # AKIA + 16 [A-Z2-7]
    "<<PC_OPENAI>>": "sk-" + "A" * 48,                   # sk- + {20,200}
    "<<PC_GHTOKEN>>": "ghp_" + "b" * 36,                 # ghp_ + 36 alnum
    "<<PC_GOOGLE>>": "AIza" + "C" * 35,                  # AIza + 35
    "<<PC_SLACK>>": "xoxb-" + "d" * 24,                  # xox[baprs]- + {10,200}
    "<<PC_STRIPE>>": "sk_live_" + "e" * 24,              # (sk|rk)_(live|test)_ + {10,200}
    "<<PC_PEM>>": "-----BEGIN RSA PRIVATE KEY-----",
    "<<PC_GENERIC>>": "Zx9Q2mK7Lp" + "R4aT1bWv8N" + "cY6dH3eJ5g",  # high-entropy generic value
}


def _expand(text: str) -> str:
    for ph, val in SECRET_SUBS.items():
        if ph in text:
            text = text.replace(ph, val)
    return text


def _load(path: pathlib.Path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _scan(eng: Engine, row: dict):
    direction = row.get("direction", "input")
    text = _expand(row["text"])
    if direction == "output":
        return eng.scan_output(text)
    return eng.scan_input(text, provenance=direction if direction in ("retrieved", "tool") else "user")


def _attacks():
    rows = []
    for name in ("injection", "consumption", "egress"):
        rows += _load(FIX / "attacks" / f"{name}.jsonl")
    return rows


def _benign():
    return _load(FIX / "benign" / "generated.jsonl") + _load(FIX / "benign" / "curated.jsonl")


def test_recall_floor_and_report(capsys):
    eng = Engine()  # stateless scans (no session_id) => pure per-event detection
    attacks = _attacks()
    assert attacks, "attack fixtures missing"
    caught = 0
    misses = []
    for row in attacks:
        res = _scan(eng, row)
        ids = {oid for f in res.findings for oid in f.owasp_ids}
        if row["expect"] in ids:
            caught += 1
        else:
            misses.append(row["text"][:60])
    recall = caught / len(attacks)
    with capsys.disabled():
        print(f"\n[corpus] recall = {caught}/{len(attacks)} = {recall:.1%}")
        for m in misses:
            print(f"  MISS: {m}")
    assert recall >= 0.90, f"recall {recall:.1%} below floor (misses: {misses})"


def test_false_positive_ceiling_and_report(capsys):
    eng = Engine()
    benign = _benign()
    assert len(benign) >= 500, f"benign corpus too small ({len(benign)}) for a meaningful FP number"
    fps = []
    for row in benign:
        res = _scan(eng, row)
        if res.event_score >= FLAG_AT:
            fps.append((row["text"][:70], round(res.event_score, 1)))
    block_fps = [row for row in fps if row[1] >= POLICY.block_at]
    fp_rate = len(fps) / len(benign)
    block_rate = len(block_fps) / len(benign)
    with capsys.disabled():
        print(f"\n[corpus] benign={len(benign)}  flag-FP(>= {FLAG_AT:.0f}) = {len(fps)} = {fp_rate:.2%}"
              f"  block-FP(>= {POLICY.block_at:.0f}) = {len(block_fps)} = {block_rate:.2%}")
        for t, s in fps[:15]:
            print(f"  FP[{s}]: {t}")
    assert fp_rate <= 0.03, f"benign flag false-positive rate {fp_rate:.2%} exceeds 3% ceiling"
    assert block_rate <= 0.02, f"benign block false-positive rate {block_rate:.2%} exceeds 2% ceiling"
