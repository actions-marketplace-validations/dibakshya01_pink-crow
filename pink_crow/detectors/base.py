"""Detector protocol + the per-scan context.

A detector is anything with ``name``, ``direction`` ("input"/"output"/"both"), and
``detect(ctx) -> list[Finding]``. The deterministic bundled detectors implement this; an optional ML
detector (the ``[ml]`` extra) implements the same protocol, so it plugs in without touching the core.

The :class:`ScanContext` is built **once** per scan by the Engine (length-capped text, normalized
variants, decoded payloads, invisible-char summary) and shared across detectors so none of that work is
repeated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from ..models import Finding, RedactionSpan
from ..signals import decode_candidates, invisible_summary, normalized_variants
from ..signals.codecs import Decoded

if TYPE_CHECKING:
    from ..config import ScanConfig


@dataclass
class ScanContext:
    text: str                       # original full text (for length/consumption metrics)
    scan_text: str                  # length-capped text used for pattern scanning
    direction: str                  # "input" | "output"
    provenance: str                 # user | retrieved | tool | system | model
    config: ScanConfig
    variants: list[str] = field(default_factory=list)
    decoded: list[Decoded] = field(default_factory=list)
    invisible_count: int = 0
    invisible_kinds: list[str] = field(default_factory=list)
    # populated by the egress detector (M3) so the Engine can surface redactions
    redactions: list[RedactionSpan] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def full_len(self) -> int:
        return len(self.text)

    @classmethod
    def build(cls, text: str, direction: str, provenance: str, config: ScanConfig) -> ScanContext:
        scan_text = _length_cap(text, config.length_cap)
        count, kinds = invisible_summary(scan_text)
        return cls(
            text=text,
            scan_text=scan_text,
            direction=direction,
            provenance=provenance,
            config=config,
            variants=normalized_variants(scan_text, cap=config.length_cap),
            decoded=decode_candidates(scan_text),
            invisible_count=count,
            invisible_kinds=kinds,
        )

    def rule_enabled(self, rule_id: str) -> bool:
        return self.config.rule_overrides.get(rule_id, True)


def _length_cap(text: str, cap: int) -> str:
    """Scan only the first and last ``cap//2`` chars of very long inputs (FR-24 worst-case bound)."""
    if cap <= 0 or len(text) <= cap:
        return text
    half = cap // 2
    return text[:half] + "\n" + text[-half:]


@runtime_checkable
class Detector(Protocol):
    name: str
    direction: str

    def detect(self, ctx: ScanContext) -> list[Finding]:  # pragma: no cover - protocol
        ...


def runs_on(detector: Detector, direction: str) -> bool:
    return detector.direction in (direction, "both")
