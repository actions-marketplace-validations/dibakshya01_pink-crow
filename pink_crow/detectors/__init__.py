"""Bundled deterministic detectors (each maps findings to OWASP IDs)."""

from __future__ import annotations

from .base import Detector, ScanContext, runs_on
from .consumption import ConsumptionDetector
from .egress import EgressDetector
from .injection import InjectionDetector

__all__ = [
    "Detector",
    "ScanContext",
    "runs_on",
    "InjectionDetector",
    "ConsumptionDetector",
    "EgressDetector",
]
