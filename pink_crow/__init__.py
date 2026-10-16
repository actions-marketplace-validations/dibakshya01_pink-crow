"""pink-crow — deterministic, offline session-risk gateway for AI chatbots & agents.

Public API (filled in progressively as milestones land):
    scan_input, scan_output, Engine, Policy  — the one-call entry points (M2/M4)
    Finding, ScanResult, Disposition, Severity, Action, ACSDecision  — data models
    __version__
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import Policy, ScanConfig, baseline, standard, strict
from .engine import Engine, scan_input, scan_output
from .models import (
    ACSDecision,
    Action,
    Disposition,
    Finding,
    RedactionSpan,
    ScanResult,
    Severity,
)
from .scoring import ScoringParams
from .session import InMemorySessionStore, RedisSessionStore, SessionStore

__all__ = [
    "__version__",
    "Severity",
    "Action",
    "ACSDecision",
    "Finding",
    "RedactionSpan",
    "Disposition",
    "ScanResult",
    "Policy",
    "ScanConfig",
    "ScoringParams",
    "baseline",
    "standard",
    "strict",
    "Engine",
    "scan_input",
    "scan_output",
    "SessionStore",
    "InMemorySessionStore",
    "RedisSessionStore",
]
