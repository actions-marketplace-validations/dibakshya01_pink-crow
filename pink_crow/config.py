"""Policy & scan configuration (build-plan FR-13).

A :class:`Policy` is the single source of truth for thresholds, scoring parameters, scan knobs, window
caps, cooldown behaviour, and the fail mode. Three built-in profiles — ``baseline`` / ``standard`` /
``strict`` — are provided; everything is overridable and JSON/dict-loadable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .scoring import ScoringParams


@dataclass
class ScanConfig:
    """Detector-facing knobs."""

    length_cap: int = 20000                 # FR-24: cap scanned input/variant length
    max_output_chars: int = 65536           # cap egress-scanned output (bounds the redaction/scan cost)
    scan_time_budget_ms: int = 50           # FR-24: per-detector soft budget
    allowed_hosts: tuple[str, ...] = ()     # FR-11: hosts NOT treated as external in output links
    canary: str = ""                        # FR-10: system-prompt canary token (exact-match => leak)
    system_prompt: str = ""                 # FR-10: known system prompt for n-gram overlap leak check
    rule_overrides: dict[str, bool] = field(default_factory=dict)  # rule_id -> enabled
    # consumption thresholds (FR-8)
    max_input_chars: int = 50000
    max_tokens: int = 4096
    min_repetition_ratio: float = 0.2       # below => repetitive/flood-like
    min_zlib_ratio: float = 0.10            # below => compression-bomb-like

    def to_dict(self) -> dict[str, Any]:
        return {
            "length_cap": self.length_cap,
            "max_output_chars": self.max_output_chars,
            "scan_time_budget_ms": self.scan_time_budget_ms,
            "allowed_hosts": list(self.allowed_hosts),
            "canary": self.canary,
            "system_prompt": self.system_prompt,
            "rule_overrides": dict(self.rule_overrides),
            "max_input_chars": self.max_input_chars,
            "max_tokens": self.max_tokens,
            "min_repetition_ratio": self.min_repetition_ratio,
            "min_zlib_ratio": self.min_zlib_ratio,
        }


@dataclass
class Policy:
    name: str = "standard"
    scoring: ScoringParams = field(default_factory=ScoringParams)
    scan: ScanConfig = field(default_factory=ScanConfig)
    # score-band lower bounds (0–100)
    flag_at: float = 30.0
    block_at: float = 60.0        # "High" band
    critical_at: float = 85.0     # "Critical" band
    # sliding-window hard-override caps (0 = disabled)
    window_event_cap: int = 0
    window_score_cap: float = 0.0
    # cooldown (session time-out)
    cooldown_window: float = 300.0
    cooldown_on: frozenset[str] = frozenset({"critical", "window_cap"})
    fail_mode: str = "closed"     # "closed" => a scan error yields block/deny; "open" => allow
    # lethal-trifecta correlation: seconds a leg (untrusted input / sensitive data / external channel)
    # stays "active" in a session before it decays out (see pink_crow.trifecta). 0 => legs are permanent
    # for the life of the session. Disable the signal entirely via scan.rule_overrides["pc.ses.trifecta"].
    trifecta_window: float = 900.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "scoring": {
                "half_life": self.scoring.half_life,
                "ewma_halflife": self.scoring.ewma_halflife,
                "window_seconds": self.scoring.window_seconds,
            },
            "scan": self.scan.to_dict(),
            "flag_at": self.flag_at,
            "block_at": self.block_at,
            "critical_at": self.critical_at,
            "window_event_cap": self.window_event_cap,
            "window_score_cap": self.window_score_cap,
            "cooldown_window": self.cooldown_window,
            "cooldown_on": sorted(self.cooldown_on),
            "fail_mode": self.fail_mode,
            "trifecta_window": self.trifecta_window,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Policy:
        try:
            scoring = ScoringParams(**d["scoring"]) if "scoring" in d else ScoringParams()
            scan = ScanConfig(**{**d["scan"], "allowed_hosts": tuple(d["scan"].get("allowed_hosts", ()))}) if "scan" in d else ScanConfig()
            kwargs: dict[str, Any] = {k: v for k, v in d.items() if k not in ("scoring", "scan")}
            if "cooldown_on" in kwargs:
                kwargs["cooldown_on"] = frozenset(kwargs["cooldown_on"])
            return cls(scoring=scoring, scan=scan, **kwargs)
        except (KeyError, TypeError) as e:
            raise ValueError(f"invalid policy config: {e}") from e


def baseline() -> Policy:
    """Lenient: longer half-life, higher thresholds, no window caps."""
    return Policy(name="baseline", flag_at=40.0, block_at=70.0, critical_at=90.0)


def standard() -> Policy:
    """The default."""
    return Policy(name="standard", window_event_cap=20, window_score_cap=200.0)


def strict() -> Policy:
    """Aggressive: lower thresholds, shorter window, tighter caps, arm cooldown on any high+ block."""
    return Policy(
        name="strict",
        scoring=ScoringParams(half_life=180.0, ewma_halflife=45.0, window_seconds=45.0),
        flag_at=20.0,
        block_at=45.0,
        critical_at=75.0,
        window_event_cap=12,
        window_score_cap=120.0,
        cooldown_window=600.0,
        cooldown_on=frozenset({"critical", "high", "window_cap"}),  # strict: a High-band block arms cooldown too
        trifecta_window=1800.0,  # strict: remember trifecta legs longer, so a slow-assembled trifecta still trips
    )


PROFILES = {"baseline": baseline, "standard": standard, "strict": strict}


def get_profile(name: str) -> Policy:
    if name not in PROFILES:
        raise ValueError(f"unknown profile {name!r}; choose from {sorted(PROFILES)}")
    return PROFILES[name]()
