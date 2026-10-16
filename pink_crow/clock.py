"""Injectable clock.

The session risk score depends on the time elapsed between events, so scoring must never read the
wall clock directly — it reads it through a ``Clock``. In production that is :class:`SystemClock`; in
tests and replay it is :class:`FixedClock`, which makes the session-score trajectory byte-identical and
therefore *auditable and replayable* (build-plan FR-4/FR-25).
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Anything with a ``now() -> float`` (epoch seconds)."""

    def now(self) -> float:  # pragma: no cover - protocol
        ...


class SystemClock:
    """Real wall-clock time."""

    def now(self) -> float:
        return time.time()


class FixedClock:
    """Deterministic, advanceable clock for tests and replay."""

    def __init__(self, start: float = 0.0) -> None:
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def set(self, t: float) -> None:
        self._t = float(t)

    def advance(self, seconds: float) -> FixedClock:
        self._t += float(seconds)
        return self
