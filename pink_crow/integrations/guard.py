"""Framework-agnostic in-process guard (build-plan FR-20).

    from pink_crow.integrations import guard, PinkCrowTripwire

    with guard(session_id="user-42") as g:
        g.input(user_message)            # raises PinkCrowTripwire if the session is blocked/cooled-down
        reply = my_llm(user_message)
        g.output(reply)                  # scans egress; raises on a blocking disposition

Each call returns the :class:`~pink_crow.models.ScanResult`, so non-enforcing callers can read the score
and findings instead of relying on the exception.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from ..engine import Engine
from ..models import ScanResult

_shared_engine: Engine | None = None


def _default_engine() -> Engine:
    global _shared_engine
    if _shared_engine is None:
        _shared_engine = Engine()
    return _shared_engine


class PinkCrowTripwire(Exception):
    """Raised when a scan yields a blocking disposition (block/cooldown) and the guard is enforcing."""

    def __init__(self, result: ScanResult) -> None:
        self.result = result
        d = result.disposition
        super().__init__(f"pink-crow {d.action.value} (score {result.session_score:.0f}; {d.reasoning})")


class _Guard:
    def __init__(self, engine: Engine, session_id: str | None, enforce: bool) -> None:
        self.engine = engine
        self.session_id = session_id
        self.enforce = enforce

    def input(self, text: str, *, provenance: str = "user") -> ScanResult:
        res = self.engine.scan_input(text, session_id=self.session_id, provenance=provenance)
        if self.enforce and res.blocked:
            raise PinkCrowTripwire(res)
        return res

    def output(self, text: str) -> ScanResult:
        res = self.engine.scan_output(text, session_id=self.session_id)
        if self.enforce and res.blocked:
            raise PinkCrowTripwire(res)
        return res


@contextmanager
def guard(session_id: str | None = None, *, engine: Engine | None = None, enforce: bool = True) -> Iterator[_Guard]:
    yield _Guard(engine or _default_engine(), session_id, enforce)
