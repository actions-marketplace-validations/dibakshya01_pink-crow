"""Session risk scoring — the deterministic, auditable core (build-plan FR-4).

The session score is a **decayed cumulative accumulator** that decays *on read*:

    A_decayed = A_last * exp(-lambda * (now - last_seen)),   lambda = ln2 / half_life

On a scan the current event is added **before** banding, so the current turn counts toward its own
disposition:

    A_new        = A_decayed + event_score
    session_score = clamp(round(A_new), 0, 100)        # on a scan (post-update)
    session_score = clamp(round(A_decayed), 0, 100)    # on a pure read (no event)

Decay operates on the *unclamped* accumulator, so a sustained campaign can push the internal accumulator
well above 100 and therefore stay in the Critical band longer than "score 100" alone would suggest — this
is intentional (see build-plan §8). EWMA is an advisory recent-severity signal; sliding-window counters
feed the policy's hard-override caps. All time comes from an injectable clock, never ``time.time()`` here.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

LN2 = math.log(2.0)


@dataclass
class ScoringParams:
    half_life: float = 300.0          # seconds; accumulator half-life
    ewma_halflife: float = 60.0       # seconds; EWMA time-constant basis
    window_seconds: float = 60.0      # sliding window for flood/burst caps

    def __post_init__(self) -> None:
        if self.half_life <= 0 or self.ewma_halflife <= 0 or self.window_seconds <= 0:
            raise ValueError("scoring half_life / ewma_halflife / window_seconds must be > 0")


@dataclass
class SessionState:
    session_id: str
    accumulator: float = 0.0          # unclamped
    ewma: float = 0.0
    events: int = 0
    window_events: list[tuple[float, float]] = field(default_factory=list)  # (timestamp, event_score)
    created: float = 0.0
    last_seen: float = 0.0
    flagged: bool = False
    cooldown_until: float = float("-inf")  # fresh session is never "in cooldown", even at now<=0
    # lethal-trifecta legs: leg-name -> last-seen timestamp (see pink_crow.trifecta). A leg decays out of
    # the active set after the policy's trifecta_window; stored so correlation survives a shared store.
    trifecta_legs: dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "accumulator": self.accumulator,
            "ewma": self.ewma,
            "events": self.events,
            "created": self.created,
            "last_seen": self.last_seen,
            "flagged": self.flagged,
            # -inf (fresh session, never cooled) -> 0.0 so the dict is valid JSON (no -Infinity)
            "cooldown_until": self.cooldown_until if math.isfinite(self.cooldown_until) else 0.0,
            "trifecta_legs": dict(self.trifecta_legs),
        }

    def to_state_dict(self) -> dict[str, Any]:
        """Lossless, JSON-safe serialization for a shared store (includes window_events; -inf -> None)."""
        return {
            "session_id": self.session_id,
            "accumulator": self.accumulator,
            "ewma": self.ewma,
            "events": self.events,
            "window_events": [[t, s] for (t, s) in self.window_events],
            "created": self.created,
            "last_seen": self.last_seen,
            "flagged": self.flagged,
            "cooldown_until": None if self.cooldown_until == float("-inf") else self.cooldown_until,
            "trifecta_legs": dict(self.trifecta_legs),
        }

    @classmethod
    def from_state_dict(cls, d: dict[str, Any]) -> SessionState:
        cd = d.get("cooldown_until")
        return cls(
            session_id=d["session_id"],
            accumulator=d.get("accumulator", 0.0),
            ewma=d.get("ewma", 0.0),
            events=d.get("events", 0),
            window_events=[(float(t), float(s)) for t, s in d.get("window_events", [])],
            created=d.get("created", 0.0),
            last_seen=d.get("last_seen", 0.0),
            flagged=d.get("flagged", False),
            cooldown_until=float("-inf") if cd is None else float(cd),
            trifecta_legs={str(k): float(v) for k, v in d.get("trifecta_legs", {}).items()},
        )


def clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


def decay_factor(dt: float, half_life: float) -> float:
    """0.5 ** (dt / half_life), with dt floored at 0 (clocks must not go backwards into a score)."""
    if dt <= 0:
        return 1.0
    return math.pow(0.5, dt / half_life)


def combine_findings(scores: Iterable[float]) -> float:
    """Noisy-OR combination of per-finding scores into a single 0–100 event score.

    Order-independent and saturating: two medium signals raise the score more than one, but it never
    exceeds 100 and never trivially sums there."""
    product = 1.0
    any_score = False
    for s in scores:
        any_score = True
        product *= 1.0 - clamp(s) / 100.0
    if not any_score:
        return 0.0
    return round(100.0 * (1.0 - product), 2)


def _ewma_alpha(dt: float, ewma_halflife: float) -> float:
    tau = ewma_halflife / LN2
    return 1.0 - math.exp(-max(dt, 0.0) / tau)


def read_score(state: SessionState, now: float, params: ScoringParams) -> float:
    """Pure read: the decayed accumulator, banded. Does NOT mutate state."""
    dt = now - state.last_seen
    a_decayed = state.accumulator * decay_factor(dt, params.half_life)
    return clamp(round(a_decayed, 4))


# Hard cap on retained window events — bounds memory even if timestamps never advance (so pruning by
# time never fires). Adversarial-review round 1.
MAX_WINDOW_EVENTS = 1024


def apply_event(
    state: SessionState,
    event_score: float,
    now: float,
    params: ScoringParams,
) -> float:
    """Apply one event at time ``now``; mutate ``state``; return the post-update banded session score.

    The current event is included in the returned score (no one-turn lag). Non-finite inputs are
    neutralized so a poisoned timestamp/score cannot wedge the accumulator at NaN."""
    if not math.isfinite(now):
        now = state.last_seen
    if not math.isfinite(event_score):
        event_score = 0.0
    event_score = max(0.0, min(100.0, event_score))

    dt = now - state.last_seen
    a_decayed = state.accumulator * decay_factor(dt, params.half_life)
    if not math.isfinite(a_decayed):
        a_decayed = 0.0
    a_new = a_decayed + event_score

    if state.events == 0:
        state.ewma = event_score
    else:
        alpha = _ewma_alpha(dt, params.ewma_halflife)
        state.ewma = alpha * event_score + (1.0 - alpha) * state.ewma

    state.accumulator = a_new
    state.last_seen = now
    state.events += 1

    # sliding window for flood/burst caps
    state.window_events.append((now, event_score))
    cutoff = now - params.window_seconds
    if state.window_events and state.window_events[0][0] < cutoff:
        state.window_events = [(t, s) for (t, s) in state.window_events if t >= cutoff]
    # hard bound regardless of time (defends against non-advancing/backwards timestamps)
    if len(state.window_events) > MAX_WINDOW_EVENTS:
        state.window_events = state.window_events[-MAX_WINDOW_EVENTS:]

    return clamp(round(a_new, 4))


def window_event_count(state: SessionState, now: float, window_seconds: float, min_score: float = 0.0) -> int:
    """Count events in the window. ``min_score`` lets the policy count only *risky* events so a benign
    (zero-score) chat burst doesn't trip the flood cap (adversarial-review round 1)."""
    cutoff = now - window_seconds
    return sum(1 for (t, s) in state.window_events if t >= cutoff and s > min_score)


def window_score_sum(state: SessionState, now: float, window_seconds: float) -> float:
    cutoff = now - window_seconds
    return round(sum(s for (t, s) in state.window_events if t >= cutoff), 4)


def new_state(session_id: str, now: float) -> SessionState:
    return SessionState(session_id=session_id, created=now, last_seen=now)


def replay_scores(events, params: ScoringParams):
    """Recompute the session-score trajectory from stored ``(session_id, occurred_at, event_score)`` tuples.

    This is the text-free replay (FR-25): it proves the accumulator trajectory is reproducible from an
    audit log that stores no raw prompt text. Returns the list of banded session scores in input order."""
    states: dict = {}
    out = []
    for sid, ts, ev in events:
        st = states.get(sid)
        if st is None:
            st = new_state(sid, ts)
            states[sid] = st
        out.append(apply_event(st, ev, ts, params))
    return out
