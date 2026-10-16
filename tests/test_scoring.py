"""M1 — scoring core: decay-on-read, current-event-counts, monotonic burst, window, noisy-OR (FR-4/FR-5)."""

from __future__ import annotations

from pink_crow.scoring import (
    ScoringParams,
    apply_event,
    combine_findings,
    new_state,
    read_score,
    window_event_count,
    window_score_sum,
)


def test_decay_halves_after_one_half_life():
    p = ScoringParams(half_life=100.0)
    s = new_state("s", now=0.0)
    apply_event(s, 80.0, now=0.0, params=p)
    assert read_score(s, now=100.0, params=p) == 40.0          # one half-life -> 50%
    assert abs(read_score(s, now=200.0, params=p) - 20.0) < 1e-6  # two half-lives -> 25%


def test_current_event_counts_toward_its_own_disposition():
    # A fresh single scan of score s must report exactly s (no one-turn lag) — the FR-4 regression.
    p = ScoringParams()
    s = new_state("s", now=0.0)
    assert apply_event(s, 30.0, now=0.0, params=p) == 30.0


def test_accumulator_monotonic_within_same_instant_burst():
    p = ScoringParams()
    s = new_state("s", now=0.0)
    r1 = apply_event(s, 10.0, now=0.0, params=p)
    r2 = apply_event(s, 10.0, now=0.0, params=p)
    r3 = apply_event(s, 10.0, now=0.0, params=p)
    assert r1 < r2 < r3
    assert r3 == 30.0


def test_one_off_spike_decays_below_threshold():
    # FR-5: the score never latches; a one-off spike bleeds off.
    p = ScoringParams(half_life=60.0)
    s = new_state("s", now=0.0)
    apply_event(s, 50.0, now=0.0, params=p)
    assert read_score(s, now=600.0, params=p) < 1.0  # 10 half-lives later


def test_decay_acts_on_unclamped_accumulator():
    # A sustained campaign pushes the accumulator above 100; it stays Critical (>=85) longer than
    # a naive "max 100" reading would suggest.
    p = ScoringParams(half_life=100.0)
    s = new_state("s", now=0.0)
    for _ in range(5):
        apply_event(s, 90.0, now=0.0, params=p)  # accumulator ~ 450, banded 100
    assert s.accumulator > 100.0
    assert read_score(s, now=100.0, params=p) == 100.0  # 450*0.5=225 -> still clamped at 100


def test_window_counters():
    p = ScoringParams(window_seconds=60.0)
    s = new_state("s", now=0.0)
    apply_event(s, 10.0, now=0.0, params=p)
    apply_event(s, 10.0, now=10.0, params=p)
    apply_event(s, 10.0, now=20.0, params=p)
    assert window_event_count(s, now=20.0, window_seconds=60.0) == 3
    assert window_score_sum(s, now=20.0, window_seconds=60.0) == 30.0
    assert window_event_count(s, now=120.0, window_seconds=60.0) == 0  # all aged out


def test_combine_findings_noisy_or_and_order_independent():
    assert combine_findings([]) == 0.0
    assert combine_findings([50.0, 50.0]) == 75.0        # 1-(0.5*0.5)=0.75
    assert combine_findings([100.0]) == 100.0
    assert combine_findings([30.0, 70.0]) == combine_findings([70.0, 30.0])
    # more signals never decrease the score
    assert combine_findings([30.0, 30.0]) >= combine_findings([30.0])


def test_deterministic_same_input_same_score():
    p = ScoringParams()
    out = []
    for _ in range(3):
        s = new_state("s", now=0.0)
        out.append(apply_event(s, 42.0, now=0.0, params=p))
    assert out[0] == out[1] == out[2]
