"""Attack-tests guarding the fixes from adversarial-review round 3."""

from __future__ import annotations

import json
import time

from pink_crow.catalog import catalog
from pink_crow.clock import FixedClock
from pink_crow.engine import Engine
from pink_crow.models import Action
from pink_crow.scoring import SessionState, new_state
from pink_crow.session import InMemorySessionStore


# 🟡1 — the markdown-link regex ReDoS: a run of "[" must not drive O(n^2) scanning
def test_markdown_link_redos_bounded():
    eng = Engine(clock=FixedClock(0.0))
    for name, payload in [
        ("all-bracket", "[" * 65536),                       # no "](http" -> pre-filter skips, fast
        ("bracket-bomb", "[" * 65000 + "](http" + "a" * 100),  # pre-filter passes -> bounded by {0,256}+cap
    ]:
        t = time.perf_counter()
        eng.scan_output(payload)
        elapsed = time.perf_counter() - t
        assert elapsed < 0.3, f"{name}: MARKDOWN_LINK_RE not bounded ({elapsed * 1000:.0f}ms; was ~1450ms/23s)"


# 🟡3 — the in-memory session store must not grow without bound
def test_session_store_lru_cap():
    store = InMemorySessionStore(ttl_seconds=3600.0, max_sessions=1000)
    for i in range(5000):
        store.put(new_state(f"s{i}", now=float(i)))
    assert len(store) <= 1000, f"session store grew unbounded: {len(store)}"
    # most-recently-used survive; oldest evicted
    assert store.get("s4999") is not None
    assert store.get("s0") is None


# ⚪4 — a non-str session_id must not crash (coerced, not an uncaught AttributeError)
def test_non_str_session_id_does_not_crash():
    eng = Engine(clock=FixedClock(0.0))
    r = eng.scan_input("hello", session_id=12345)  # type: ignore[arg-type]
    assert r.disposition.action in (Action.ALLOW, Action.FLAG, Action.BLOCK, Action.REDACT, Action.COOLDOWN)


# ⚪5 — SessionState.to_dict() must be valid JSON even for a fresh (-inf cooldown) session
def test_session_state_to_dict_is_json_safe():
    d = new_state("s", now=0.0).to_dict()
    assert d["cooldown_until"] == 0.0
    json.dumps(d, allow_nan=False)  # must not raise


# ⚪7 — pc.out.oversize is in the catalog with a consumption-only crosswalk
def test_oversize_rule_in_catalog():
    rows = {r["rule_id"]: r for r in catalog()}
    assert "pc.out.oversize" in rows
    assert rows["pc.out.oversize"]["owasp_ids"] == ["LLM06:2026", "LLM10:2025"]


# determinism unaffected by the round-3 changes
def test_determinism_after_round3():
    def run():
        return Engine(clock=FixedClock(0.0)).scan_output("your key AKIAIOSFODNN7EXAMPLE").to_dict()

    assert run() == run()


def test_fresh_state_never_in_cooldown_at_any_now():
    st: SessionState = new_state("s", now=0.0)
    assert st.cooldown_until == float("-inf")  # so cooldown_until > now is false for any finite now
