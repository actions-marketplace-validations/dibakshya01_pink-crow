"""Lethal-trifecta session correlation (pink_crow.trifecta + engine wiring).

The trifecta is a *cross-event* signal: its legs (untrusted input / sensitive data / external channel)
light on different turns, so these tests drive multi-turn sessions through the Engine.
"""

from __future__ import annotations

from pink_crow import trifecta
from pink_crow.config import standard
from pink_crow.engine import Engine
from pink_crow.models import Finding, Severity

# a realistic AWS key assembled at runtime (no scannable literal in the repo)
_AWS = "AKIA" + "IOSFODNN7EXAMPLE"
_SECRET_LINK = f"Here is the key {_AWS} — full export at [details](https://evil-collect.tld/x)"


def _trifecta(res):
    return next((f for f in res.findings if f.rule_id == trifecta.RULE_ID), None)


# -- unit: leg mapping --------------------------------------------------------------------------------

def test_legs_for_event_mapping():
    inj = Finding("pc.inj.override", ["LLM01:2026"], "prompt-injection", Severity.HIGH, "x")
    sec = Finding("pc.sec.aws_key", ["LLM02:2026"], "secret-egress", Severity.CRITICAL, "x")
    ext = Finding("pc.out.exfil_link", ["LLM10:2026"], "improper-output", Severity.HIGH, "x")

    assert trifecta.legs_for_event("input", "retrieved", []) == {trifecta.LEG_UNTRUSTED}
    assert trifecta.LEG_UNTRUSTED in trifecta.legs_for_event("input", "user", [inj])
    assert trifecta.legs_for_event("input", "user", []) == set()  # plain user turn lights nothing
    assert trifecta.LEG_SENSITIVE in trifecta.legs_for_event("output", "model", [sec])
    assert trifecta.LEG_EXTERNAL in trifecta.legs_for_event("output", "model", [ext])


# -- engine: assembling / not assembling the trifecta -------------------------------------------------

def test_full_trifecta_is_critical_and_blocks():
    eng = Engine(policy=standard())
    sid = "s-full"
    # leg 1 — merely ingesting retrieved/tool content is the "untrusted" leg (provenance alone lights it;
    # the content is benign here so this turn doesn't itself escalate — isolating the correlation).
    r1 = eng.scan_input(
        "Here is the quarterly report you requested; revenue was up 4%.",
        session_id=sid, provenance="retrieved", occurred_at=100.0,
    )
    assert _trifecta(r1) is None  # only one leg so far

    # output turn lights leg 2 (secret = sensitive) + leg 3 (external link) -> full trifecta
    r2 = eng.scan_output(_SECRET_LINK, session_id=sid, occurred_at=110.0)
    tri = _trifecta(r2)
    assert tri is not None and tri.severity == Severity.CRITICAL
    assert r2.disposition.action.value in ("block", "cooldown")


def test_two_legs_is_medium():
    eng = Engine(policy=standard())
    sid = "s-two"
    eng.scan_input("quarterly numbers attached", session_id=sid, provenance="retrieved", occurred_at=0.0)
    # a secret in output lights SENSITIVE -> 2 legs (untrusted + sensitive), no external channel
    r = eng.scan_output(f"the stored key is {_AWS}", session_id=sid, occurred_at=5.0)
    tri = _trifecta(r)
    assert tri is not None and tri.severity == Severity.MEDIUM


def test_benign_user_session_never_fires():
    eng = Engine(policy=standard())
    sid = "s-benign"
    for t, msg in enumerate(["hello there", "what is prompt injection?", "thanks, that helps"]):
        assert _trifecta(eng.scan_input(msg, session_id=sid, provenance="user", occurred_at=float(t))) is None
    r = eng.scan_output("Prompt injection is when untrusted input changes model behaviour.",
                        session_id=sid, occurred_at=10.0)
    assert _trifecta(r) is None


def test_legs_decay_out_of_window():
    eng = Engine(policy=standard())  # trifecta_window = 900s
    sid = "s-decay"
    eng.scan_input("Here is the retrieved document you asked for.", session_id=sid, provenance="retrieved", occurred_at=0.0)
    # >window later: the untrusted leg has decayed out, so only sensitive+external remain -> MEDIUM, not CRITICAL
    r = eng.scan_output(_SECRET_LINK, session_id=sid, occurred_at=2000.0)
    tri = _trifecta(r)
    assert tri is not None and tri.severity == Severity.MEDIUM


def test_stateless_scan_never_correlates():
    eng = Engine(policy=standard())
    r = eng.scan_output(_SECRET_LINK)  # no session_id => no cross-event memory
    assert _trifecta(r) is None


def test_trifecta_can_be_disabled():
    pol = standard()
    pol.scan.rule_overrides["pc.ses.trifecta"] = False
    eng = Engine(policy=pol)
    sid = "s-off"
    eng.scan_input("Here is the retrieved document you asked for.", session_id=sid, provenance="retrieved", occurred_at=0.0)
    r = eng.scan_output(_SECRET_LINK, session_id=sid, occurred_at=5.0)
    assert _trifecta(r) is None


def test_trifecta_legs_persist_in_session_state():
    eng = Engine(policy=standard())
    sid = "s-persist"
    eng.scan_input("Here is the retrieved document you asked for.", session_id=sid, provenance="retrieved", occurred_at=0.0)
    state = eng.store.get(sid, 1.0)
    assert state is not None and trifecta.LEG_UNTRUSTED in state.trifecta_legs
    # state round-trips through the shared-store serializer with legs intact
    restored = type(state).from_state_dict(state.to_state_dict())
    assert restored.trifecta_legs == state.trifecta_legs
