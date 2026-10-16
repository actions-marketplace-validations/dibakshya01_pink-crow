"""The Engine — the one object that ties detectors → scoring → session → policy → result, with an
injectable clock and an optional audit log. ``scan_input`` / ``scan_output`` are the entry points
(build-plan FR-1/FR-2); they are fail-closed by default (FR-16).
"""

from __future__ import annotations

import contextlib
import math
import threading
import time
import zlib
from typing import Any

from . import __version__
from .audit import AuditEntry, AuditLog
from .clock import Clock, SystemClock
from .config import Policy, get_profile
from .detectors.base import Detector, ScanContext, runs_on
from .models import ACSDecision, Action, Disposition, Finding, RedactionSpan, ScanResult
from .policy import evaluate, fail_closed
from .scoring import apply_event, combine_findings, new_state, read_score
from .session import InMemorySessionStore, SessionStore
from .trifecta import correlate as correlate_trifecta

_LOCK_STRIPES = 64
# reject timestamps outside a sane epoch range (year ~2286) — blocks the 1e308/1e12 cooldown wedge while
# still accepting real epoch times and replay/test clocks. occurred_at must be a host-trusted value.
_MAX_ABS_TS = 1e10


def default_detectors() -> list[Detector]:
    """The deterministic bundled detectors. Extended per milestone (injection → +egress → +consumption)."""
    from .detectors.injection import InjectionDetector

    dets: list[Detector] = [InjectionDetector()]
    try:  # egress + consumption land in M3; import lazily so M2 works standalone
        from .detectors.consumption import ConsumptionDetector
        from .detectors.egress import EgressDetector

        dets.extend([ConsumptionDetector(), EgressDetector()])
    except ImportError:
        pass
    return dets


class Engine:
    def __init__(
        self,
        policy: Policy | str | None = None,
        *,
        store: SessionStore | None = None,
        clock: Clock | None = None,
        audit: AuditLog | None = None,
        detectors: list[Detector] | None = None,
    ) -> None:
        if isinstance(policy, str):
            policy = get_profile(policy)
        self.policy: Policy = policy or Policy()
        self.clock: Clock = clock or SystemClock()
        self.store: SessionStore = store if store is not None else InMemorySessionStore()
        self.audit: AuditLog | None = audit
        self.detectors: list[Detector] = list(detectors) if detectors is not None else default_detectors()
        # striped per-session locks: serialize the read-modify-write of one session's state (the gateway
        # runs scans in a threadpool) without unbounded lock growth (adversarial-review round 2).
        self._locks: list[threading.Lock] = [threading.Lock() for _ in range(_LOCK_STRIPES)]

    def _lock_for(self, session_id: str):
        return self._locks[zlib.crc32(session_id.encode("utf-8", "ignore")) % _LOCK_STRIPES]

    # -- public API -------------------------------------------------------------------------------
    def scan_input(
        self,
        text: str,
        *,
        session_id: str | None = None,
        provenance: str = "user",
        context: dict | None = None,
        occurred_at: float | None = None,
    ) -> ScanResult:
        return self._scan(text, "input", session_id, provenance, occurred_at)

    def scan_output(
        self,
        text: str,
        *,
        session_id: str | None = None,
        context: dict | None = None,
        occurred_at: float | None = None,
    ) -> ScanResult:
        return self._scan(text, "output", session_id, "model", occurred_at)

    # -- internals --------------------------------------------------------------------------------
    def _scan(
        self,
        text: str,
        direction: str,
        session_id: str | None,
        provenance: str,
        occurred_at: float | None,
    ) -> ScanResult:
        # a non-str session_id would crash _lock_for before the fail-closed guards; coerce it defensively
        if session_id is not None and not isinstance(session_id, str):
            session_id = str(session_id)
        # resolve + validate the timestamp; a non-finite/garbage occurred_at fails closed rather than
        # poisoning the accumulator (adversarial-review round 1).
        try:
            now = self.clock.now() if occurred_at is None else float(occurred_at)
            if not math.isfinite(now) or abs(now) > _MAX_ABS_TS:
                raise ValueError("occurred_at must be finite and within a sane range")
        except (TypeError, ValueError) as exc:
            disp = fail_closed(self.policy, f"bad occurred_at: {type(exc).__name__}")
            ts = self.clock.now()
            res = ScanResult(session_id, direction, 100.0, 100.0, 0.0, [], disp, text, [], ts)
            self._record(res, text)
            return res

        # serialize same-session read-modify-write so concurrent scans can't lose updates. A shared store
        # (e.g. Redis) may provide a cross-worker lock; otherwise use the in-process striped lock.
        if not session_id:
            lock: Any = contextlib.nullcontext()
        elif hasattr(self.store, "lock"):
            lock = self.store.lock(session_id)
        else:
            lock = self._lock_for(session_id)
        with lock:
            return self._scan_body(text, direction, session_id, provenance, now)

    def _scan_body(
        self,
        text: str,
        direction: str,
        session_id: str | None,
        provenance: str,
        now: float,
    ) -> ScanResult:
        try:
            state = self.store.get(session_id, now) if session_id else None
        except Exception as exc:  # noqa: BLE001 - store fault must fail closed, never silently allow
            disp = fail_closed(self.policy, type(exc).__name__)
            res = ScanResult(session_id, direction, 100.0, 100.0, 0.0, [], disp, text, [], now)
            self._record(res, text)
            return res

        # early cooldown short-circuit — refuse without re-scoring (FR-14)
        if state is not None and state.cooldown_until > now:
            disp = Disposition(
                Action.COOLDOWN, ACSDecision.DENY, ["pink-crow:session-cooldown"],
                f"session in cooldown for {state.cooldown_until - now:.0f}s more",
            )
            res = ScanResult(session_id, direction, 0.0, read_score(state, now, self.policy.scoring),
                             state.ewma, [], disp, text, [], now)
            self._record(res, text)
            return res

        # run detectors (fail-closed on any error — FR-16)
        try:
            ctx = ScanContext.build(text, direction, provenance, self.policy.scan)
            findings: list[Finding] = []
            redactions: list[RedactionSpan] = []
            redacted_text = text
            # Soft time budget: stop running further detectors once the budget is spent, so a slow scan
            # can't compound across detectors. (A single regex can't be interrupted in stdlib `re`; the
            # post-normalization length cap bounds that case — see docs/LIMITS.md.)
            budget = self.policy.scan.scan_time_budget_ms / 1000.0
            start = time.perf_counter()
            for det in self.detectors:
                if runs_on(det, direction):
                    findings.extend(det.detect(ctx))
                    if budget > 0 and (time.perf_counter() - start) > budget:
                        break
            # egress detector attaches redactions on the context; collected here if present
            redactions = list(ctx.redactions)
            redacted_text = ctx.redacted_text or text
        except Exception as exc:  # noqa: BLE001 - deliberate: any detector fault must fail closed
            disp = fail_closed(self.policy, type(exc).__name__)
            res = ScanResult(session_id, direction, 100.0, 100.0, 0.0, [], disp, text, [], now)
            self._record(res, text)
            return res

        if session_id:
            if state is None:
                state = new_state(session_id, now)
            # lethal-trifecta session correlation (cross-event): light this event's legs and, if two or
            # three are now active, fold in a correlation finding BEFORE scoring so it counts toward this
            # turn's disposition. Only runs for session scans — correlation needs cross-event memory.
            tri = correlate_trifecta(
                state, direction, provenance, findings, now, self.policy.trifecta_window,
                enabled=self.policy.scan.rule_overrides.get("pc.ses.trifecta", True),
            )
            if tri is not None:
                findings.append(tri)
            event_score = combine_findings([f.score for f in findings])
            session_score = apply_event(state, event_score, now, self.policy.scoring)
            ewma = state.ewma
        else:
            event_score = combine_findings([f.score for f in findings])
            session_score = event_score
            ewma = event_score

        disp = evaluate(self.policy, session_score, state, findings, redactions, now)
        if state is not None:
            state.flagged = disp.action != Action.ALLOW
            if session_id:
                self.store.put(state)

        res = ScanResult(session_id, direction, event_score, session_score, ewma,
                         findings, disp, redacted_text, redactions, now)
        self._record(res, text)
        return res

    def replay(self, entries: list) -> list:
        """Re-scan a REPLAY log (entries carrying ``.text``) through a fresh engine + ``FixedClock``,
        returning the recomputed ``(session_score, action)`` per entry. Proves detector+scoring
        determinism end-to-end (FR-25). Raises if given a text-free audit log."""
        from .clock import FixedClock

        clk = FixedClock(0.0)
        fresh = Engine(policy=self.policy, store=InMemorySessionStore(), clock=clk, detectors=self.detectors)
        traj = []
        for e in entries:
            if e.text is None:
                raise ValueError("replay() requires a replay log recorded with keep_text=True")
            clk.set(e.occurred_at)
            if e.direction == "output":
                r = fresh.scan_output(e.text, session_id=e.session_id, occurred_at=e.occurred_at)
            else:
                prov = e.provenance if e.provenance in ("retrieved", "tool") else "user"
                r = fresh.scan_input(e.text, session_id=e.session_id, provenance=prov, occurred_at=e.occurred_at)
            traj.append((r.session_score, r.disposition.action.value))
        return traj

    def _record(self, res: ScanResult, text: str) -> None:
        if self.audit is None:
            return
        rule_ids = [f.rule_id for f in res.findings]
        owasp = sorted({oid for f in res.findings for oid in f.owasp_ids})
        self.audit.record(
            AuditEntry(
                session_id=res.session_id,
                direction=res.direction,
                occurred_at=res.occurred_at,
                provenance="model" if res.direction == "output" else "user",
                event_score=res.event_score,
                session_score=res.session_score,
                action=res.disposition.action.value,
                acs_decision=res.disposition.acs_decision.value,
                rule_ids=rule_ids,
                owasp_ids=owasp,
                engine_version=__version__,
                text=text if self.audit.keep_text else None,
            )
        )


# -- module-level convenience (default process-wide engine) ------------------------------------------
_default_engine: Engine | None = None


def _engine() -> Engine:
    global _default_engine
    if _default_engine is None:
        _default_engine = Engine()
    return _default_engine


def scan_input(text: str, **kwargs) -> ScanResult:
    return _engine().scan_input(text, **kwargs)


def scan_output(text: str, **kwargs) -> ScanResult:
    return _engine().scan_output(text, **kwargs)
