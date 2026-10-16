"""Session store.

The default :class:`InMemorySessionStore` is **single-process only** — under multiple workers/replicas a
logical session fragments across processes and the cumulative score is computed on partial data. Any
multi-worker deployment must use a shared store (the ``[redis]`` extra); the gateway enforces this via
explicit config (build-plan FR-18).
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
import uuid
from collections import OrderedDict
from collections.abc import Iterator
from typing import Any, Protocol, runtime_checkable

from .scoring import SessionState


@runtime_checkable
class SessionStore(Protocol):
    def get(self, session_id: str, now: float | None = None) -> SessionState | None: ...
    def put(self, state: SessionState) -> None: ...
    def delete(self, session_id: str) -> None: ...


class InMemorySessionStore:
    """Process-local store with TTL eviction AND a hard LRU size cap, so an attacker spamming unique
    session-ids (ids are free-form on the gateway) can't grow memory without bound, and silent sessions
    are eventually freed. Not shared across workers (see module docstring). (adversarial-review round 3)"""

    def __init__(self, ttl_seconds: float = 3600.0, max_sessions: int = 100_000) -> None:
        self._ttl = ttl_seconds
        self._max = max_sessions
        self._data: OrderedDict[str, SessionState] = OrderedDict()
        self._lock = threading.Lock()  # guards the shared OrderedDict's compound operations

    def get(self, session_id: str, now: float | None = None) -> SessionState | None:
        with self._lock:
            st = self._data.get(session_id)
            if st is None:
                return None
            if now is not None and self._ttl > 0 and (now - st.last_seen) > self._ttl:
                self._data.pop(session_id, None)
                return None
            self._data.move_to_end(session_id)  # mark recently used
            return st

    def put(self, state: SessionState) -> None:
        with self._lock:
            self._data[state.session_id] = state
            self._data.move_to_end(state.session_id)
            while len(self._data) > self._max:  # evict least-recently-used
                self._data.popitem(last=False)

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._data.pop(session_id, None)

    def __len__(self) -> int:
        return len(self._data)


class RedisSessionStore:
    """Shared, cross-process session store backed by Redis (the ``[redis]`` extra) — required for a
    multi-worker / multi-replica gateway deployment, where the in-memory store would fragment.

    Session state is stored as JSON under ``{prefix}{id}`` with a TTL. It exposes a best-effort per-session
    distributed ``lock()`` (SET NX PX) so the Engine serializes the cross-worker read-modify-write, not just
    the in-process one. The client is duck-typed (pass a ``redis.Redis``), so the core stays dependency-free
    and the store is testable with a fake client.
    """

    def __init__(self, client: Any, *, ttl_seconds: float = 3600.0, prefix: str = "pinkcrow:sess:",
                 lock_timeout_ms: int = 5000, lock_wait_ms: int = 2000) -> None:
        self._r = client
        self._ttl = int(ttl_seconds)
        self._prefix = prefix
        self._lock_timeout_ms = lock_timeout_ms
        self._lock_wait_ms = lock_wait_ms

    @classmethod
    def from_url(cls, url: str = "redis://localhost:6379/0", **kwargs: Any) -> RedisSessionStore:
        try:
            import redis  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover
            raise ImportError("RedisSessionStore needs the [redis] extra: pip install 'pink-crow[redis]'") from exc
        return cls(redis.Redis.from_url(url, decode_responses=True), **kwargs)

    def _key(self, session_id: str) -> str:
        return f"{self._prefix}{session_id}"

    def get(self, session_id: str, now: float | None = None) -> SessionState | None:
        raw = self._r.get(self._key(session_id))
        if not raw:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", "ignore")
        return SessionState.from_state_dict(json.loads(raw))

    def put(self, state: SessionState) -> None:
        payload = json.dumps(state.to_state_dict())
        if self._ttl > 0:
            self._r.set(self._key(state.session_id), payload, ex=self._ttl)
        else:
            self._r.set(self._key(state.session_id), payload)

    def delete(self, session_id: str) -> None:
        self._r.delete(self._key(session_id))

    @contextlib.contextmanager
    def lock(self, session_id: str) -> Iterator[None]:
        """Best-effort cross-worker per-session lock (SET NX PX with spin). On timeout it proceeds anyway
        rather than hanging the gateway (documented in docs/LIMITS.md)."""
        lock_key = f"{self._prefix}lock:{session_id}"
        token = uuid.uuid4().hex
        deadline = time.monotonic() + self._lock_wait_ms / 1000.0
        acquired = False
        while True:
            try:
                acquired = bool(self._r.set(lock_key, token, nx=True, px=self._lock_timeout_ms))
            except Exception:  # noqa: BLE001 - lock is best-effort; never block scanning on a lock error
                acquired = False
                break
            if acquired or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        try:
            yield
        finally:
            if acquired:
                with contextlib.suppress(Exception):
                    # release only if we still own it
                    if self._r.get(lock_key) in (token, token.encode() if hasattr(token, "encode") else token):
                        self._r.delete(lock_key)
