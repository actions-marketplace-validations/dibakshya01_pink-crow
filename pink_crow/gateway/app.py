"""FastAPI gateway (build-plan FR-18) — the language-agnostic drop-in.

Routes:
    POST /v1/scan/input   {text, session_id?, provenance?}
    POST /v1/scan/output  {text, session_id?}
    GET  /v1/session/{id}
    GET  /healthz
    GET  /metrics         (plain text)

Every scan response carries the ``X-PinkCrow-Risk`` header. The gateway is fail-closed and assumes a
trusted network; set ``PINKCROW_TOKEN`` to require a bearer token on the scan/session routes. The default
in-memory store is single-process only — set ``PINKCROW_STORE=shared`` (with a shared store) for multi
worker/replica deploys; selecting ``memory`` without acknowledging single-process emits a startup warning.
"""

from __future__ import annotations

import hmac
import logging
import os
from contextlib import asynccontextmanager

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Response
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise ImportError("pink-crow gateway needs the [gateway] extra: pip install 'pink-crow[gateway]'") from exc

from .. import __version__
from ..config import Policy, get_profile
from ..engine import Engine
from ..riskheader import HEADER_NAME

log = logging.getLogger("pink_crow.gateway")


class ScanBody(BaseModel):
    text: str
    session_id: str | None = None
    provenance: str = "user"


def _store_from_env():
    """Use a shared Redis store when PINKCROW_STORE=shared (required for multi-worker); else the default
    single-process in-memory store."""
    if os.environ.get("PINKCROW_STORE", "").lower() == "shared":
        from ..session import RedisSessionStore

        url = os.environ.get("PINKCROW_REDIS_URL", "redis://localhost:6379/0")
        log.info("pink-crow: using shared Redis session store at %s", url)
        return RedisSessionStore.from_url(url)
    return None  # Engine builds its default InMemorySessionStore


def _store_startup_check() -> None:
    mode = os.environ.get("PINKCROW_STORE", "").lower()
    if mode not in ("shared", "memory-single"):
        log.warning(
            "pink-crow gateway is using the in-memory session store, which is SINGLE-PROCESS only. "
            "Under multiple workers/replicas the cumulative session score is computed on partial data. "
            "For multi-worker deploys use a shared store and set PINKCROW_STORE=shared; "
            "to silence this on a single worker set PINKCROW_STORE=memory-single."
        )


def create_app(engine: Engine | None = None, policy: Policy | None = None) -> FastAPI:
    eng = engine or Engine(policy=policy or Policy(), store=_store_from_env())
    token = os.environ.get("PINKCROW_TOKEN", "")
    counters = {"input": 0, "output": 0, "blocked": 0}

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        _store_startup_check()
        yield

    app = FastAPI(title="pink-crow", version=__version__, lifespan=lifespan)

    def auth(authorization: str = Header(default="")) -> None:
        if token and not hmac.compare_digest(authorization, f"Bearer {token}"):  # constant-time
            raise HTTPException(status_code=401, detail="missing or invalid bearer token")

    def _run(body: ScanBody, direction: str, response: Response):
        if direction == "input":
            res = eng.scan_input(body.text, session_id=body.session_id, provenance=body.provenance)
        else:
            res = eng.scan_output(body.text, session_id=body.session_id)
        counters[direction] += 1
        if res.blocked:
            counters["blocked"] += 1
        response.headers[HEADER_NAME] = res.risk_header
        return res.to_dict()

    @app.post("/v1/scan/input")
    def scan_input(body: ScanBody, response: Response, _: None = Depends(auth)):
        return _run(body, "input", response)

    @app.post("/v1/scan/output")
    def scan_output(body: ScanBody, response: Response, _: None = Depends(auth)):
        return _run(body, "output", response)

    @app.get("/v1/session/{session_id}")
    def get_session(session_id: str, _: None = Depends(auth)):
        st = eng.store.get(session_id, eng.clock.now())
        if st is None:
            raise HTTPException(status_code=404, detail="unknown session")
        from ..scoring import read_score

        return {
            "session_id": session_id,
            "session_score": read_score(st, eng.clock.now(), eng.policy.scoring),
            "ewma": st.ewma,
            "events": st.events,
            "flagged": st.flagged,
            "cooldown_until": st.cooldown_until if st.cooldown_until > 0 else 0.0,
        }

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__, "policy": eng.policy.name}

    @app.get("/metrics")
    def metrics(_: None = Depends(auth)) -> Response:
        lines = [
            "# pink-crow gateway metrics",
            f'pink_crow_version{{v="{__version__}"}} 1',
            f"pink_crow_scans_input_total {counters['input']}",
            f"pink_crow_scans_output_total {counters['output']}",
            f"pink_crow_blocked_total {counters['blocked']}",
        ]
        return Response("\n".join(lines) + "\n", media_type="text/plain")

    return app


def run(host: str = "127.0.0.1", port: int = 8000, profile: str = "standard") -> None:  # pragma: no cover
    import uvicorn

    uvicorn.run(create_app(policy=get_profile(profile)), host=host, port=port)
