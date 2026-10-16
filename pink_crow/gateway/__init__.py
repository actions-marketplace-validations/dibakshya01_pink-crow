"""HTTP gateway + pure-ASGI middleware (the ``[gateway]`` extra for the server routes).

``PinkCrowMiddleware`` needs only the core; ``create_app`` / ``run`` need FastAPI and are imported lazily.
"""

from __future__ import annotations

from typing import Any

from .middleware import PinkCrowMiddleware

__all__ = ["PinkCrowMiddleware", "create_app", "run"]


def __getattr__(name: str) -> Any:
    if name in ("create_app", "run"):
        from . import app

        return getattr(app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
