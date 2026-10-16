"""Thin integration helpers: a framework-agnostic ``guard`` and an OpenAI-style client wrapper."""

from __future__ import annotations

from .guard import PinkCrowTripwire, guard
from .openai import GuardedOpenAI

__all__ = ["guard", "PinkCrowTripwire", "GuardedOpenAI"]
