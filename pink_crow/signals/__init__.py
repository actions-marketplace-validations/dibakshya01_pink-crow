"""Deterministic, stdlib-only signal primitives shared by detectors."""

from __future__ import annotations

from .codecs import Decoded, decode_candidates
from .entropy import shannon_entropy
from .luhn import luhn_ok
from .normalize import (
    find_invisible,
    homoglyph_skeleton,
    invisible_summary,
    normalized_variants,
    strip_invisible,
)
from .tokens import (
    char_len,
    estimate_tokens,
    max_char_run,
    repetition_ratio,
    zlib_ratio,
)

__all__ = [
    "Decoded",
    "decode_candidates",
    "shannon_entropy",
    "luhn_ok",
    "find_invisible",
    "homoglyph_skeleton",
    "invisible_summary",
    "normalized_variants",
    "strip_invisible",
    "char_len",
    "estimate_tokens",
    "max_char_run",
    "repetition_ratio",
    "zlib_ratio",
]
