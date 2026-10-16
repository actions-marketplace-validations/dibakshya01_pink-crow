"""Cheap, dependency-free text measurements for the unbounded-consumption detector (LLM06).

No tokenizer dependency: ``estimate_tokens`` uses the well-known ~4-chars/token heuristic (good enough
for a pre-flight resource check — the host can feed exact counts if it has them).
"""

from __future__ import annotations

import re
import zlib

_WORD_RE = re.compile(r"\w+", re.UNICODE)


def char_len(text: str) -> int:
    return len(text)


def estimate_tokens(text: str) -> int:
    """~4 characters per token (OpenAI's rule of thumb). Deterministic, offline, tokenizer-free."""
    return max(len(text) // 4, len(_WORD_RE.findall(text)))


def repetition_ratio(text: str) -> float:
    """unique-words / total-words over the text. Low ratio => highly repetitive (flood-like).

    Returns 1.0 for text with fewer than 2 words (nothing to repeat)."""
    words = _WORD_RE.findall(text.lower())
    if len(words) < 2:
        return 1.0
    return len(set(words)) / len(words)


def max_char_run(text: str) -> int:
    """Length of the longest run of a single repeated character."""
    best = run = 0
    prev = ""
    for ch in text:
        run = run + 1 if ch == prev else 1
        prev = ch
        if run > best:
            best = run
    return best


def zlib_ratio(text: str) -> float:
    """compressed / original size. A very low ratio (<~0.1) means the input is highly repetitive and
    cheap to amplify (compression-bomb-like). Returns 1.0 for tiny inputs where it is not meaningful."""
    raw = text.encode("utf-8", "ignore")
    if len(raw) < 64:
        return 1.0
    comp = zlib.compress(raw, 6)
    return len(comp) / len(raw)
