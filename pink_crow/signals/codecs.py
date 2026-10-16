"""Bounded base64 / hex decode-and-rescan.

Attackers hide instructions inside encoded blobs. We decode a *bounded* number of candidates to a
bounded length (so decoding can't itself be a DoS) and hand the decoded text back to the detectors for a
second-order scan.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import NamedTuple

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,8192}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,8192}")

MAX_CANDIDATES = 8
MAX_DECODE_LEN = 8192


class Decoded(NamedTuple):
    text: str
    kind: str
    span: tuple[int, int]


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / len(s)


def decode_candidates(text: str, max_candidates: int = MAX_CANDIDATES) -> list[Decoded]:
    """Return decoded payloads that look like meaningful text (mostly printable), bounded in count/size."""
    out: list[Decoded] = []
    for m in _B64_RE.finditer(text):
        if len(out) >= max_candidates:
            break
        s = m.group(0)[:MAX_DECODE_LEN]
        try:
            decoded = base64.b64decode(s + "=" * ((-len(s)) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        dt = decoded.decode("utf-8", "ignore")
        if len(dt) >= 4 and _printable_ratio(dt) > 0.8:
            out.append(Decoded(dt, "base64", m.span()))
    for m in _HEX_RE.finditer(text):
        if len(out) >= max_candidates:
            break
        s = m.group(0)
        if len(s) % 2:
            s = s[:-1]
        s = s[:MAX_DECODE_LEN]
        try:
            decoded = bytes.fromhex(s)
        except ValueError:
            continue
        dt = decoded.decode("utf-8", "ignore")
        if len(dt) >= 4 and _printable_ratio(dt) > 0.8:
            out.append(Decoded(dt, "hex", m.span()))
    return out
