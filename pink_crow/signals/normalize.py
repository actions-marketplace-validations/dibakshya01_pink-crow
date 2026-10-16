"""Obfuscation normalization.

Injection payloads hide behind invisible characters, bidi overrides, homoglyphs, leetspeak and
character-spacing. We (a) *detect* those as signals in their own right and (b) produce normalized
*variants* of the text so the phrase/role detectors can match a payload that was obfuscated. All of this
is deterministic and stdlib-only (``re`` + ``unicodedata``).
"""

from __future__ import annotations

import re
import unicodedata
from typing import NamedTuple

# --- invisible / control character classes -------------------------------------------------------
# Zero-width, joiners, BOM, soft hyphen, word joiner, Mongolian vowel separator, zero-width no-break.
INVISIBLE_RE = re.compile("[​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎]")
# Unicode "tag" block — invisible to humans, readable by models. Very high-signal smuggling indicator.
TAGBLOCK_RE = re.compile("[\U000e0000-\U000e007f]")
# Bidirectional overrides / isolates (Trojan-Source style).
BIDI_RE = re.compile("[‪-‮⁦-⁩]")
# Variation selectors (can carry smuggled data in some attacks).
VARSEL_RE = re.compile("[︀-️]")

_ALL_INVISIBLE_RE = re.compile(
    "[​‌‍‎‏⁠⁡⁢⁣⁤﻿­᠎"
    "‪-‮⁦-⁩︀-️]|[\U000e0000-\U000e007f]"
)


class Invisible(NamedTuple):
    start: int
    end: int
    kind: str


def find_invisible(text: str) -> list[Invisible]:
    """Locate invisible/bidi/tag-block/variation-selector characters, classified by kind."""
    found: list[Invisible] = []
    for m in TAGBLOCK_RE.finditer(text):
        found.append(Invisible(m.start(), m.end(), "tag-block"))
    for m in BIDI_RE.finditer(text):
        found.append(Invisible(m.start(), m.end(), "bidi"))
    for m in VARSEL_RE.finditer(text):
        found.append(Invisible(m.start(), m.end(), "variation-selector"))
    for m in INVISIBLE_RE.finditer(text):
        found.append(Invisible(m.start(), m.end(), "zero-width"))
    return sorted(found, key=lambda i: (i.start, i.kind))


def strip_invisible(text: str) -> str:
    return _ALL_INVISIBLE_RE.sub("", text)


def nfkc(text: str) -> str:
    return unicodedata.normalize("NFKC", text)


# --- leetspeak ------------------------------------------------------------------------------------
_LEET = str.maketrans({"4": "a", "3": "e", "1": "i", "0": "o", "5": "s", "7": "t", "$": "s", "@": "a"})


def deleet(text: str) -> str:
    return text.translate(_LEET)


# --- homoglyph skeleton ---------------------------------------------------------------------------
# A curated confusables map (Cyrillic / Greek / common lookalikes -> Latin). NFKC handles fullwidth and
# compatibility forms; this covers the script-confusable cases NFKC does not.
_CONFUSABLES = {
    # Cyrillic -> Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ѕ": "s", "і": "i",
    "ј": "j", "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "г": "r", "А": "A", "Е": "E",
    "О": "O", "Р": "P", "С": "C", "Х": "X", "У": "Y", "К": "K", "М": "M", "Т": "T", "В": "B",
    "Н": "H", "І": "I", "Ј": "J",
    # Greek -> Latin
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "υ": "u",
    "χ": "x", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M",
    "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}


def homoglyph_skeleton(text: str) -> str:
    """Fold common homoglyphs to a Latin skeleton (after NFKC)."""
    return nfkc(text).translate(_CONFUSABLE_TABLE)


# --- character-spacing / punctuation evasion ("i g n o r e", "i.g.n.o.r.e") -----------------------
_SPACED_RE = re.compile(r"\b(\w(?:[ \t]\w){3,4096})\b")
# single word-chars joined by punctuation separators (dot/dash/underscore/star/middots/slashes)
_PUNCT_SEP_RE = re.compile(r"(\w(?:[.\-_*·•/|]\w){3,4096})")

# Default post-normalization cap: NFKC can expand one char ~18x, so a variant is re-truncated to bound
# the regex work regardless of expansion (adversarial-review round 1 self-DoS fix).
DEFAULT_VARIANT_CAP = 20000


def collapse_spacing(text: str) -> str:
    """Collapse runs of single characters separated by single spaces (4+), leaving normal words alone."""
    return _SPACED_RE.sub(lambda m: m.group(1).replace(" ", "").replace("\t", ""), text)


def collapse_separators(text: str) -> str:
    """Collapse single chars joined by punctuation ("i.g.n.o.r.e" -> "ignore"), leaving words alone."""
    return _PUNCT_SEP_RE.sub(lambda m: re.sub(r"[.\-_*·•/|]", "", m.group(1)), text)


# --- variants for re-scan -------------------------------------------------------------------------
def normalized_variants(text: str, cap: int = DEFAULT_VARIANT_CAP) -> list[str]:
    """Deterministic, de-duplicated list of normalized forms to run phrase/role detectors against.

    Always includes the original first so spans from the primary match stay meaningful. The normalized
    base is truncated to ``cap`` *before* the derived variants are built, so NFKC expansion (one char can
    become ~18) cannot blow up the downstream regex work."""
    base = strip_invisible(nfkc(text))
    if cap and len(base) > cap:
        base = base[:cap]
    variants = [
        text,
        base,
        homoglyph_skeleton(base),
        deleet(base),
        collapse_spacing(base),
        collapse_separators(base),
    ]
    seen: set = set()
    out: list[str] = []
    for v in variants:
        if cap and len(v) > cap:
            v = v[:cap]
        if v and v not in seen:
            seen.add(v)
            out.append(v)
    return out


def invisible_summary(text: str) -> tuple[int, list[str]]:
    """(count, sorted distinct kinds) of invisible/bidi/tag-block characters present."""
    inv = find_invisible(text)
    kinds = sorted({i.kind for i in inv})
    return len(inv), kinds
