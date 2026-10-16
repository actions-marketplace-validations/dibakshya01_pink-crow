"""Shannon entropy — used to gate the generic secret rule so random-looking high-entropy strings score
and ordinary prose does not."""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(s: str) -> float:
    """Bits per character. Empty string -> 0.0."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
