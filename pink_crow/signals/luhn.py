"""Luhn mod-10 checksum — required before flagging a digit run as a credit-card number, to cut false
positives on arbitrary 13–19 digit sequences."""

from __future__ import annotations


def luhn_ok(num: str) -> bool:
    """True iff the digits in ``num`` pass the Luhn checksum. Requires 12–19 digits."""
    digits = [int(c) for c in num if c.isdigit()]
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0
