"""Append-only audit log + replay (build-plan FR-25).

Two artifacts:

* **Audit log** (production): one entry per scanned event, storing *no raw prompt text* (so no secrets are
  persisted) yet enough to reproduce the session-score trajectory and dispositions — this backs
  "why was this session blocked?".
* **Replay log** (``keep_text=True``, opt-in forensics): additionally stores ``text`` so a replay also
  re-derives each event score from input and proves detector determinism end-to-end.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Any

_UNICODE_VERSION = unicodedata.unidata_version


@dataclass
class AuditEntry:
    session_id: str | None
    direction: str
    occurred_at: float
    provenance: str
    event_score: float
    session_score: float
    action: str
    acs_decision: str
    rule_ids: list[str]
    owasp_ids: list[str]
    engine_version: str
    unicode_version: str = _UNICODE_VERSION
    text: str | None = None  # present only in a replay log

    def to_dict(self) -> dict[str, Any]:
        d = {
            "session_id": self.session_id,
            "direction": self.direction,
            "occurred_at": self.occurred_at,
            "provenance": self.provenance,
            "event_score": self.event_score,
            "session_score": self.session_score,
            "action": self.action,
            "acs_decision": self.acs_decision,
            "rule_ids": list(self.rule_ids),
            "owasp_ids": list(self.owasp_ids),
            "engine_version": self.engine_version,
            "unicode_version": self.unicode_version,
        }
        if self.text is not None:
            d["text"] = self.text
        return d


class AuditLog:
    """In-memory append-only log. ``keep_text=True`` makes it a replay log (stores raw text)."""

    def __init__(self, keep_text: bool = False, max_entries: int = 10000) -> None:
        self.keep_text = keep_text
        self.max_entries = max_entries
        self._entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        if not self.keep_text:
            entry.text = None
        self._entries.append(entry)
        if len(self._entries) > self.max_entries:
            self._entries = self._entries[-self.max_entries :]

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def to_list(self) -> list[dict[str, Any]]:
        return [e.to_dict() for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)
