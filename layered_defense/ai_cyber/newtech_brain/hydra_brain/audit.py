"""
hydra_brain.audit
=================

Tamper-evident, hash-chained audit log for every decision the wired
HYDRA brain makes (ingest, quarantine, recommendation, authorization,
simulation, verification, re-planning).

Each entry commits to the previous entry's hash, so any edit, deletion or
reordering of past entries is detectable with ``verify()``.

Standard library only.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Tuple

GENESIS_HASH = "0" * 64


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    timestamp: str
    kind: str
    data: Mapping[str, Any]
    previous_hash: str
    entry_hash: str


class AuditChain:
    """Append-only hash chain. Thread-safe."""

    def __init__(self) -> None:
        self._entries: List[AuditEntry] = []
        self._lock = threading.RLock()

    @staticmethod
    def _compute_hash(
        sequence: int,
        timestamp: str,
        kind: str,
        data: Mapping[str, Any],
        previous_hash: str,
    ) -> str:
        material = _canonical(
            [sequence, timestamp, kind, data, previous_hash]
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def append(self, kind: str, data: Mapping[str, Any]) -> AuditEntry:
        if not kind or not kind.strip():
            raise ValueError("audit kind must not be empty")

        with self._lock:
            sequence = len(self._entries)
            previous_hash = (
                self._entries[-1].entry_hash
                if self._entries
                else GENESIS_HASH
            )
            timestamp = datetime.now(timezone.utc).isoformat()

            # Round-trip through JSON so the stored data is exactly what
            # was hashed (no later mutation through shared references).
            frozen_data = json.loads(_canonical(dict(data)))

            entry = AuditEntry(
                sequence=sequence,
                timestamp=timestamp,
                kind=kind,
                data=frozen_data,
                previous_hash=previous_hash,
                entry_hash=self._compute_hash(
                    sequence,
                    timestamp,
                    kind,
                    frozen_data,
                    previous_hash,
                ),
            )
            self._entries.append(entry)
            return entry

    def entries(self, kind: str | None = None) -> Tuple[AuditEntry, ...]:
        with self._lock:
            if kind is None:
                return tuple(self._entries)
            return tuple(e for e in self._entries if e.kind == kind)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    @property
    def head_hash(self) -> str:
        with self._lock:
            return (
                self._entries[-1].entry_hash
                if self._entries
                else GENESIS_HASH
            )

    def verify(self) -> List[str]:
        """Return a list of integrity errors (empty list == chain intact)."""
        errors: List[str] = []
        with self._lock:
            previous = GENESIS_HASH
            for index, entry in enumerate(self._entries):
                if entry.sequence != index:
                    errors.append(f"entry {index}: bad sequence")
                if entry.previous_hash != previous:
                    errors.append(f"entry {index}: broken chain link")
                expected = self._compute_hash(
                    entry.sequence,
                    entry.timestamp,
                    entry.kind,
                    entry.data,
                    entry.previous_hash,
                )
                if expected != entry.entry_hash:
                    errors.append(f"entry {index}: hash mismatch")
                previous = entry.entry_hash
        return errors

    def export_jsonl(self, path: str) -> int:
        """Write the chain to a JSON-lines file; returns entries written."""
        with self._lock:
            with open(path, "w", encoding="utf-8") as handle:
                for entry in self._entries:
                    handle.write(
                        _canonical(
                            {
                                "sequence": entry.sequence,
                                "timestamp": entry.timestamp,
                                "kind": entry.kind,
                                "data": entry.data,
                                "previous_hash": entry.previous_hash,
                                "entry_hash": entry.entry_hash,
                            }
                        )
                        + "\n"
                    )
            return len(self._entries)
