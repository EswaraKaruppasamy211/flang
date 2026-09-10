"""
Audit / Chain-of-Custody Log
-----------------------------
Append-only, hash-chained log. Every evidence access and every
forensic-module call is recorded here automatically by the interpreter
(scripts cannot opt out or run "quietly" -- there is no such mode).

Each entry embeds the hash of the previous entry, so any retroactive
edit to an earlier entry breaks the chain for every entry after it.
`AuditLog.verify()` independently re-walks the chain and reports the
first point of tampering, if any.
"""

from __future__ import annotations
import hashlib
import json
import time
from dataclasses import dataclass, asdict
from typing import List, Optional, Any, Dict


GENESIS_HASH = "0" * 64


@dataclass
class AuditEntry:
    index: int
    timestamp: float
    action: str
    actor: str
    case_id: str
    detail: Dict[str, Any]
    prev_hash: str
    entry_hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "index": self.index,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "case_id": self.case_id,
            "detail": self.detail,
            "prev_hash": self.prev_hash,
        }
        blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()


class AuditLog:
    def __init__(self, log_path: Optional[str] = None):
        self.entries: List[AuditEntry] = []
        self.log_path = log_path

    def record(self, action: str, actor: str, case_id: str, detail: Dict[str, Any]) -> AuditEntry:
        prev_hash = self.entries[-1].entry_hash if self.entries else GENESIS_HASH
        entry = AuditEntry(
            index=len(self.entries),
            timestamp=time.time(),
            action=action,
            actor=actor,
            case_id=case_id,
            detail=detail,
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()
        self.entries.append(entry)
        if self.log_path:
            self._append_to_disk(entry)
        return entry

    def _append_to_disk(self, entry: AuditEntry):
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(entry), default=str) + "\n")

    def verify(self) -> Dict[str, Any]:
        """
        Independently re-walk the hash chain. Returns a report dict:
        {"ok": bool, "broken_at": int|None, "checked": int}
        """
        prev_hash = GENESIS_HASH
        for entry in self.entries:
            if entry.prev_hash != prev_hash:
                return {"ok": False, "broken_at": entry.index, "checked": entry.index}
            recomputed = entry.compute_hash()
            if recomputed != entry.entry_hash:
                return {"ok": False, "broken_at": entry.index, "checked": entry.index}
            prev_hash = entry.entry_hash
        return {"ok": True, "broken_at": None, "checked": len(self.entries)}

    def as_list(self) -> List[Dict[str, Any]]:
        return [asdict(e) for e in self.entries]
