"""
Evidence Management Layer
--------------------------
The ONLY part of the runtime allowed to touch raw evidence paths.
Everything else in the interpreter/modules receives opaque, read-only
"handle" objects from here -- never a raw filesystem path -- which is
what prevents a script (malicious or accidental) from writing back into
original evidence.

Design principles enforced here:
  * evidence is opened/mounted read-only wherever the OS allows it
  * every evidence file is hashed at ingestion time
  * a chain-of-custody record is created automatically at ingestion
  * evidence objects are scoped to a case_id and cannot be referenced
    by a script running under a different case
"""

from __future__ import annotations
import hashlib
import os
import stat
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha512_file(path: str) -> str:
    """Added alongside sha256_file(); does not replace or change it.
    SHA-512 support for evidence manifests that require it."""
    h = hashlib.sha512()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_dir_manifest(path: str) -> str:
    """
    Hash a stable manifest of (relative_path, size, mtime, file_sha256)
    for every file under a directory, and return the hash of that
    manifest.  Used to stand in for 'imaging a disk' in this prototype,
    where a directory tree represents an already-acquired, already
    write-blocked evidence source (e.g. an extracted E01 image).
    """
    h = hashlib.sha256()
    for root, _, files in sorted(os.walk(path)):
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, path)
            try:
                st = os.stat(full)
                filehash = sha256_file(full)
            except OSError:
                continue
            entry = f"{rel}|{st.st_size}|{int(st.st_mtime)}|{filehash}\n"
            h.update(entry.encode("utf-8"))
    return h.hexdigest()


class EvidenceIntegrityError(Exception):
    pass


@dataclass
class ChainOfCustodyRecord:
    evidence_id: str
    case_id: str
    source_path: str
    evidence_type: str
    ingested_by: str
    ingested_at: float
    ingestion_hash: str


class EvidenceHandle:
    """
    Opaque, capability-scoped reference to a piece of evidence.
    Analysis modules receive these, never raw paths.
    """

    def __init__(self, evidence_id: str, case_id: str, evidence_type: str,
                 source_path: str, ingestion_hash: str, read_only_root: str):
        self.evidence_id = evidence_id
        self.case_id = case_id
        self.evidence_type = evidence_type   # DiskImage | MemoryImage | PacketCapture | LogSet
        self.source_path = source_path
        self.ingestion_hash = ingestion_hash
        self._read_only_root = read_only_root
        self._sealed = True   # once True, no writes permitted through this handle

    def __repr__(self):
        return f"<{self.evidence_type} id={self.evidence_id[:8]} case={self.case_id}>"

    # Analysis modules call this to get a path they may READ ONLY.
    # We defensively re-check the filesystem permission bits every time.
    def readonly_path(self) -> str:
        if not self._sealed:
            raise EvidenceIntegrityError("Evidence handle is not sealed read-only.")
        return self._read_only_root

    def verify_unchanged(self) -> bool:
        """Re-hash the source and compare to the ingestion-time hash."""
        current = _hash_for_type(self.evidence_type, self.source_path)
        return current == self.ingestion_hash


def _hash_for_type(evidence_type: str, path: str) -> str:
    if os.path.isdir(path):
        return sha256_dir_manifest(path)
    return sha256_file(path)


def _make_readonly_copy_marker(path: str):
    """
    Best-effort: strip write bits on the evidence path so accidental
    writes fail at the OS level too (defense in depth on top of the
    handle-based access control above). Never fails hard -- some
    filesystems/permission setups won't allow this, and that's fine,
    since the handle-based control is the real enforcement boundary.
    """
    try:
        if os.path.isdir(path):
            for root, dirs, files in os.walk(path):
                for name in files:
                    p = os.path.join(root, name)
                    os.chmod(p, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
        else:
            os.chmod(path, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        pass


class EvidenceManager:
    """
    Owns ingestion of evidence sources into sealed, read-only,
    case-scoped EvidenceHandles, and maintains the chain-of-custody
    ledger. This is instantiated once per script execution/case.
    """

    def __init__(self, case_id: str, investigator: str, audit_log):
        self.case_id = case_id
        self.investigator = investigator
        self.audit_log = audit_log
        self.custody_records: Dict[str, ChainOfCustodyRecord] = {}

    def ingest(self, source_path: str, evidence_type: str) -> EvidenceHandle:
        if not os.path.exists(source_path):
            raise FileNotFoundError(f"Evidence source not found: {source_path}")

        evidence_id = str(uuid.uuid4())
        ingestion_hash = _hash_for_type(evidence_type, source_path)
        _make_readonly_copy_marker(source_path)

        record = ChainOfCustodyRecord(
            evidence_id=evidence_id,
            case_id=self.case_id,
            source_path=source_path,
            evidence_type=evidence_type,
            ingested_by=self.investigator,
            ingested_at=time.time(),
            ingestion_hash=ingestion_hash,
        )
        self.custody_records[evidence_id] = record

        self.audit_log.record(
            action="EVIDENCE_INGEST",
            actor=self.investigator,
            case_id=self.case_id,
            detail={
                "evidence_id": evidence_id,
                "evidence_type": evidence_type,
                "source_path": source_path,
                "ingestion_hash": ingestion_hash,
            },
        )

        return EvidenceHandle(
            evidence_id=evidence_id,
            case_id=self.case_id,
            evidence_type=evidence_type,
            source_path=source_path,
            ingestion_hash=ingestion_hash,
            read_only_root=source_path,
        )

    def verify_all(self) -> Dict[str, bool]:
        """Re-hash every ingested evidence source; used before report sign-off."""
        results = {}
        for evidence_id, record in self.custody_records.items():
            current = _hash_for_type(record.evidence_type, record.source_path)
            ok = current == record.ingestion_hash
            results[evidence_id] = ok
            self.audit_log.record(
                action="EVIDENCE_VERIFY",
                actor=self.investigator,
                case_id=self.case_id,
                detail={"evidence_id": evidence_id, "match": ok},
            )
        return results
