"""
Evidence Manifest Module
----------------------------
Builds a standalone evidence-integrity manifest for an arbitrary file
(SHA-256 + SHA-512, evidence ID, investigator, acquisition timestamp).
This is distinct from -- and does not modify -- runtime/evidence.py's
EvidenceManager, which governs the read-only DiskImage/MemoryImage/
PacketCapture/LogSet handles used by load_disk_image() and friends.
This module is for the simpler, common case: "hash this one file and
record who did it and when," optionally attached to a case via
case.py's add_evidence().
"""

from __future__ import annotations
import time
import uuid
from typing import Any, Dict, Optional

from ..evidence import sha256_file, sha512_file


def manifest(path: str, investigator: str) -> Dict[str, Any]:
    return {
        "evidence_id": str(uuid.uuid4()),
        "path": path,
        "sha256": sha256_file(path),
        "sha512": sha512_file(path),
        "investigator": investigator,
        "acquired_at": time.time(),
    }


def verify_manifest(path: str, expected_manifest: Dict[str, Any]) -> Dict[str, Any]:
    current_sha256 = sha256_file(path)
    current_sha512 = sha512_file(path)
    return {
        "path": path,
        "sha256_match": current_sha256 == expected_manifest.get("sha256"),
        "sha512_match": current_sha512 == expected_manifest.get("sha512"),
        "current_sha256": current_sha256,
        "current_sha512": current_sha512,
    }
