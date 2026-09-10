"""
Filesystem Analysis Module
----------------------------
Operates only on read-only paths handed back by an EvidenceHandle.
In this prototype, a "DiskImage" evidence source is a directory tree
representing already-acquired, already write-blocked evidence (e.g.
files extracted from an E01/raw image by a separate acquisition tool
such as The Sleuth Kit -- see README for how a production build would
call `pytsk3` directly against a raw image instead of a directory).

Provides: list_files, get_metadata, carve_deleted, flag_suspicious
"""

from __future__ import annotations
import os
from typing import List, Dict, Any
from ..evidence import EvidenceHandle, sha256_file


def list_files(handle: EvidenceHandle, subpath: str = ".") -> List[Dict[str, Any]]:
    if handle.evidence_type != "DiskImage":
        raise TypeError("list_files() requires a DiskImage evidence handle")

    root = handle.readonly_path()
    target = os.path.normpath(os.path.join(root, subpath.lstrip("/")))
    # containment check: never allow escaping the evidence root
    if not target.startswith(os.path.normpath(root)):
        raise PermissionError("Path traversal outside evidence root is not permitted")

    records = []
    if not os.path.exists(target):
        return records

    for dirpath, _, filenames in os.walk(target):
        for name in filenames:
            full = os.path.join(dirpath, name)
            try:
                st = os.stat(full)
            except OSError:
                continue
            records.append({
                "type": "FileRecord",
                "name": name,
                "path": os.path.relpath(full, root),
                "size": st.st_size,
                "mtime": st.st_mtime,
                "atime": st.st_atime,
                "ctime": st.st_ctime,
                "sha256": sha256_file(full),
            })
    return records


def get_metadata(file_record: Dict[str, Any]) -> Dict[str, Any]:
    # In this prototype list_files() already returns full metadata;
    # this function exists as the documented single-file accessor and
    # is where extended attributes / alternate-data-stream extraction
    # would be added for a production NTFS/TSK-backed implementation.
    return file_record


def carve_deleted(handle: EvidenceHandle) -> List[Dict[str, Any]]:
    """
    Placeholder for deleted-file carving. A production implementation
    would call into The Sleuth Kit (pytsk3) against the raw image to
    walk unallocated inodes/MFT entries. Returning an empty, clearly
    labeled result here keeps the language's output honest about what
    this prototype does vs. does not yet implement.
    """
    return []


def flag_suspicious(files: List[Dict[str, Any]], iocs: Dict[str, Any]) -> List[Dict[str, Any]]:
    bad_hashes = set(iocs.get("file_hashes", []))
    bad_names = set(iocs.get("file_names", []))
    flagged = []
    for f in files:
        if f.get("sha256") in bad_hashes or f.get("name") in bad_names:
            f = dict(f)
            f["flagged_reason"] = "matched IOC (hash or filename)"
            flagged.append(f)
    return flagged
