"""
Memory Analysis Module
-------------------------
Prototype implementation. A production build would shell out to /
bind against Volatility 3 (`vol3 -f <image> windows.pslist`, etc.)
against a raw memory image and normalize its output into the record
shapes used here. To keep this prototype runnable without a multi-GB
memory image and the Volatility3 dependency, `load_memory_image()`
(see interpreter builtins) accepts a small JSON file describing
processes/connections/strings in the same shape Volatility3's JSON
output would take -- the analysis functions below are written against
that normalized shape, so swapping in real Volatility3 output later
only requires changing the loader, not these functions.

Provides: list_processes, list_network_connections, detect_injection,
          extract_strings
"""

from __future__ import annotations
import re
from typing import List, Dict, Any
from ..evidence import EvidenceHandle


def _require_memory(handle: EvidenceHandle):
    if handle.evidence_type != "MemoryImage":
        raise TypeError("This function requires a MemoryImage evidence handle")


def list_processes(handle: EvidenceHandle, _data: Dict[str, Any]) -> List[Dict[str, Any]]:
    _require_memory(handle)
    return _data.get("processes", [])


def list_network_connections(handle: EvidenceHandle, _data: Dict[str, Any]) -> List[Dict[str, Any]]:
    _require_memory(handle)
    return _data.get("connections", [])


def detect_injection(handle: EvidenceHandle, _data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flags processes whose record has been annotated (by the acquisition
    / Volatility malfind-equivalent step) as containing anomalous
    memory regions -- e.g. RWX private allocations, PE headers in
    private memory, or a parent/child relationship inconsistent with
    the known-good process tree. This prototype trusts pre-computed
    `suspicious: true` flags in the normalized input; a production
    build would compute this from raw VAD/malfind data itself.
    """
    _require_memory(handle)
    return [p for p in _data.get("processes", []) if p.get("suspicious")]


def extract_strings(handle: EvidenceHandle, _data: Dict[str, Any], pattern: str) -> List[str]:
    _require_memory(handle)
    regex = re.compile(pattern)
    return [s for s in _data.get("strings", []) if regex.search(s)]
