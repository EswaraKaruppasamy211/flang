"""
Detection Predicate Library
------------------------------
FLANG v1's "rule engine" is realized as composable predicate functions
called from ordinary if-statements, rather than inventing a whole new
`rule NAME { when ... }` grammar (that richer event-driven rule syntax
is documented as roadmap Phase 2 -- see README). This keeps the
detection engine inside the same audited, RBAC-gated built-in call
model as everything else in the language, rather than introducing a
second, parallel execution path.
"""

from __future__ import annotations
from typing import Any, Dict, List


def unexpected_parent(processes: List[Dict[str, Any]], expected_parents: Dict[str, List[str]]) -> List[Dict[str, Any]]:
    """
    Flags processes whose name is a key in `expected_parents` but whose
    actual parent process name is not in that key's allow-list.
    Example: expected_parents = {"explorer.exe": ["userinit.exe"]}
    """
    by_pid = {p["pid"]: p for p in processes if "pid" in p}
    flagged = []
    for p in processes:
        name = (p.get("name") or "").lower()
        for watched_name, allowed_parents in expected_parents.items():
            if name != watched_name.lower():
                continue
            parent = by_pid.get(p.get("ppid"))
            parent_name = (parent.get("name") if parent else None) or "unknown"
            if parent_name.lower() not in [a.lower() for a in allowed_parents]:
                flagged.append({**p, "flagged_reason": f"unexpected parent '{parent_name}' for '{name}'"})
    return flagged


def suspicious_port(connections: List[Dict[str, Any]], allowed_ports: List[int]) -> List[Dict[str, Any]]:
    """Flags established/listening connections on a port not in the allow-list."""
    flagged = []
    for c in connections:
        addr = c.get("local_address") or c.get("remote_address") or ""
        if ":" not in addr:
            continue
        try:
            port = int(addr.rsplit(":", 1)[1])
        except ValueError:
            continue
        if port not in allowed_ports and c.get("status") in ("ESTABLISHED", "LISTEN"):
            flagged.append({**c, "flagged_reason": f"port {port} not in allow-list"})
    return flagged


def new_entries(current: List[Dict[str, Any]], baseline: List[Dict[str, Any]], key: str) -> List[Dict[str, Any]]:
    """Generic baseline diff: entries in `current` whose `key` value was
    not present in `baseline` -- useful for startup-entry or
    service-list drift detection between two collection runs."""
    baseline_keys = {b.get(key) for b in baseline}
    return [c for c in current if c.get(key) not in baseline_keys]
