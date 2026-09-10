"""
Case Management Module
--------------------------
A local, file-backed case registry -- NOT a centralized multi-user
database. Each case is one JSON file under a `cases/` directory
(created relative to the current working directory unless overridden).
This is an honestly-scoped implementation: it gives a script a real,
persistent place to register a case and attach evidence records to it
across multiple runs, but it does not implement locking, concurrent
multi-investigator access, or a server -- those are exactly the kind
of centralized-case-management requirements that belong to the
optional multi-host dashboard architecture, which remains documented
as roadmap (see SCOPE_AND_ROADMAP.md) rather than implemented here.
"""

from __future__ import annotations
import json
import os
import time
from typing import Any, Dict, List, Optional

DEFAULT_CASES_DIR = "cases"


def _case_path(case_id: str, cases_dir: str = DEFAULT_CASES_DIR) -> str:
    os.makedirs(cases_dir, exist_ok=True)
    safe_id = "".join(c for c in case_id if c.isalnum() or c in "-_")
    return os.path.join(cases_dir, f"{safe_id}.json")


def create_case(case_id: str, title: str, investigator: str,
                 cases_dir: str = DEFAULT_CASES_DIR) -> Dict[str, Any]:
    path = _case_path(case_id, cases_dir)
    if os.path.exists(path):
        raise ValueError(f"Case '{case_id}' already exists at {path}")
    record = {
        "case_id": case_id, "title": title, "opened_by": investigator,
        "opened_at": time.time(), "status": "open", "evidence": [], "notes": [],
    }
    with open(path, "w") as f:
        json.dump(record, f, indent=2, default=str)
    return record


def open_case(case_id: str, cases_dir: str = DEFAULT_CASES_DIR) -> Dict[str, Any]:
    path = _case_path(case_id, cases_dir)
    if not os.path.exists(path):
        raise ValueError(f"No such case: '{case_id}'")
    with open(path, "r") as f:
        return json.load(f)


def add_evidence(case_id: str, evidence_record: Dict[str, Any],
                  cases_dir: str = DEFAULT_CASES_DIR) -> Dict[str, Any]:
    case = open_case(case_id, cases_dir)
    case["evidence"].append(evidence_record)
    path = _case_path(case_id, cases_dir)
    with open(path, "w") as f:
        json.dump(case, f, indent=2, default=str)
    return case


def list_evidence(case_id: str, cases_dir: str = DEFAULT_CASES_DIR) -> List[Dict[str, Any]]:
    return open_case(case_id, cases_dir).get("evidence", [])


def add_note(case_id: str, note: str, investigator: str,
             cases_dir: str = DEFAULT_CASES_DIR) -> Dict[str, Any]:
    case = open_case(case_id, cases_dir)
    case["notes"].append({"note": note, "by": investigator, "at": time.time()})
    path = _case_path(case_id, cases_dir)
    with open(path, "w") as f:
        json.dump(case, f, indent=2, default=str)
    return case


def close_case(case_id: str, cases_dir: str = DEFAULT_CASES_DIR) -> Dict[str, Any]:
    case = open_case(case_id, cases_dir)
    case["status"] = "closed"
    case["closed_at"] = time.time()
    path = _case_path(case_id, cases_dir)
    with open(path, "w") as f:
        json.dump(case, f, indent=2, default=str)
    return case


def list_cases(cases_dir: str = DEFAULT_CASES_DIR) -> List[str]:
    if not os.path.isdir(cases_dir):
        return []
    return [f[:-5] for f in os.listdir(cases_dir) if f.endswith(".json")]
