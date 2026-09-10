"""
Timeline Operations Module
------------------------------
Operates on the Timeline dict shape already produced by
runtime/modules/correlate.py's correlate() function (unchanged --
this module only adds new ways to work with its output, it does not
modify correlate() or its existing return shape in any way).

A Timeline looks like:
    {"type": "Timeline", "window_seconds": N, "clusters": [...],
     "unordered_records": [...], "total_records": N}

These functions flatten that into a plain chronological list of
records (each cluster's records, in order, followed by the
unordered ones) and provide sort/filter/search/group/export on that
flat list -- the operations an investigator actually wants when
building or reviewing an investigation timeline.
"""

from __future__ import annotations
import csv
import json
import os
from typing import Any, Dict, List


def flatten(timeline: Dict[str, Any]) -> List[Dict[str, Any]]:
    flat = []
    for cluster in timeline.get("clusters", []):
        flat.extend(cluster.get("records", []))
    flat.extend(timeline.get("unordered_records", []))
    return flat


def sort_by_time(timeline: Dict[str, Any]) -> List[Dict[str, Any]]:
    records = flatten(timeline)
    def _ts(r):
        for key in ("timestamp", "mtime", "ctime", "atime"):
            if r.get(key) is not None:
                return r[key]
        return float("inf")
    return sorted(records, key=_ts)


def filter_events(timeline: Dict[str, Any], field: str, value: Any) -> List[Dict[str, Any]]:
    return [r for r in flatten(timeline) if r.get(field) == value]


def search(timeline: Dict[str, Any], keyword: str) -> List[Dict[str, Any]]:
    keyword_lower = keyword.lower()
    matched = []
    for r in flatten(timeline):
        haystack = " ".join(str(v) for v in r.values())
        if keyword_lower in haystack.lower():
            matched.append(r)
    return matched


def group_by(timeline: Dict[str, Any], field: str) -> Dict[str, List[Dict[str, Any]]]:
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for r in flatten(timeline):
        key = str(r.get(field, "unknown"))
        groups.setdefault(key, []).append(r)
    return groups


def export_timeline(timeline: Dict[str, Any], format: str, path: str) -> None:
    records = sort_by_time(timeline)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if format == "json":
        with open(path, "w") as f:
            json.dump(records, f, indent=2, default=str)
    elif format == "csv":
        all_fields: List[str] = []
        for r in records:
            for k in r.keys():
                if k not in all_fields:
                    all_fields.append(k)
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=all_fields, extrasaction="ignore")
            writer.writeheader()
            for r in records:
                writer.writerow({k: r.get(k, "") for k in all_fields})
    else:
        raise ValueError(f"Unsupported timeline export format: {format} (use 'json' or 'csv')")
