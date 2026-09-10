"""
Log Analysis Module
----------------------
Normalizes common log formats into a flat Event schema:
    {type: "Event", timestamp, source, category, message, raw}

Supports a simple syslog-like line format and JSON-lines out of the
box; this is where python-evtx (Windows Event Log) or Grok/Logstash
patterns would be plugged in for a production build (see README).
"""

from __future__ import annotations
import json
import os
import re
from typing import List, Dict, Any
from ..evidence import EvidenceHandle

SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>\S+):\s+"
    r"(?P<message>.*)$"
)


def _require_logs(handle: EvidenceHandle):
    if handle.evidence_type != "LogSet":
        raise TypeError("This function requires a LogSet evidence handle")


def parse_log_directory(path: str, fmt: str) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    files = []
    if os.path.isdir(path):
        for root, _, names in os.walk(path):
            for name in names:
                files.append(os.path.join(root, name))
    else:
        files = [path]

    for filepath in files:
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if fmt == "json":
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    events.append({
                        "type": "Event",
                        "timestamp": obj.get("timestamp"),
                        "source": os.path.basename(filepath),
                        "category": obj.get("category", "generic"),
                        "message": obj.get("message", ""),
                        "raw": obj,
                    })
                else:  # syslog-style, default
                    m = SYSLOG_RE.match(line)
                    if not m:
                        continue
                    events.append({
                        "type": "Event",
                        "timestamp": m.group("ts"),
                        "source": m.group("host"),
                        "category": m.group("proc"),
                        "message": m.group("message"),
                        "raw": line,
                    })
    return events


def parse_events(handle: EvidenceHandle, data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    _require_logs(handle)
    return data


def match_iocs(events: List[Dict[str, Any]], iocs: Dict[str, Any]) -> List[Dict[str, Any]]:
    needles = set(iocs.get("keywords", [])) | set(iocs.get("usernames", []))
    matched = []
    for e in events:
        haystack = f"{e.get('message', '')} {e.get('category', '')}"
        if any(needle.lower() in haystack.lower() for needle in needles):
            e = dict(e)
            e["flagged_reason"] = "matched IOC keyword/username"
            matched.append(e)
    return matched
