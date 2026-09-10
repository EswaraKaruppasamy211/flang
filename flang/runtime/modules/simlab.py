"""
Simulation Module
---------------------
Generates synthetic process, file, network, DNS, authentication, and
log EVENTS (plain dict records with plausible fields and a
timestamp) so an investigator can exercise the timeline and
correlation engines without needing real evidence or a real
incident. Every record is clearly marked "synthetic": true.

This is distinct from testlab.py's Security Testing Laboratory
(which mutates synthetic FILES to test detection-rule robustness):
this module produces synthetic EVENT records for pipeline testing,
training, and Practice-style exercises. Nothing here touches the
real filesystem, network, or process table.
"""

from __future__ import annotations
import random
import time
from typing import Any, Dict, List

_PROCESS_NAMES = ["explorer.exe", "svchost.exe", "powershell.exe", "cmd.exe", "chrome.exe"]
_FILE_PATHS = ["C:\\Users\\demo\\Downloads\\invoice.pdf.exe", "/tmp/update.sh", "C:\\Windows\\Temp\\a.dll"]
_IPS = ["10.0.0.5", "192.168.1.20", "203.0.113.77", "198.51.100.23"]
_DOMAINS = ["example-c2-simulation.test", "updates.example.test", "cdn.example.test"]
_USERS = ["demo.user", "svc_backup", "admin"]


def _now_offset(max_seconds_ago: int = 3600) -> float:
    return time.time() - random.uniform(0, max_seconds_ago)


def simulate_process_event() -> Dict[str, Any]:
    return {
        "type": "ProcessEvent", "synthetic": True,
        "pid": random.randint(1000, 9000),
        "name": random.choice(_PROCESS_NAMES),
        "timestamp": _now_offset(),
    }


def simulate_file_event() -> Dict[str, Any]:
    return {
        "type": "FileEvent", "synthetic": True,
        "path": random.choice(_FILE_PATHS),
        "action": random.choice(["created", "modified", "deleted"]),
        "timestamp": _now_offset(),
    }


def simulate_network_event() -> Dict[str, Any]:
    return {
        "type": "NetworkEvent", "synthetic": True,
        "src_ip": random.choice(_IPS), "dst_ip": random.choice(_IPS),
        "dst_port": random.choice([443, 80, 4444, 8080]),
        "timestamp": _now_offset(),
    }


def simulate_dns_event() -> Dict[str, Any]:
    return {
        "type": "DNSEvent", "synthetic": True,
        "query": random.choice(_DOMAINS),
        "timestamp": _now_offset(),
    }


def simulate_auth_event() -> Dict[str, Any]:
    return {
        "type": "AuthEvent", "synthetic": True,
        "user": random.choice(_USERS),
        "result": random.choice(["success", "failure"]),
        "timestamp": _now_offset(),
    }


def simulate_log_event() -> Dict[str, Any]:
    return {
        "type": "LogEvent", "synthetic": True,
        "source": random.choice(["Security", "Application", "System"]),
        "message": "synthetic log entry for testing",
        "timestamp": _now_offset(),
    }


_GENERATORS = {
    "process": simulate_process_event, "file": simulate_file_event,
    "network": simulate_network_event, "dns": simulate_dns_event,
    "auth": simulate_auth_event, "log": simulate_log_event,
}


def simulate_scenario(kinds: List[str], count: int) -> List[Dict[str, Any]]:
    """Generates `count` synthetic events, evenly drawn from the given
    kind names (any of: process, file, network, dns, auth, log)."""
    unknown = [k for k in kinds if k not in _GENERATORS]
    if unknown:
        raise ValueError(f"Unknown simulation kind(s): {unknown} -- valid: {list(_GENERATORS)}")
    events = []
    for i in range(int(count)):
        kind = kinds[i % len(kinds)]
        events.append(_GENERATORS[kind]())
    return sorted(events, key=lambda e: e["timestamp"])
