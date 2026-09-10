"""
Live Network Observation Module (read-only)
-----------------------------------------------
Observes the current network state -- interfaces, active connections,
DNS configuration, routes. No function here opens a socket, sends
traffic, or changes any network configuration.
"""

from __future__ import annotations
import os
from typing import Any, Dict, List

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False


def net_interfaces() -> Dict[str, Any]:
    if not HAVE_PSUTIL:
        return {"available": False, "reason": "psutil not installed"}
    result = {}
    for name, addrs in psutil.net_if_addrs().items():
        result[name] = [{"family": str(a.family), "address": a.address,
                          "netmask": a.netmask} for a in addrs]
    return {"available": True, "interfaces": result}


def net_connections() -> Dict[str, Any]:
    if not HAVE_PSUTIL:
        return {"available": False, "reason": "psutil not installed"}
    try:
        conns = psutil.net_connections(kind="inet")
    except (PermissionError, psutil.AccessDenied) as e:
        return {"available": False, "reason": f"insufficient privilege: {e}"}
    results = []
    for c in conns:
        results.append({
            "local_address": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
            "remote_address": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else None,
            "status": c.status,
            "pid": c.pid,
        })
    return {"available": True, "connections": results}


def net_dns() -> Dict[str, Any]:
    path = "/etc/resolv.conf"
    if not os.path.exists(path):
        return {"available": False, "reason": "resolv.conf not found on this host"}
    nameservers = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line.startswith("nameserver"):
                parts = line.split()
                if len(parts) >= 2:
                    nameservers.append(parts[1])
    return {"available": True, "nameservers": nameservers}


def net_routes() -> Dict[str, Any]:
    path = "/proc/net/route"
    if not os.path.exists(path):
        return {"available": False, "reason": "/proc/net/route not available on this host"}
    routes = []
    with open(path, "r") as f:
        lines = f.readlines()[1:]
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            routes.append({"interface": parts[0], "destination_hex": parts[1], "gateway_hex": parts[2]})
    return {"available": True, "routes": routes}


def net_analyze() -> Dict[str, Any]:
    conns = net_connections()
    if not conns.get("available"):
        return conns
    by_status: Dict[str, int] = {}
    remote_ips: Dict[str, int] = {}
    for c in conns["connections"]:
        by_status[c["status"]] = by_status.get(c["status"], 0) + 1
        if c["remote_address"]:
            ip = c["remote_address"].rsplit(":", 1)[0]
            remote_ips[ip] = remote_ips.get(ip, 0) + 1
    top_remote = sorted(remote_ips.items(), key=lambda kv: kv[1], reverse=True)[:10]
    return {
        "available": True,
        "total_connections": len(conns["connections"]),
        "by_status": by_status,
        "top_remote_ips": [{"ip": ip, "count": n} for ip, n in top_remote],
    }
