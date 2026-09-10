"""
System Information Module (live host introspection)
-------------------------------------------------------
Read-only. No function in this module can change system state --
there is no service.start/stop, no user.create/delete, no
process.kill anywhere in this module by design, matching the
project's "read-only wherever possible" and "transparent, logged"
requirements. Everything here is comparable in spirit to Sysinternals'
read-only utilities (Process Explorer, Autoruns, TCPView) -- inspect
and report, never modify.
"""

from __future__ import annotations
import datetime
import os
import platform
import shutil
import socket
import subprocess
from typing import Any, Dict, List

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False


def system_info() -> Dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "machine": platform.machine(),
        "python_runtime": platform.python_version(),
        "boot_time": (datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
                      if HAVE_PSUTIL else None),
        "collected_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def system_os() -> Dict[str, Any]:
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "platform": platform.platform(),
    }


def system_cpu() -> Dict[str, Any]:
    if not HAVE_PSUTIL:
        return {"available": False, "reason": "psutil not installed"}
    return {
        "available": True,
        "physical_cores": psutil.cpu_count(logical=False),
        "logical_cores": psutil.cpu_count(logical=True),
        "usage_percent": psutil.cpu_percent(interval=0.2),
        "processor": platform.processor() or "unknown",
    }


def system_memory() -> Dict[str, Any]:
    if not HAVE_PSUTIL:
        return {"available": False, "reason": "psutil not installed"}
    vm = psutil.virtual_memory()
    return {
        "available": True,
        "total_bytes": vm.total,
        "available_bytes": vm.available,
        "used_bytes": vm.used,
        "percent_used": vm.percent,
    }


def system_disk() -> List[Dict[str, Any]]:
    if not HAVE_PSUTIL:
        return [{"available": False, "reason": "psutil not installed"}]
    results = []
    for part in psutil.disk_partitions(all=False):
        entry = {"device": part.device, "mountpoint": part.mountpoint, "fstype": part.fstype}
        try:
            usage = psutil.disk_usage(part.mountpoint)
            entry.update({"total_bytes": usage.total, "used_bytes": usage.used,
                          "free_bytes": usage.free, "percent_used": usage.percent})
        except (PermissionError, OSError) as e:
            entry["error"] = str(e)
        results.append(entry)
    return results


def process_list() -> List[Dict[str, Any]]:
    if not HAVE_PSUTIL:
        return [{"available": False, "reason": "psutil not installed"}]
    results = []
    for p in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "create_time"]):
        try:
            info = p.info
            results.append({
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


def process_info(pid) -> Dict[str, Any]:
    if not HAVE_PSUTIL:
        raise ValueError("psutil not installed -- process.info() unavailable")
    try:
        p = psutil.Process(int(pid))
        with p.oneshot():
            return {
                "pid": p.pid,
                "ppid": p.ppid(),
                "name": p.name(),
                "username": p.username(),
                "cmdline": p.cmdline(),
                "create_time": p.create_time(),
                "status": p.status(),
            }
    except psutil.NoSuchProcess:
        raise ValueError(f"No such process: {pid}")
    except psutil.AccessDenied:
        raise ValueError(f"Access denied reading process {pid} (insufficient privilege)")


def service_list() -> Dict[str, Any]:
    """Linux: systemd units via `systemctl` (read-only listing). Windows
    runtime layer would call the Service Control Manager's enumeration
    API (EnumServicesStatus) here instead -- see README for the
    platform-abstraction design."""
    if shutil.which("systemctl") is None:
        return {"platform": platform.system(), "available": False,
                "reason": "systemctl not found on this host"}
    try:
        out = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--no-legend", "--no-pager"],
            capture_output=True, text=True, timeout=5,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        return {"platform": platform.system(), "available": False, "reason": str(e)}

    services = []
    for line in out.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            services.append({"unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3]})
    return {"platform": platform.system(), "available": True, "services": services}


def user_list() -> Dict[str, Any]:
    """Linux: /etc/passwd via the `pwd` module (read-only). Windows
    runtime layer would call NetUserEnum here instead."""
    try:
        import pwd
    except ImportError:
        return {"platform": platform.system(), "available": False,
                "reason": "user enumeration on this platform not implemented in the prototype"}
    users = []
    for entry in pwd.getpwall():
        users.append({
            "username": entry.pw_name, "uid": entry.pw_uid, "gid": entry.pw_gid,
            "home": entry.pw_dir, "shell": entry.pw_shell,
        })
    return {"platform": platform.system(), "available": True, "users": users}


def startup_list() -> Dict[str, Any]:
    """Best-effort autostart-entry enumeration. Linux: XDG autostart
    .desktop files. Windows runtime layer would enumerate the Run/RunOnce
    registry keys and the Startup folder here instead."""
    candidate_dirs = [
        os.path.expanduser("~/.config/autostart"),
        "/etc/xdg/autostart",
    ]
    entries = []
    for d in candidate_dirs:
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if name.endswith(".desktop"):
                entries.append({"name": name, "source_dir": d, "path": os.path.join(d, name)})
    return {"platform": platform.system(), "available": True, "entries": entries}


def eventlog_read(lines: int = 50) -> Dict[str, Any]:
    """Best-effort recent-log read. Linux: journalctl if present, else
    tail of /var/log/syslog. Windows runtime layer would call
    OpenEventLog/ReadEventLog here instead."""
    if shutil.which("journalctl") is not None:
        try:
            out = subprocess.run(
                ["journalctl", "-n", str(int(lines)), "--no-pager", "-o", "short-iso"],
                capture_output=True, text=True, timeout=5,
            )
            return {"source": "journalctl", "available": True,
                    "lines": out.stdout.splitlines()}
        except (subprocess.TimeoutExpired, OSError):
            pass
    for path in ("/var/log/syslog", "/var/log/messages"):
        if os.path.exists(path):
            try:
                with open(path, "r", errors="ignore") as f:
                    all_lines = f.readlines()
                return {"source": path, "available": True, "lines": [l.rstrip() for l in all_lines[-int(lines):]]}
            except OSError as e:
                return {"source": path, "available": False, "reason": str(e)}
    return {"source": None, "available": False, "reason": "no accessible system log found"}
