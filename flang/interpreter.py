"""
FLANG Interpreter
-------------------
Tree-walking interpreter over the AST produced by parser.py.

This is where the "effect tagging" described in the project's execution
model is enforced: every built-in function is registered with
  * a minimum RBAC role required to call it
  * an effect class: READ (touches evidence), DERIVE (pure computation
    on already-loaded data), or EXPORT (writes outside the sandbox,
    e.g. the final report)
and every call to a built-in is automatically written to the
hash-chained audit log BEFORE the call's result is returned to the
script -- scripts cannot suppress or skip this.
"""

from __future__ import annotations
import hashlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from . import ast_nodes as A
from .runtime.evidence import EvidenceManager, EvidenceHandle, sha256_file, sha512_file
from .runtime.audit import AuditLog
from .runtime.security import SecurityContext, AuthorizationError
from .runtime.modules import filesystem, memory, network, logs, correlate, anomaly
from .runtime.modules import sysinfo, fileforensics, netlive, detectlib, testlab
from .runtime.modules import timeline_ops, evidence_module, simlab
from .runtime.modules import case as case_module
from .runtime.namespace import FlangNamespace, FlangObject, MethodSpec
from .runtime import report as reporting


class FlangRuntimeError(Exception):
    def __init__(self, message: str, line: Optional[int] = None):
        loc = f" (line {line})" if line is not None else ""
        super().__init__(f"{message}{loc}")


@dataclass
class BuiltinSpec:
    func: Callable
    min_role: str
    effect: str  # READ | DERIVE | EXPORT


class Environment:
    def __init__(self, parent: Optional["Environment"] = None):
        self.parent = parent
        self.vars: Dict[str, Any] = {}

    def get(self, name: str):
        env = self
        while env is not None:
            if name in env.vars:
                return env.vars[name]
            env = env.parent
        raise FlangRuntimeError(f"Undefined variable '{name}'")

    def set_local(self, name: str, value: Any):
        self.vars[name] = value

    def assign(self, name: str, value: Any):
        env = self
        while env is not None:
            if name in env.vars:
                env.vars[name] = value
                return
            env = env.parent
        self.vars[name] = value


class ReturnSignal(Exception):
    def __init__(self, value):
        self.value = value


class BreakSignal(Exception):
    pass


class ContinueSignal(Exception):
    pass


class Interpreter:
    # a runaway `while true { }` in a script shouldn't be able to hang
    # the process forever -- this mirrors the "resource limits" bullet
    # in the project's non-functional requirements (sandboxed execution).
    MAX_LOOP_ITERATIONS = 2_000_000

    def __init__(self, case_id: str, investigator: str, role: str,
                 audit_log_path: Optional[str] = None,
                 script_path: Optional[str] = None):
        self.audit_log = AuditLog(log_path=audit_log_path)
        self.security = SecurityContext(investigator=investigator, role=role, case_id=case_id)
        self.evidence_mgr = EvidenceManager(case_id=case_id, investigator=investigator, audit_log=self.audit_log)
        self.global_env = Environment()
        self.functions: Dict[str, A.FunctionDef] = {}
        # side-channel store for parsed evidence payloads (memory/pcap/log
        # JSON data) keyed by evidence_id, since EvidenceHandle itself only
        # exposes a read-only path/root, never mutable script-facing state
        self.evidence_data: Dict[str, Any] = {}
        self.script_hash: Optional[str] = None
        if script_path and os.path.exists(script_path):
            with open(script_path, "rb") as f:
                self.script_hash = hashlib.sha256(f.read()).hexdigest()

        self.builtins: Dict[str, BuiltinSpec] = {}
        self._register_builtins()

    # -------------------------------------------------------------- audit
    def _audited_call(self, name: str, spec: BuiltinSpec, args: list, kwargs: dict):
        self.security.require(spec.min_role, name)
        detail = {
            "function": name,
            "effect": spec.effect,
            "arg_summary": _summarize_args(args, kwargs),
        }
        self.audit_log.record(
            action=f"CALL:{name}",
            actor=self.security.investigator,
            case_id=self.security.case_id,
            detail=detail,
        )
        try:
            return spec.func(*args, **kwargs)
        except (FlangRuntimeError, AuthorizationError):
            raise
        except Exception as e:
            # Any built-in that raises a plain Python exception (ValueError,
            # TypeError, RuntimeError, etc.) is converted here, at the call
            # site, not just at the top of run(). This is what lets a
            # script's own try/catch actually catch it -- previously only
            # the top-level run() wrapper did this conversion, which meant
            # a script-level try/catch around a builtin call like
            # case.create() silently failed to catch anything and the
            # whole script aborted anyway. Found via real testing.
            raise FlangRuntimeError(f"{type(e).__name__}: {e}") from None

    # -------------------------------------------------------------- builtins
    def _register_builtins(self):
        def load_disk_image(path: str) -> EvidenceHandle:
            return self.evidence_mgr.ingest(path, "DiskImage")

        def load_memory_image(path: str) -> EvidenceHandle:
            handle = self.evidence_mgr.ingest(path, "MemoryImage")
            with open(path, "r") as f:
                self.evidence_data[handle.evidence_id] = json.load(f)
            return handle

        def load_pcap(path: str) -> EvidenceHandle:
            handle = self.evidence_mgr.ingest(path, "PacketCapture")
            if path.endswith((".pcap", ".pcapng")) and network.HAVE_SCAPY:
                data = network.parse_pcap_file(path)
            else:
                with open(path, "r") as f:
                    data = json.load(f)
            self.evidence_data[handle.evidence_id] = data
            return handle

        def load_logs(path: str, format: str = "syslog") -> EvidenceHandle:
            handle = self.evidence_mgr.ingest(path, "LogSet")
            events = logs.parse_log_directory(path, format)
            self.evidence_data[handle.evidence_id] = events
            return handle

        def sha256(evidence: EvidenceHandle) -> str:
            return evidence.ingestion_hash

        def verify_hash(evidence: EvidenceHandle, expected: str) -> bool:
            return evidence.ingestion_hash == expected

        def fs_list_files(img: EvidenceHandle, path: str = ".") -> list:
            return filesystem.list_files(img, path)

        def fs_carve_deleted(img: EvidenceHandle) -> list:
            return filesystem.carve_deleted(img)

        def fs_get_metadata(f: dict) -> dict:
            return filesystem.get_metadata(f)

        def fs_flag_suspicious(files: list, iocs: dict) -> list:
            return filesystem.flag_suspicious(files, iocs)

        def mem_list_processes(mem_handle: EvidenceHandle) -> list:
            return memory.list_processes(mem_handle, self.evidence_data[mem_handle.evidence_id])

        def mem_list_connections(mem_handle: EvidenceHandle) -> list:
            return memory.list_network_connections(mem_handle, self.evidence_data[mem_handle.evidence_id])

        def mem_detect_injection(mem_handle: EvidenceHandle) -> list:
            return memory.detect_injection(mem_handle, self.evidence_data[mem_handle.evidence_id])

        def mem_extract_strings(mem_handle: EvidenceHandle, pattern: str) -> list:
            return memory.extract_strings(mem_handle, self.evidence_data[mem_handle.evidence_id], pattern)

        def net_list_flows(cap: EvidenceHandle) -> list:
            return network.list_flows(cap, self.evidence_data[cap.evidence_id])

        def net_extract_dns(cap: EvidenceHandle) -> list:
            return network.extract_dns(cap, self.evidence_data[cap.evidence_id])

        def net_flag_suspicious_connections(flows: list, iocs: dict) -> list:
            return network.flag_suspicious_connections(flows, iocs)

        def log_parse_events(log_handle: EvidenceHandle) -> list:
            return logs.parse_events(log_handle, self.evidence_data[log_handle.evidence_id])

        def log_match_iocs(events: list, iocs: dict) -> list:
            return logs.match_iocs(events, iocs)

        def do_correlate(sources: list, window_seconds: int = 300) -> dict:
            return correlate.correlate(sources, int(window_seconds))

        def new_report(title: str):
            r = reporting.new_report(title)
            r.script_hash = self.script_hash
            r.audit_summary = self.audit_log.verify()
            return r

        def add_section(r, title: str, content):
            return reporting.add_section(r, title, content)

        def add_timeline(r, timeline):
            return reporting.add_timeline(r, timeline)

        def sign_report(r, key_id: str):
            r.audit_summary = self.audit_log.verify()
            return reporting.sign_report(r, key_id)

        def do_export(r, format: str, path: str):
            reporting.export(r, format, path)
            return None

        def length(x) -> float:
            return float(len(x))

        def print_value(x):
            print(x)
            return None

        def reverse(x):
            # works for strings and lists alike
            if isinstance(x, str):
                return x[::-1]
            return list(reversed(x))

        def substring(s: str, start: int, end: int) -> str:
            return s[int(start):int(end)]

        def char_at(s: str, index: int) -> str:
            return s[int(index)]

        def to_upper(s: str) -> str:
            return s.upper()

        def to_lower(s: str) -> str:
            return s.lower()

        def to_string(x) -> str:
            if isinstance(x, float) and x.is_integer():
                return str(int(x))
            return str(x)

        def to_number(s):
            try:
                v = float(s)
            except (TypeError, ValueError):
                raise FlangRuntimeError(f"Cannot convert {s!r} to a number")
            return int(v) if v.is_integer() else v

        def range_list(*args) -> list:
            # range(stop) | range(start, stop) | range(start, stop, step)
            nums = [int(a) for a in args]
            if len(nums) == 1:
                start, stop, step = 0, nums[0], 1
            elif len(nums) == 2:
                start, stop, step = nums[0], nums[1], 1
            elif len(nums) == 3:
                start, stop, step = nums
            else:
                raise FlangRuntimeError("range() takes 1 to 3 arguments")
            return list(range(start, stop, step))

        # ---- dictionaries / maps ----
        def dict_get(d: dict, key, default=None):
            return d.get(key, default)

        def dict_has_key(d: dict, key) -> bool:
            return key in d

        def dict_keys(d: dict) -> list:
            return list(d.keys())

        def dict_values(d: dict) -> list:
            return list(d.values())

        def dict_set(d: dict, key, value) -> dict:
            d[key] = value
            return d

        # ---- list utilities ----
        def list_append(lst: list, item) -> list:
            lst = list(lst)
            lst.append(item)
            return lst

        def list_contains(lst, item) -> bool:
            return item in lst

        def list_unique(lst: list) -> list:
            seen = []
            for item in lst:
                if item not in seen:
                    seen.append(item)
            return seen

        def list_sort_by(lst: list, field: str, descending: bool = False) -> list:
            return sorted(lst, key=lambda r: r.get(field), reverse=bool(descending))

        def list_sum(lst) -> float:
            return float(sum(lst))

        # ---- regex ----
        def matches(text: str, pattern: str) -> bool:
            return re.search(pattern, text) is not None

        # ---- parallel hashing (advanced runtime feature) ----
        def hash_many(paths: list) -> list:
            def _hash_one(p):
                return {"path": p, "sha256": sha256_file(p)}
            with ThreadPoolExecutor(max_workers=min(8, max(1, len(paths)))) as pool:
                return list(pool.map(_hash_one, paths))

        # ---- statistical anomaly detection ----
        def stat_mean(values: list) -> float:
            return anomaly.mean(values)

        def stat_median(values: list) -> float:
            return anomaly.median(values)

        def stat_stdev(values: list) -> float:
            return anomaly.stdev(values)

        def stat_detect_outliers(values: list, threshold_stdevs: float = 2.0) -> list:
            return anomaly.detect_outliers(values, float(threshold_stdevs))

        def stat_detect_anomalies(records: list, field: str, threshold_stdevs: float = 2.0) -> list:
            return anomaly.detect_anomalies(records, field, float(threshold_stdevs))

        # ---- advanced reporting: dual-control signing + encryption at rest ----
        def co_sign_report(r, key_id: str):
            return reporting.co_sign_report(r, key_id)

        def export_encrypted(r, path: str, key_id: str):
            reporting.export_encrypted(r, path, key_id)
            return None

        # name -> (callable, min_role, effect)
        registry = {
            "load_disk_image": (load_disk_image, "TIER1_TRIAGE", "READ"),
            "load_memory_image": (load_memory_image, "TIER1_TRIAGE", "READ"),
            "load_pcap": (load_pcap, "TIER1_TRIAGE", "READ"),
            "load_logs": (load_logs, "TIER1_TRIAGE", "READ"),

            "sha256": (sha256, "TIER1_TRIAGE", "DERIVE"),
            "verify_hash": (verify_hash, "TIER1_TRIAGE", "DERIVE"),

            "list_files": (fs_list_files, "TIER1_TRIAGE", "READ"),
            "carve_deleted": (fs_carve_deleted, "TIER2_ANALYST", "READ"),
            "get_metadata": (fs_get_metadata, "TIER1_TRIAGE", "DERIVE"),
            "flag_suspicious": (fs_flag_suspicious, "TIER2_ANALYST", "DERIVE"),

            "list_processes": (mem_list_processes, "TIER2_ANALYST", "READ"),
            "list_network_connections": (mem_list_connections, "TIER2_ANALYST", "READ"),
            "detect_injection": (mem_detect_injection, "TIER2_ANALYST", "DERIVE"),
            "extract_strings": (mem_extract_strings, "TIER2_ANALYST", "READ"),

            "list_flows": (net_list_flows, "TIER2_ANALYST", "READ"),
            "extract_dns": (net_extract_dns, "TIER2_ANALYST", "READ"),
            "flag_suspicious_connections": (net_flag_suspicious_connections, "TIER2_ANALYST", "DERIVE"),

            "parse_events": (log_parse_events, "TIER1_TRIAGE", "READ"),
            "match_iocs": (log_match_iocs, "TIER2_ANALYST", "DERIVE"),

            "correlate": (do_correlate, "TIER2_ANALYST", "DERIVE"),

            "new_report": (new_report, "TIER1_TRIAGE", "DERIVE"),
            "add_section": (add_section, "TIER1_TRIAGE", "DERIVE"),
            "add_timeline": (add_timeline, "TIER1_TRIAGE", "DERIVE"),
            "sign_report": (sign_report, "LEAD_INVESTIGATOR", "EXPORT"),
            "export": (do_export, "LEAD_INVESTIGATOR", "EXPORT"),

            "length": (length, "TIER1_TRIAGE", "DERIVE"),
            "print": (print_value, "TIER1_TRIAGE", "DERIVE"),
            "reverse": (reverse, "TIER1_TRIAGE", "DERIVE"),
            "substring": (substring, "TIER1_TRIAGE", "DERIVE"),
            "char_at": (char_at, "TIER1_TRIAGE", "DERIVE"),
            "to_upper": (to_upper, "TIER1_TRIAGE", "DERIVE"),
            "to_lower": (to_lower, "TIER1_TRIAGE", "DERIVE"),
            "to_string": (to_string, "TIER1_TRIAGE", "DERIVE"),
            "to_number": (to_number, "TIER1_TRIAGE", "DERIVE"),
            "range": (range_list, "TIER1_TRIAGE", "DERIVE"),

            "get": (dict_get, "TIER1_TRIAGE", "DERIVE"),
            "has_key": (dict_has_key, "TIER1_TRIAGE", "DERIVE"),
            "keys": (dict_keys, "TIER1_TRIAGE", "DERIVE"),
            "values": (dict_values, "TIER1_TRIAGE", "DERIVE"),
            "map_set": (dict_set, "TIER1_TRIAGE", "DERIVE"),

            "append": (list_append, "TIER1_TRIAGE", "DERIVE"),
            "contains": (list_contains, "TIER1_TRIAGE", "DERIVE"),
            "unique": (list_unique, "TIER1_TRIAGE", "DERIVE"),
            "sort_by": (list_sort_by, "TIER1_TRIAGE", "DERIVE"),
            "sum_list": (list_sum, "TIER1_TRIAGE", "DERIVE"),

            "matches": (matches, "TIER1_TRIAGE", "DERIVE"),
            "hash_many": (hash_many, "TIER2_ANALYST", "READ"),

            "mean": (stat_mean, "TIER1_TRIAGE", "DERIVE"),
            "median": (stat_median, "TIER1_TRIAGE", "DERIVE"),
            "stdev": (stat_stdev, "TIER1_TRIAGE", "DERIVE"),
            "detect_outliers": (stat_detect_outliers, "TIER2_ANALYST", "DERIVE"),
            "detect_anomalies": (stat_detect_anomalies, "TIER2_ANALYST", "DERIVE"),

            "co_sign_report": (co_sign_report, "LEAD_INVESTIGATOR", "EXPORT"),
            "export_encrypted": (export_encrypted, "LEAD_INVESTIGATOR", "EXPORT"),
        }
        for name, (func, min_role, effect) in registry.items():
            self.builtins[name] = BuiltinSpec(func=func, min_role=min_role, effect=effect)

        self._register_namespaces(
            new_report=new_report, add_section=add_section, add_timeline=add_timeline,
            sign_report=sign_report, co_sign_report=co_sign_report,
            do_export=do_export, export_encrypted=export_encrypted,
            net_list_flows=net_list_flows, net_extract_dns=net_extract_dns,
            net_flag_suspicious_connections=net_flag_suspicious_connections,
        )

    def _register_namespaces(self, new_report, add_section, add_timeline,
                              sign_report, co_sign_report, do_export, export_encrypted,
                              net_list_flows, net_extract_dns, net_flag_suspicious_connections):
        """
        Registers the namespaced stdlib objects (system, process, file,
        network, hash, analyze, detection, report, test) as global
        variables every script starts with -- this is what makes
        `system.info()` / `process.list()` / `sample.hash()` work.
        Every method still goes through the same RBAC + audit path as
        the flat builtins (see MemberCall handling in eval_expr).
        """
        def M(func, min_role, effect="READ"):
            return MethodSpec(func=func, min_role=min_role, effect=effect)

        def hash_sha256(value):
            if isinstance(value, str) and os.path.isfile(value):
                return sha256_file(value)
            return hashlib.sha256(str(value).encode("utf-8")).hexdigest()

        def hash_sha512(value):
            if isinstance(value, str) and os.path.isfile(value):
                return sha512_file(value)
            return hashlib.sha512(str(value).encode("utf-8")).hexdigest()

        def analyze_file(path: str) -> FlangObject:
            methods = {
                "hash": M(lambda: fileforensics.file_hash(path), "TIER1_TRIAGE"),
                "metadata": M(lambda: fileforensics.file_metadata(path), "TIER1_TRIAGE"),
                "strings": M(lambda min_length=4, limit=200: fileforensics.file_strings(
                    path, int(min_length), int(limit)), "TIER2_ANALYST"),
                "entropy": M(lambda: fileforensics.file_entropy(path), "TIER2_ANALYST"),
                "imports": M(lambda: fileforensics.parse_imports(path), "TIER2_ANALYST"),
                "sections": M(lambda: fileforensics.parse_sections(path), "TIER2_ANALYST"),
            }
            return FlangObject(name=f"Sample({os.path.basename(path)})", methods=methods)

        test_session = testlab.TestLabSession()

        namespaces = {
            "system": FlangNamespace("system", {
                "info": M(sysinfo.system_info, "TIER1_TRIAGE"),
                "os": M(sysinfo.system_os, "TIER1_TRIAGE"),
                "cpu": M(sysinfo.system_cpu, "TIER1_TRIAGE"),
                "memory": M(sysinfo.system_memory, "TIER1_TRIAGE"),
                "disk": M(sysinfo.system_disk, "TIER1_TRIAGE"),
            }),
            "process": FlangNamespace("process", {
                "list": M(sysinfo.process_list, "TIER1_TRIAGE"),
                "info": M(sysinfo.process_info, "TIER1_TRIAGE"),
            }),
            "service": FlangNamespace("service", {
                "list": M(sysinfo.service_list, "TIER2_ANALYST"),
            }),
            "user": FlangNamespace("user", {
                "list": M(sysinfo.user_list, "TIER2_ANALYST"),
            }),
            "startup": FlangNamespace("startup", {
                "list": M(sysinfo.startup_list, "TIER2_ANALYST"),
            }),
            "eventlog": FlangNamespace("eventlog", {
                "read": M(sysinfo.eventlog_read, "TIER2_ANALYST"),
            }),
            "file": FlangNamespace("file", {
                "info": M(fileforensics.file_info, "TIER1_TRIAGE"),
                "hash": M(fileforensics.file_hash, "TIER1_TRIAGE"),
                "metadata": M(fileforensics.file_metadata, "TIER1_TRIAGE"),
                "strings": M(fileforensics.file_strings, "TIER2_ANALYST"),
                "entropy": M(fileforensics.file_entropy, "TIER2_ANALYST"),
            }),
            "network": FlangNamespace("network", {
                "interfaces": M(netlive.net_interfaces, "TIER1_TRIAGE"),
                "connections": M(netlive.net_connections, "TIER2_ANALYST"),
                "dns": M(netlive.net_dns, "TIER1_TRIAGE"),
                "routes": M(netlive.net_routes, "TIER1_TRIAGE"),
                "analyze": M(netlive.net_analyze, "TIER2_ANALYST", "DERIVE"),
                # added: evidence-based (PCAP) network analysis, alongside
                # the live-host methods above -- same namespace, so a
                # script only needs to remember one name ("network") for
                # both live and evidence-based network work.
                "pcap_flows": M(net_list_flows, "TIER2_ANALYST", "READ"),
                "pcap_dns": M(net_extract_dns, "TIER2_ANALYST", "READ"),
                "pcap_flag_suspicious": M(net_flag_suspicious_connections, "TIER2_ANALYST", "DERIVE"),
            }),
            "hash": FlangNamespace("hash", {
                "sha256": M(hash_sha256, "TIER1_TRIAGE", "DERIVE"),
                "sha512": M(hash_sha512, "TIER1_TRIAGE", "DERIVE"),
            }),
            "analyze": FlangNamespace("analyze", {
                "file": M(analyze_file, "TIER1_TRIAGE"),
            }),
            "detection": FlangNamespace("detection", {
                "unexpected_parent": M(detectlib.unexpected_parent, "TIER2_ANALYST", "DERIVE"),
                "suspicious_port": M(detectlib.suspicious_port, "TIER2_ANALYST", "DERIVE"),
                "new_entries": M(detectlib.new_entries, "TIER2_ANALYST", "DERIVE"),
            }),
            # added: dotted access to the DiskImage-evidence filesystem
            # functions (previously only reachable as flat builtins
            # list_files/carve_deleted/get_metadata/flag_suspicious,
            # which remain unchanged and fully usable on their own).
            "filesystem": FlangNamespace("filesystem", {
                "list_files": M(filesystem.list_files, "TIER1_TRIAGE", "READ"),
                "carve_deleted": M(filesystem.carve_deleted, "TIER2_ANALYST", "READ"),
                "get_metadata": M(filesystem.get_metadata, "TIER1_TRIAGE", "DERIVE"),
                "flag_suspicious": M(filesystem.flag_suspicious, "TIER2_ANALYST", "DERIVE"),
            }),
            # added: timeline operations over the Timeline shape correlate()
            # already produces (correlate() itself is unchanged).
            "timeline": FlangNamespace("timeline", {
                "flatten": M(timeline_ops.flatten, "TIER1_TRIAGE", "DERIVE"),
                "sort": M(timeline_ops.sort_by_time, "TIER1_TRIAGE", "DERIVE"),
                "filter": M(timeline_ops.filter_events, "TIER1_TRIAGE", "DERIVE"),
                "search": M(timeline_ops.search, "TIER1_TRIAGE", "DERIVE"),
                "group_by": M(timeline_ops.group_by, "TIER1_TRIAGE", "DERIVE"),
                "export": M(timeline_ops.export_timeline, "TIER2_ANALYST", "EXPORT"),
            }),
            # added: cross-artifact relationship linking, alongside (not
            # replacing) the flat correlate() builtin, which remains the
            # time-proximity correlation entry point.
            "correlation": FlangNamespace("correlation", {
                "correlate": M(correlate.correlate, "TIER2_ANALYST", "DERIVE"),
                "link": M(correlate.link, "TIER1_TRIAGE", "DERIVE"),
                "find_related": M(correlate.find_related, "TIER1_TRIAGE", "DERIVE"),
                "build_graph": M(correlate.build_relationship_graph, "TIER2_ANALYST", "DERIVE"),
            }),
            # added: local, file-backed case management (see
            # runtime/modules/case.py docstring for honest scope notes --
            # this is not a centralized multi-user case database).
            "case": FlangNamespace("case", {
                "create": M(case_module.create_case, "TIER1_TRIAGE", "DERIVE"),
                "open": M(case_module.open_case, "TIER1_TRIAGE", "READ"),
                "add_evidence": M(case_module.add_evidence, "TIER2_ANALYST", "DERIVE"),
                "list_evidence": M(case_module.list_evidence, "TIER1_TRIAGE", "READ"),
                "add_note": M(case_module.add_note, "TIER1_TRIAGE", "DERIVE"),
                "close": M(case_module.close_case, "LEAD_INVESTIGATOR", "DERIVE"),
                "list_cases": M(case_module.list_cases, "TIER1_TRIAGE", "READ"),
            }),
            # added: standalone multi-hash evidence manifests for a single
            # file (distinct from, and layered on top of, the read-only
            # EvidenceHandle system used by load_disk_image() and friends).
            "evidence": FlangNamespace("evidence", {
                "manifest": M(evidence_module.manifest, "TIER1_TRIAGE", "READ"),
                "verify": M(evidence_module.verify_manifest, "TIER1_TRIAGE", "READ"),
            }),
            # added: query/export the interpreter's own hash-chained audit
            # log from within a script (the automatic logging behavior
            # itself -- every built-in call being recorded -- is unchanged).
            "audit": FlangNamespace("audit", {
                "verify": M(lambda: self.audit_log.verify(), "TIER1_TRIAGE", "DERIVE"),
                "export": M(self._audit_export, "TIER2_ANALYST", "EXPORT"),
                "summary": M(self._audit_summary, "TIER1_TRIAGE", "DERIVE"),
            }),
            # added: read the current session's own identity/role, and
            # verify an arbitrary file's hash against an expected value
            # (distinct from evidence.verify(), which checks a full
            # manifest; this is a quick single-hash check).
            "security": FlangNamespace("security", {
                "whoami": M(self._security_whoami, "TIER1_TRIAGE", "DERIVE"),
                "verify_hash": M(self._security_verify_hash, "TIER1_TRIAGE", "DERIVE"),
            }),
            # added: small composite/orchestration helpers -- genuinely
            # new logic (not just aliases), kept intentionally short
            # rather than becoming a monolithic catch-all namespace.
            "forensics": FlangNamespace("forensics", {
                "acquire_and_hash": M(evidence_module.manifest, "TIER1_TRIAGE", "READ"),
                "quick_triage": M(self._forensics_quick_triage, "TIER1_TRIAGE", "READ"),
            }),
            # added: synthetic event generation for exercising the
            # timeline/correlation engines without real data (distinct
            # from `test`'s file-mutation detection-robustness testing).
            "simulation": FlangNamespace("simulation", {
                "process_event": M(simlab.simulate_process_event, "TIER1_TRIAGE", "DERIVE"),
                "file_event": M(simlab.simulate_file_event, "TIER1_TRIAGE", "DERIVE"),
                "network_event": M(simlab.simulate_network_event, "TIER1_TRIAGE", "DERIVE"),
                "dns_event": M(simlab.simulate_dns_event, "TIER1_TRIAGE", "DERIVE"),
                "auth_event": M(simlab.simulate_auth_event, "TIER1_TRIAGE", "DERIVE"),
                "log_event": M(simlab.simulate_log_event, "TIER1_TRIAGE", "DERIVE"),
                "scenario": M(simlab.simulate_scenario, "TIER1_TRIAGE", "DERIVE"),
            }),
            "report": FlangNamespace("report", {
                "create": M(new_report, "TIER1_TRIAGE", "DERIVE"),
                "add": M(add_section, "TIER1_TRIAGE", "DERIVE"),
                "timeline": M(add_timeline, "TIER1_TRIAGE", "DERIVE"),
                "sign": M(sign_report, "LEAD_INVESTIGATOR", "EXPORT"),
                "cosign": M(co_sign_report, "LEAD_INVESTIGATOR", "EXPORT"),
                "save": M(do_export, "LEAD_INVESTIGATOR", "EXPORT"),
                "save_encrypted": M(export_encrypted, "LEAD_INVESTIGATOR", "EXPORT"),
            }),
            "test": FlangNamespace("test", {
                "create": M(test_session.create, "TIER2_ANALYST", "DERIVE"),
                "generate_variants": M(test_session.generate_variants, "TIER2_ANALYST", "DERIVE"),
                "compare_detection": M(test_session.compare_detection, "TIER2_ANALYST", "DERIVE"),
                "generate_report": M(test_session.generate_report, "TIER2_ANALYST", "DERIVE"),
            }),
        }
        # added: "reporting" is a pure additive alias for "report" (same
        # underlying namespace object, same methods) -- satisfies the
        # flang.reporting naming convention without renaming the
        # existing, already-tested "report" namespace.
        namespaces["reporting"] = namespaces["report"]

        for name, ns in namespaces.items():
            self.global_env.set_local(name, ns)
        self.reserved_namespace_names = frozenset(namespaces.keys())

    def _audit_export(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(self.audit_log.as_list(), f, indent=2, default=str)

    def _audit_summary(self) -> Dict[str, Any]:
        return {
            "case_id": self.security.case_id,
            "investigator": self.security.investigator,
            "entry_count": len(self.audit_log.entries),
            "chain_verified": self.audit_log.verify(),
        }

    def _security_whoami(self) -> Dict[str, Any]:
        return {
            "investigator": self.security.investigator,
            "role": self.security.role,
            "case_id": self.security.case_id,
        }

    def _security_verify_hash(self, path: str, expected_sha256: str) -> bool:
        return sha256_file(path) == expected_sha256

    def _forensics_quick_triage(self) -> Dict[str, Any]:
        """A small composite convenience: one call that pulls together
        system info + a process count, useful as a first line of a
        triage report. Genuinely new logic, not a re-export."""
        info = sysinfo.system_info()
        procs = sysinfo.process_list()
        return {
            "hostname": info.get("hostname"), "os": info.get("os"),
            "os_release": info.get("os_release"), "process_count": len(procs),
            "collected_at": info.get("collected_at"),
        }

    # -------------------------------------------------------------- run
    def run(self, program: A.Program):
        for stmt in program.statements:
            if isinstance(stmt, A.FunctionDef):
                self.functions[stmt.name] = stmt
        for stmt in program.statements:
            if not isinstance(stmt, A.FunctionDef):
                try:
                    self.exec_stmt(stmt, self.global_env)
                except (FlangRuntimeError, AuthorizationError):
                    raise
                except (BreakSignal, ContinueSignal):
                    raise FlangRuntimeError("'break'/'continue' used outside of a loop")
                except ReturnSignal:
                    raise FlangRuntimeError("'return' used outside of a function")
                except Exception as e:
                    # Security-relevant: a raw Python traceback (with file
                    # paths, library internals, etc.) is exactly the kind
                    # of unpredictable, unexplainable failure that makes a
                    # tool look untrustworthy to both investigators and
                    # security monitoring. Every failure mode surfaces as
                    # a single, clean FlangRuntimeError instead -- nothing
                    # about the interpreter's internals ever leaks to the
                    # script's output.
                    raise FlangRuntimeError(f"{type(e).__name__}: {e}") from None

    # -------------------------------------------------------------- statements
    def exec_stmt(self, stmt, env: Environment):
        if isinstance(stmt, A.Import):
            with open(stmt.path, "r") as f:
                env.assign(stmt.name, json.load(f))
            return

        if isinstance(stmt, A.Assign):
            if stmt.target in self.reserved_namespace_names:
                raise FlangRuntimeError(
                    f"'{stmt.target}' is a built-in namespace (like system, file, "
                    f"report) and cannot be used as a variable name -- pick a "
                    f"different name, e.g. '{stmt.target}_result'", stmt.line)
            value = self.eval_expr(stmt.value, env)
            env.assign(stmt.target, value)
            return

        if isinstance(stmt, A.ExprStmt):
            self.eval_expr(stmt.expr, env)
            return

        if isinstance(stmt, A.If):
            # NOTE: if/else bodies share the enclosing scope rather than
            # introducing a new block scope. FLANG has no `let`/`var`
            # distinction, so a script that assigns a variable inside a
            # branch (e.g. `severity := "HIGH";`) expects that name to be
            # visible after the if-statement, matching investigators'
            # expectations from shell-style scripting rather than C-style
            # block scoping.
            cond = self.eval_expr(stmt.condition, env)
            branch = stmt.then_block if _truthy(cond) else stmt.else_block
            if branch is not None:
                for s in branch:
                    self.exec_stmt(s, env)
            return

        if isinstance(stmt, A.For):
            if stmt.var_name in self.reserved_namespace_names:
                raise FlangRuntimeError(
                    f"'{stmt.var_name}' is a built-in namespace and cannot be used "
                    f"as a loop variable name", stmt.line)
            iterable = self.eval_expr(stmt.iterable, env)
            for item in iterable:
                env.assign(stmt.var_name, item)
                try:
                    for s in stmt.body:
                        self.exec_stmt(s, env)
                except ContinueSignal:
                    continue
                except BreakSignal:
                    break
            return

        if isinstance(stmt, A.While):
            iterations = 0
            while _truthy(self.eval_expr(stmt.condition, env)):
                iterations += 1
                if iterations > self.MAX_LOOP_ITERATIONS:
                    raise FlangRuntimeError(
                        f"while loop exceeded {self.MAX_LOOP_ITERATIONS} iterations "
                        "(safety limit -- check the loop condition)", stmt.line)
                try:
                    for s in stmt.body:
                        self.exec_stmt(s, env)
                except ContinueSignal:
                    continue
                except BreakSignal:
                    break
            return

        if isinstance(stmt, A.Try):
            try:
                for s in stmt.try_block:
                    self.exec_stmt(s, env)
            except (FlangRuntimeError, AuthorizationError) as e:
                env.assign(stmt.err_name, str(e))
                for s in stmt.catch_block:
                    self.exec_stmt(s, env)
            return

        if isinstance(stmt, A.Break):
            raise BreakSignal()

        if isinstance(stmt, A.Continue):
            raise ContinueSignal()

        if isinstance(stmt, A.Return):
            raise ReturnSignal(self.eval_expr(stmt.value, env))

        if isinstance(stmt, A.FunctionDef):
            return  # already hoisted in run()

        raise FlangRuntimeError(f"Unknown statement node: {stmt!r}")

    # -------------------------------------------------------------- expressions
    def eval_expr(self, expr, env: Environment):
        if isinstance(expr, A.NumberLiteral):
            return expr.value
        if isinstance(expr, A.StringLiteral):
            return expr.value
        if isinstance(expr, A.BoolLiteral):
            return expr.value
        if isinstance(expr, A.FStringLiteral):
            return self._eval_fstring(expr.raw, env)
        if isinstance(expr, A.ListLiteral):
            return [self.eval_expr(e, env) for e in expr.elements]
        if isinstance(expr, A.DictLiteral):
            return {self.eval_expr(k, env): self.eval_expr(v, env) for k, v in expr.pairs}
        if isinstance(expr, A.Identifier):
            return env.get(expr.name)
        if isinstance(expr, A.BinaryOp):
            if expr.op == "and":
                left = self.eval_expr(expr.left, env)
                if not _truthy(left):
                    return False
                return _truthy(self.eval_expr(expr.right, env))
            if expr.op == "or":
                left = self.eval_expr(expr.left, env)
                if _truthy(left):
                    return True
                return _truthy(self.eval_expr(expr.right, env))
            return self._eval_binary(expr, env)
        if isinstance(expr, A.UnaryOp):
            value = self.eval_expr(expr.operand, env)
            if expr.op == "-":
                return -value
            if expr.op == "not":
                return not _truthy(value)
            raise FlangRuntimeError(f"Unknown unary operator {expr.op}", expr.line)
        if isinstance(expr, A.Ternary):
            cond = self.eval_expr(expr.condition, env)
            return self.eval_expr(expr.then_expr, env) if _truthy(cond) else self.eval_expr(expr.else_expr, env)
        if isinstance(expr, A.Call):
            return self._eval_call(expr, env)
        if isinstance(expr, A.MemberCall):
            return self._eval_member_call(expr, env)
        raise FlangRuntimeError(f"Unknown expression node: {expr!r}", getattr(expr, "line", None))

    def _eval_fstring(self, raw: str, env: Environment) -> str:
        def repl(match):
            inner = match.group(1)
            from .lexer import tokenize
            from .parser import Parser
            tokens = tokenize(inner + ";")
            expr = Parser(tokens).parse_expression()
            return str(self.eval_expr(expr, env))
        return re.sub(r"\{([^{}]+)\}", repl, raw)

    def _eval_binary(self, expr: A.BinaryOp, env: Environment):
        left = self.eval_expr(expr.left, env)
        right = self.eval_expr(expr.right, env)
        op = expr.op
        try:
            if op == "+":
                return left + right
            if op == "-":
                return left - right
            if op == "*":
                return left * right
            if op == "/":
                return left / right
            if op == "%":
                return left % right
            if op == "**":
                return left ** right
            if op == "//":
                return left // right
            if op == "in":
                return left in right
            if op == "==":
                return left == right
            if op == "!=":
                return left != right
            if op == "<":
                return left < right
            if op == ">":
                return left > right
            if op == "<=":
                return left <= right
            if op == ">=":
                return left >= right
        except ZeroDivisionError:
            raise FlangRuntimeError(f"Division by zero evaluating '{op}'", expr.line)
        except TypeError as e:
            raise FlangRuntimeError(f"Type mismatch evaluating '{op}': {e}", expr.line)
        raise FlangRuntimeError(f"Unknown operator {op}", expr.line)

    def _eval_call(self, expr: A.Call, env: Environment):
        args = [self.eval_expr(a, env) for a in expr.args]
        kwargs = {k: self.eval_expr(v, env) for k, v in expr.kwargs.items()}

        if expr.name in self.functions:
            return self._call_user_function(expr.name, args, kwargs, env)

        if expr.name in self.builtins:
            spec = self.builtins[expr.name]
            try:
                return self._audited_call(expr.name, spec, args, kwargs)
            except AuthorizationError as e:
                raise FlangRuntimeError(str(e), expr.line)

        raise FlangRuntimeError(f"Unknown function '{expr.name}'", expr.line)

    def _eval_member_call(self, expr: A.MemberCall, env: Environment):
        obj = self.eval_expr(expr.object_expr, env)
        if not isinstance(obj, FlangNamespace):
            raise FlangRuntimeError(
                f"'.{expr.method_name}(...)' is not valid here -- the value on the "
                f"left is not a namespace or object", expr.line)
        spec = obj.methods.get(expr.method_name)
        if spec is None:
            raise FlangRuntimeError(f"'{obj.name}' has no method '{expr.method_name}'", expr.line)

        args = [self.eval_expr(a, env) for a in expr.args]
        kwargs = {k: self.eval_expr(v, env) for k, v in expr.kwargs.items()}
        try:
            return self._audited_call(f"{obj.name}.{expr.method_name}", spec, args, kwargs)
        except AuthorizationError as e:
            raise FlangRuntimeError(str(e), expr.line)

    def _call_user_function(self, name: str, args: list, kwargs: dict, caller_env: Environment):
        fn = self.functions[name]
        local = Environment(parent=self.global_env)
        for i, pname in enumerate(fn.params):
            if i < len(args):
                local.set_local(pname, args[i])
        for k, v in kwargs.items():
            local.set_local(k, v)
        try:
            for s in fn.body:
                self.exec_stmt(s, local)
        except ReturnSignal as r:
            return r.value
        except BreakSignal:
            # a bare break/continue inside a function body (not inside a
            # loop of that same function) must not leak out and silently
            # terminate a loop in the *caller* -- that would be a scoping
            # bug, not a feature.
            raise FlangRuntimeError(f"'break' used outside of a loop (inside function '{name}')")
        except ContinueSignal:
            raise FlangRuntimeError(f"'continue' used outside of a loop (inside function '{name}')")
        return None


def _truthy(value) -> bool:
    if isinstance(value, (list, dict, str)):
        return len(value) > 0
    return bool(value)


def _summarize_args(args: list, kwargs: dict) -> Dict[str, Any]:
    def brief(v):
        if isinstance(v, EvidenceHandle):
            return repr(v)
        if isinstance(v, (list, dict)):
            return f"{type(v).__name__}[{len(v)}]"
        return str(v)[:120]
    return {
        "args": [brief(a) for a in args],
        "kwargs": {k: brief(v) for k, v in kwargs.items()},
    }
