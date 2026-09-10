# FLANG — Forensic Language (Working Prototype)

A domain-specific language and runtime for **authorized** computer and network
forensic investigations, implementing the architecture described in the
accompanying project proposal: lexer → parser → interpreter → sandboxed
forensic runtime → evidence-management layer → analysis modules →
audit/chain-of-custody log → reporting engine, wrapped in an RBAC security
layer.

This is a runnable prototype, not a toy syntax demo: it parses and executes
real `.flang` scripts, hashes and seals evidence read-only, enforces
role-based access control per function, writes a tamper-evident hash-chained
audit log, correlates findings into a timeline, and produces a signed
JSON + HTML investigation report.

## What this deliberately does NOT do

Per the scope boundary in the project proposal: this tool does not disable,
hide from, or evade antivirus/EDR/IDS/IPS/firewalls, and it contains no
exploit, malware, or intrusion code. It is a **read-only evidence analysis**
tool. Trust with security tooling is meant to be earned through code signing,
least privilege, and auditability (see proposal §6, "Establishing Trust With
Security Solutions") — not by hiding.

## Project layout

```
flang/
  lexer.py              tokenizer
  ast_nodes.py           AST node dataclasses
  parser.py              recursive-descent parser -> AST
  interpreter.py          tree-walking interpreter, built-in registry,
                          RBAC + audit-log wiring
  cli.py                  `python -m flang.cli run ...` entry point
  runtime/
    evidence.py           EvidenceManager / EvidenceHandle (read-only,
                          hash-verified, case-scoped evidence access)
    audit.py               hash-chained tamper-evident audit log
    security.py             RBAC role hierarchy + enforcement
    report.py               report builder, HMAC signing, JSON/HTML export
    modules/
      filesystem.py         list_files / carve_deleted / flag_suspicious
      memory.py              list_processes / detect_injection / extract_strings
      network.py             list_flows / extract_dns / flag_suspicious_connections
      logs.py                 log parsing + IOC matching
      correlate.py             cross-source timeline correlation
examples/
  sample_investigation.flang     end-to-end example script
  demo_evidence/                 synthetic fixtures (fake disk dir, fake
                                 memory-image JSON, fake pcap JSON, fake
                                 Windows-event-style log, IOC list)
tests/
  test_flang.py                unittest suite (lexer/parser, interpreter,
                                RBAC, evidence integrity, audit-chain tamper
                                detection)
```

## Running the example investigation

## Web IDE (Lab / Learn / Tips / Applications / Facts)

A local, no-build-step web front end that wraps the CLI so you don't need a
terminal for every run. Zero new dependencies -- the backend is Python's
standard library `http.server` only.

```bash
cd webapp
python3 server.py
```

Then open **http://localhost:8765**. This binds to `localhost` only and is
meant for local personal use, not for exposing on a network.


```bash
cd examples
PYTHONPATH=.. python3 -m flang.cli run sample_investigation.flang \
    --case CASE-2026-0417 \
    --investigator "j.doe" \
    --role LEAD_INVESTIGATOR \
    --audit-log output/audit.log
```

This will:
1. Ingest the four synthetic evidence fixtures read-only and hash them.
2. Run filesystem / memory / network / log analysis against IOCs in
   `demo_evidence/case_2026_0417_iocs.json`.
3. Correlate findings into a timeline.
4. Produce `output/report.json` and `output/report.html`, HMAC-signed.
5. Print evidence-integrity and audit-log-integrity check results.

To see **RBAC enforcement**, re-run with a lower role:

```bash
PYTHONPATH=.. python3 -m flang.cli run sample_investigation.flang \
    --case CASE-2026-0417 --investigator trainee --role TIER1_TRIAGE \
    --audit-log output/audit_denied.log
```

It will stop with `Role 'TIER1_TRIAGE' may not call 'carve_deleted' ...` the
moment the script reaches an operation above that role's clearance.

To independently verify an audit log's hash chain (and see tamper detection
in action if you hand-edit a line in the log file):

```bash
PYTHONPATH=.. python3 -m flang.cli verify-audit output/audit.log
```

## Running the tests

```bash
python3 tests/test_flang.py -v
```

## Language quick reference

```flang
import iocs from "case_iocs.json";

disk := load_disk_image("/evidence/host_files");
h := sha256(disk);

files := list_files(disk, ".");
suspicious := flag_suspicious(files, iocs);

if length(suspicious) > 0 {
    severity := "HIGH";
} else {
    severity := "LOW";
}

for f in suspicious {
    # (loop body has access to outer scope too)
}

report := new_report(f"Investigation - {severity}");
report := add_section(report, "Suspicious Files", suspicious);
report := sign_report(report, key_id: "my_key");
export(report, format: "json", path: "output/report.json");
```

**Control flow:** `if / elif / else`, `while`, `for ... in ...`, `break`, `continue`,
`try { } catch err { }`, `function name(params) { return ...; }` (with recursion).

**Operators:**

```flang
+  -  *  /  %  **  //        # arithmetic (** = exponent, // = floor division)
==  !=  <  >  <=  >=          # comparison
and  or  not                  # logical
in                             # membership: "x.exe" in suspicious_names
+=  -=  *=  /=  %=            # compound assignment
++  --                        # increment / decrement (statement form: count++;)
cond ? a : b                  # ternary conditional expression
```

**Data types:** number, string, f-string (`f"...{expr}..."`), boolean, `[list, literal]`,
`{"dict": "literal"}`, and the opaque evidence types (`DiskImage`, `MemoryImage`,
`PacketCapture`, `LogSet`, `Report`).

Every runtime error (bad input, division by zero, a type mismatch, an unauthorized
call) surfaces as a single clean `FlangRuntimeError` message — no raw Python
traceback, internal file path, or library detail is ever exposed to a script's
output, by design.

Full built-in catalogue (see `interpreter.py::_register_builtins` for the
authoritative list, including each function's minimum RBAC role):

| Category | Functions |
|---|---|
| Acquisition | `load_disk_image`, `load_memory_image`, `load_pcap`, `load_logs` |
| Integrity | `sha256`, `verify_hash`, `hash_many` (parallel) |
| Filesystem | `list_files`, `carve_deleted`, `get_metadata`, `flag_suspicious` |
| Memory | `list_processes`, `list_network_connections`, `detect_injection`, `extract_strings` |
| Network | `list_flows`, `extract_dns`, `flag_suspicious_connections` |
| Logs | `parse_events`, `match_iocs` |
| Correlation | `correlate` |
| Anomaly detection | `mean`, `median`, `stdev`, `detect_outliers`, `detect_anomalies` |
| Dictionaries | `get`, `has_key`, `keys`, `values`, `map_set` |
| Lists | `append`, `contains`, `unique`, `sort_by`, `sum_list` |
| Strings | `reverse`, `substring`, `char_at`, `to_upper`, `to_lower`, `matches` (regex) |
| Casting | `to_string`, `to_number`, `range` |
| Reporting | `new_report`, `add_section`, `add_timeline`, `sign_report`, `co_sign_report` (dual-control), `export`, `export_encrypted` (AES at rest) |
| Misc | `length`, `print` |

## Namespaced stdlib (v2) — `system.info()`, `process.list()`, `sample.hash()`, ...

Alongside the flat built-ins above, FLANG also supports dotted namespace/method
call syntax for live-host and static-file analysis. See
`SCOPE_AND_ROADMAP.md` for exactly what is and isn't implemented against the
full cross-platform specification this was built against.

```flang
info := system.info();
print(f"Host: {get(info, \"hostname\")}");

processes := process.list();
flagged := detection.unexpected_parent(processes, {"sshd": ["systemd"]});

sample := analyze.file("suspicious.exe");
print(sample.hash());
print(to_string(sample.entropy()));

test.create("marker_check");
test.generate_variants(10);
test.compare_detection();
lab_report := test.generate_report();
```

| Namespace | Methods |
|---|---|
| `system` | `info`, `os`, `cpu`, `memory`, `disk` |
| `process` | `list`, `info(pid)` |
| `service`, `user`, `startup`, `eventlog` | `list` / `list` / `list` / `read` (Linux implemented and tested; Windows stubbed, untested — see roadmap doc) |
| `file` | `info`, `hash`, `metadata`, `strings`, `entropy` |
| `analyze` | `file(path)` → returns a `Sample` object with `.hash() .metadata() .strings() .entropy() .imports() .sections()` |
| `network` | `interfaces`, `connections`, `dns`, `routes`, `analyze` |
| `hash` | `sha256(path_or_text)` |
| `detection` | `unexpected_parent`, `suspicious_port`, `new_entries` |
| `report` | `create`, `add`, `timeline`, `sign`, `cosign`, `save`, `save_encrypted` |
| `test` | `create`, `generate_variants`, `compare_detection`, `generate_report` (synthetic Security Testing Laboratory) |

**Important:** these namespace names (`system`, `process`, `file`, `network`,
`hash`, `analyze`, `detection`, `report`, `test`, `service`, `user`,
`startup`, `eventlog`) are reserved — a script cannot use them as a variable
or loop-variable name (the interpreter rejects this with a clear error rather
than silently letting a script shadow the namespace).

## Notes on fidelity to the full proposal / what a production build adds

This prototype is intentionally dependency-light so it runs anywhere with
just the Python standard library (plus optional `scapy` for real `.pcap`
parsing). It stands in for the heavier forensic backends the full proposal
recommends:

- **Filesystem/disk**: real builds would call `pytsk3` (The Sleuth Kit)
  against a raw/E01 image for real inode-level parsing and deleted-file
  carving, instead of walking an already-extracted directory tree.
- **Memory**: real builds would shell out to **Volatility 3** against a raw
  memory image; `memory.py` is already written against the normalized
  process/connection/string shape Volatility3's JSON output takes, so only
  the loader needs to change.
- **Network**: `network.py` already uses `scapy` for real `.pcap`/`.pcapng`
  files when the package is available, falling back to a JSON fixture
  otherwise (used here purely so the demo doesn't require a real capture
  file to run).
- **Logs**: real builds would add `python-evtx` for native Windows Event Log
  (`.evtx`) parsing and Grok-style patterns for arbitrary log formats,
  alongside the syslog/JSON parsers implemented here.
- **Signing**: this prototype signs reports with a locally generated
  HMAC-SHA256 key (see `keystore/`, created on first run) as a stand-in for
  a production PKI/HSM-backed code-signing key.
- **Sandboxing**: the security architecture (namespaces/seccomp/gVisor or
  Firecracker microVMs) described in the proposal is not implemented in this
  prototype's process model — the prototype enforces evidence read-only-ness
  and RBAC in-process, which is the logical boundary a real sandbox would
  wrap.
