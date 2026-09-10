# FLANG v2 — Scope & Roadmap Against the Full Cross-Platform Specification

The full specification (compiler with LLVM backend, cross-platform Windows/Linux
runtime, central management dashboard, fleet of live agents, CI/CD pipeline,
malware research lab, rule-engine DSL) describes a multi-month, multi-engineer
platform. This document is an honest map of **what has actually been built and
tested in this prototype** against that specification, organized by the
project's own phase plan, so nothing here is overclaimed.

## What's real and tested right now

### Language (Phase 1) — done, extended beyond the original scope
- Lexer, recursive-descent parser, AST, tree-walking interpreter (Python-hosted).
- Variables, functions (with recursion), `if/elif/else`, `while`, `for...in`,
  `break`/`continue`, `try/catch`.
- Full operator set: `+ - * / % ** //`, comparison, `and or not`, `in`
  (membership), compound assignment (`+= -= *= /= %=`), increment/decrement
  (`++ --`), ternary (`?:`).
- Data types: number, string, f-string, boolean, list, dict.
- **New in this revision: namespaced method-call syntax** (`system.info()`,
  `process.list()`, `sample.hash()`) — a real grammar extension (see
  `ast_nodes.MemberCall`, `parser.parse_postfix`), not string-matched sugar.
  Every namespace method goes through the same RBAC + audit path as every
  other built-in.
- Every runtime error surfaces as one clean message — no raw Python
  traceback, internal file path, or library detail ever reaches a script's
  output (verified: division-by-zero, type mismatches, bad casts all produce
  a single sanitized line).

### Standard library — implemented and live-tested against this machine
| Requested module | Status |
|---|---|
| `system.*` (info/os/cpu/memory/disk) | **Implemented**, backed by `psutil` + `platform`. Live-tested against the actual host running this prototype. |
| `process.*` (list/info) | **Implemented** via `psutil`. Live-tested: correctly enumerated 48 real processes on this host. |
| `service.*`, `user.*`, `startup.*`, `eventlog.*` | **Implemented for Linux** (`systemctl`, `pwd`, XDG autostart, `journalctl`/syslog). Windows equivalents (Service Control Manager, `NetUserEnum`, Run-key/Startup-folder enumeration, `ReadEventLog`) are documented stubs in the code — the platform-abstraction seam exists (see below), but only the Linux side is implemented and tested, since this prototype runs in a Linux sandbox with no Windows host available to test against. |
| `file.*` (info/hash/strings/metadata/entropy) | **Implemented** — Shannon entropy, printable-string extraction, and a hand-written PE and ELF header parser (deliberately not depending on `pefile`, to keep the format-parsing attack surface small and auditable). |
| `analyze.file(path)` → `sample.hash()/.metadata()/.strings()/.entropy()/.imports()/.sections()` | **Implemented** as a genuine object-with-methods (`FlangObject`), tested live against a synthetic sample. `imports()` is an honest stub — real PE/ELF import-table walking is flagged as a documented gap, not silently faked. |
| `network.*` (interfaces/connections/dns/routes/analyze) | **Implemented** via `psutil` + `/etc/resolv.conf` + `/proc/net/route`. Live-tested. |
| `hash.sha256(...)` | **Implemented** — hashes a file if the argument is a path, otherwise hashes the string itself. Verified against a known SHA-256 test vector. |
| `detection.*` (rule predicates) | **Implemented as composable functions** (`unexpected_parent`, `suspicious_port`, `new_entries`) called from ordinary `if` statements — **not** the `rule NAME { when ... }` custom grammar shown in the spec. That richer event-driven rule syntax is real additional grammar/semantics work and is Phase-2 roadmap, not built here. Every predicate in this prototype is a plain, auditable function call, which was the pragmatic trade-off made to avoid a second, parallel execution path alongside the interpreter. |
| `test.*` (Security Testing Laboratory) | **Implemented**, operating only on synthetic, non-executable placeholder text files — never real or simulated malicious payloads. Live-tested: generated 10 variants, 100% detection rate on the unmutated marker string. |
| `report.*` (create/add/sign/cosign/save/save_encrypted) | **Implemented** as namespace wrappers around the existing signed-report engine (HMAC signing, dual-control co-signing, AES/Fernet encrypted export — all from the prior revision, unchanged). Supports JSON and HTML; CSV/PDF export are not yet implemented. |

### Security properties — unchanged and re-verified after every addition above
- Evidence and analyzed files are read-only in every code path; no function
  in any new module writes to, deletes, or modifies anything it inspects.
- RBAC (`TIER1_TRIAGE` / `TIER2_ANALYST` / `LEAD_INVESTIGATOR` / `ADMIN`) is
  enforced identically for namespace methods and flat built-ins — verified
  live (`report.sign()` correctly rejected under `TIER1_TRIAGE`).
- Every namespace call is written to the hash-chained audit log automatically.
- **New hardening in this revision:** a script can no longer accidentally
  shadow a built-in namespace with a same-named variable (e.g.
  `report := 5;`) — this is rejected with a clear error instead of silently
  breaking every later `report.*` call in the script. This was found and
  fixed via testing, not merely designed on paper: an earlier draft of the
  demo script below hit exactly this bug before the guard was added.
- Full regression: all 11 automated unit tests plus all 7 example scripts
  (original forensic investigation, advanced-features demo, operators demo,
  general-purpose demo, and the new live-triage demo) still pass together.

## What is explicitly NOT built (and why), by specification section

| Spec section | Status | Why |
|---|---|---|
| §2 Compiler with LLVM backend, native code generation | **Not built.** The interpreter remains a Python-hosted tree-walker. | A real LLVM-backed native compiler (lexer→AST→IR→optimization→machine code for two OSes) is itself a multi-month project even for an experienced compiler team, and cannot be honestly delivered as a byproduct of a single development session without becoming a non-functional stub pretending to be real. The IR/codegen *architecture* is documented; the actual native-codegen work is Phase-2/3 roadmap. |
| §4 Cross-platform Windows support | **Linux only, tested.** Windows API call sites are named and stubbed in the code (see `sysinfo.py` docstrings) but not implemented or tested, since no Windows host is available in this environment. | Honest scoping: claiming Windows support without a Windows machine to test against would be an unverified claim. |
| §9 Malware Research Module — "known test samples," "suspicious files," "behavioral observations" | **Static-analysis-on-synthetic-content only.** No real or simulated malicious binary is created, stored, or executed anywhere in this codebase. | Matches the spec's own §17 safety boundary. `analyze.file()` works on *any* file a user legitimately points it at (including real evidence, under RBAC), but this prototype's own test fixtures are exclusively synthetic placeholder text. |
| §7 Rule-engine DSL (`rule NAME { when ... } alert(...)`) | **Not built as new grammar.** Implemented instead as plain composable predicate functions (`detection.*`) called from `if` statements. | A second declarative rule-evaluation grammar running alongside the interpreter is real additional design work (event model, `when`-clause semantics, `alert()` side effects) that would roughly double the language's grammar surface — deferred rather than rushed. |
| §10 CI/CD pipeline automation | **Not built.** | Requires an actual CI runner/environment to integrate with; there is no concrete system to wire this prototype into from within this sandbox. |
| §11 Central web dashboard + multi-machine agent fleet | **Not built.** | This prototype runs in a single sandboxed Linux container with no ability to reach or deploy onto real remote Windows/Linux machines. Building a dashboard that only ever talks to itself would demonstrate nothing real; the architecture (secure API, per-client registration, central DB, report engine) is documented in the original project proposal's system-architecture section instead of faked here. |
| CSV / PDF report export | **Not built.** JSON and HTML are implemented and tested. | Straightforward follow-on work, simply not yet done. |

## Honest summary

This revision delivers a real, tested Phase-1-plus-partial-Phase-3 slice: the
language itself now supports the requested namespaced syntax end-to-end, and
five of the seven requested standard-library module families (system,
process/service/user/startup/eventlog, file, network, malware-research
static-analysis, security-testing-lab) are implemented and verified against
this actual machine — not mocked. The remaining scope (native LLVM
compilation, Windows runtime, the rule DSL, CI/CD integration, and the
multi-machine dashboard) is real, substantial engineering work that has been
left as clearly-labeled roadmap rather than represented as done.

---

# Revision 2 — Forensic Subsystem Extension (Preserve-First)

This revision was scoped to a specific instruction: preserve all existing
FLANG functionality exactly as-is, and add a forensic subsystem additively.
Everything below follows the same "state only what's actually built and
tested" rule as the section above.

## Process followed

1. Ran the existing test suite before any change: **11/11 passing baseline.**
2. Inspected the existing architecture (lexer → parser → AST → interpreter →
   `runtime/` evidence/audit/security/report engines → `runtime/modules/`
   analysis modules → namespace registration in `interpreter.py`) to find the
   correct extension points rather than guessing.
3. Made additive changes only — new files, new dict entries, new function
   parameters with defaults — never editing the behavior of an existing
   function.
4. Ran the full test suite and every existing example script after each
   batch of changes.
5. Found two real regressions through this process (below) and fixed both
   before considering any of this "done."

## Architecture changes

None. The pipeline (Lexer → Parser → AST → Interpreter → Runtime) is
unchanged in shape. All additions are new modules under
`flang/runtime/modules/`, new namespace registrations inside
`Interpreter._register_namespaces`, and new functions appended to two
existing files. No existing class, function signature, keyword, or grammar
rule was altered or removed.

## Files added

| File | Purpose |
|---|---|
| `flang/runtime/modules/timeline_ops.py` | `flatten`, `sort_by_time`, `filter_events`, `search`, `group_by`, `export_timeline` — operate on the `Timeline` shape `correlate()` already produced |
| `flang/runtime/modules/case.py` | Local, file-backed case registry: `create_case`, `open_case`, `add_evidence`, `list_evidence`, `add_note`, `close_case`, `list_cases` |
| `flang/runtime/modules/evidence_module.py` | Standalone SHA-256+SHA-512 evidence manifests with investigator/timestamp/evidence-ID, independent of the `EvidenceHandle` system |
| `flang/runtime/modules/simlab.py` | Synthetic process/file/network/DNS/auth/log event generators for exercising the timeline/correlation engines without real data |

## Files modified (additive only)

| File | What changed |
|---|---|
| `flang/runtime/evidence.py` | Added `sha512_file`; `sha256_file`/`sha256_dir_manifest` untouched |
| `flang/runtime/security.py` | Added `ROLE_ALIASES` dict + normalization in `SecurityContext.__init__`; the four canonical role names and `ROLE_RANK` are unchanged, and every existing caller that passes a canonical name behaves identically |
| `flang/runtime/modules/correlate.py` | Added `link`, `find_related`, `build_relationship_graph`; existing `correlate()` and `_finish_cluster()` unchanged |
| `flang/runtime/modules/sysinfo.py` | One-line fix to avoid a Python deprecation warning in `system_info()` (introduced by me, then fixed in the same revision) |
| `flang/interpreter.py` | Registered 9 new namespaces; extended `network` namespace with 3 additive keys (`pcap_flows`, `pcap_dns`, `pcap_flag_suspicious`) and `hash` namespace with 1 additive key (`sha512`); added a `filesystem` namespace as dotted access to already-existing flat functions |
| `flang/cli.py` | Extended `--role` choices list; original four choices still present and still the documented default form |
| `tests/test_flang.py` | Appended 13 new tests after the existing 11 (see below); no existing test changed |
| `examples/sample_investigation.flang` | **One required fix** — see "Compatibility issue found and fixed" below |

## New language features

None at the grammar level. All new capability is standard-library surface
(new namespace objects), which the existing `MemberCall` grammar (added in a
prior revision) already supported — no lexer, parser, or AST change was
needed for any of this.

## New forensic APIs (namespace.method — dotted syntax, matching existing convention)

| Namespace | Methods | Status |
|---|---|---|
| `timeline` | `flatten`, `sort`, `filter`, `search`, `group_by`, `export` (json/csv) | Implemented, tested |
| `case` | `create`, `open`, `add_evidence`, `list_evidence`, `add_note`, `close`, `list_cases` | Implemented, tested (local file-backed only — see limitations) |
| `evidence` | `manifest` (SHA-256+SHA-512+ID+investigator+timestamp), `verify` | Implemented, tested |
| `correlation` | `correlate` (dotted access to existing engine), `link`, `find_related`, `build_graph` | Implemented, tested |
| `audit` | `verify`, `export`, `summary` | Implemented, tested — reads the interpreter's own already-existing hash-chained log; does not change how logging happens |
| `security` | `whoami`, `verify_hash` | Implemented, tested |
| `forensics` | `acquire_and_hash`, `quick_triage` | Implemented, tested — small composite helpers, not a monolithic catch-all |
| `simulation` | `process_event`, `file_event`, `network_event`, `dns_event`, `auth_event`, `log_event`, `scenario` | Implemented, tested — every record marked `synthetic: true` |
| `filesystem` | `list_files`, `carve_deleted`, `get_metadata`, `flag_suspicious` | Dotted alias to already-existing, already-tested flat functions |
| `reporting` | Same methods as `report` | Same underlying object as `report` (verified via test that both names mutate the same instance) |
| `hash.sha512`, `network.pcap_flows/pcap_dns/pcap_flag_suspicious` | — | Additive keys on existing namespaces |

## Security model

Unchanged in structure, extended in coverage:
- RBAC: same 4-rank hierarchy; 5 new role-name aliases map onto it, verified
  by test to produce identical `.role` values to using the canonical name.
- Audit logging: still automatic and non-optional for every built-in and
  namespace-method call, including every new one added this revision — no
  new "quiet mode" was introduced anywhere.
- Evidence integrity: SHA-512 sits alongside SHA-256, does not replace it;
  `evidence.manifest()` is intentionally a separate, simpler mechanism from
  `EvidenceHandle`, not a modification of it.
- Namespace-shadowing guard (from the prior revision) automatically covers
  every new namespace name, verified by a new test.

## Windows support

Not extended. Still Linux-only and tested-on-Linux-only, as stated in the
prior revision's roadmap. `case`, `evidence`, `timeline`, `correlation`,
`audit`, `security`, `forensics`, and `simulation` are all pure-Python and
platform-independent in principle, but have only been run and verified on
Linux in this environment.

## Ubuntu/Linux support

All new namespaces tested and working on the actual Linux machine running
this session (real process list, real file hashing, real case files written
to disk).

## Tests added

13 new tests appended to `tests/test_flang.py` (file went from 11 tests to
24, all passing): role-alias mapping, SHA-512 correctness against Python's
own `hashlib`, `hash.sha512()`, the `reporting`/`report` alias identity,
timeline sort/group operations, correlation link/graph building, a full
case-management round trip (in an isolated temp directory), evidence
manifest shape, synthetic-event marking, audit summary contents, security
`whoami()`, the namespace-shadowing guard, and a regression guard proving
the *prior* revision's `system`/`process` namespaces still behave identically
after this revision's changes.

## Backward-compatibility results

- **11/11 pre-existing tests**: still passing, unchanged.
- **8/8 example scripts** (including all from the prior revision): all pass
  after one required fix.
- **Compatibility issue found and fixed**: `sample_investigation.flang` used
  a variable named `timeline`, which collided with the newly-added `timeline`
  namespace. This is a genuine, non-hypothetical instance of the general risk
  that adding a new global namespace name can conflict with a pre-existing
  script's own variable name of the same word. I did not hide this — I found
  it via full regression testing, fixed the one affected line (variable
  renamed to `case_timeline`, behavior otherwise identical), and it is
  recorded here rather than glossed over.
- **Second bug found and fixed**: `timeline.export()`'s Python parameter was
  named `fmt` while every other export function in the language uses
  `format` as the keyword name — caught by the new demo script failing,
  fixed for consistency, re-verified.

## Known limitations

- `case` module is local and file-backed (one JSON file per case under
  `cases/`), not a centralized multi-user database — no locking, no
  concurrent-writer safety, no network access. This is the correct
  boundary for what "centralized investigation management" would require;
  building that is unstarted, separate work.
- `evidence.manifest()` does not integrate with `EvidenceHandle`'s read-only
  enforcement — it operates on a plain file path. It is meant for the common
  "hash this one file for the record" case, not as a replacement for
  `load_disk_image()` and friends.
- FLANG still has **no list-indexing syntax** (`events[0]` does not parse) —
  discovered while writing this revision's demo script and worked around by
  generating fresh values instead of indexing. This is a real, currently
  unaddressed gap in the core language grammar, not specific to the forensic
  subsystem.
- Adding new namespace names remains a soft compatibility risk for any
  script that already used that identifier as a variable name (see above).
  The shadowing guard turns this into a clear, immediate error rather than
  silent breakage, but it cannot make the rename unnecessary.
- `registry` (Windows) module: not implemented; no Windows host available to
  build or test against honestly.
- The richer `rule NAME { when ... }` grammar, FLANG Studio/Learn/
  Practice/Build IDE, centralized multi-host dashboard, and CI/CD pipeline
  integration remain entirely unbuilt, as stated in Revision 1's roadmap
  above — nothing in this revision changes that status.

## Recommended next development steps

1. Add list-indexing syntax (`list[i]`) to the core grammar — the most
   impactful small language gap found during this revision's own testing.
2. Decide on a namespace-collision mitigation strategy before adding further
   namespaces (e.g. requiring an explicit `import` to bind a namespace name
   into scope, rather than binding all namespaces globally by default) —
   documented here as a design question, not resolved.
3. If centralized case management is actually needed (multiple
   investigators, concurrent access), that is new infrastructure work
   (a small server + client), not an extension of the current file-backed
   `case` module.
4. Extend `case`/`evidence` test coverage to concurrent-access scenarios
   once/if that becomes a real requirement.
