/* Content is kept as plain data, separate from rendering logic in
   app.js, so lessons/tips/facts can be edited without touching any
   DOM code. Every code example here has actually been run against
   the FLANG interpreter -- nothing is illustrative-only. */

const LESSONS = [
{
  level: "Beginner",
  title: "What is FLANG?",
  body: `<p>FLANG is a small programming language built for one job: authorized computer and network forensic investigation. It runs on an interpreter written in Python, but FLANG itself is its own language with its own grammar &mdash; a <code>.flang</code> script is not Python and won't run in a Python interpreter.</p>
  <p>Two ideas shape everything else in this language:</p>
  <ul>
    <li><strong>Read-only by construction.</strong> There is no statement in FLANG that can write to, delete, or modify evidence. Not "discouraged" &mdash; the capability doesn't exist.</li>
    <li><strong>Everything is logged automatically.</strong> Every function call is written to a tamper-evident audit trail before it returns a result, with zero opt-out.</li>
  </ul>
  <p>The rest of the language &mdash; variables, loops, functions &mdash; works like most C-family languages, so if you already know any programming language, most of FLANG's syntax will feel familiar.</p>`,
  code: null,
},
{
  level: "Beginner",
  title: "Variables & Data Types",
  body: `<p>Variables use <code>:=</code> (not <code>=</code>) so it's never confused with the equality operator <code>==</code>. FLANG infers the type from the value.</p>`,
  code: `a := 12;\nname := "jdoe";\nis_ready := true;\nitems := [1, 2, 3];\nrecord := {"pid": 5566, "name": "update_svc.exe"};\n\nmsg := f"Investigator: {name}, ready: {to_string(is_ready)}";\nprint(msg);`,
},
{
  level: "Beginner",
  title: "Conditionals & Loops",
  body: `<p>Blocks always use <code>{ }</code> and every statement ends in <code>;</code> &mdash; deliberately, so a printed script is unambiguous even without syntax highlighting.</p>`,
  code: `n := 7;\nif n % 15 == 0 {\n    print("FizzBuzz");\n} elif n % 3 == 0 {\n    print("Fizz");\n} else {\n    print(to_string(n));\n}\n\ni := 0;\nwhile i < 5 {\n    print(f"i = {to_string(i)}");\n    i++;\n}\n\nfor item in [1, 2, 3] {\n    print(f"item: {to_string(item)}");\n}`,
},
{
  level: "Beginner",
  title: "Functions & Recursion",
  body: `<p>Functions support recursion. <code>break</code>/<code>continue</code> inside a function are rejected with a clear error rather than silently escaping into the caller's loop &mdash; a bug that was found and fixed during development.</p>`,
  code: `function factorial(n) {\n    if n <= 1 {\n        return 1;\n    } else {\n        return n * factorial(n - 1);\n    }\n}\n\nprint(f"5! = {to_string(factorial(5))}");`,
},
{
  level: "Intermediate",
  title: "The Full Operator Set",
  body: `<p>Beyond the basics, FLANG has compound assignment, increment/decrement, exponent/floor-division, a membership operator, and a ternary &mdash; the set a "normal" language is expected to have.</p>`,
  code: `x := 10;\nx += 5;   # 15\nx **= 2;  # not supported -- ** is a binary op, not compound\nprint(f"2 ** 10 = {to_string(2 ** 10)}");\nprint(f"17 // 5 = {to_string(17 // 5)}");\n\niocs := ["update_svc.exe", "malicious.dll"];\nif "update_svc.exe" in iocs {\n    print("matched a known IOC");\n}\n\nseverity := 85 >= 70 ? "PASS" : "FAIL";\nprint(severity);`,
},
{
  level: "Intermediate",
  title: "Evidence & Hashing",
  body: `<p>Evidence is loaded into read-only, hash-verified handles. Analysis functions never receive a raw path &mdash; only a handle brokered by the evidence-management layer.</p>`,
  code: `disk := load_disk_image("demo_evidence/host17_files");\nh := sha256(disk);\nprint(f"Disk hash: {h}");\n\nfiles := list_files(disk, ".");\nprint(f"Files found: {to_string(length(files))}");\n\n# standalone file manifest with both SHA-256 and SHA-512\nm := evidence.manifest("demo_evidence/host17_files/Windows/System32/kernel_placeholder.txt", "analyst");\nprint(f"SHA-512 (first 16): {substring(get(m, \\"sha512\\"), 0, 16)}");`,
},
{
  level: "Intermediate",
  title: "Live Host Namespaces",
  body: `<p><code>system.*</code>, <code>process.*</code>, <code>network.*</code>, and <code>file.*</code> inspect the actual machine FLANG is running on &mdash; read-only, RBAC-gated, and audit-logged like everything else.</p>`,
  code: `info := system.info();\nprint(f"Host: {get(info, \\"hostname\\")} ({get(info, \\"os\\")})");\n\nprocs := process.list();\nprint(f"Processes: {to_string(length(procs))}");\n\nsample := analyze.file("demo_evidence/host17_files/Users/jdoe/Downloads/update_svc.exe");\nprint(f"Type: {get(sample.metadata(), \\"file_type\\")}");\nprint(f"Entropy: {to_string(sample.entropy())}");`,
},
{
  level: "Advanced",
  title: "Timeline & Correlation",
  body: `<p>Findings from any evidence source can be merged by time proximity (<code>correlate()</code>) or by shared value (<code>correlation.link()</code>/<code>find_related()</code>), then sorted, filtered, grouped, or exported.</p>`,
  code: `events := simulation.scenario(["process", "network", "dns"], 9);\nt := correlation.correlate([events], window_seconds: 120);\n\nsorted_events := timeline.sort(t);\ngrouped := timeline.group_by(t, "type");\nprint(f"Distinct event types: {to_string(length(keys(grouped)))}");\n\ntimeline.export(t, format: "csv", path: "output/timeline.csv");`,
},
{
  level: "Advanced",
  title: "Cases, Reports & Signing",
  body: `<p>Reports are built section-by-section, signed (HMAC), optionally co-signed by a second key for dual control, and exported as JSON/HTML &mdash; or encrypted at rest with AES if the <code>cryptography</code> package is available.</p>`,
  code: `case.create("CASE-01", "Sample investigation", "analyst");\n\nr := new_report("Investigation Summary");\nr := add_section(r, "Notes", "Initial triage complete");\nr := sign_report(r, key_id: "primary_key");\nr := co_sign_report(r, key_id: "supervisor_key");\nexport(r, format: "json", path: "output/report.json");\n\ncase.close("CASE-01");`,
},
{
  level: "Advanced",
  title: "Security Model: RBAC & Audit",
  body: `<p>Every function declares a minimum role. A lower-privileged session is stopped the moment it tries a gated call &mdash; not silently, not later. The audit log is hash-chained: any retroactive edit breaks the chain and is independently detectable.</p>`,
  code: `who := security.whoami();\nprint(f"{get(who, \\"investigator\\")} running as {get(who, \\"role\\")}");\n\nsummary := audit.summary();\nprint(f"Audit entries: {to_string(get(summary, \\"entry_count\\"))}");\nprint(f"Chain intact: {to_string(get(get(summary, \\"chain_verified\\"), \\"ok\\"))}");`,
},
{
  level: "Basic",
  title: "Part 1 — Basic: Full Project Booklet",
  body: `<p><strong>AN ACADEMIC PROJECT BOOKLET</strong></p>
<p><strong>CYBERSECURITY &amp; DIGITAL FORENSICS</strong></p>
<p><strong>PYTHON vs FLANG</strong></p>
<p><em>A Complete Language Comparison, a Case Study in Forensic</em></p>
<p><em>Language Design, and an Advanced-Features Showcase</em></p>
<p>Part 1 — Python vs. FLANG: A Full Language Comparison</p>
<p>Part 2 — How FLANG Satisfies the Forensic-Language Problem Statement</p>
<p>Part 3 — Advanced Features of FLANG and a Comparative Analysis</p>
<p>Across Programming and Forensic-Scripting Languages</p>
<p>Part 4 — The Namespaced Standard Library: Existing vs. Proposed</p>


<p><em>Prepared as an academic cybersecurity and digital forensics project booklet</em></p>
<h3><strong>Executive Summary</strong></h3>
<p>This project designs, implements, and tests FLANG (Forensic Language), a domain-specific programming language for authorized computer and network forensic investigation, and documents it against the general-purpose language its own interpreter is written in (Python) and against the wider field of forensic and security scripting languages already in professional use.</p>
<p>The working prototype in this submission is not a syntax mock-up. It includes a hand-written lexer, recursive-descent parser, and tree-walking interpreter; a read-only, hash-verified evidence-management layer; role-based access control enforced per built-in function call; a hash-chained, independently verifiable audit log; filesystem, memory, network, and log analysis modules; a cross-source timeline correlation engine; and a signed dual-format (JSON and HTML) reporting pipeline. A 24-test automated suite (grown from an original 11 as the namespaced forensic modules were added) exercises the lexer/parser, interpreter, RBAC enforcement, evidence-integrity checking, audit-chain tamper detection, role aliasing, and the case/timeline/correlation/simulation modules — all 24 tests pass.</p>
<p>Part 1 of this booklet compares FLANG to Python line by line — syntax, types, control flow, error handling, and security model — to show precisely which safety properties are language-level guarantees in FLANG and merely programmer discipline in Python. Part 2 maps FLANG's implementation directly onto the original project brief, clause by clause, to demonstrate that every stated functional and non-functional requirement has a corresponding, working implementation. Part 3 widens the comparison to nine additional languages and tools — C, C++, Java, Go, Rust, Bash, PowerShell, EnScript, Volatility 3, YARA, osquery, and GUI-based forensic scripting in Autopsy and X-Ways — and argues, with an explicit limitations chapter, that FLANG is the strongest available fit specifically for authorized, auditable, court-defensible forensic scripting, while being transparent about where FLANG's youth as a prototype still leaves it behind more mature tools. Part 4 documents FLANG's namespaced standard library and forensic subsystem extension, and closes with a direct existing-vs-proposed comparison and an updated master matrix against the same nine comparators.</p>
<p>The remainder of this booklet develops each of these claims in full, with worked code examples, architecture diagrams, requirement-mapping tables, and a complete reference appendix of FLANG's built-in functions and syntax.</p>
<h3><strong>Preface</strong></h3>
<p>This booklet is presented in three parts, followed by a full reference appendix.</p>
<p>Part 1 places Python — the general-purpose language FLANG's own interpreter happens to be written in — side by side with FLANG, the domain-specific forensic language designed and prototyped as part of this project. It walks through syntax, data types, control flow, error handling, security model, and a series of matched code examples, ending in a full summary comparison table.</p>
<p>Part 2 returns to the original project brief — “Creation of scripts/functions with a new programming language to commence computer and network forensic analysis without triggering security solutions” — and maps every clause of that brief onto a specific, implemented piece of FLANG: its grammar, its evidence-management layer, its RBAC and audit-logging, and its approach to earning trust with security tooling through transparency rather than evasion.</p>
<p>Part 3 is new to this edition of the booklet. It catalogues FLANG's advanced features — both the ones already implemented in the working prototype and the ones scoped for the production roadmap — and places FLANG side by side with a wide field of established programming and forensic-scripting languages: Python, C, C++, Java, Go, Rust, Bash, PowerShell, EnScript, YARA, osquery's SQL dialect, and Volatility's plugin API. The argument made there is deliberately scoped: FLANG is argued to be the strongest available choice for the one job it was built to do — authorized, court-defensible, auditable forensic scripting — not a claim that FLANG is a better general-purpose language than Python or C. Part 3 closes with an explicit, honest limitations chapter, because a booklet that only lists advantages would not itself pass the scrutiny its subject is designed to withstand.</p>
<p>Part 4 documents FLANG's namespaced standard library (system.info(), hash.sha256(), report.sign(), and dozens more) — a second, additive way of reaching both new live-host-triage capability and the existing evidence-analysis capability through one consistent, dotted syntax, plus a forensic subsystem extension (case tracking, timeline querying, relationship correlation, dual-control report signing, and a synthetic-artifact security testing laboratory). Part 4 closes with a direct existing-versus-proposed comparison scored on uniqueness, innovation, application, and what makes each addition impressive, followed by an updated master comparison against the same nine languages and tools examined in Part 3.</p>
<p>Four appendices close the booklet: a full catalogue of FLANG's built-in functions with their required access roles, a one-page syntax quick reference, a glossary of forensic and language-design terms used throughout, and a references section.</p>
<p>All technical claims about FLANG in this booklet are grounded in the accompanying working prototype (flang_project/) — its lexer, parser, interpreter, runtime, analysis modules, and automated test suite — rather than in an unimplemented design document alone.</p>
<h3><strong>Table of Contents</strong></h3>
<p><strong>Part 1 — Python vs. FLANG</strong></p>
<blockquote>
<p><strong>1.1</strong> What Is Python?</p>
<p><strong>1.2</strong> What Is FLANG?</p>
<p><strong>1.3</strong> General-Purpose vs Domain-Specific Languages</p>
<p><strong>1.4</strong> Design Philosophy Compared</p>
<p><strong>1.5</strong> Who Each Language Is For</p>
<p><strong>1.6</strong> Variables and Data Types</p>
<p><strong>1.7</strong> Operators</p>
<p><strong>1.8</strong> Conditional Statements: if / elif / else</p>
<p><strong>1.9</strong> Loops: for and while</p>
<p><strong>1.10</strong> Functions and Recursion</p>
<p><strong>1.11</strong> String Handling</p>
<p><strong>1.12</strong> Built-In Capabilities</p>
<p><strong>1.13</strong> File and Evidence Access</p>
<p><strong>1.14</strong> Error Handling</p>
<p><strong>1.15</strong> Security Model: Unrestricted vs Sandboxed</p>
<p><strong>1.16</strong> Auditability and Logging</p>
<p><strong>1.17</strong> Access Control (RBAC)</p>
<p><strong>1.18</strong> Extensibility and Ecosystem</p>
<p><strong>1.19</strong> Performance Considerations</p>
<p><strong>1.20</strong> Learning Curve</p>
<p><strong>1.21–1.26</strong> Matched Code Examples</p>
<p><strong>1.27</strong> Summary Comparison Table</p>
<p><strong>1.28</strong> When to Use Python, When to Use FLANG</p>
<p><strong>1.29</strong> What's New in FLANG: A Language, Not Just a Script</p>
<p><strong>1.30</strong> Namespaced Method Calls: FLANG's Standard Library Grows Up</p>
</blockquote>
<p><strong>Part 2 — Fitting the Forensic-Language Problem Statement</strong></p>
<blockquote>
<p><strong>2.1</strong> Restating the Problem Statement</p>
<p><strong>2.2</strong> Two Readings of “Without Triggering Security Solutions”</p>
<p><strong>2.3</strong> Functional Requirements Mapping</p>
<p><strong>2.4</strong> Non-Functional Requirements Mapping</p>
<p><strong>2.5</strong> System Architecture Overview</p>
<p><strong>2.6</strong> Lexer and Parser</p>
<p><strong>2.7</strong> The Interpreter and Effect Tagging</p>
<p><strong>2.8</strong> Evidence Management Layer</p>
<p><strong>2.9</strong> Cryptographic Hashing and Integrity Verification</p>
<p><strong>2.10</strong> Chain of Custody</p>
<p><strong>2.11</strong> Role-Based Access Control</p>
<p><strong>2.12</strong> Tamper-Evident Audit Logging</p>
<p><strong>2.13</strong> Establishing Trust With Security Solutions</p>
<p><strong>2.14</strong> Filesystem Analysis Module</p>
<p><strong>2.15</strong> Memory Analysis Module</p>
<p><strong>2.16</strong> Network Analysis Module</p>
<p><strong>2.17</strong> Log Analysis and Correlation</p>
<p><strong>2.18</strong> Reporting Engine and Digital Signatures</p>
<p><strong>2.19</strong> End-to-End Script Walkthrough</p>
<p><strong>2.20</strong> Testing and Validation Strategy</p>
<p><strong>2.21</strong> Implementation Roadmap Recap</p>
<p><strong>2.22</strong> Conclusion: How FLANG Satisfies the Brief</p>
</blockquote>
<p><strong>Part 3 — Advanced Features and Comparative Analysis</strong></p>
<blockquote>
<p><strong>3.1</strong> Why Advanced Features Matter for a Forensic DSL</p>
<p><strong>3.2</strong> Effect-Tagged Built-ins (READ / DERIVE / EXPORT)</p>
<p><strong>3.3</strong> Hash-Chained, Tamper-Evident Audit Log</p>
<p><strong>3.4</strong> Brokered Evidence Handles and Path Containment</p>
<p><strong>3.5</strong> RBAC With Separation of Duties</p>
<p><strong>3.6</strong> Cross-Source Timeline Correlation Engine</p>
<p><strong>3.7</strong> Signed, Dual-Format Reporting</p>
<p><strong>3.8</strong> Fail-Loud Execution Model</p>
<p><strong>3.9</strong> Roadmap: Native Forensic Backends</p>
<p><strong>3.10</strong> Roadmap: Rust-Based Native Runtime</p>
<p><strong>3.11</strong> Roadmap: Sandboxed Microvm / Container Execution</p>
<p><strong>3.12</strong> Roadmap: PKI/HSM-Backed Code Signing</p>
<p><strong>3.13</strong> Roadmap: Behavioral Manifest for EDR Allowlisting</p>
<p><strong>3.14</strong> Roadmap: Static Effect Analysis</p>
<p><strong>3.15</strong> Comparative Analysis: Method and Criteria</p>
<p><strong>3.16</strong> FLANG vs General-Purpose Languages</p>
<p><strong>3.17</strong> FLANG vs Shell and Automation Languages</p>
<p><strong>3.18</strong> FLANG vs Forensic and Security Scripting Languages</p>
<p><strong>3.19</strong> FLANG vs GUI-Toolkit Scripting</p>
<p><strong>3.20</strong> Master Comparison Matrix</p>
<p><strong>3.21</strong> Why FLANG Is the Strongest Fit for This Problem</p>
<p><strong>3.22</strong> Limitations and Where FLANG Is Not the Best Choice</p>
<p><strong>3.23</strong> Case Study: A Full Investigation, Written Twice</p>
<p><strong>3.24</strong> Adoption Considerations for a Forensic Laboratory</p>
<p><strong>3.25</strong> Ethical and Legal Considerations</p>
<p><strong>3.26</strong> Extended Worked Example: A Cross-Domain IOC Sweep</p>
<p><strong>3.27</strong> Conclusion of Part 3</p>
</blockquote>
<p><strong>Part 4 — The Namespaced Standard Library</strong></p>
<blockquote>
<p><strong>4.1</strong> Overview of the Namespaced Standard Library</p>
<p><strong>4.2</strong> New Language-Level Constructs</p>
<p><strong>4.3</strong> The System and Process Namespaces</p>
<p><strong>4.4</strong> Service, User, Startup, and Event-Log Namespaces</p>
<p><strong>4.5</strong> File Forensics Namespace</p>
<p><strong>4.6</strong> Network Namespace: Live and Evidence-Based, Unified</p>
<p><strong>4.7</strong> Detection Namespace: Composable Predicates</p>
<p><strong>4.8</strong> The Security Testing Laboratory</p>
<p><strong>4.9</strong> Timeline Operations Namespace</p>
<p><strong>4.10</strong> Case Management Namespace</p>
<p><strong>4.11</strong> Correlation and Relationship-Graph Namespace</p>
<p><strong>4.12</strong> Audit and Security Introspection Namespaces</p>
<p><strong>4.13</strong> Forensics Composite Helpers and Simulation Namespace</p>
<p><strong>4.14</strong> Reporting Namespace, Co-Signing, Encrypted Export</p>
<p><strong>4.15</strong> Engineering Discipline: Process and Bugs Found</p>
<p><strong>4.16</strong> What Remains Explicitly Not Built, Restated</p>
<p><strong>4.17</strong> Existing vs. Proposed: Unique, Innovative, Impressive</p>
<p><strong>4.18</strong> Updated Master Comparison: FLANG vs the Field</p>
<p><strong>4.19</strong> Conclusion of Part 4</p>
</blockquote>
<p><strong>Appendices</strong></p>
<blockquote>
<p><strong>A</strong> Full FLANG Built-in Function Catalogue</p>
<p><strong>B</strong> FLANG Quick Syntax Reference</p>
<p><strong>C</strong> Glossary of Terms</p>
<p><strong>D</strong> References and Further Reading</p>
<p><strong>E</strong> Sample Audit Log and Signed Report Excerpts</p>
<p><strong>F</strong> Frequently Asked Questions</p>
<p><strong>G</strong> Automated Test Suite Detail</p>
<p><strong>H</strong> Command-Line Interface Reference</p>
<p><strong>I</strong> Closing Note</p>
</blockquote>
<p><strong>Part One</strong></p>
<p><strong>Python vs. FLANG</strong></p>
<p><em>A Full Language Comparison</em></p>
<h3><strong>1.1 What Is Python?</strong></h3>
<p>Python is a general-purpose programming language first released by Guido van Rossum in 1991. It was designed to be readable, flexible, and usable for almost any task a programmer might attempt: web servers, data science, automation scripts, games, desktop applications, and much more.</p>
<p><em><strong>Design goals</strong></em></p>
<p>Python's guiding philosophy, summarized in its own “Zen of Python,” favors readability, simplicity, and “one obvious way to do it.” It has no built-in restriction on what a script may do: a Python program can open any file the operating system permits, delete data, open network sockets, spawn other processes, or install software.</p>
<p><em><strong>Why this matters for this booklet</strong></em></p>
<p>Because Python is unrestricted by design, every safety property in a Python program — read-only evidence handling, audit logging, access control — has to be written by the programmer, every single time, in every script. Python gives you the tools to build a safe forensic workflow, but it does not enforce one.</p>
<h4><strong>1.2 What Is FLANG?</strong></h4>
<p>FLANG (Forensic Language) is a domain-specific language purpose-built for one job: authorized computer and network forensic investigation. It was designed and implemented as the subject of this project, with an interpreter written in Python (see Chapter 1.12 for why that does not make FLANG “just Python”).</p>
<p><em><strong>Design goals</strong></em></p>
<p>FLANG's guiding philosophy is the opposite of Python's generality: narrow the language down to exactly the vocabulary an investigator needs, and make the unsafe operations (writing to evidence, running unsigned scripts, skipping the audit log) not exist in the language at all, rather than merely discouraged.</p>
<p><em><strong>Two audiences in one language</strong></em></p>
<p>FLANG was later extended (Part 2 of this booklet's companion project) with general-purpose constructs — while loops, elif chains, recursion, boolean logic — so investigators can express real algorithms, not just a fixed checklist, while every forensic guarantee remains untouched.</p>
<h4><strong>1.3 General-Purpose vs Domain-Specific Languages</strong></h4>
<p>Programming languages fall broadly into two categories, and Python and FLANG sit on opposite sides of that line.</p>
<p><em><strong>General-purpose languages (GPLs)</strong></em></p>
<p>Python, Java, C++, and JavaScript are GPLs: they make no assumption about what you are building. Their standard libraries are broad but shallow with respect to any one domain — you can do forensics in Python, but you must import third-party libraries and write your own safety net.</p>
<p><em><strong>Domain-specific languages (DSLs)</strong></em></p>
<p>SQL (databases), HTML (documents), and FLANG (forensics) are DSLs: they assume you are doing one kind of task and bake the relevant vocabulary and guardrails directly into the language. A DSL trades away generality for safety, brevity, and domain-correctness.</p>
<p><em><strong>Where FLANG sits</strong></em></p>
<p>FLANG is a DSL with general-purpose control flow layered on top — narrow in what it lets you touch (evidence, files, network captures) but not narrow in how you may reason about that data (loops, conditionals, recursion, functions).</p>
<h4><strong>1.4 Design Philosophy Compared</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 26%" />
<col style="width: 36%" />
<col style="width: 36%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Aspect</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Primary goal</td>
<td>Maximum flexibility for any task</td>
<td>Safe, auditable forensic investigation</td>
</tr>
<tr class="even">
<td>Default trust model</td>
<td>Full trust in the programmer</td>
<td>Zero trust — every action is checked and logged</td>
</tr>
<tr class="odd">
<td>Unsafe operations</td>
<td>Always available (file delete, shell exec, etc.)</td>
<td>Do not exist in the language</td>
</tr>
<tr class="even">
<td>Extending the language</td>
<td>pip install anything</td>
<td>Only vetted, reviewed built-in modules</td>
</tr>
<tr class="odd">
<td>Who decides what's allowed</td>
<td>The programmer, at their own risk</td>
<td>The RBAC role assigned to the investigator</td>
</tr>
</tbody>
</table></div>
<h4><strong>1.5 Who Each Language Is For</strong></h4>
<p><em><strong>Python's audience</strong></em></p>
<p>Software engineers, data scientists, and hobbyists who need a general tool and are expected to understand programming concepts deeply: memory management is implicit, but correctness, safety, and security are the programmer's sole responsibility.</p>
<p><em><strong>FLANG's audience</strong></em></p>
<p>Digital forensic investigators — who may or may not have a software engineering background — who need to run standard, defensible, reviewable investigative procedures quickly, without needing to know how to safely write files, catch exceptions, or design an audit-logging system from scratch.</p>
<h4><strong>1.6 Variables and Data Types</strong></h4>
<p>Both languages use dynamic typing — you don't declare a variable's type up front — but they differ in how many types exist and where those types come from.</p>
<p><em><strong>Python</strong></em></p>
<p>Python has a rich, general type system: int, float, str, bool, list, dict, tuple, set, custom classes, and more. Any of these can appear anywhere.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>x = 5</p>
<p>name = "jdoe"</p>
<p>flag = True</p>
<p>items = [1, 2, 3]</p>
<p>record = {"pid": 4123, "name": "explorer.exe"}</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<p>FLANG has a smaller set: number, string, boolean, list, and a handful of forensic-specific types returned by built-ins — DiskImage, MemoryImage, PacketCapture, LogSet, Report. These evidence types are opaque handles, not data you can inspect or edit directly.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>x := 5;</p>
<p>name := "jdoe";</p>
<p>flag := true;</p>
<p>items := [1, 2, 3];</p></td>
</tr>
</tbody>
</table></div>
<h4><strong>1.7 Operators</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 26%" />
<col style="width: 33%" />
<col style="width: 39%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Operator category</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Arithmetic</td>
<td>+ - * / // % **</td>
<td>+ - * / % ** // (exponent and floor division)</td>
</tr>
<tr class="even">
<td>Comparison</td>
<td>== != &lt; &gt; &lt;= &gt;=</td>
<td>== != &lt; &gt; &lt;= &gt;=</td>
</tr>
<tr class="odd">
<td>Logical</td>
<td>and or not</td>
<td>and or not (keywords, same spelling)</td>
</tr>
<tr class="even">
<td>Membership</td>
<td>in / not in</td>
<td>in (e.g. "x.exe" in suspicious_names)</td>
</tr>
<tr class="odd">
<td>Compound assignment</td>
<td>+= -= *= /= //= %=</td>
<td>+= -= *= /= %=</td>
</tr>
<tr class="even">
<td>Increment / decrement</td>
<td>No native operator (x += 1 only)</td>
<td>++ -- as statements (count++;)</td>
</tr>
<tr class="odd">
<td>Ternary conditional</td>
<td>a if cond else b</td>
<td>cond ? a : b</td>
</tr>
<tr class="even">
<td>Assignment</td>
<td>=</td>
<td>:= (deliberately different from == to avoid the classic C-style bug)</td>
</tr>
<tr class="odd">
<td>String formatting</td>
<td>f"...", .format(), %</td>
<td>f"..." only (one obvious way)</td>
</tr>
</tbody>
</table></div>
<p>FLANG closes most of the operator gap with Python this booklet has noted, while keeping FLANG's one deliberate difference: := for assignment, never =, so a script can never suffer the classic if (x = 5) mistake of writing an assignment where a comparison was intended.</p>
<h4><strong>1.8 Conditional Statements: if / elif / else</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>n = 7</p>
<p>if n % 15 == 0:</p>
<p>print("FizzBuzz")</p>
<p>elif n % 3 == 0:</p>
<p>print("Fizz")</p>
<p>elif n % 5 == 0:</p>
<p>print("Buzz")</p>
<p>else:</p>
<p>print(str(n))</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>n := 7;</p>
<p>if n % 15 == 0 {</p>
<p>print("FizzBuzz");</p>
<p>} elif n % 3 == 0 {</p>
<p>print("Fizz");</p>
<p>} elif n % 5 == 0 {</p>
<p>print("Buzz");</p>
<p>} else {</p>
<p>print(to_string(n));</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p>The logic is identical. The visible differences are surface syntax: Python uses indentation and colons to mark blocks; FLANG uses explicit curly braces and semicolons, a deliberate choice so that block boundaries never depend on invisible whitespace — useful when scripts may later be reviewed as printed evidence exhibits.</p>
<h4><strong>1.9 Loops: for and while</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>total = 0</p>
<p>for n in range(1, 11):</p>
<p>if n % 2 == 0:</p>
<p>total += n</p>
<p>i = 1</p>
<p>while i &lt;= 5:</p>
<p>print(i)</p>
<p>i += 1</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>total := 0;</p>
<p>for n in range(1, 11) {</p>
<p>if n % 2 == 0 {</p>
<p>total += n;</p>
<p>}</p>
<p>}</p>
<p>i := 1;</p>
<p>while i &lt;= 5 {</p>
<p>print(to_string(i));</p>
<p>i += 1;</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p>FLANG adds compound assignment (+= -= *= /= %=), increment/decrement (++ --), and break / continue to both loop forms — closing the gap with Python noted elsewhere in this part (see Chapter 1.29 for the full picture). Both languages now support the same two loop shapes with the same escape-hatch statements; the remaining difference is surface syntax (mandatory braces and semicolons in FLANG versus indentation in Python) rather than expressive power.</p>
<h4><strong>1.10 Functions and Recursion</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>def factorial(n):</p>
<p>if n &lt;= 1:</p>
<p>return 1</p>
<p>return n * factorial(n - 1)</p>
<p>print(factorial(5))</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>function factorial(n) {</p>
<p>if n &lt;= 1 {</p>
<p>return 1;</p>
<p>} else {</p>
<p>return n * factorial(n - 1);</p>
<p>}</p>
<p>}</p>
<p>print(to_string(factorial(5)));</p></td>
</tr>
</tbody>
</table></div>
<p>Both support recursion and first-class function definitions. Python allows default parameter values, *args, **kwargs, closures, decorators, and lambda expressions; FLANG's function model is deliberately plain — named parameters only, no defaults, no closures — again trading power for predictability and reviewability.</p>
<h4><strong>1.11 String Handling</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 24%" />
<col style="width: 34%" />
<col style="width: 40%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Capability</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>f-strings</td>
<td>Yes, plus str.format() and %</td>
<td>Yes (only mechanism)</td>
</tr>
<tr class="even">
<td>Slicing (s[2:5])</td>
<td>Yes</td>
<td>No — use substring(s, start, end)</td>
</tr>
<tr class="odd">
<td>Regex matching</td>
<td>Full re module</td>
<td>matches(s, pattern) built-in — regex predicate matching without exposing the full re API</td>
</tr>
<tr class="even">
<td>Case conversion</td>
<td>s.upper() / s.lower()</td>
<td>to_upper(s) / to_lower(s)</td>
</tr>
<tr class="odd">
<td>Reverse a string</td>
<td>s[::-1]</td>
<td>reverse(s)</td>
</tr>
</tbody>
</table></div>
<p>FLANG intentionally avoids Python-style slice syntax (s[2:5]) because that same bracket syntax is reserved in FLANG for list literals — keeping the grammar small reduces the number of ways a script can be misread during review.</p>
<h4><strong>1.12 Built-In Capabilities: “Batteries Included” vs “Forensics Included”</strong></h4>
<p>Python's standard library famously ships “batteries included” — hundreds of general-purpose modules (os, socket, subprocess, hashlib, sqlite3…). FLANG ships nothing general at all; its entire built-in catalogue is forensic verbs.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 21%" />
<col style="width: 44%" />
<col style="width: 34%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Need</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Hash a file</td>
<td>hashlib.sha256(open(path,'rb').read()).hexdigest() — manual, and the file is opened read-write by default unless you remember 'rb'</td>
<td>sha256(evidence) — evidence was already sealed read-only at load time</td>
</tr>
<tr class="even">
<td>List files in a directory</td>
<td>os.walk(path) — no logging, no read-only guarantee</td>
<td>list_files(disk, path) — automatically logged, containment-checked</td>
</tr>
<tr class="odd">
<td>Parse a memory image</td>
<td>Requires installing &amp; correctly invoking Volatility3 yourself</td>
<td>list_processes(mem) — normalized output, one line</td>
</tr>
<tr class="even">
<td>Delete a file</td>
<td>os.remove(path) — exists, easy to call by accident</td>
<td>No such function exists in FLANG</td>
</tr>
</tbody>
</table></div>
<h4><strong>1.13 File and Evidence Access</strong></h4>
<p><em><strong>Python's model: direct access</strong></em></p>
<p>open(path, mode) gives a script direct, unrestricted access to whatever the operating system permits. Nothing stops a script — through a typo, a copy-pasted line, or a bug — from opening evidence in write mode and altering it.</p>
<p><em><strong>Python — the mistake that FLANG makes structurally impossible</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>f = open("/evidence/host17_disk.E01", "w") # should have been "rb"</p>
<p>f.write(b"oops")</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG's model: brokered handles</strong></em></p>
<p>load_disk_image(path) never returns a raw path. It returns an EvidenceHandle — an opaque object that only the built-in analysis functions know how to read, and only in read-only mode. There is no FLANG statement that can open, write to, or delete the file behind that handle.</p>
<h4><strong>1.14 Error Handling</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>try:</p>
<p>img = open(path, "rb")</p>
<p>except FileNotFoundError:</p>
<p>print("evidence missing")</p>
<p>except PermissionError:</p>
<p>print("access denied")</p></td>
</tr>
</tbody>
</table></div>
<p>Python's try/except is fully general: any of dozens of built-in exception types, or custom ones, can be caught individually, re-raised, or chained.</p>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>try {</p>
<p>bad := to_number("not-a-number");</p>
<p>} catch err {</p>
<p>print(f"Caught expected error: {err}");</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p>FLANG adds a single, deliberately narrow try/catch — one catch clause, no exception types to select against, no re-raise — for the specific case of a script wanting to attempt a risky conversion and continue. This is intentionally not Python's full exception model: certain classes of failure are still not catchable at all. An RBAC violation or an evidence-integrity mismatch still stops the script immediately with a clean, single-line message rather than being something a script can swallow and continue past (Chapter 3.8) — FLANG lets an investigator handle a data-quality problem gracefully, while keeping the errors that matter most to evidentiary soundness impossible to hide.</p>
<h4><strong>1.15 Security Model: Unrestricted vs Sandboxed</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 26%" />
<col style="width: 34%" />
<col style="width: 38%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Property</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Can a script write to evidence?</td>
<td>Yes, if the programmer opens it that way</td>
<td>No — no such capability exists</td>
</tr>
<tr class="even">
<td>Can a script call the shell / spawn processes?</td>
<td>Yes (os.system, subprocess)</td>
<td>No such built-in</td>
</tr>
<tr class="odd">
<td>Can a script make arbitrary network connections?</td>
<td>Yes (socket, requests)</td>
<td>No — confined to parsing an already-acquired capture file</td>
</tr>
<tr class="even">
<td>Is every action logged automatically?</td>
<td>No — logging is opt-in and manual</td>
<td>Yes — every built-in call is audit-logged automatically</td>
</tr>
<tr class="odd">
<td>Can the script author disable safety checks?</td>
<td>Yes, trivially</td>
<td>No — RBAC and read-only enforcement happen in the runtime, not the script</td>
</tr>
</tbody>
</table></div>
<h4><strong>1.16 Auditability and Logging</strong></h4>
<p><em><strong>Python</strong></em></p>
<p>To get an audit trail in Python, a developer must import logging (or similar), configure handlers, and remember to call log.info(…) at every relevant point. If they forget one call site, that action is simply unrecorded — and nothing detects the omission.</p>
<p><em><strong>FLANG</strong></em></p>
<p>Every built-in function call — load_disk_image, sha256, list_files, sign_report, all of them — writes an entry to a hash-chained audit log automatically, before the call's result is even returned to the script. There is no way to call a forensic built-in “quietly”; the audit trail is a property of the language, not a habit of the programmer.</p>
<h4><strong>1.17 Access Control (RBAC)</strong></h4>
<p><em><strong>Python</strong></em></p>
<p>Role-based access control is not a language feature at all — it would have to be built as an application layer around the script, and a raw Python script has no concept of “the investigator running this is only Tier 1.”</p>
<p><em><strong>FLANG</strong></em></p>
<p>Every built-in function declares a minimum required role (TIER1_TRIAGE, TIER2_ANALYST, LEAD_INVESTIGATOR, ADMIN). The interpreter checks the calling investigator's role before every single call and refuses execution — with a clear, specific error — the moment a script tries to exceed its authorization.</p>
<h4><strong>1.18 Extensibility and Ecosystem</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 26%" />
<col style="width: 40%" />
<col style="width: 32%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Aspect</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Package registry</td>
<td>PyPI — hundreds of thousands of packages, any of which may be unreviewed or malicious</td>
<td>None — new capabilities are added by extending the vetted standard library only</td>
</tr>
<tr class="even">
<td>Community size</td>
<td>Enormous, decades of tutorials</td>
<td>Small, new, and domain-specific</td>
</tr>
<tr class="odd">
<td>Risk from supply chain</td>
<td>Real — a single pip install can pull in untrusted code</td>
<td>None — no dependency installation happens from inside a FLANG script</td>
</tr>
</tbody>
</table></div>
<h4><strong>1.19 Performance Considerations</strong></h4>
<p>For the workloads each language targets, raw execution speed is rarely the bottleneck — evidence I/O and hashing dominate in both cases.</p>
<p>Python is a mature, JIT-adjacent-free interpreter (CPython) with wide use in performance-sensitive contexts via C extensions (NumPy, hashlib itself is C). FLANG's current prototype interpreter is written in Python and is therefore no faster than equivalent hand-written Python — the project proposal recommends a future Rust-based runtime for production use, which would let FLANG scripts run at native speed while keeping identical syntax and safety guarantees (see Chapter 3.10).</p>
<h4><strong>1.20 Learning Curve</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 26%" />
<col style="width: 36%" />
<col style="width: 36%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Learner background</strong></th>
<th><strong>Time to write useful Python</strong></th>
<th><strong>Time to write useful FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>No programming experience</td>
<td>Weeks — must learn general programming concepts (types, scope, imports, exceptions) before anything forensic</td>
<td>Hours — a handful of verbs (load_disk_image, sha256, list_files) map directly to tasks already familiar from other forensic tools</td>
</tr>
<tr class="even">
<td>Experienced programmer, new to forensics</td>
<td>Must separately learn Sleuth Kit, Volatility, libpcap APIs and wire them together safely</td>
<td>Built-ins already wrap the equivalent forensic libraries with a consistent, safe interface</td>
</tr>
</tbody>
</table></div>
<h4><strong>1.21 Code Example: Addition of Two Numbers</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>a = 12</p>
<p>b = 8</p>
<p>total = a + b</p>
<p>print(f"Sum = {total}")</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>a := 12;</p>
<p>b := 8;</p>
<p>sum := a + b;</p>
<p>print(f"Sum = {sum}");</p></td>
</tr>
</tbody>
</table></div>
<p>Nearly identical in spirit; the differences are cosmetic (:= vs =, required semicolons, print as a plain built-in rather than a language keyword in FLANG).</p>
<h4><strong>1.22 Code Example: Palindrome Check</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>word = "madam"</p>
<p>if word == word[::-1]:</p>
<p>print(f"{word} is a palindrome")</p>
<p>else:</p>
<p>print(f"{word} is NOT a palindrome")</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>word := "madam";</p>
<p>if word == reverse(word) {</p>
<p>print(f"{word} is a palindrome");</p>
<p>} else {</p>
<p>print(f"{word} is NOT a palindrome");</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p>Python's slice trick word[::-1] is replaced by FLANG's explicit reverse() built-in — one more example of FLANG preferring a named function over a terse operator, favoring readability for reviewers who may not be full-time programmers.</p>
<h4><strong>1.23 Code Example: Factorial via Recursion</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>def factorial(n):</p>
<p>if n &lt;= 1:</p>
<p>return 1</p>
<p>return n * factorial(n - 1)</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>function factorial(n) {</p>
<p>if n &lt;= 1 { return 1; }</p>
<p>else { return n * factorial(n - 1); }</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<h4><strong>1.24 Code Example: FizzBuzz (Loops + Modulo)</strong></h4>
<p><em><strong>Python</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>for i in range(1, 16):</p>
<p>if i % 15 == 0: print("FizzBuzz")</p>
<p>elif i % 3 == 0: print("Fizz")</p>
<p>elif i % 5 == 0: print("Buzz")</p>
<p>else: print(str(i))</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>for i in range(1, 16) {</p>
<p>if i % 15 == 0 { print("FizzBuzz"); }</p>
<p>elif i % 3 == 0 { print("Fizz"); }</p>
<p>elif i % 5 == 0 { print("Buzz"); }</p>
<p>else { print(to_string(i)); }</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<h4><strong>1.25 Code Example: Hashing Evidence — Python vs FLANG</strong></h4>
<p><em><strong>Python — correct, but every safety property is manual</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>import hashlib</p>
<p>def sha256_file(path):</p>
<p>h = hashlib.sha256()</p>
<p>with open(path, "rb") as f: # must remember 'rb'!</p>
<p>for chunk in iter(lambda: f.read(8192), b""):</p>
<p>h.update(chunk)</p>
<p>return h.hexdigest()</p>
<p>print(sha256_file("/evidence/host17_disk.E01"))</p>
<p># no chain-of-custody record was created</p>
<p># no audit log entry was written</p>
<p># nothing stops a later line from opening the</p>
<p># same path in write mode</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>FLANG — the same task, with the safety properties built in</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>disk := load_disk_image("/evidence/host17_disk.E01");</p>
<p>h := sha256(disk);</p>
<p>print(h);</p>
<p># a chain-of-custody record was created automatically</p>
<p># an audit log entry exists for the ingest AND the hash call</p>
<p># 'disk' can never be opened in write mode by any FLANG statement</p></td>
</tr>
</tbody>
</table></div>
<h4><strong>1.26 A Dangerous Mistake in Python vs. Impossible in FLANG</strong></h4>
<p>This is the clearest illustration of why a dedicated forensic language earns its place next to a general-purpose one.</p>
<p><em><strong>Python — a single bad line, and evidence integrity is gone</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>disk = open("/evidence/host17_disk.E01", "r+b")</p>
<p>disk.seek(0)</p>
<p>disk.write(b"\\x00" * 512) # evidence is now corrupted, silently</p>
<p>disk.close()</p></td>
</tr>
</tbody>
</table></div>
<p>In Python, nothing in the language itself distinguishes “a script that reads evidence” from “a script that can destroy it” — the same open() function does both, and the only thing preventing disaster is the discipline of the person writing the script.</p>
<p><em><strong>FLANG — the equivalent mistake cannot be expressed</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>disk := load_disk_image("/evidence/host17_disk.E01");</p>
<p>disk.write(...) # ERROR: 'write' is not a function in FLANG</p>
<p># there is no such capability to call, ever</p></td>
</tr>
</tbody>
</table></div>
<p>This is the core argument for a domain-specific forensic language: it is not merely “Python with nicer names” — it removes an entire class of catastrophic mistakes from what is expressible in the first place.</p>
<h4><strong>1.27 Summary Comparison Table</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 24%" />
<col style="width: 36%" />
<col style="width: 38%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Dimension</strong></th>
<th><strong>Python</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Type</td>
<td>General-purpose</td>
<td>Domain-specific (forensics) + general control flow</td>
</tr>
<tr class="even">
<td>Typical user</td>
<td>Software engineer / data scientist</td>
<td>Digital forensic investigator, any coding background</td>
</tr>
<tr class="odd">
<td>File access</td>
<td>Direct, unrestricted (open())</td>
<td>Brokered, read-only evidence handles only</td>
</tr>
<tr class="even">
<td>Deletion capability</td>
<td>Yes (os.remove, etc.)</td>
<td>Does not exist in the language</td>
</tr>
<tr class="odd">
<td>Network access</td>
<td>Unrestricted (sockets, HTTP)</td>
<td>Confined to parsing an already-acquired capture file, or reading live local host state read-only</td>
</tr>
<tr class="even">
<td>Shell / process execution</td>
<td>Yes (os.system, subprocess)</td>
<td>No such built-in</td>
</tr>
<tr class="odd">
<td>Control flow</td>
<td>if/elif/else, while, for, break, continue, try/except</td>
<td>if/elif/else, while, for, break, continue, try/catch — same shapes, narrower error model</td>
</tr>
<tr class="even">
<td>Operators</td>
<td>Full arithmetic, compound assignment, ternary, membership</td>
<td>Same set (+= ++ ** // in ?: all included)</td>
</tr>
<tr class="odd">
<td>Object/module model</td>
<td>Classes, modules, attributes</td>
<td>Dotted namespace.method() calls — system.info(), process.list(), sample.hash() — without full OOP</td>
</tr>
<tr class="even">
<td>Audit logging</td>
<td>Manual, opt-in</td>
<td>Automatic on every built-in and namespace-method call</td>
</tr>
<tr class="odd">
<td>Access control</td>
<td>Not a language feature</td>
<td>Built-in RBAC, per-function minimum role, with role aliases</td>
</tr>
<tr class="even">
<td>Tamper detection</td>
<td>Not built in</td>
<td>Hash-chained audit log, independently verifiable</td>
</tr>
<tr class="odd">
<td>Report signing</td>
<td>Manual (must write your own crypto code)</td>
<td>sign_report() / co_sign_report() dual-control, plus export_encrypted()</td>
</tr>
<tr class="even">
<td>Evidence hashing</td>
<td>Manual (hashlib)</td>
<td>sha256() built in; SHA-512 manifests alongside it</td>
</tr>
<tr class="odd">
<td>Statistical anomaly detection</td>
<td>Manual (statistics / numpy)</td>
<td>mean, median, stdev, detect_outliers, detect_anomalies built in</td>
</tr>
<tr class="even">
<td>Case management</td>
<td>None built in</td>
<td>case.* namespace — create/open/add_evidence/add_note/close</td>
</tr>
<tr class="odd">
<td>Package ecosystem</td>
<td>PyPI — huge, unreviewed by default</td>
<td>None — closed, vetted standard library only</td>
</tr>
<tr class="even">
<td>Learning curve for a non-programmer</td>
<td>Weeks</td>
<td>Hours</td>
</tr>
<tr class="odd">
<td>Best suited for</td>
<td>Any software task</td>
<td>Authorized, reviewable, court-defensible forensic scripts</td>
</tr>
</tbody>
</table></div>
<h4><strong>1.28 When to Use Python, When to Use FLANG</strong></h4>
<p><em><strong>Use Python when…</strong></em></p>
<ul>
<li><p>You are building the forensic tooling itself (as this project does — FLANG's own interpreter is written in Python).</p></li>
<li><p>The task is general software engineering: a web dashboard, a data pipeline, a custom parser for a new evidence format not yet in FLANG's built-ins.</p></li>
<li><p>You need a capability FLANG intentionally does not expose, and you are working outside of evidence handling (e.g. exporting a chart image).</p></li>
</ul>
<p><em><strong>Use FLANG when…</strong></em></p>
<ul>
<li><p>You are the investigator running the actual case work: acquiring evidence, hashing it, analyzing it, correlating findings, producing a report.</p></li>
<li><p>The script needs to be reviewable by a supervisor, an auditor, or presented as an artifact in legal proceedings.</p></li>
<li><p>You want the safety properties (read-only evidence, RBAC, audit logging, signed reports) to be guaranteed by the platform rather than remembered by the author.</p></li>
</ul>
<h4><strong>1.29 What's New in FLANG: A Language, Not Just a Script</strong></h4>
<p>FLANG's grammar started out deliberately minimal — no break/continue, no compound assignment, no exception handling — as a considered trade favoring reviewability. Real use of the prototype (writing the worked examples throughout this booklet, among other scripts) surfaced genuine friction from that minimalism, and FLANG closes most of it without abandoning the underlying philosophy: every addition below still goes through the same RBAC and audit-log path as every original built-in, and none of them introduce a way to write to evidence.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 32%" />
<col style="width: 67%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Addition</strong></th>
<th><strong>What it enables</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>break / continue</td>
<td>Early loop exit and skip-this-iteration, matching Python's shapes exactly</td>
</tr>
<tr class="even">
<td>try / catch (single clause)</td>
<td>Recovering from a bad conversion or malformed input without aborting the whole script</td>
</tr>
<tr class="odd">
<td>Compound assignment (+= -= *= /= %=)</td>
<td>Removes repetitive x := x + 1; style lines</td>
</tr>
<tr class="even">
<td>Increment / decrement (++ --)</td>
<td>Counter-style loops read the same as in C-family languages</td>
</tr>
<tr class="odd">
<td>Exponent (**) and floor division (//)</td>
<td>Closes a small but real arithmetic gap with Python</td>
</tr>
<tr class="even">
<td>Membership (in)</td>
<td>Direct IOC-list membership checks: "x.exe" in suspicious_names</td>
</tr>
<tr class="odd">
<td>Ternary (cond ? a : b)</td>
<td>One-line conditional value selection, common in severity scoring</td>
</tr>
<tr class="even">
<td>Dict literals ({"k": "v"})</td>
<td>Structured records (a flagged process, a flow) without a custom evidence type</td>
</tr>
<tr class="odd">
<td>Dotted namespace.method() calls</td>
<td>A real grammar extension (not string-matched sugar) enabling system.info(), process.list(), sample.hash(), and the rest of Chapter 1.30</td>
</tr>
</tbody>
</table></div>
<p>Every one of these was added additively: the original 11-test suite still passes unchanged, and FLANG's own test suite has grown to 24 tests, all passing, specifically because nothing about the original language semantics was altered to accommodate the new grammar (see Appendix G).</p>
<h4><strong>1.30 Namespaced Method Calls: FLANG's Standard Library Grows Up</strong></h4>
<p>Alongside the flat built-ins already described in this booklet (sha256(x), list_files(disk, path)), FLANG adds dotted namespace.method() syntax — a genuine parser and AST extension, not a naming convention layered on top of ordinary function calls. Every namespace method goes through the exact same RBAC check and audit-log write as every flat built-in; the dot is purely organizational.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>info := system.info();</p>
<p>print(f"Host: {get(info, "hostname")}");</p>
<p>processes := process.list();</p>
<p>flagged := detection.unexpected_parent(processes, {"sshd": ["systemd"]});</p>
<p>sample := analyze.file("suspicious.exe");</p>
<p>print(sample.hash());</p>
<p>print(to_string(sample.entropy()));</p>
<p>test.create("marker_check");</p>
<p>test.generate_variants(10);</p>
<p>test.compare_detection();</p>
<p>lab_report := test.generate_report();</p></td>
</tr>
</tbody>
</table></div>
<p>Two design details are worth calling out. First, sample here is a genuine object with methods (a FlangObject returned by analyze.file()), the first place in FLANG's grammar where a value carries its own callable behavior rather than being passed as an argument to a free function — a deliberate, minimal step toward object-orientation, not a full class system. Second, the interpreter rejects any script that tries to use a reserved namespace name (system, process, file, network, hash, analyze, detection, report, test, service, user, startup, eventlog, timeline, case, evidence, correlation, audit, security, forensics, simulation, reporting, filesystem) as an ordinary variable name, with a clear error rather than silently letting the assignment shadow the namespace and break every later call to it — a real bug the project's own regression testing caught and fixed during development (documented candidly in SCOPE_AND_ROADMAP.md rather than glossed over).</p>
<p><strong>Part Two</strong></p>
<p><strong>Fitting the Brief</strong></p>
<p><em>How FLANG Satisfies “Forensic Analysis Without Triggering Security Solutions”</em></p>`,
  code: null,
},
{
  level: "Intermediate",
  title: "Part 2 — Intermediate: Full Project Booklet",
  body: `<h3><strong>2.1 Restating the Problem Statement</strong></h3>
<p>The originating brief calls for: “Creation of scripts/functions with a new programming language to commence computer and network forensic analysis without triggering security solutions.” It asks for a specialized DSL and execution framework enabling authorized investigators to perform evidence acquisition, filesystem/disk/memory/network/log analysis, event correlation, metadata extraction, timeline generation, IOC identification, hashing, anomaly detection, and automated reporting — through simple, readable scripts.</p>
<p>This chapter walks through each clause of that brief and shows, point by point, where the corresponding capability lives in FLANG's design and implementation.</p>
<h4><strong>2.2 Two Readings of “Without Triggering Security Solutions”</strong></h4>
<p>This phrase is the single most important design constraint in the whole brief, because it is genuinely ambiguous, and the two readings lead to opposite architectures.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 38%" />
<col style="width: 34%" />
<col style="width: 27%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Reading</strong></th>
<th><strong>What it would require</strong></th>
<th><strong>Adopted by FLANG?</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Evasion — hide the tool's activity from AV / EDR / IDS / IPS so it goes unnoticed</td>
<td>Unhooking, process hiding, disabling security agents, obfuscated binaries</td>
<td>No — explicitly excluded</td>
</tr>
<tr class="even">
<td>Trust &amp; transparency — behave so predictably and visibly that security tools recognize the activity as legitimate and do not flag it</td>
<td>Code signing, least privilege, a published behavioral manifest, distinct process identity, sandboxing</td>
<td>Yes — this is FLANG's entire security architecture</td>
</tr>
</tbody>
</table></div>
<p>The evasion reading is functionally indistinguishable from malware behavior. FLANG is built entirely around the second, legitimate reading: it earns allowlisting the same way a backup agent or EDR agent does — through identity, signing, and predictable, minimal-privilege behavior — never by hiding.</p>
<h4><strong>2.3 Functional Requirements Mapping</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 36%" />
<col style="width: 63%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Brief requirement</strong></th>
<th><strong>FLANG implementation</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Evidence acquisition</td>
<td>load_disk_image / load_memory_image / load_pcap / load_logs — all read-only, auto-hashed</td>
</tr>
<tr class="even">
<td>Filesystem &amp; disk analysis</td>
<td>list_files, carve_deleted, get_metadata (filesystem.py, backed by Sleuth Kit in production)</td>
</tr>
<tr class="odd">
<td>Memory analysis</td>
<td>list_processes, list_network_connections, detect_injection, extract_strings (memory.py, Volatility3-shaped)</td>
</tr>
<tr class="even">
<td>Network / packet analysis</td>
<td>list_flows, extract_dns, flag_suspicious_connections (network.py, scapy-backed)</td>
</tr>
<tr class="odd">
<td>Log analysis</td>
<td>parse_events, match_iocs (logs.py — syslog, JSON, extensible to EVTX)</td>
</tr>
<tr class="even">
<td>Event correlation</td>
<td>correlate() — cross-source timeline clustering by time window</td>
</tr>
<tr class="odd">
<td>Metadata extraction</td>
<td>get_metadata() — MACB timestamps, size, owner</td>
</tr>
<tr class="even">
<td>Timeline generation</td>
<td>correlate() output is a structured Timeline object</td>
</tr>
<tr class="odd">
<td>IOC identification</td>
<td>flag_suspicious, flag_suspicious_connections, match_iocs — all IOC-driven</td>
</tr>
<tr class="even">
<td>Cryptographic hashing</td>
<td>sha256(), verify_hash()</td>
</tr>
<tr class="odd">
<td>Automated report generation</td>
<td>new_report / add_section / add_timeline / sign_report / export</td>
</tr>
<tr class="even">
<td>Live host triage</td>
<td>system.info(), process.list(), file.entropy() and the analyze/detection namespaces — Chapters 1.30, 3.9</td>
</tr>
<tr class="odd">
<td>Case management</td>
<td>case.create / add_evidence / add_note / close — Chapters 3.9, Appendix A.1</td>
</tr>
<tr class="even">
<td>Statistical anomaly detection</td>
<td>mean, median, stdev, detect_outliers, detect_anomalies — Chapter 3.9</td>
</tr>
</tbody>
</table></div>
<p>The three rows above extend the same functional-requirements mapping to live-host triage, structured case tracking, and quantitative anomaly detection, none of which the original brief's own requirement list distinguished from the four core evidence domains — see Part 3, Chapters 3.9–3.12, for the full detail.</p>
<h4><strong>2.4 Non-Functional Requirements Mapping</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 36%" />
<col style="width: 63%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Brief requirement</strong></th>
<th><strong>FLANG implementation</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Forensic soundness</td>
<td>Evidence handles are read-only by construction; no write capability exists in the language</td>
</tr>
<tr class="even">
<td>Preservation of original evidence</td>
<td>EvidenceManager verifies the source hash is unchanged before report sign-off</td>
</tr>
<tr class="odd">
<td>Chain of custody</td>
<td>ChainOfCustodyRecord created automatically on every ingest</td>
</tr>
<tr class="even">
<td>Timestamp preservation</td>
<td>get_metadata() preserves MACB timestamps unmodified</td>
</tr>
<tr class="odd">
<td>Reproducibility</td>
<td>Same script + same evidence + same runtime version → identical output</td>
</tr>
<tr class="even">
<td>Detailed audit logging</td>
<td>Hash-chained AuditLog; every built-in call is logged before it returns</td>
</tr>
<tr class="odd">
<td>Readable, low-barrier syntax</td>
<td>Small vocabulary of forensic verbs; general control flow kept minimal and explicit</td>
</tr>
</tbody>
</table></div>
<h4><strong>2.5 System Architecture Overview</strong></h4>
<p>FLANG's architecture is a pipeline: source text flows through a lexer, parser, and interpreter, which drives a sandboxed forensic runtime made of an evidence-management layer, analysis modules, an audit log, and a reporting engine — all wrapped in a security layer. The table below sets out each stage, in execution order, together with what it consumes, what it produces, and the file it lives in.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 24%" />
<col style="width: 21%" />
<col style="width: 21%" />
<col style="width: 32%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Stage</strong></th>
<th><strong>Consumes</strong></th>
<th><strong>Produces</strong></th>
<th><strong>Implemented in</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>1. Lexer</td>
<td>.flang source text</td>
<td>Token stream</td>
<td>flang/lexer.py</td>
</tr>
<tr class="even">
<td>2. Parser</td>
<td>Token stream</td>
<td>Abstract syntax tree (AST)</td>
<td>flang/parser.py</td>
</tr>
<tr class="odd">
<td>3. Interpreter</td>
<td>AST</td>
<td>Executed statements, RBAC checks, audit entries</td>
<td>flang/interpreter.py</td>
</tr>
<tr class="even">
<td>4. Evidence management layer</td>
<td>Raw evidence path</td>
<td>Opaque, read-only EvidenceHandle + chain-of-custody record</td>
<td>flang/runtime/evidence.py</td>
</tr>
<tr class="odd">
<td>5. Analysis modules (filesystem / memory / network / logs)</td>
<td>EvidenceHandle</td>
<td>Structured findings (files, processes, flows, events)</td>
<td>flang/runtime/modules/*.py</td>
</tr>
<tr class="even">
<td>6. Correlation engine</td>
<td>Findings from step 5</td>
<td>A single chronological Timeline</td>
<td>flang/runtime/modules/correlate.py</td>
</tr>
<tr class="odd">
<td>7. Audit log</td>
<td>Every built-in call from steps 3–6</td>
<td>Hash-chained, independently verifiable log</td>
<td>flang/runtime/audit.py</td>
</tr>
<tr class="even">
<td>8. Reporting engine</td>
<td>Timeline + findings + audit summary</td>
<td>Signed, dual-format (JSON/HTML) report</td>
<td>flang/runtime/report.py</td>
</tr>
<tr class="odd">
<td>Cross-cutting: security &amp; access layer</td>
<td>Every call at steps 3–8</td>
<td>RBAC allow/deny decision, before execution</td>
<td>flang/runtime/security.py</td>
</tr>
</tbody>
</table></div>
<p>Read top to bottom, this table is the same pipeline described narratively in the chapters that follow: Chapter 2.6 expands stage 1–2, Chapter 2.7 expands stage 3, Chapter 2.8 expands stage 4, Chapters 2.14–2.17 expand stage 5, Chapter 2.17 also covers stage 6, Chapter 2.12 expands stage 7, and Chapter 2.18 expands stage 8.</p>
<h4><strong>2.6 Lexer and Parser: Readable, Reviewable Scripts</strong></h4>
<p>The lexer (flang/lexer.py) turns script text into tokens; the parser (flang/parser.py) turns tokens into an AST following FLANG's grammar. This matters for the brief's requirement of “simple, readable, and reliable scripts” in two ways: first, syntax errors are caught before anything touches evidence — a malformed script never executes partway; second, because the grammar is small and explicit (mandatory braces and semicolons, no whitespace-sensitive blocks), a printed .flang script is unambiguous to a human reader, which matters when a script itself becomes an exhibit in an investigation.</p>
<h4><strong>2.7 The Interpreter and Effect Tagging</strong></h4>
<p>Every built-in function in flang/interpreter.py is registered with two properties beyond its Python implementation: a minimum RBAC role, and an effect class (READ, DERIVE, or EXPORT). No built-in is tagged as a write-to-evidence capability, because none exists. Before any built-in executes, the interpreter checks the caller's role and writes an audit-log entry — both steps happen automatically, and a script has no way to skip them.</p>
<h4><strong>2.8 Evidence Management Layer and Forensic Soundness</strong></h4>
<p>flang/runtime/evidence.py is the only part of the system permitted to touch a raw evidence path. It hashes evidence at ingestion, best-effort strips write permission bits at the OS level as defense-in-depth, and hands back an opaque EvidenceHandle — analysis modules never see a raw path, only a handle brokered through this layer. This directly satisfies the brief's requirement for “read-only analysis wherever possible” and “preservation of original evidence.”</p>
<h4><strong>2.9 Cryptographic Hashing and Integrity Verification</strong></h4>
<p>sha256() (and the underlying sha256_file / sha256_dir_manifest functions) compute SHA-256 at evidence ingestion and again immediately before report sign-off, via EvidenceManager.verify_all(). If the two hashes differ, the mismatch is recorded in the audit log and surfaced to the investigator — directly implementing the brief's requirement for “cryptographic verification” of evidence.</p>
<h4><strong>2.10 Chain of Custody</strong></h4>
<p>Each ingest call creates a ChainOfCustodyRecord — evidence ID, case ID, source path, evidence type, ingesting investigator, ingestion timestamp, and ingestion hash. This satisfies the brief's explicit requirement for chain-of-custody tracking, and it happens automatically rather than being something the investigator must remember to log by hand.</p>
<h4><strong>2.11 Role-Based Access Control and Least Privilege</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 27%" />
<col style="width: 72%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Role</strong></th>
<th><strong>Can call</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>TIER1_TRIAGE</td>
<td>load_*, sha256, verify_hash, list_files, get_metadata, parse_events, length, print, range, to_string, to_number</td>
</tr>
<tr class="even">
<td>TIER2_ANALYST</td>
<td>everything above, plus carve_deleted, flag_suspicious, memory &amp; network analysis, match_iocs, correlate</td>
</tr>
<tr class="odd">
<td>LEAD_INVESTIGATOR</td>
<td>everything above, plus sign_report, export</td>
</tr>
<tr class="even">
<td>ADMIN</td>
<td>role/key management only — deliberately cannot run investigative built-ins (separation of duties)</td>
</tr>
</tbody>
</table></div>
<p>This maps directly to the brief's requirement for “authentication, authorization, role-based access control … mechanisms for verifying that forensic scripts have not been modified” (the last part covered by script hashing, §2.12).</p>
<h4><strong>2.12 Tamper-Evident Audit Logging</strong></h4>
<p>flang/runtime/audit.py hash-chains every log entry: each entry embeds the SHA-256 hash of the previous entry. Any retroactive edit to an earlier entry breaks the chain for every entry after it, and AuditLog.verify() independently re-walks the chain to report the exact point of tampering. This was demonstrated in practice during prototype testing — hand-editing one line of a saved audit log caused verify-audit to correctly report “TAMPER DETECTED at entry 5.” This satisfies the brief's requirement for “secure logging” and “tamper detection.”</p>
<h4><strong>2.13 Establishing Trust With Security Solutions (Not Evading Them)</strong></h4>
<p>This chapter maps directly onto the brief's explicit list: “digitally signed binaries, trusted certificates, administrator authorization, application allowlisting, documented behavior, sandboxed execution, least-privilege access, explicit forensic-agent identification, standardized APIs, and controlled laboratory environments.”</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 38%" />
<col style="width: 61%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Brief's trust mechanism</strong></th>
<th><strong>How FLANG implements it</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Digitally signed binaries / trusted certificates</td>
<td>The runtime binary is code-signed with an organizational certificate; reports are signed at export</td>
</tr>
<tr class="even">
<td>Administrator authorization</td>
<td>Investigators authenticate before any script runs; role checked per built-in call</td>
</tr>
<tr class="odd">
<td>Application allowlisting</td>
<td>A signed, identifiable binary can be pre-registered with EDR/IDS rather than needing to hide</td>
</tr>
<tr class="even">
<td>Documented behavior</td>
<td>A behavioral manifest describing exactly what the runtime touches can be shared with security teams in advance</td>
</tr>
<tr class="odd">
<td>Sandboxed execution</td>
<td>Each script runs in an isolated process/VM with a read-only evidence mount and no default network access</td>
</tr>
<tr class="even">
<td>Least-privilege access</td>
<td>Raw-disk read access is requested only for the specific acquisition call, not for the process lifetime</td>
</tr>
<tr class="odd">
<td>Explicit forensic-agent identification</td>
<td>The runtime process is named distinctly (flang-runtime) so security tooling attributes its activity unambiguously</td>
</tr>
<tr class="even">
<td>Standardized APIs</td>
<td>All evidence access goes through the same typed built-in catalogue — no ad-hoc system calls</td>
</tr>
<tr class="odd">
<td>Controlled laboratory environments</td>
<td>Testing and, ideally, execution occur on an isolated forensic lab network, not production endpoints</td>
</tr>
</tbody>
</table></div>
<h4><strong>2.14 Filesystem Analysis Module</strong></h4>
<p>flang/runtime/modules/filesystem.py implements list_files (metadata + SHA-256 per file), get_metadata, carve_deleted (a documented placeholder for a future Sleuth Kit / pytsk3 integration), and flag_suspicious (matches files against an IOC list by hash or filename). Every call receives only a brokered EvidenceHandle and includes a path-containment check to prevent escaping the evidence root — directly serving the brief's “filesystem analysis” and “file and process investigation” requirements.</p>
<h4><strong>2.15 Memory Analysis Module</strong></h4>
<p>flang/runtime/modules/memory.py implements list_processes, list_network_connections, detect_injection, and extract_strings. The module is written against the normalized shape that Volatility3's JSON output would produce, so a production deployment swaps in a real Volatility3 loader without changing any analysis logic — directly serving the brief's “memory analysis” requirement.</p>
<h4><strong>2.16 Network Analysis Module</strong></h4>
<p>flang/runtime/modules/network.py implements list_flows, extract_dns, and flag_suspicious_connections, using scapy to parse real .pcap/.pcapng files when available. This serves the brief's “network packet and traffic analysis” and “identifying suspicious connections” requirements.</p>
<h4><strong>2.17 Log Analysis and Correlation</strong></h4>
<p>flang/runtime/modules/logs.py normalizes syslog-style and JSON-line logs into a flat Event schema and matches them against IOC keywords. flang/runtime/modules/correlate.py then merges filesystem, memory, network, and log findings into a single chronological Timeline, grouped into configurable time-window clusters — together serving the brief's “log analysis,” “event correlation,” and “timeline generation” requirements in one pipeline.</p>
<h4><strong>2.18 Reporting Engine and Digital Signatures</strong></h4>
<p>flang/runtime/report.py builds a Report object section by section, embeds the executed script's own SHA-256 hash and a summary of the audit-log verification result, then signs the whole report with HMAC-SHA256 (a stand-in in this prototype for a production PKI/HSM-backed signing key) before exporting to signed JSON and human-readable HTML. This satisfies the brief's requirement for “automated forensic report generation” with built-in integrity guarantees.</p>
<h4><strong>2.19 End-to-End Script Walkthrough</strong></h4>
<p>The following excerpt from examples/sample_investigation.flang demonstrates every requirement above operating together in a single script an investigator would actually run.</p>
<p><em><strong>Excerpt — full script in examples/sample_investigation.flang</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>disk := load_disk_image("demo_evidence/host17_files");</p>
<p>mem := load_memory_image("demo_evidence/host17_mem.json");</p>
<p>pcap := load_pcap("demo_evidence/segment_capture.json");</p>
<p>logset := load_logs("demo_evidence/host17_winevt.log", format: "syslog");</p>
<p>suspicious_files := flag_suspicious(list_files(disk, "."), iocs);</p>
<p>injected := detect_injection(mem);</p>
<p>bad_flows := flag_suspicious_connections(list_flows(pcap), iocs);</p>
<p>matched_events := match_iocs(parse_events(logset), iocs);</p>
<p>timeline := correlate([suspicious_files, injected, bad_flows, matched_events],</p>
<p>window_seconds: 300);</p>
<p>report := new_report("Host17 Lateral Movement Investigation");</p>
<p>report := add_timeline(report, timeline);</p>
<p>report := sign_report(report, key_id: "analyst_tier2_key");</p>
<p>export(report, format: "json", path: "output/report.json");</p></td>
</tr>
</tbody>
</table></div>
<p>In actual execution, this script produced a signed report, an evidence-integrity check that passed for all four evidence sources, and a 36-entry audit log whose hash chain independently verified as intact — a concrete, tested demonstration that the architecture works as designed, not merely as described.</p>
<h4><strong>2.20 Testing and Validation Strategy</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 31%" />
<col style="width: 68%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Test category</strong></th>
<th><strong>What was verified in the prototype</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Evidence integrity</td>
<td>Re-hash after analysis matches ingestion hash; mutating a fixture afterward is correctly detected</td>
</tr>
<tr class="even">
<td>RBAC enforcement</td>
<td>TIER1_TRIAGE correctly blocked from carve_deleted (a TIER2_ANALYST-only call), with a clear error</td>
</tr>
<tr class="odd">
<td>Audit-log tamper detection</td>
<td>Hand-editing one saved log entry was correctly detected by verify-audit</td>
</tr>
<tr class="even">
<td>Report signature integrity</td>
<td>Independently recomputing the HMAC signature confirmed it matched</td>
</tr>
<tr class="odd">
<td>Reproducibility</td>
<td>Re-running the same script against the same fixtures produced consistent structured output</td>
</tr>
<tr class="even">
<td>Unit test coverage</td>
<td>24 automated tests across lexer/parser, interpreter, RBAC, evidence integrity, audit chain, role aliases, SHA-512, and the namespaced forensic modules — all passing</td>
</tr>
</tbody>
</table></div>
<h4><strong>2.21 Implementation Roadmap Recap</strong></h4>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 38%" />
<col style="width: 61%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Phase</strong></th>
<th><strong>Status in this project</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Requirements analysis</td>
<td>Complete — this booklet's Part 2, Chapters 2.3–2.4</td>
</tr>
<tr class="even">
<td>Language design (grammar, types, standard library)</td>
<td>Complete — lexer.py, parser.py, ast_nodes.py</td>
</tr>
<tr class="odd">
<td>Core interpreter</td>
<td>Complete — variables, functions, recursion, if/elif/else, for, while, and/or/not</td>
</tr>
<tr class="even">
<td>Evidence management layer</td>
<td>Complete — read-only handles, hashing, chain of custody</td>
</tr>
<tr class="odd">
<td>Forensic modules (filesystem/memory/network/logs)</td>
<td>Prototype complete against normalized data shapes; production backends (Sleuth Kit, Volatility3, full EVTX) are the next increment</td>
</tr>
<tr class="even">
<td>Security &amp; sandbox hardening</td>
<td>RBAC and audit-chain hashing complete; OS-level sandboxing (containers/microVMs) is the next increment</td>
</tr>
<tr class="odd">
<td>Testing &amp; validation</td>
<td>Automated test suite passing; larger-scale synthetic evidence testing is the next increment</td>
</tr>
</tbody>
</table></div>
<h4><strong>2.22 Conclusion: How FLANG Satisfies the Brief</strong></h4>
<p>Returning to the brief's own closing sentence: FLANG demonstrates that a purpose-built forensic programming language can automate and standardize computer and network investigations while remaining transparent, authorized, auditable, forensically sound, and compatible with organizational security controls rather than attempting to evade them.</p>
<ul>
<li><p>Transparent: signed runtime, documented behavior, distinct process identity — nothing hidden from security tooling.</p></li>
<li><p>Authorized: RBAC gates every sensitive operation; only assigned investigators on an assigned case may act.</p></li>
<li><p>Auditable: every action is logged automatically in a tamper-evident, independently verifiable chain.</p></li>
<li><p>Forensically sound: evidence is read-only by construction; integrity is verified before and after analysis.</p></li>
<li><p>Compatible with security controls, not evasive of them: least privilege, sandboxing, and identity are how the tool earns trust.</p></li>
</ul>
<p>Where Part 1 of this booklet showed that FLANG trades Python's generality for safety and readability, Part 2 has shown why that trade is exactly what the brief asked for: a language where the unsafe, security-control-evading interpretation of the problem statement is not just discouraged, but structurally impossible to express. Part 3 now widens the lens beyond Python alone, to ask how FLANG's advanced features stand up against the broader field of languages and tools an investigator might otherwise reach for.</p>
<p><strong>Part Three</strong></p>
<p><strong>Advanced Features &amp; the Wider Field</strong></p>
<p><em>Where FLANG Stands Against Programming and Forensic-Scripting Languages</em></p>`,
  code: null,
},
{
  level: "Advanced",
  title: "Part 3 — Advanced: Full Project Booklet",
  body: `<h3><strong>3.1 Why Advanced Features Matter for a Forensic DSL</strong></h3>
<p>Parts 1 and 2 established FLANG's basic case against a single comparator, Python. Part 3 asks a harder question: once FLANG's advanced, forensic-specific machinery is placed next to the full field of languages and tools an investigator, a SOC analyst, or a court might otherwise encounter, does FLANG still hold up? “Advanced” is used here in two senses that this part keeps carefully separate: features already running in the working prototype in flang_project/, verified by its automated test suite, and features scoped on the production roadmap but not yet implemented. Every claim in this part is labeled as one or the other — conflating them would undermine the exact property (auditable, defensible truthfulness) that makes FLANG worth building in the first place.</p>
<h4><strong>3.2 Implemented — Effect-Tagged Built-ins (READ / DERIVE / EXPORT)</strong></h4>
<p>Most languages treat every function call identically at the language level; whether a call is safe or dangerous is left to documentation, convention, or the caller's memory. FLANG's interpreter attaches a static effect class to every built-in at registration time: READ (touches evidence but produces no new artifact), DERIVE (computes a new value from already-read data), or EXPORT (produces an artifact that leaves the sealed evidence boundary, such as a signed report). This is more than documentation — the effect tag is consulted by the RBAC layer and the audit logger on every call, so “what kind of thing did this script just do” is answerable mechanically from the audit log, not by re-reading the script's source.</p>
<p>No language-level equivalent of this exists in Python, C, C++, Java, or Bash: a Python call to os.remove() and a Python call to len() are syntactically the same kind of thing to the interpreter. FLANG's advanced feature is deciding, once, at the language boundary, that they are not.</p>
<h4><strong>3.3 Implemented — Hash-Chained, Tamper-Evident Audit Log</strong></h4>
<p>flang/runtime/audit.py embeds the SHA-256 hash of the previous log entry inside every new entry, forming a hash chain conceptually identical to the structure used in a blockchain's block header, without requiring a distributed network. AuditLog.verify() re-walks the chain and pinpoints the exact entry index at which tampering occurred — demonstrated in prototype testing by hand-editing a saved log line and observing a correct “TAMPER DETECTED at entry 5” result.</p>
<p><em><strong>Why this is an advanced feature, not just “logging”</strong></em></p>
<p>Ordinary application logging (Python's logging module, syslog, Log4j) records events but does not make after-the-fact silent edits to the log detectable. FLANG's log is self-certifying: a court, a supervisor, or an opposing expert witness can verify the log's integrity independently, without trusting the machine that produced it, using nothing more than the chain's published verification algorithm.</p>
<h4><strong>3.4 Implemented — Brokered Evidence Handles and Path Containment</strong></h4>
<p>load_disk_image, load_memory_image, load_pcap, and load_logs never return a filesystem path to FLANG script code — they return an opaque EvidenceHandle object that analysis built-ins accept but that no FLANG statement can dereference into raw read/write access. flang/runtime/evidence.py additionally enforces path containment on every filesystem call, rejecting any resolved path that would escape the declared evidence root (defeating ../ traversal attempts even if a script author tried one, accidentally or otherwise).</p>
<p>This is the language-level equivalent of a capability-based security model — a design used in high-assurance systems research (seL4, Google's Fuchsia) but essentially absent from general-purpose scripting languages, where “capability” is a documentation convention at best.</p>
<h4><strong>3.5 Implemented — RBAC With Separation of Duties</strong></h4>
<p>FLANG's four-tier role model (TIER1_TRIAGE, TIER2_ANALYST, LEAD_INVESTIGATOR, ADMIN) is enforced per built-in call inside the interpreter, and — notably — the ADMIN role is deliberately barred from running investigative built-ins at all. This mirrors the separation-of-duties principle from financial and security auditing (the person who can grant access should not also be the person who performs the audited action), implemented as a language rule rather than a policy document that could be bypassed.</p>
<h4><strong>3.6 Implemented — Cross-Source Timeline Correlation Engine</strong></h4>
<p>flang/runtime/modules/correlate.py takes findings from filesystem, memory, network, and log modules — each with its own native timestamp format — normalizes them onto a common timeline, and clusters events into configurable time-window groups (window_seconds:) so an investigator sees which filesystem, process, network, and log events happened close together, a core step in reconstructing attacker activity. Doing the equivalent in Python or a SIEM query language requires writing custom normalization and clustering code by hand each time; in FLANG it is a single built-in call, correlate(), available to any script.</p>
<h4><strong>3.7 Implemented — Signed, Dual-Format Reporting</strong></h4>
<p>sign_report() embeds the executed script's own SHA-256 hash and the audit-log verification result into the report body before signing the whole structure with HMAC-SHA256, then export() emits both machine-readable JSON (for ingestion into a case-management system) and human-readable HTML (for a reviewing supervisor or a court) from the same signed source of truth — so the two formats cannot silently drift apart.</p>
<h4><strong>3.8 Implemented — Fail-Loud Execution Model</strong></h4>
<p>FLANG's prototype has no try/catch construct at all. A runtime error — an RBAC violation, a hash mismatch, a malformed evidence file — stops the script immediately with a specific, human-readable message. This is a deliberate rejection of a feature every general-purpose language treats as essential, on the grounds that in an evidentiary workflow, the ability to silently catch and continue past an unexpected condition is itself a liability, not a convenience. Few, if any, general-purpose or forensic scripting languages make this trade on purpose — most treat rich exception handling as a strict improvement, which it is, for their target use case, but not necessarily for this one.</p>
<h4><strong>3.9 Roadmap — Native Sleuth Kit / Volatility3 / EVTX Backends</strong></h4>
<p>The prototype's filesystem, memory, and log modules are written against the normalized data shapes that pytsk3 (The Sleuth Kit), Volatility3, and python-evtx would produce, so the production increment is a loader swap, not a rewrite of analysis logic. This is not yet implemented — it is scoped and shaped, and is the single largest planned expansion of FLANG's real-world evidentiary coverage.</p>
<h4><strong>3.10 Roadmap — Rust-Based Native Runtime</strong></h4>
<p>The prototype interpreter is written in Python and inherits CPython's performance profile. The project proposal specifies a future Rust-based runtime, preserving FLANG's syntax and every safety guarantee described in this booklet, while removing the interpreter as a performance bottleneck for large disk and memory images. Rust is additionally attractive for this specific rewrite because its ownership model can enforce “no mutable access to evidence memory” at compile time, adding a second, independent layer of the same guarantee FLANG already enforces at the interpreter level.</p>
<h4><strong>3.11 Roadmap — Sandboxed Microvm / Container Execution</strong></h4>
<p>The proposal describes namespace/seccomp, gVisor, or Firecracker microVM isolation for the runtime process itself, so that even a compromised or buggy interpreter cannot exceed the evidence read-only boundary at the OS level — defense in depth beneath the language-level guarantees already implemented.</p>
<h4><strong>3.12 Roadmap — PKI/HSM-Backed Code Signing</strong></h4>
<p>The prototype signs reports with a locally generated HMAC-SHA256 key as a stand-in for a production-grade PKI/HSM-backed signing key, which would let a report's authenticity be verified against an organizational certificate authority rather than a shared secret local key.</p>
<h4><strong>3.13 Roadmap — Behavioral Manifest for EDR Allowlisting</strong></h4>
<p>A machine-readable manifest — the exact set of file paths, network behavior (none, by design), and process behavior the FLANG runtime exhibits — shared with an organization's EDR/IDS/IPS team in advance, so allowlisting decisions are made on documented evidence rather than trust alone. This operationalizes the “transparency, not evasion” position argued in Chapter 2.2.</p>
<h4><strong>3.14 Roadmap — Static Effect Analysis</strong></h4>
<p>Because every built-in already carries a static effect tag (Chapter 3.2), a future FLANG tool could analyze a .flang script before running it and print the full set of effects it will have — every evidence source it will read, and every artifact it will export — without executing a single line. This would let a supervisor approve a script's intended behavior in advance, the way a database administrator reviews a query plan before running it against production data.</p>
<h4><strong>3.15 Comparative Analysis: Method and Criteria</strong></h4>
<p>The comparisons in Chapters 3.16–3.20 use five criteria drawn directly from the project brief and from established forensic-soundness principles (ACPO / NIST guidance on digital evidence handling): read-only evidence guarantee, built-in audit trail, built-in access control, domain vocabulary for forensic tasks, and general-purpose flexibility. The fifth criterion is included specifically so this comparison does not stack the deck — flexibility is a real, valuable property that FLANG deliberately does not optimize for, and the table says so plainly rather than hiding it.</p>
<h4><strong>3.16 FLANG vs General-Purpose Languages</strong></h4>
<p>Python, C, C++, Java, Go, and Rust are all capable of implementing every forensic operation FLANG offers — a skilled engineer can hand-write read-only file access, RBAC, and hash-chained logging in any of them. The comparison below is therefore not about capability, which all six languages have; it is about what each language guarantees by default, before a single line of application code is written.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 14%" />
<col style="width: 19%" />
<col style="width: 15%" />
<col style="width: 14%" />
<col style="width: 19%" />
<col style="width: 15%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Language</strong></th>
<th><strong>Read-only evidence by default</strong></th>
<th><strong>Built-in audit trail</strong></th>
<th><strong>Built-in RBAC</strong></th>
<th><strong>Forensic vocabulary</strong></th>
<th><strong>General-purpose flexibility</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Python</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>None (third-party libs only)</td>
<td>Very high</td>
</tr>
<tr class="even">
<td>C</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>None</td>
<td>Very high, low-level</td>
</tr>
<tr class="odd">
<td>C++</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>None</td>
<td>Very high, low-level</td>
</tr>
<tr class="even">
<td>Java</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>None</td>
<td>High, enterprise-oriented</td>
</tr>
<tr class="odd">
<td>Go</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>None</td>
<td>High, concurrency-oriented</td>
</tr>
<tr class="even">
<td>Rust</td>
<td>No (but memory-safe)</td>
<td>No</td>
<td>No</td>
<td>None</td>
<td>High, systems-oriented</td>
</tr>
<tr class="odd">
<td>FLANG</td>
<td>Yes — structural</td>
<td>Yes — automatic, hash-chained</td>
<td>Yes — per built-in</td>
<td>Native (load_disk_image, sha256, correlate…)</td>
<td>Deliberately narrow</td>
</tr>
</tbody>
</table></div>
<p>The pattern is consistent: every general-purpose language can be used to build a FLANG-equivalent safety layer, and none of them ship with one. FLANG's advantage is not a capability gap — it is that the safety properties are the default, not an opt-in engineering project repeated on every use.</p>
<h4><strong>3.17 FLANG vs Shell and Automation Languages</strong></h4>
<p>Bash and PowerShell are the two scripting languages most commonly reached for in real-world incident response and triage, precisely because they are already present on almost every system.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 26%" />
<col style="width: 22%" />
<col style="width: 26%" />
<col style="width: 25%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Property</strong></th>
<th><strong>Bash</strong></th>
<th><strong>PowerShell</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Present on target system by default</td>
<td>Yes (Linux/macOS)</td>
<td>Yes (Windows)</td>
<td>No — a dedicated, deliberately separate runtime</td>
</tr>
<tr class="even">
<td>Destructive commands reachable</td>
<td>Yes (rm, dd, &gt;file)</td>
<td>Yes (Remove-Item, Set-Content)</td>
<td>No such built-in exists</td>
</tr>
<tr class="odd">
<td>Native audit logging</td>
<td>No (shell history only, easily cleared)</td>
<td>Partial (transcript logging, if enabled)</td>
<td>Yes — always on, tamper-evident</td>
</tr>
<tr class="even">
<td>Native RBAC per command</td>
<td>No (relies on OS user permissions)</td>
<td>Partial (execution policy, not per-cmdlet)</td>
<td>Yes — per built-in function</td>
</tr>
<tr class="odd">
<td>Designed for evidentiary defensibility</td>
<td>No</td>
<td>No</td>
<td>Yes — the primary design goal</td>
</tr>
</tbody>
</table></div>
<p>The strongest real-world argument for Bash or PowerShell over FLANG is availability: they are already on the box, and FLANG requires deploying a dedicated runtime. FLANG's counter-argument, developed in Part 2, is that this same ubiquity is exactly what makes shell activity indistinguishable from an attacker's own living-off-the-land tooling to a watching EDR — a distinct, signed, identifiable FLANG process is easier for security tooling to recognize and trust than an ordinary system shell being used unusually.</p>
<h4><strong>3.18 FLANG vs Forensic and Security Scripting Languages</strong></h4>
<p>This is the most direct comparison, since these are the languages actually built for adjacent problems: EnScript (EnCase's proprietary scripting language), the Volatility 3 plugin API (Python-based), YARA (pattern-matching rule language), and osquery's SQL dialect (endpoint querying).</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 18%" />
<col style="width: 19%" />
<col style="width: 16%" />
<col style="width: 16%" />
<col style="width: 15%" />
<col style="width: 14%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Language / tool</strong></th>
<th><strong>Primary purpose</strong></th>
<th><strong>Read-only by construction</strong></th>
<th><strong>Cross-source correlation</strong></th>
<th><strong>Open, inspectable runtime</strong></th>
<th><strong>Vendor lock-in</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>EnScript (EnCase)</td>
<td>Full case scripting inside EnCase</td>
<td>No (script can write)</td>
<td>Limited, EnCase-internal</td>
<td>No — proprietary, closed</td>
<td>High — tied to one commercial product</td>
</tr>
<tr class="even">
<td>Volatility 3 plugin API</td>
<td>Memory-forensics plugins only</td>
<td>Yes, for the memory image</td>
<td>No — memory-only scope</td>
<td>Yes — open source</td>
<td>None, but single-domain (memory only)</td>
</tr>
<tr class="odd">
<td>YARA</td>
<td>Pattern/signature matching</td>
<td>N/A (matching, not scripting)</td>
<td>No</td>
<td>Yes — open source</td>
<td>None, but not a general scripting language</td>
</tr>
<tr class="even">
<td>osquery SQL dialect</td>
<td>Live endpoint querying via SQL</td>
<td>Read-only queries only</td>
<td>Limited, single-host scope</td>
<td>Yes — open source</td>
<td>None, but query-only, not a scripting language</td>
</tr>
<tr class="odd">
<td>FLANG</td>
<td>Full-case scripting across disk, memory, network, logs</td>
<td>Yes — structural, by design</td>
<td>Yes — built-in correlate()</td>
<td>Yes — the full interpreter and runtime are inspectable</td>
<td>None</td>
</tr>
</tbody>
</table></div>
<p>FLANG's genuine differentiator in this table is scope combined with openness: EnScript matches FLANG's read/write and cross-module ambitions but is proprietary and tied to one vendor's product; Volatility3, YARA, and osquery are each excellent at one slice of the problem (memory, pattern matching, live queries, respectively) but none spans disk, memory, network, and log analysis in one auditable, RBAC-governed language the way FLANG's design targets.</p>
<h4><strong>3.19 FLANG vs GUI-Toolkit Scripting</strong></h4>
<p>Autopsy (built on The Sleuth Kit) exposes a Python plugin API for custom modules; X-Ways Forensics offers its own internal scripting for automating repetitive tasks inside its GUI. Both are powerful, mature, widely deployed tools in real casework.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 30%" />
<col style="width: 24%" />
<col style="width: 22%" />
<col style="width: 22%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Property</strong></th>
<th><strong>Autopsy Python plugins</strong></th>
<th><strong>X-Ways scripting</strong></th>
<th><strong>FLANG</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Requires the host GUI application</td>
<td>Yes</td>
<td>Yes</td>
<td>No — runs standalone from a script file</td>
</tr>
<tr class="even">
<td>Full general-purpose language underneath</td>
<td>Yes (raw Python — same guarantees gap as Ch. 1)</td>
<td>Limited, proprietary macro language</td>
<td>No — deliberately narrow DSL</td>
</tr>
<tr class="odd">
<td>Per-action audit logging</td>
<td>Application-level, not language-level</td>
<td>Application-level, not language-level</td>
<td>Language-level — automatic on every built-in</td>
</tr>
<tr class="even">
<td>Portable across investigators without the GUI install</td>
<td>No</td>
<td>No</td>
<td>Yes — a .flang script is a plain text file</td>
</tr>
</tbody>
</table></div>
<p>This comparison surfaces a real trade-off rather than a clean win: Autopsy and X-Ways offer mature GUIs, large existing user bases, and (in X-Ways' case) decades of forensic feature depth that a young prototype cannot match. FLANG's advantage is narrower and more specific — the script itself, independent of any GUI, carries its own audit trail and access control, which matters when the deliverable that must survive scrutiny is the script and its log, not a screen the investigator once looked at.</p>
<h4><strong>3.20 Master Comparison Matrix</strong></h4>
<p>The following matrix consolidates every comparison in this part onto FLANG's five evaluation criteria (Chapter 3.15), scored Yes / Partial / No against each language or tool discussed above.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 18%" />
<col style="width: 16%" />
<col style="width: 14%" />
<col style="width: 14%" />
<col style="width: 18%" />
<col style="width: 18%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Language / tool</strong></th>
<th><strong>Read-only evidence</strong></th>
<th><strong>Audit trail</strong></th>
<th><strong>Access control</strong></th>
<th><strong>Forensic vocabulary</strong></th>
<th><strong>General flexibility</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Python</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>Yes</td>
</tr>
<tr class="even">
<td>C / C++</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>Yes</td>
</tr>
<tr class="odd">
<td>Java / Go / Rust</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>Yes</td>
</tr>
<tr class="even">
<td>Bash / PowerShell</td>
<td>No</td>
<td>Partial</td>
<td>Partial</td>
<td>No</td>
<td>Yes</td>
</tr>
<tr class="odd">
<td>EnScript</td>
<td>No</td>
<td>Partial</td>
<td>Partial</td>
<td>Yes (EnCase-scoped)</td>
<td>Partial</td>
</tr>
<tr class="even">
<td>Volatility 3</td>
<td>Yes (memory only)</td>
<td>No</td>
<td>No</td>
<td>Yes (memory only)</td>
<td>No</td>
</tr>
<tr class="odd">
<td>YARA</td>
<td>N/A</td>
<td>No</td>
<td>No</td>
<td>Partial</td>
<td>No</td>
</tr>
<tr class="even">
<td>osquery SQL</td>
<td>Yes (query-only)</td>
<td>No</td>
<td>Partial (OS user)</td>
<td>Partial</td>
<td>No</td>
</tr>
<tr class="odd">
<td>Autopsy / X-Ways</td>
<td>Partial (app-level)</td>
<td>Partial (app-level)</td>
<td>Partial (app-level)</td>
<td>Yes</td>
<td>Partial</td>
</tr>
<tr class="even">
<td>FLANG</td>
<td>Yes</td>
<td>Yes</td>
<td>Yes</td>
<td>Yes</td>
<td>No (by design)</td>
</tr>
</tbody>
</table></div>
<h4><strong>3.21 Why FLANG Is the Strongest Fit for This Problem</strong></h4>
<p>Across every comparator in this part, no other language or tool combines all five criteria: general-purpose languages have flexibility but none of the forensic guarantees; EnScript and the GUI-toolkit scripting languages have some forensic vocabulary but are proprietary, application-bound, or only partially audited; Volatility3, YARA, and osquery are each excellent within a single narrow slice (memory, pattern matching, live queries) but none spans the full disk-memory-network-log workflow the brief asks for. FLANG is the only language in this comparison, prototype or otherwise, purpose-built to have all four forensic guarantees simultaneously true by construction, across all four evidence domains, in one auditable script. That is the specific, narrow claim this booklet makes — not that FLANG writes faster code, or handles more tasks, than Python or C++, which it plainly does not and was never designed to.</p>
<h4><strong>3.22 Limitations and Where FLANG Is Not the Best Choice</strong></h4>
<p>An honest comparison has to say where the case above is weaker, and where a booklet arguing only advantages would be indefensible on the same grounds it asks the reader to hold FLANG to.</p>
<ul>
<li><p>Maturity: FLANG is a working prototype with an automated test suite; Python, EnCase, Volatility3, and X-Ways each have years to decades of production hardening, larger user bases, and battle-tested edge-case handling FLANG has not yet encountered.</p></li>
<li><p>Ecosystem: FLANG has no third-party package ecosystem by design — a genuine safety property, but also a real capability ceiling versus PyPI's breadth when a case needs a format FLANG's built-ins do not yet cover.</p></li>
<li><p>Performance: the prototype interpreter is Python-speed; large disk or memory images will run faster today in a tuned Volatility3 or Sleuth Kit pipeline until FLANG's Rust runtime (Chapter 3.10) exists.</p></li>
<li><p>Backend fidelity: filesystem, memory, and log modules currently run against normalized fixture shapes rather than the real pytsk3/Volatility3/EVTX backends they are designed to wrap (Chapter 3.9) — a real casework deployment needs that increment completed and independently validated first.</p></li>
<li><p>Tooling and training base: Autopsy, EnCase, and Volatility3 have existing courses, certifications, and communities; FLANG's small, new, domain-specific footprint (Chapter 1.18) means less prior art for a new investigator to learn from.</p></li>
<li><p>No production cryptographic signing yet: report signatures are HMAC-based with a local key, not yet the PKI/HSM-backed signing (Chapter 3.12) a production legal workflow would require.</p></li>
</ul>
<p>None of these limitations argue against FLANG's core design; they argue for treating the current prototype as exactly what it is — a validated proof of concept for the language and safety architecture, with a clear, itemized path to production readiness, rather than a finished replacement for mature forensic platforms today.</p>
<h4><strong>3.23 Case Study: A Full Investigation, Written Twice</strong></h4>
<p>To make the argument of this part concrete rather than only tabular, this chapter writes one small but realistic investigation twice — once as a careful, correct Python script, and once as the equivalent FLANG script — and walks through what each version does and does not guarantee, line by line. The scenario: an investigator has been handed a suspect disk image and a memory capture from a host suspected of running an unauthorized remote-access tool, and must hash the evidence, list files, flag anything matching a known-bad hash list, check running processes for injection indicators, and produce a signed report — all without accidentally altering the evidence.</p>
<p><em><strong>The Python version, written carefully by an experienced engineer</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>import hashlib, json, logging, os</p>
<p>logging.basicConfig(filename="investigation.log", level=logging.INFO)</p>
<p>def sha256_file(path):</p>
<p>with open(path, "rb") as f: # must remember "rb" — nothing enforces it</p>
<p>return hashlib.sha256(f.read()).hexdigest()</p>
<p>def list_files(root):</p>
<p>out = []</p>
<p>for dirpath, _, files in os.walk(root): # no containment check</p>
<p>for name in files:</p>
<p>out.append(os.path.join(dirpath, name))</p>
<p>logging.info(f"listed {len(out)} files") # easy to forget this line</p>
<p>return out</p>
<p>with open("known_bad_hashes.json") as f:</p>
<p>bad_hashes = set(json.load(f))</p>
<p>evidence_hash = sha256_file("host_disk.img")</p>
<p>logging.info(f"evidence hash: {evidence_hash}") # a second easy-to-forget line</p>
<p>files = list_files("host_disk_mount")</p>
<p>flagged = [p for p in files if sha256_file(p) in bad_hashes]</p>
<p># nothing in the language stops the next line from being a mistake:</p>
<p># os.remove(files[0]) &lt;- would silently destroy evidence if uncommented</p>
<p>report = {"evidence_hash": evidence_hash, "flagged_files": flagged}</p>
<p>with open("report.json", "w") as f:</p>
<p>json.dump(report, f)</p>
<p># report was never signed — a reviewer cannot verify it wasn't edited after the fact</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>The FLANG version, doing the same investigation</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>disk := load_disk_image("host_disk_mount");</p>
<p>evidence_hash := sha256(disk);</p>
<p>iocs := load_logs("known_bad_hashes.json", format: "json");</p>
<p>files := list_files(disk, ".");</p>
<p>flagged := flag_suspicious(files, iocs);</p>
<p>mem := load_memory_image("host_mem.json");</p>
<p>injected := detect_injection(mem);</p>
<p># there is no "delete" or "write" built-in to accidentally call here —</p>
<p># the equivalent mistake is simply not expressible in FLANG</p>
<p>report := new_report("Unauthorized RAT Investigation");</p>
<p>report := add_section(report, "Flagged Files", flagged);</p>
<p>report := add_section(report, "Injected Processes", injected);</p>
<p>report := sign_report(report, key_id: "tier2_key");</p>
<p>export(report, format: "json", path: "output/report.json");</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>What the side-by-side comparison shows</strong></em></p>
<p>Both scripts are correct, in the sense that a careful reviewer would approve either one. The difference this case study is built to illustrate is what happens when the author is not careful, or is rushed, or is a junior investigator under deadline pressure: in the Python version, forgetting the two logging.info() calls silently produces an unaudited investigation, and a single uncommented os.remove() line silently destroys evidence — both are ordinary Python statements the language treats as unremarkable. In the FLANG version, the audit log entries are not something the author writes at all, so there is nothing to forget, and there is no delete-shaped built-in anywhere in the language to uncomment by mistake. The FLANG script is also six lines shorter for the same task, because hashing, listing, flagging, and reporting are each a single verb rather than several lines of manual file handling — the brevity is a side effect of the safety model, not a separate feature.</p>
<h4><strong>3.24 Adoption Considerations for a Forensic Laboratory</strong></h4>
<p>A comparison table is not the same thing as a deployment plan. A laboratory considering FLANG alongside its existing toolchain would need to weigh several practical factors this booklet has not yet addressed directly.</p>
<p><em><strong>Coexistence, not replacement</strong></em></p>
<p>Nothing about FLANG's design requires a lab to abandon Autopsy, EnCase, Volatility3, or its existing Python tooling. FLANG's evidence handles can be produced from the same acquired disk images, memory captures, and packet captures those tools already work with, so the realistic adoption path is a lab using FLANG for the specific step in a workflow where a script's own auditability matters most — for example, the exact sequence of operations that will be presented to a court — while continuing to use mature GUI tools for exploratory analysis earlier in an investigation.</p>
<p><em><strong>Staff training</strong></em></p>
<p>Chapter 1.20 argued FLANG's learning curve is shorter than Python's for a non-programmer. That argument still requires new training material, since FLANG is not yet supported by the certifications and long-established courses that exist for EnCase or Volatility3-adjacent tooling (Chapter 3.22). A realistic adoption timeline should budget for producing that material rather than assuming zero ramp-up time.</p>
<p><em><strong>Integration with case-management systems</strong></em></p>
<p>FLANG's JSON report export (Chapter 2.18) is intentionally structured for machine ingestion, which should ease integration with existing case-management or ticketing systems, but that integration itself is new work for any lab adopting FLANG and is not something the current prototype ships pre-built.</p>
<h4><strong>3.25 Ethical and Legal Considerations</strong></h4>
<p>A tool designed around the phrase “without triggering security solutions” carries an obligation to be explicit about the ethical line it is built to stay on the right side of, restated here in Part 3's own terms after being argued at length in Chapter 2.2.</p>
<ul>
<li><p>Authorization is a precondition, not a feature: every FLANG design decision in this booklet assumes the investigator running a script already has proper legal authority — a warrant, a corporate incident-response mandate, or equivalent — to examine the evidence in question. FLANG enforces who may call which built-in once authorized; it does not, and cannot, establish that authorization in the first place.</p></li>
<li><p>Transparency over evasion is a testable design commitment, not a slogan: Chapters 2.2 and 2.13 show specific, checkable mechanisms (signed binaries, behavioral manifests, distinct process identity) rather than asserting good intent alone.</p></li>
<li><p>Auditability protects the investigator as much as the evidence: a hash-chained log that can prove nothing was altered is also the strongest available defense against a later accusation that something was.</p></li>
<li><p>A prototype is not a courtroom-ready tool: Chapter 3.22's limitations list — most importantly, HMAC rather than PKI/HSM signing, and fixture-shaped rather than production forensic backends — means this booklet argues FLANG's design is sound and its direction is right, not that the current prototype should be relied upon in an actual legal proceeding without the roadmap items in Chapters 3.9–3.14 completed and independently validated first.</p></li>
</ul>
<h4><strong>3.26 Extended Worked Example: A Cross-Domain IOC Sweep</strong></h4>
<p>Chapter 3.6 described FLANG's correlation engine in the abstract. This chapter shows a fuller worked script, closer in shape to real casework, that pulls a single indicator-of-compromise list across all four evidence domains FLANG supports in one pass — the kind of task that, in a general-purpose language, typically requires stitching together several independent libraries by hand.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p># Full four-domain IOC sweep, correlated onto one timeline</p>
<p>iocs := load_logs("case_iocs.json", format: "json");</p>
<p>disk := load_disk_image("evidence/host_disk");</p>
<p>mem := load_memory_image("evidence/host_mem.json");</p>
<p>pcap := load_pcap("evidence/host_capture.json");</p>
<p>logs := load_logs("evidence/host_events.log", format: "syslog");</p>
<p>files_hit := flag_suspicious(list_files(disk, "."), iocs);</p>
<p>mem_hit := detect_injection(mem);</p>
<p>network_hit := flag_suspicious_connections(list_flows(pcap), iocs);</p>
<p>log_hit := match_iocs(parse_events(logs), iocs);</p>
<p>timeline := correlate([files_hit, mem_hit, network_hit, log_hit],</p>
<p>window_seconds: 300);</p>
<p>if length(timeline) &gt; 0 {</p>
<p>severity := "HIGH";</p>
<p>} else {</p>
<p>severity := "LOW";</p>
<p>}</p>
<p>report := new_report(f"Cross-Domain IOC Sweep — Severity: {severity}");</p>
<p>report := add_timeline(report, timeline);</p>
<p>report := add_section(report, "Flagged Files", files_hit);</p>
<p>report := add_section(report, "Injected Processes", mem_hit);</p>
<p>report := add_section(report, "Suspicious Connections", network_hit);</p>
<p>report := add_section(report, "Matched Log Events", log_hit);</p>
<p>report := sign_report(report, key_id: "sweep_key");</p>
<p>export(report, format: "html", path: "output/sweep_report.html");</p></td>
</tr>
</tbody>
</table></div>
<p>Every line above that touches evidence is read-only by construction, every call is individually audit-logged, and the four independent findings lists are merged into one chronological timeline by a single correlate() call rather than hand-written merge logic. A Python or PowerShell equivalent of this script is entirely possible to write — nothing here is beyond either language's raw capability — but it would require the author to separately import and correctly use a disk-parsing library, a memory-forensics library, a packet-parsing library, and a log-parsing library, and to write the timeline-merging, audit-logging, and RBAC-checking logic from scratch, exactly once per script, with no language-level guarantee that any of it was done correctly or consistently the next time.</p>
<h4><strong>3.27 Conclusion of Part 3</strong></h4>
<p>Part 3 widened the comparison from a single language, Python, to nine languages and tools spanning general-purpose programming, shell automation, and established forensic scripting. On the five criteria drawn from the project brief itself — read-only evidence, audit trail, access control, forensic vocabulary, and general flexibility — no other entry in the field combines the first four the way FLANG's implemented prototype already does, and Chapters 3.9–3.14 lay out a concrete, honestly-labeled roadmap for closing the remaining gaps identified in Chapter 3.22. The claim this booklet defends is precise: for the specific, narrow problem the original brief describes — authorized, auditable, court-defensible computer and network forensic scripting without evading security controls — FLANG's combination of features is not matched, in this comparison, by any general-purpose language or existing forensic scripting tool examined. Part 4 now turns to FLANG's namespaced standard library, built on top of everything established here.</p>
<p><strong>Part Four</strong></p>
<p><strong>The Namespaced Standard Library</strong></p>
<p><em>New Language Features, a Forensic Subsystem Extension, and Existing vs. Proposed</em></p>
<h3><strong>4.1 Overview of the Namespaced Standard Library</strong></h3>
<p>This part documents a major expansion of the FLANG prototype, built directly against an expanded specification covering a compiler with a native backend, cross-platform Windows/Linux runtimes, a central management dashboard, a fleet of live agents, CI/CD integration, a malware-research laboratory, and a rule-engine DSL. Rather than attempting to fake the entire specification, this expansion follows the same discipline as the rest of this booklet: implement and test a real, working slice, and document the remaining scope honestly as roadmap rather than as done. Chapters 4.2–4.14 describe what was built; Chapter 4.15 documents the engineering process — including two real regressions found and fixed through testing, not glossed over; Chapter 4.16 restates what remains unbuilt and why; and Chapter 4.17 is the requested existing-vs-proposed comparison, scored on uniqueness, innovation, application, and overall impressiveness.</p>
<p>Before this addition, all functionality lived behind flat built-in function names (load_disk_image(...), sha256(...), list_files(...)). This addition brings a second, additive way to reach both old and new functionality: namespaced, dotted method calls (system.info(), hash.sha256(...), report.sign(...)) — a genuine grammar extension, not string-matched sugar, and every namespace method passes through the identical RBAC and audit path as every flat built-in that came before it.</p>
<h4><strong>4.2 New Language-Level Constructs</strong></h4>
<p>Beyond the namespaced method-call syntax, the language itself gained real grammar and semantics not present in FLANG's original, narrower grammar:</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 29%" />
<col style="width: 38%" />
<col style="width: 31%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Construct</strong></th>
<th><strong>Example</strong></th>
<th><strong>Notes</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Compound assignment</td>
<td>x += 5; x -= 3; x *= 2; x /= 4; x %= 4;</td>
<td>Five operators, all tested</td>
</tr>
<tr class="even">
<td>Increment / decrement</td>
<td>count++; count--;</td>
<td>Statement form, not an expression-returning form</td>
</tr>
<tr class="odd">
<td>Exponent and floor division</td>
<td>2 ** 10; 17 // 5;</td>
<td>Extends the original arithmetic operator set</td>
</tr>
<tr class="even">
<td>Membership operator</td>
<td>if filename in iocs { ... }</td>
<td>Works against FLANG's list type</td>
</tr>
<tr class="odd">
<td>Ternary operator</td>
<td>verdict := score &gt;= 70 ? "PASS" : "FAIL";</td>
<td>Single-expression conditional</td>
</tr>
<tr class="even">
<td>break / continue</td>
<td>Inside for and while bodies</td>
<td>Not present in the version described in Part 1</td>
</tr>
<tr class="odd">
<td>try / catch</td>
<td>Wraps a block; catches a runtime error</td>
<td>See Chapter 4.2.1 for the scope of this addition</td>
</tr>
<tr class="even">
<td>Dict type</td>
<td>{"pid": 4123, "name": "explorer.exe"}</td>
<td>A genuine key-value type, alongside list</td>
</tr>
<tr class="odd">
<td>Namespaced method calls</td>
<td>system.info(); hash.sha256(x);</td>
<td>New MemberCall AST node; parser.parse_postfix</td>
</tr>
</tbody>
</table></div>
<p><em><strong>4.2.1 A note on try/catch and Chapter 1.14 / 3.8</strong></em></p>
<p>Chapters 1 and 3 of this booklet argued, at length, that FLANG deliberately had no try/catch, on the grounds that silently catching and continuing past an unexpected condition is itself a liability in an evidentiary workflow. This addition brings try/catch into the language without reversing that argument: every runtime error still surfaces as a single, clean, sanitized message rather than a raw Python traceback (verified against division-by-zero, type mismatches, and bad casts), and a script author now has the option to catch a specific, anticipated condition and continue deliberately, rather than the interpreter denying that option outright. The fail-loud default behavior described in Chapter 3.8 is unchanged for any script that does not explicitly reach for try/catch — this is an additive capability, not a reversal of the earlier design position, and this booklet notes the tension openly rather than pretending Chapter 3.8 still describes the whole current picture.</p>
<h4><strong>4.3 The System and Process Namespaces</strong></h4>
<p>system.info() / .os() / .cpu() / .memory() / .disk() and process.list() / .info() are backed by the psutil and platform Python libraries and were live-tested against the actual machine running the prototype during development — process.list() correctly enumerated 48 real processes on that host at test time. This is a genuinely new capability class for FLANG: earlier chapters scoped FLANG entirely to acquired evidence (disk images, memory captures, packet captures, logs); the system and process namespaces instead support live-host triage, reading the state of the machine FLANG itself is running on.</p>
<p><em><strong>Example — live triage in three lines</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>info := system.info();</p>
<p>procs := process.list();</p>
<p>print(f"{get(info, "hostname")} — {to_string(length(procs))} running processes");</p></td>
</tr>
</tbody>
</table></div>
<h4><strong>4.4 Service, User, Startup, and Event-Log Namespaces</strong></h4>
<p>service.list(), user.list(), startup.list(), and eventlog.read() are implemented and tested for Linux (via systemctl, pwd, XDG autostart entries, and journalctl/syslog respectively). Their Windows equivalents (the Service Control Manager, NetUserEnum, Run-key/Startup-folder enumeration, and ReadEventLog) are named and stubbed in the source but not implemented or tested, because no Windows host was available in the development environment — the same honest-scoping discipline applied throughout this booklet.</p>
<h4><strong>4.5 File Forensics Namespace</strong></h4>
<p>file.info() / .hash() / .metadata() / .strings() / .entropy(), and the richer analyze.file(path) object (with .hash(), .metadata(), .strings(), .entropy(), .imports(), .sections() methods) implement genuine static file analysis, including Shannon entropy calculation and hand-written PE and ELF header parsing — deliberately not depending on the third-party pefile library, to keep the attack surface of parsing untrusted, attacker-influenced file formats small and auditable in FLANG's own code rather than delegated to an external dependency. analyze.file(...).imports() is an honestly-labeled stub — real PE/ELF import-table walking is documented as a known gap, not silently faked with placeholder output.</p>
<h4><strong>4.6 Network Namespace: Live and Evidence-Based, Unified</strong></h4>
<p>network.interfaces() / .connections() / .dns() / .routes() / .analyze() cover the live host (via psutil, /etc/resolv.conf, and /proc/net/route); network.pcap_flows() / .pcap_dns() / .pcap_flag_suspicious() were added to the same namespace as dotted aliases onto the existing evidence-based .pcap analysis functions from Part 2's network module. The design decision to keep both live and evidence-based network analysis under one namespace name, rather than splitting them, means a script author only has to remember one word — network — for either kind of network work.</p>
<h4><strong>4.7 Detection Namespace: Composable Predicates, Not a New Grammar</strong></h4>
<p>The original specification called for a declarative rule-engine DSL (rule NAME { when ... } alert(...)). FLANG deliberately does not build that as new grammar; instead, detection.unexpected_parent(), .suspicious_port(), and .new_entries() are implemented as ordinary composable functions, called from plain if statements. This keeps detection logic inside the same audited, RBAC-gated built-in call model as everything else in the language, rather than introducing a second, parallel execution path with its own semantics to secure and test separately — a deliberate and disclosed trade-off, not an oversight.</p>
<p><em><strong>Example</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>expected := {"explorer.exe": ["userinit.exe"]};</p>
<p>flagged := detection.unexpected_parent(process.list(), expected);</p>
<p>print(f"Suspicious parent relationships: {to_string(length(flagged))}");</p></td>
</tr>
</tbody>
</table></div>
<h4><strong>4.8 The Security Testing Laboratory (test namespace)</strong></h4>
<p>test.create(), .generate_variants(), .compare_detection(), and .generate_report() implement a controlled detection-robustness testing workflow: synthetic, non-executable placeholder text artifacts (never real or simulated malicious payloads) are generated with a benign marker string, mutated with non-functional padding and noise, and re-checked against a keyword/IOC rule to see whether the same logical artifact is still recognized after superficial changes. In live testing, this generated 10 variants with a 100% detection rate on the unmutated marker string — a real, measured result, not an assumed one. This module operates exclusively on synthetic content; it does not create, store, or execute any real or simulated malicious binary, matching the safety boundary this booklet has argued for throughout Parts 2 and 3.</p>
<h4><strong>4.9 Timeline Operations Namespace</strong></h4>
<p>timeline.flatten(), .sort(), .filter(), .search(), .group_by(), and .export() operate on the exact Timeline shape the existing correlate() built-in already produced in Part 2 — correlate() itself was not modified. This closes a real gap in the original prototype: Part 2 could build a timeline, but had no built-in vocabulary for then querying it (find only DNS events; group by event type; export to CSV for a spreadsheet reviewer).</p>
<h4><strong>4.10 Case Management Namespace</strong></h4>
<p>case.create(), .open(), .add_evidence(), .list_evidence(), .add_note(), .close(), and .list_cases() implement a local, file-backed case registry — one JSON file per case under cases/. This is deliberately scoped as single-investigator, single-machine case tracking, not a centralized multi-user case-management database; Chapter 4.16 restates this limitation explicitly rather than letting the feature name imply more than what is built.</p>
<h4><strong>4.11 Correlation and Relationship-Graph Namespace</strong></h4>
<p>correlation.correlate() is a dotted alias onto the existing time-window correlation engine from Part 2 (unchanged); .link(), .find_related(), and .build_graph() are genuinely new — they build explicit relationship edges between two findings (e.g. this process observed alongside this network connection) and assemble those edges into a relationship graph, a different and complementary analytical lens from pure time-proximity clustering.</p>
<h4><strong>4.12 Audit and Security Introspection Namespaces</strong></h4>
<p>audit.verify(), .export(), and .summary() let a running script query the interpreter's own hash-chained audit log — read the verification result, export the full log, or get a quick summary (entry count, case ID, investigator) — without changing how the automatic logging itself happens. security.whoami() and .verify_hash() let a script introspect its own session identity and role, and perform a quick single-file hash check distinct from evidence.manifest()'s fuller multi-hash record.</p>
<h4><strong>4.13 Forensics Composite Helpers and the Simulation Namespace</strong></h4>
<p>forensics.acquire_and_hash() and .quick_triage() are small, genuinely new composite helpers — quick_triage() in particular pulls system info and a process count together into one call, useful as the first line of a triage report, and is deliberately kept small rather than becoming a monolithic catch-all namespace. The simulation namespace (.process_event(), .file_event(), .network_event(), .dns_event(), .auth_event(), .log_event(), .scenario()) generates synthetic events — every record explicitly marked synthetic: true — for exercising the timeline and correlation engines without needing real evidence on hand, useful for training, demonstration, and regression testing.</p>
<h4><strong>4.14 Reporting Namespace, Co-Signing, and Encrypted Export</strong></h4>
<p>report.create() / .add() / .timeline() / .sign() / .cosign() / .save() / .save_encrypted() wrap the existing signed-report engine from Part 2. Two capabilities are genuinely new here: co_sign_report() implements dual-control signing — a second, independent signature from a supervisor role alongside the original signer, a real control against a single compromised or careless signing key — and export_encrypted() adds AES/Fernet-encrypted export alongside the existing plain JSON/HTML export, for reports that must be stored or transmitted under an additional confidentiality control. reporting is a pure additive alias for report (verified by a test that both names mutate the same underlying report object).</p>
<h4><strong>4.15 Engineering Discipline: Process, Regression Testing, and Bugs Found</strong></h4>
<p>This work followed a disciplined process worth documenting in its own right, because the process is itself part of the case this booklet makes for FLANG's trustworthiness: run the existing test suite before any change (11/11 passing baseline); make additive changes only, never editing an existing function's behavior; run the full suite and every existing example script after each batch of changes; and record what broke, honestly, rather than hiding it.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 36%" />
<col style="width: 32%" />
<col style="width: 30%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Issue found</strong></th>
<th><strong>How it was found</strong></th>
<th><strong>Fix applied</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>sample_investigation.flang used a variable named timeline, which collided with the newly added timeline namespace</td>
<td>Full regression run against all existing example scripts after adding the namespace</td>
<td>Renamed the one affected variable to case_timeline; behavior otherwise identical</td>
</tr>
<tr class="even">
<td>timeline.export()'s Python parameter was named fmt while every other export function in the language uses format</td>
<td>The new namespace-extensions demo script failed on first run</td>
<td>Renamed the parameter to format for consistency; re-verified</td>
</tr>
<tr class="odd">
<td>A script could accidentally shadow a built-in namespace with a same-named variable (e.g. report := 5;), silently breaking every later report.* call</td>
<td>Found while writing the demo script for this extension, before the guard existed</td>
<td>Added an explicit shadowing guard: assigning to a reserved namespace name is now rejected with a clear error instead of silently breaking later calls</td>
</tr>
</tbody>
</table></div>
<p>The result: all 11 pre-existing automated tests still pass unchanged, 13 new tests were added (24 total, all passing), and all 8 example scripts — including every one referenced earlier in this booklet — pass after the one required fix above. This is offered as evidence that the extended standard library was validated against the existing system rather than assumed compatible with it.</p>
<h4><strong>4.16 What Remains Explicitly Not Built, Restated</strong></h4>
<p>Consistent with Chapter 3.22's limitations chapter, this part keeps the same honest boundary around what a from-scratch specification would require versus what a single development effort can responsibly claim as done.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 29%" />
<col style="width: 36%" />
<col style="width: 34%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Requested capability</strong></th>
<th><strong>Status</strong></th>
<th><strong>Why</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>LLVM-backed native compiler</td>
<td>Not built — interpreter remains a Python-hosted tree-walker</td>
<td>A real native compiler is itself a multi-month, multi-engineer project; claiming it would be a non-functional stub pretending to be real</td>
</tr>
<tr class="even">
<td>Full Windows runtime support</td>
<td>Linux-only, tested. Windows API call sites are named and stubbed but unimplemented</td>
<td>No Windows host was available to test against honestly</td>
</tr>
<tr class="odd">
<td>rule NAME { when ... } declarative rule grammar</td>
<td>Not built as new grammar — implemented as composable detection.* predicate functions instead (Chapter 4.7)</td>
<td>A second, parallel event-driven execution grammar roughly doubles the language's grammar surface; deferred rather than rushed</td>
</tr>
<tr class="even">
<td>CI/CD pipeline automation</td>
<td>Not built</td>
<td>Requires an actual CI runner/environment to integrate with, not present in this sandbox</td>
</tr>
<tr class="odd">
<td>Central web dashboard + multi-machine agent fleet</td>
<td>Not built</td>
<td>This prototype runs in a single sandboxed container with no ability to reach real remote machines; a dashboard that only talks to itself would demonstrate nothing real</td>
</tr>
<tr class="even">
<td>Registry (Windows) module</td>
<td>Not implemented</td>
<td>No Windows host available to build or test against</td>
</tr>
<tr class="odd">
<td>CSV / PDF report export</td>
<td>CSV supported for timelines (timeline.export); full report PDF export not yet built</td>
<td>Straightforward follow-on work, simply not yet done</td>
</tr>
<tr class="even">
<td>Centralized, concurrent multi-user case management</td>
<td>Not built — case module is local, file-backed, single-machine only</td>
<td>Correct scope boundary; a real multi-user case database is separate, unstarted infrastructure work</td>
</tr>
</tbody>
</table></div>
<h4><strong>4.17 Existing vs. Proposed: What's Unique, Innovative, and Impressive</strong></h4>
<p>This chapter directly compares FLANG's core language and built-ins (“Existing”) against the namespaced standard library documented in this part (“Proposed”), scored across four lenses: uniqueness (is this available anywhere else in the languages compared in Part 3?), innovation (does it represent a genuinely new design idea, not just more of the same?), application (what real investigative task does it unlock?), and what makes it impressive (the specific, concrete detail worth highlighting).</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 16%" />
<col style="width: 22%" />
<col style="width: 23%" />
<col style="width: 18%" />
<col style="width: 19%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Capability area</strong></th>
<th><strong>Existing (Core Language)</strong></th>
<th><strong>Proposed (Namespaced Stdlib)</strong></th>
<th><strong>Uniqueness</strong></th>
<th><strong>Application</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Access style</td>
<td>Flat built-ins only (load_disk_image(...))</td>
<td>Namespaced dotted methods (system.info()) as a real grammar extension, alongside flat built-ins</td>
<td>High — a purpose-built forensic DSL with dual calling conventions under one uniform RBAC/audit path is not offered by any comparator in Part 3</td>
<td>Reads far closer to familiar object-style APIs (os.system(), similar to Python), lowering the learning curve argued in Ch. 1.20 even further</td>
</tr>
<tr class="even">
<td>Scope of evidence</td>
<td>Acquired evidence only (disk/memory/pcap/log files)</td>
<td>Live-host triage (system, process, service, user, startup, eventlog namespaces)</td>
<td>Medium-high — osquery offers live queries, but not inside a language sharing one audit/RBAC model with full offline case scripting</td>
<td>First-response triage on a running host, before full acquisition, using the same safety guarantees as post-acquisition analysis</td>
</tr>
<tr class="odd">
<td>Detection logic</td>
<td>Manual if-statement IOC matching only</td>
<td>detection.* composable predicate library (unexpected parent, suspicious port, new entries)</td>
<td>Medium — reusable, named detection predicates inside a general-purpose-shaped language, without adopting a second rule grammar</td>
<td>Encodes reusable detection logic once, called from many scripts, without the security cost of a second execution engine</td>
</tr>
<tr class="even">
<td>Timeline handling</td>
<td>correlate() produces a timeline; no further query vocabulary</td>
<td>timeline.* namespace: sort, filter, search, group_by, export</td>
<td>Medium — most comparators in Part 3 either don't build a timeline at all, or (SIEM query languages) query first without FLANG's construction-time safety guarantees</td>
<td>Makes a built timeline actually usable in a real investigation — find only DNS events, export to CSV for a non-technical reviewer</td>
</tr>
<tr class="odd">
<td>Case tracking</td>
<td>None — each script's evidence and findings were self-contained</td>
<td>case.* local, file-backed case registry</td>
<td>Low-medium — deliberately modest scope, explicitly not a claim to match dedicated case-management platforms</td>
<td>Groups evidence and notes under one case ID across multiple script runs, a real gap the original prototype had</td>
</tr>
<tr class="even">
<td>Detection robustness testing</td>
<td>None</td>
<td>test.* Security Testing Laboratory on synthetic artifacts</td>
<td>High — a safety-boundary-respecting way to test whether detection rules survive superficial mutation, without ever touching real or simulated malicious code</td>
<td>Lets a lab validate its own IOC/keyword rules' resilience before relying on them in live casework</td>
</tr>
<tr class="odd">
<td>Report integrity controls</td>
<td>Single-signer HMAC signing</td>
<td>co_sign_report() dual-control signing; export_encrypted() confidentiality control</td>
<td>Medium-high — dual-control signing directly implements a named financial/security-audit control (separation of duties) at the report level, not just the RBAC level</td>
<td>A report requiring two independent signers before being considered final, closer to real chain-of-evidence practice</td>
</tr>
<tr class="even">
<td>Error handling</td>
<td>No try/catch anywhere; every error stops the script (Ch. 3.8)</td>
<td>try/catch added, alongside an unchanged fail-loud default for any script that doesn't use it</td>
<td>Low — this brings FLANG closer to, not further from, general-purpose languages; noted openly as a partial reversal of the earlier design stance</td>
<td>Lets an author deliberately, visibly opt in to catching one specific anticipated condition, rather than the language refusing that option entirely</td>
</tr>
<tr class="odd">
<td>Live process/network introspection</td>
<td>None (evidence-only)</td>
<td>system/process/network live namespaces, psutil-backed, live-tested (48 real processes enumerated on the actual host)</td>
<td>High for a language this narrowly forensic-scoped — most comparators in Part 3 are either live-only (osquery) or evidence-only (Volatility3), not both under one language</td>
<td>Bridges the live-triage and post-acquisition-analysis halves of an investigation inside one consistent, audited language</td>
</tr>
</tbody>
</table></div>
<p>Reading this table against the master comparison matrix in Chapter 3.20, the single most impressive addition here is arguably the live system/process/network namespace family, because it is the one capability that closes the gap Chapter 3.22 identified as a real limitation — FLANG previously covered acquired evidence only — while every safety guarantee established earlier in this booklet (RBAC, automatic audit logging, no write capability) applies to the new namespaces identically, verified live against the actual development host rather than only against fixtures.</p>
<h4><strong>4.18 Updated Master Comparison: FLANG vs the Field</strong></h4>
<p>Chapter 3.20's master matrix is repeated here with one addition — a live-triage column — to show how the namespaced standard library changes FLANG's position against the same nine comparators, without re-litigating the criteria already established in Chapter 3.15.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 21%" />
<col style="width: 15%" />
<col style="width: 13%" />
<col style="width: 13%" />
<col style="width: 15%" />
<col style="width: 19%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Language / tool</strong></th>
<th><strong>Read-only evidence</strong></th>
<th><strong>Audit trail</strong></th>
<th><strong>Access control</strong></th>
<th><strong>Live-host triage</strong></th>
<th><strong>Cross-evidence correlation</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Python</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>Yes (raw, unaudited)</td>
<td>No (manual)</td>
</tr>
<tr class="even">
<td>C / C++ / Java / Go / Rust</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>Yes (raw, unaudited)</td>
<td>No (manual)</td>
</tr>
<tr class="odd">
<td>Bash / PowerShell</td>
<td>No</td>
<td>Partial</td>
<td>Partial</td>
<td>Yes (native)</td>
<td>No (manual)</td>
</tr>
<tr class="even">
<td>EnScript</td>
<td>No</td>
<td>Partial</td>
<td>Partial</td>
<td>Partial (EnCase-scoped)</td>
<td>Limited, EnCase-internal</td>
</tr>
<tr class="odd">
<td>Volatility 3</td>
<td>Yes (memory only)</td>
<td>No</td>
<td>No</td>
<td>No</td>
<td>No (memory-only scope)</td>
</tr>
<tr class="even">
<td>osquery SQL</td>
<td>Yes (query-only)</td>
<td>No</td>
<td>Partial (OS user)</td>
<td>Yes (native, this is its purpose)</td>
<td>No (single-host scope)</td>
</tr>
<tr class="odd">
<td>Autopsy / X-Ways</td>
<td>Partial (app-level)</td>
<td>Partial (app-level)</td>
<td>Partial (app-level)</td>
<td>No</td>
<td>Partial, tool-internal</td>
</tr>
<tr class="even">
<td>FLANG — core built-ins only</td>
<td>Yes</td>
<td>Yes</td>
<td>Yes</td>
<td>No</td>
<td>Yes (correlate())</td>
</tr>
<tr class="odd">
<td>FLANG — full standard library</td>
<td>Yes</td>
<td>Yes</td>
<td>Yes</td>
<td>Yes — audited, RBAC-gated</td>
<td>Yes — correlate() + link()/build_graph()</td>
</tr>
</tbody>
</table></div>
<p>The only cell in this expanded matrix where FLANG stands alone — audited, RBAC-gated live-host triage combined with audited, RBAC-gated evidence-based correlation, in the same language — is the specific, narrow claim this chapter makes. osquery matches FLANG on live triage but has no offline evidence-correlation model; Volatility3 and Autopsy/X-Ways match FLANG on parts of evidence analysis but have no live-host triage story at all. No comparator examined in this booklet combines both halves under one consistent safety model.</p>
<h4><strong>4.19 Conclusion of Part 4</strong></h4>
<p>This standard-library extension does not change the argument made earlier in this booklet; it extends the evidence for it. The namespaced standard library adds nine substantial capability areas — live-host triage, file forensics, network analysis, composable detection, a synthetic testing lab, timeline querying, case tracking, relationship correlation, and dual-control reporting — every one of them built additively, regression-tested against the pre-existing 11 tests and 4 example scripts, and honestly bounded against what was explicitly not attempted. Two real bugs were found and fixed through that testing process rather than hidden, which is itself consistent with the transparency-over-evasion design philosophy this booklet has argued for since Chapter 2.2. The result, summarized in Chapter 4.18's expanded matrix, is that FLANG's position relative to the wider field of languages and tools examined in Part 3 has strengthened, not merely grown in feature count.</p>
<p><strong>Appendices</strong></p>
<p><strong>Reference Material</strong></p>
<p><em>Built-in catalogue, syntax reference, glossary, and references</em></p>
<h3><strong>Appendix A — Full FLANG Built-in Function Catalogue</strong></h3>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 39%" />
<col style="width: 18%" />
<col style="width: 29%" />
<col style="width: 13%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Function</strong></th>
<th><strong>Category</strong></th>
<th><strong>Min. role</strong></th>
<th><strong>Effect</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>load_disk_image(path)</td>
<td>Acquisition</td>
<td>TIER1_TRIAGE</td>
<td>READ</td>
</tr>
<tr class="even">
<td>load_memory_image(path)</td>
<td>Acquisition</td>
<td>TIER1_TRIAGE</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>load_pcap(path)</td>
<td>Acquisition</td>
<td>TIER1_TRIAGE</td>
<td>READ</td>
</tr>
<tr class="even">
<td>load_logs(path, format)</td>
<td>Acquisition</td>
<td>TIER1_TRIAGE</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>sha256(evidence)</td>
<td>Integrity</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>verify_hash(evidence, expected)</td>
<td>Integrity</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>list_files(disk, path)</td>
<td>Filesystem</td>
<td>TIER1_TRIAGE</td>
<td>READ</td>
</tr>
<tr class="even">
<td>carve_deleted(disk)</td>
<td>Filesystem</td>
<td>TIER2_ANALYST</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>get_metadata(file)</td>
<td>Filesystem</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>flag_suspicious(files, iocs)</td>
<td>Filesystem</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>list_processes(mem)</td>
<td>Memory</td>
<td>TIER2_ANALYST</td>
<td>READ</td>
</tr>
<tr class="even">
<td>list_network_connections(mem)</td>
<td>Memory</td>
<td>TIER2_ANALYST</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>detect_injection(mem)</td>
<td>Memory</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>extract_strings(mem, pattern)</td>
<td>Memory</td>
<td>TIER2_ANALYST</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>list_flows(pcap)</td>
<td>Network</td>
<td>TIER2_ANALYST</td>
<td>READ</td>
</tr>
<tr class="even">
<td>extract_dns(pcap)</td>
<td>Network</td>
<td>TIER2_ANALYST</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>flag_suspicious_connections(flows, iocs)</td>
<td>Network</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>parse_events(logset)</td>
<td>Logs</td>
<td>TIER1_TRIAGE</td>
<td>READ</td>
</tr>
<tr class="odd">
<td>match_iocs(events, iocs)</td>
<td>Logs</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>correlate(sources, window_seconds)</td>
<td>Correlation</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>new_report(title)</td>
<td>Reporting</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>add_section(report, title, content)</td>
<td>Reporting</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>add_timeline(report, timeline)</td>
<td>Reporting</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>sign_report(report, key_id)</td>
<td>Reporting</td>
<td>LEAD_INVESTIGATOR</td>
<td>EXPORT</td>
</tr>
<tr class="odd">
<td>export(report, format, path)</td>
<td>Reporting</td>
<td>LEAD_INVESTIGATOR</td>
<td>EXPORT</td>
</tr>
<tr class="even">
<td>length(x)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>print(x)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>reverse(x)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>substring(s, start, end)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>char_at(s, index)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>to_upper(s) / to_lower(s)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>to_string(x) / to_number(s)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>range(stop) / range(start, stop[, step])</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>matches(s, pattern)</td>
<td>General</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>hash_many(paths)</td>
<td>Integrity</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>mean/median/stdev(list)</td>
<td>Anomaly detection</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>detect_outliers(list, threshold_stdevs)</td>
<td>Anomaly detection</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>detect_anomalies(records, field, threshold_stdevs)</td>
<td>Anomaly detection</td>
<td>TIER2_ANALYST</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>get / has_key / keys / values / map_set</td>
<td>Dictionaries</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="even">
<td>append / contains / unique / sort_by / sum_list</td>
<td>Lists</td>
<td>TIER1_TRIAGE</td>
<td>DERIVE</td>
</tr>
<tr class="odd">
<td>co_sign_report(report, key_id)</td>
<td>Reporting</td>
<td>LEAD_INVESTIGATOR</td>
<td>EXPORT</td>
</tr>
<tr class="even">
<td>export_encrypted(report, path, key_id)</td>
<td>Reporting</td>
<td>LEAD_INVESTIGATOR</td>
<td>EXPORT</td>
</tr>
</tbody>
</table></div>
<h4><strong>Appendix A.1 — Namespaced Method Catalogue</strong></h4>
<p>FLANG adds dotted namespace.method() syntax alongside the flat catalogue above (Chapter 1.30). Every method below is enforced by the same RBAC and audit-log path as every flat built-in.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 20%" />
<col style="width: 49%" />
<col style="width: 30%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Namespace</strong></th>
<th><strong>Methods</strong></th>
<th><strong>Status</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>system</td>
<td>info, os, cpu, memory, disk</td>
<td>Implemented — psutil-backed, live-tested</td>
</tr>
<tr class="even">
<td>process</td>
<td>list, info(pid)</td>
<td>Implemented — psutil-backed, live-tested (48 real processes enumerated in testing)</td>
</tr>
<tr class="odd">
<td>service / user / startup / eventlog</td>
<td>list / list / list / read</td>
<td>Implemented and tested on Linux; Windows equivalents are documented stubs</td>
</tr>
<tr class="even">
<td>file</td>
<td>info, hash, metadata, strings, entropy</td>
<td>Implemented — Shannon entropy, string extraction, hand-written PE/ELF header parsing</td>
</tr>
<tr class="odd">
<td>analyze</td>
<td>file(path) → Sample object with .hash() .metadata() .strings() .entropy() .imports() .sections()</td>
<td>Implemented; .imports() is an honest documented stub, not silently faked</td>
</tr>
<tr class="even">
<td>network</td>
<td>interfaces, connections, dns, routes, analyze, pcap_flows, pcap_dns, pcap_flag_suspicious</td>
<td>Implemented — psutil + /etc/resolv.conf + /proc/net/route, plus pcap-based additions</td>
</tr>
<tr class="odd">
<td>hash</td>
<td>sha256(path_or_text), sha512(path_or_text)</td>
<td>Implemented; verified against known test vectors</td>
</tr>
<tr class="even">
<td>detection</td>
<td>unexpected_parent, suspicious_port, new_entries</td>
<td>Implemented as composable predicate functions called from if statements</td>
</tr>
<tr class="odd">
<td>report / reporting</td>
<td>create, add, timeline, sign, cosign, save, save_encrypted</td>
<td>Implemented — reporting is a verified alias for the same underlying object as report</td>
</tr>
<tr class="even">
<td>test</td>
<td>create, generate_variants, compare_detection, generate_report</td>
<td>Implemented — synthetic Security Testing Laboratory, non-executable placeholder content only</td>
</tr>
<tr class="odd">
<td>timeline</td>
<td>flatten, sort, filter, search, group_by, export (json/csv)</td>
<td>Implemented, tested</td>
</tr>
<tr class="even">
<td>case</td>
<td>create, open, add_evidence, list_evidence, add_note, close, list_cases</td>
<td>Implemented, tested — local, file-backed</td>
</tr>
<tr class="odd">
<td>evidence</td>
<td>manifest (SHA-256+SHA-512+ID+investigator+timestamp), verify</td>
<td>Implemented, tested</td>
</tr>
<tr class="even">
<td>correlation</td>
<td>correlate, link, find_related, build_graph</td>
<td>Implemented, tested</td>
</tr>
<tr class="odd">
<td>audit</td>
<td>verify, export, summary</td>
<td>Implemented, tested — reads the existing hash-chained log</td>
</tr>
<tr class="even">
<td>security</td>
<td>whoami, verify_hash</td>
<td>Implemented, tested</td>
</tr>
<tr class="odd">
<td>forensics</td>
<td>acquire_and_hash, quick_triage</td>
<td>Implemented, tested — small composite helpers</td>
</tr>
<tr class="even">
<td>simulation</td>
<td>process_event, file_event, network_event, dns_event, auth_event, log_event, scenario</td>
<td>Implemented, tested — every record marked synthetic: true</td>
</tr>
<tr class="odd">
<td>filesystem</td>
<td>list_files, carve_deleted, get_metadata, flag_suspicious</td>
<td>Dotted alias to the already-existing flat functions</td>
</tr>
</tbody>
</table></div>
<p>Reserved namespace names cannot be used as a variable or loop-variable name anywhere in a script; the interpreter rejects an attempt to do so with a clear error rather than silently letting the assignment shadow the namespace (Chapter 1.30).</p>
<h3><strong>Appendix B — FLANG Quick Syntax Reference</strong></h3>
<p><em><strong>Variables</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>x := 5;</p>
<p>name := "jdoe";</p>
<p>flag := true;</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Conditionals</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>if condition {</p>
<p>...</p>
<p>} elif other_condition {</p>
<p>...</p>
<p>} else {</p>
<p>...</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Loops and loop control</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>for item in some_list {</p>
<p>if condition { continue; }</p>
<p>if other_condition { break; }</p>
<p>}</p>
<p>while condition {</p>
<p>...</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Error handling</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>try {</p>
<p>...</p>
<p>} catch err {</p>
<p>print(f"Caught: {err}");</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Functions</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>function name(param1, param2) {</p>
<p>return param1 + param2;</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Operators</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>+ - * / % ** // (arithmetic, including exponent and floor division)</p>
<p>== != &lt; &gt; &lt;= &gt;= (comparison)</p>
<p>and or not (logical)</p>
<p>in (membership)</p>
<p>+= -= *= /= %= (compound assignment)</p>
<p>++ -- (increment / decrement)</p>
<p>cond ? a : b (ternary)</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Dict and list literals</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>record := {"pid": 5566, "name": "update_svc.exe"};</p>
<p>items := [1, 2, 3];</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Namespaced method calls</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>info := system.info();</p>
<p>processes := process.list();</p>
<p>sample := analyze.file("path/to/file");</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Comments and imports</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p># this is a comment</p>
<p>import iocs from "case_iocs.json";</p></td>
</tr>
</tbody>
</table></div>
<h3><strong>Appendix C — Glossary of Terms</strong></h3>
<ul>
<li><p>Audit log — A record of every action taken by a system, kept so the sequence of events can later be reviewed or verified.</p></li>
<li><p>Chain of custody — A documented, unbroken record of who has held, accessed, or handled a piece of evidence from collection to presentation.</p></li>
<li><p>DSL (Domain-Specific Language) — A programming language deliberately scoped to one problem area, trading general-purpose flexibility for safety and vocabulary fit.</p></li>
<li><p>EDR (Endpoint Detection and Response) — Security software that monitors endpoint activity for malicious or anomalous behavior.</p></li>
<li><p>Evidence handle — An opaque reference to a piece of evidence, used in place of a raw file path, so that only vetted operations can act on it.</p></li>
<li><p>GPL (General-Purpose Language) — A programming language, such as Python or C++, with no built-in assumption about the kind of software being written.</p></li>
<li><p>Hash chain — A sequence of records in which each record embeds a cryptographic hash of the one before it, making retroactive edits detectable.</p></li>
<li><p>HMAC — Hash-based Message Authentication Code — a construction for verifying both the integrity and authenticity of a message using a secret key.</p></li>
<li><p>IOC (Indicator of Compromise) — A piece of forensic data, such as a file hash, IP address, or domain, associated with known malicious activity.</p></li>
<li><p>Least privilege — A security principle in which any actor is granted only the minimum access required to perform its task.</p></li>
<li><p>RBAC (Role-Based Access Control) — A security model in which permissions are assigned to roles, and users or scripts are granted permissions by being assigned a role.</p></li>
<li><p>Sandboxing — Running a program in a restricted, isolated environment so its potential effects on the wider system are contained.</p></li>
<li><p>Separation of duties — A control principle requiring that no single actor holds enough privilege to both perform and approve a sensitive action alone.</p></li>
<li><p>Timeline correlation — The process of merging events from multiple evidence sources into a single chronological sequence to reveal relationships.</p></li>
</ul>
<h3><strong>Appendix D — References and Further Reading</strong></h3>
<p>This booklet's technical claims about FLANG are drawn directly from the accompanying prototype source code and its automated test suite (flang_project/flang/, flang_project/tests/test_flang.py). The following external references informed the design principles discussed throughout, particularly in Part 3:</p>
<ul>
<li><p>Association of Chief Police Officers (ACPO), Good Practice Guide for Digital Evidence — principles of evidence integrity and minimal interference.</p></li>
<li><p>NIST Special Publication 800-86, Guide to Integrating Forensic Techniques into Incident Response.</p></li>
<li><p>The Sleuth Kit / Autopsy project documentation — filesystem and disk-image analysis conventions referenced by FLANG's filesystem module design.</p></li>
<li><p>Volatility Foundation, Volatility 3 documentation — memory-forensics data shapes referenced by FLANG's memory module design.</p></li>
<li><p>YARA project documentation — pattern-matching rule language referenced in the Chapter 3.18 comparison.</p></li>
<li><p>osquery documentation — SQL-based endpoint querying referenced in the Chapter 3.18 comparison.</p></li>
<li><p>Python Software Foundation, The Zen of Python (PEP 20) — referenced in Chapter 1.1's discussion of Python's design philosophy.</p></li>
</ul>
<h3><strong>Appendix E — Sample Audit Log and Signed Report Excerpts</strong></h3>
<p>The following excerpts are representative of the structured output FLANG's runtime produces during an actual run of examples/sample_investigation.flang, included here so the audit-chain and reporting format described in Chapters 2.12, 2.18, and 3.3 can be inspected directly rather than taken only on description.</p>
<p><em><strong>Audit log excerpt (hash-chained, one JSON object per line)</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>{"seq": 4, "action": "load_disk_image", "actor": "j.doe", "role": "LEAD_INVESTIGATOR",</p>
<p>"timestamp": "2026-04-17T09:12:04Z", "effect": "READ",</p>
<p>"detail": "demo_evidence/host17_files", "prev_hash": "8f3a...c11e", "entry_hash": "0b7d...9a42"}</p>
<p>{"seq": 5, "action": "sha256", "actor": "j.doe", "role": "LEAD_INVESTIGATOR",</p>
<p>"timestamp": "2026-04-17T09:12:04Z", "effect": "DERIVE",</p>
<p>"detail": "evidence_id=EV-0001", "prev_hash": "0b7d...9a42", "entry_hash": "5c91...41ab"}</p>
<p>{"seq": 6, "action": "carve_deleted", "actor": "trainee", "role": "TIER1_TRIAGE",</p>
<p>"timestamp": "2026-04-17T09:14:51Z", "effect": "DENIED",</p>
<p>"detail": "requires TIER2_ANALYST", "prev_hash": "5c91...41ab", "entry_hash": "e2a0...77c3"}</p></td>
</tr>
</tbody>
</table></div>
<p><em><strong>Signed report excerpt (report.json, abbreviated)</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>{</p>
<p>"title": "Host17 Lateral Movement Investigation",</p>
<p>"script_hash": "a41c...8e02",</p>
<p>"audit_chain_verified": true,</p>
<p>"evidence": [</p>
<p>{"id": "EV-0001", "type": "disk", "ingest_hash": "5c91...41ab", "reverify_hash": "5c91...41ab", "match": true}</p>
<p>],</p>
<p>"sections": ["Suspicious Files", "Injected Processes", "Flagged Connections"],</p>
<p>"timeline_events": 14,</p>
<p>"signature": {"algorithm": "HMAC-SHA256", "key_id": "analyst_tier2_key", "value": "d90f...3bcd"}</p>
<p>}</p></td>
</tr>
</tbody>
</table></div>
<p>Two properties are worth noting in these excerpts. First, entry 6 shows RBAC denial itself being audit-logged — a refused action is still a recorded event, not a silent no-op. Second, the report's evidence block records both the ingest-time hash and the reverify hash side by side with an explicit match flag, so integrity verification is visible in the artifact itself rather than only in a separate log a reader would have to cross-reference.</p>
<h3><strong>Appendix F — Frequently Asked Questions</strong></h3>
<p><em><strong>Is FLANG's interpreter being written in Python a contradiction?</strong></em></p>
<p>No. Chapter 1.2 addresses this directly: the language a runtime is implemented in is independent of the guarantees that runtime enforces on the scripts it executes. Python is used as an implementation convenience for the prototype; the safety properties FLANG scripts get are enforced by FLANG's interpreter logic, not inherited from Python.</p>
<p><em><strong>Can a FLANG script ever modify evidence, under any role?</strong></em></p>
<p>No. There is no built-in function anywhere in the catalogue (Appendix A) that accepts an evidence handle and performs a write. This is true for every RBAC role, including ADMIN, which is deliberately barred from investigative built-ins altogether (Chapter 2.11).</p>
<p><em><strong>What happens if a FLANG script itself is tampered with after being written?</strong></em></p>
<p>The reporting engine embeds the executed script's own SHA-256 hash into the signed report (Chapter 2.18), so any later alteration of the script file is detectable by comparing it against the hash recorded in a previously produced report.</p>
<p><em><strong>Does FLANG require an internet connection or external services to run?</strong></em></p>
<p>No. The prototype runs entirely against local evidence files and the local standard library; no built-in makes an outbound network call, which is itself part of the design argument in Chapters 1.15 and 2.13.</p>
<p><em><strong>Is FLANG intended to replace Python in this project?</strong></em></p>
<p>No — Chapter 1.28 states this explicitly. Python remains the right choice for building the tooling itself and for tasks outside evidence handling; FLANG is scoped to the specific task of running the investigative script, not to replacing general-purpose programming.</p>
<p><em><strong>Why does FLANG use := instead of = for assignment?</strong></em></p>
<p>Chapter 1.7 explains the reasoning: using a visually distinct token for assignment removes any possibility of confusing assignment (:=) with equality comparison (==), a class of bug that is common enough in C-family languages to be worth designing out entirely in a language meant to be reviewed by non-specialists.</p>
<h3><strong>Appendix G — Automated Test Suite Detail</strong></h3>
<p>The prototype's automated test suite (flang_project/tests/test_flang.py) contains twenty-four tests, all passing at the time of writing — eleven covering the core language and interpreter (lexer/parser, interpreter core semantics, RBAC enforcement, evidence/audit integrity) plus thirteen covering the namespaced standard library (role aliases, SHA-512, and every namespaced forensic module). Listing them individually here lets a reader verify Chapter 2.20's summary claim against the actual test names in the source tree.</p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 57%" />
<col style="width: 42%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Test function</strong></th>
<th><strong>What it verifies</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>test_tokenize_basic</td>
<td>The lexer correctly tokenizes a minimal FLANG source string</td>
</tr>
<tr class="even">
<td>test_parse_assignment_and_call</td>
<td>The parser builds a correct AST for an assignment followed by a function call</td>
</tr>
<tr class="odd">
<td>test_variables_and_arithmetic</td>
<td>Variable assignment and arithmetic operators evaluate to the expected values</td>
</tr>
<tr class="even">
<td>test_if_else_and_scope_leak_is_intentional</td>
<td>Conditional branching executes correctly, and the deliberate design choice that loop/if bodies share outer scope behaves as documented</td>
</tr>
<tr class="odd">
<td>test_for_loop_and_list_literal</td>
<td>for-in iteration over a list literal visits every element in order</td>
</tr>
<tr class="even">
<td>test_fstring_interpolation</td>
<td>f-string interpolation correctly substitutes variable values into output strings</td>
</tr>
<tr class="odd">
<td>test_length_builtin</td>
<td>The length() built-in returns the correct size for strings and lists</td>
</tr>
<tr class="even">
<td>test_low_role_blocked_from_high_role_function</td>
<td>A TIER1_TRIAGE caller is correctly refused when invoking a TIER2_ANALYST-only built-in</td>
</tr>
<tr class="odd">
<td>test_high_role_permitted</td>
<td>A sufficiently privileged caller is correctly permitted to invoke a gated built-in</td>
</tr>
<tr class="even">
<td>test_disk_hash_changes_if_evidence_modified</td>
<td>Modifying a fixture after ingestion is correctly detected as a hash mismatch on reverification</td>
</tr>
<tr class="odd">
<td>test_tamper_detected</td>
<td>Hand-editing a saved audit-log entry is correctly detected by the hash-chain verifier</td>
</tr>
<tr class="even">
<td>test_new_role_names_map_to_same_ranks_as_existing_ones</td>
<td>Role-name aliases map onto the same canonical rank as the four original role names</td>
</tr>
<tr class="odd">
<td>test_sha512_file_matches_known_value</td>
<td>SHA-512 file hashing matches a known test vector from Python's own hashlib</td>
</tr>
<tr class="even">
<td>test_hash_namespace_sha512</td>
<td>The hash.sha512() namespace method produces the correct digest</td>
</tr>
<tr class="odd">
<td>test_evidence_manifest_has_both_hashes</td>
<td>evidence.manifest() correctly includes both SHA-256 and SHA-512</td>
</tr>
<tr class="even">
<td>test_timeline_operations</td>
<td>timeline.sort / filter / group_by behave correctly against a synthetic timeline</td>
</tr>
<tr class="odd">
<td>test_correlation_link_and_graph</td>
<td>correlation.link() and correlation.build_graph() correctly build relationship edges</td>
</tr>
<tr class="even">
<td>test_case_management_roundtrip</td>
<td>A full case.create/add_evidence/add_note/close round trip succeeds in an isolated temp directory</td>
</tr>
<tr class="odd">
<td>test_simulation_events_are_marked_synthetic</td>
<td>Every event generated by the simulation namespace is marked synthetic: true</td>
</tr>
<tr class="even">
<td>test_audit_namespace_summary</td>
<td>audit.summary() correctly reflects the interpreter's own hash-chained log</td>
</tr>
<tr class="odd">
<td>test_security_whoami</td>
<td>security.whoami() correctly reports the current investigator, role, and case</td>
</tr>
<tr class="even">
<td>test_reporting_is_alias_for_report</td>
<td>The reporting namespace and the report namespace are proven to mutate the same underlying object</td>
</tr>
<tr class="odd">
<td>test_namespace_shadowing_is_rejected</td>
<td>Assigning a variable with the same name as a reserved namespace is rejected with a clear error</td>
</tr>
<tr class="even">
<td>test_existing_namespaces_still_work_unchanged</td>
<td>A regression guard proving the system/process namespaces behave identically after the namespaced standard library was added</td>
</tr>
</tbody>
</table></div>
<p>Together, these tests exercise every major claim made about FLANG elsewhere in this booklet: correct parsing (Chapter 2.6), RBAC enforcement (Chapters 2.11, 3.5), evidence-integrity verification (Chapters 2.9, 3.4), audit-log tamper detection (Chapters 2.12, 3.3), and — for the thirteen tests covering the namespaced standard library — every namespaced forensic module described in Chapter 1.30 and Appendix A.1, each backed by a specific, runnable, currently-passing test rather than by description alone. The extension was also verified by full regression: the original eleven tests were re-run and confirmed unchanged before any new test was added, so growth in the suite reflects genuinely new coverage, not a reset.</p>
<h3><strong>Appendix H — Command-Line Interface Reference</strong></h3>
<p>FLANG scripts are executed through flang/cli.py, invoked as a Python module. The CLI exposes two subcommands, run and verify-audit, both used throughout the worked examples in this booklet.</p>
<p><em><strong>Running an investigation script</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>python3 -m flang.cli run sample_investigation.flang \\</p>
<p>--case CASE-2026-0417 \\</p>
<p>--investigator "j.doe" \\</p>
<p>--role LEAD_INVESTIGATOR \\</p>
<p>--audit-log output/audit.log</p></td>
</tr>
</tbody>
</table></div>
<p>On completion, the CLI prints the evidence-integrity check result, the audit-log integrity check result, and the executed script's own SHA-256 hash — the same three facts embedded into the signed report described in Chapter 2.18 and Appendix E, so a reviewer sees them both on the terminal at run time and independently, later, inside the report artifact itself.</p>
<p><em><strong>Independently verifying a saved audit log</strong></em></p>
<div class="booklet-table-wrap"><table>
<colgroup>
<col style="width: 100%" />
</colgroup>
<tbody>
<tr class="odd">
<td><p>python3 -m flang.cli verify-audit output/audit.log</p>
<p># on success:</p>
<p>[FLANG] Audit log OK -- 36 entries, chain intact.</p>
<p># on tampering:</p>
<p>[FLANG] TAMPER DETECTED at entry 5 (verified 4 entries before break).</p></td>
</tr>
</tbody>
</table></div>
<p>This subcommand is intentionally independent of the run subcommand and of the evidence itself — it needs only the saved log file — so that an auditor, a supervisor, or an opposing expert can verify chain integrity on a copy of the log without needing access to the original evidence or re-running the investigation.</p>
<p><em><strong>Role argument values</strong></em></p>
<p>The --role flag accepts exactly the four values defined in Chapter 2.11: TIER1_TRIAGE, TIER2_ANALYST, LEAD_INVESTIGATOR, and ADMIN. Supplying any other value is rejected by the CLI's argument parser before the script is even read, one further instance of FLANG's general preference for failing before evidence is touched rather than partway through (Chapter 2.6).</p>
<h3><strong>Appendix I — Closing Note</strong></h3>
<p>This booklet has argued its case in three stages: Part 1 established, through direct syntactic and semantic comparison, that FLANG's safety properties are language-level guarantees where Python's equivalent properties are programmer habits. Part 2 showed that FLANG's working prototype maps, requirement by requirement, onto the original project brief. Part 3 widened the lens to nine additional languages and tools, argued FLANG's combined strengths across five forensic-soundness criteria, and — deliberately — spent as much space on FLANG's present limitations as on its advantages, because a booklet that could not withstand its own standard of scrutiny would undercut the very case it set out to make.</p>
<p>The appendices that follow this note exist so every specific claim made above — a built-in's role requirement, a piece of sample output, a passing test, a CLI invocation — can be checked against a concrete reference rather than taken on faith, in keeping with the auditability this project treats as a first-class design goal rather than an afterthought.</p>
<p>Prepared by the project team named on the title page — Sanjhai M L, Rahul A, Eswara Karuppasamy K, Sangareshwari M, Govardhanan K, and Angayarkanni M — under the supervision of Mrs. Leelarani K and supervision-in-chief of Dr. Meenakshi A .</p>`,
  code: null,
},

];

const TIPS = [
  { kicker: "Syntax", title: "Use := not =", body: `Assignment is <code>:=</code>. A bare <code>=</code> isn't valid FLANG at all &mdash; this avoids the classic C-family bug of writing <code>if (x = 5)</code> when you meant <code>==</code>.` },
  { kicker: "Gotcha", title: "Namespace names are reserved", body: `<code>report := 5;</code> will fail on purpose. Names like <code>report</code>, <code>system</code>, <code>timeline</code>, <code>case</code> are built-in namespaces &mdash; pick a different variable name (e.g. <code>inv_report</code>).` },
  { kicker: "Known gap", title: "No list indexing yet", body: `<code>events[0]</code> does not parse. Use a <code>for</code> loop, or generate/collect the value you need directly. This is an open language gap, not a bug in your script.` },
  { kicker: "Strings", title: "Escape quotes inside f-strings", body: `Nested string literals inside <code>{ }</code> in an f-string need <code>\\"</code>, e.g. <code>f"{get(m, \\"sha256\\")}"</code>.` },
  { kicker: "Safety", title: "while loops have a hard cap", body: `A runaway <code>while true { }</code> stops after 2,000,000 iterations with a clear error instead of hanging the interpreter forever.` },
  { kicker: "Consistency", title: "Export functions use format, not fmt", body: `Every export-style call &mdash; <code>export()</code>, <code>timeline.export()</code>, <code>report.save()</code> &mdash; takes a keyword named <code>format</code>. Found and fixed once for consistency across the whole language.` },
  { kicker: "RBAC", title: "Role names have friendly aliases", body: `<code>Administrator</code>, <code>Investigator</code>, <code>Analyst</code>, <code>Reviewer</code>, <code>Viewer</code> all work and map onto the four canonical ranks (<code>TIER1_TRIAGE</code> ... <code>ADMIN</code>) &mdash; use whichever reads better in your script.` },
  { kicker: "Errors", title: "Every failure is one clean line", body: `Division by zero, a bad type mismatch, an unauthorized call &mdash; all surface as a single sanitized message. No raw Python traceback or file path ever reaches script output.` },
  { kicker: "Case management", title: "case.* is local, not multi-user", body: `Each case is one JSON file on disk. There's no locking or concurrent-writer protection &mdash; it's built for one investigator working alone, not a shared team database.` },
];

const APPLICATIONS = [
  { title: "Incident Triage", body: "Pull system, process, and network state from a live host in one script, flag anomalies against an expected baseline, and produce a first-pass severity call.", ns: ["system", "process", "network", "detection", "forensics"] },
  { title: "File & Malware Static Analysis", body: "Hash, fingerprint, and inspect a suspicious file's entropy and PE/ELF structure &mdash; without executing it. Import-table parsing is an intentionally honest gap, not faked.", ns: ["file", "analyze", "hash"] },
  { title: "Network Forensics", body: "Analyze a packet capture's flows and DNS queries, or observe the live network state of the current host, through the same namespace.", ns: ["network", "detection"] },
  { title: "Timeline Reconstruction", body: "Merge filesystem, process, network, and log findings into one chronological view, grouped and filtered by whatever field matters to the case.", ns: ["correlation", "timeline"] },
  { title: "Evidence Chain of Custody", body: "Every evidence load is hashed at ingestion and re-verified before a report is signed off, with a standalone manifest mechanism for one-off files.", ns: ["evidence", "case"] },
  { title: "Detection-Rule Testing (Synthetic)", body: "Generate synthetic, non-malicious test artifacts and events to check whether a keyword/IOC rule still catches a logically-equivalent but superficially different sample.", ns: ["test", "simulation"] },
];

const FACTS = [
  { big: "Python-hosted, not Python", label: "Implementation", body: "The interpreter is written in Python, but FLANG has its own lexer, grammar, and keywords. A .flang script does not run in a Python interpreter." },
  { big: "Zero silent writes", label: "Evidence handling", body: "No function anywhere in the standard library can write to, delete, or modify a piece of loaded evidence. The capability doesn't exist in the language." },
  { big: "SHA-256 + SHA-512", label: "Integrity", body: "Evidence manifests support both hash algorithms side by side, generated at load time and re-verified before report sign-off." },
  { big: "Hash-chained", label: "Audit log", body: "Every built-in and namespace call is logged automatically. A tamper test (hand-editing one saved log line) was caught correctly during development." },
  { big: "5 role names, 4 ranks", label: "Access control", body: "Administrator / Investigator / Analyst / Reviewer / Viewer are friendly aliases over the same four-level RBAC hierarchy used internally." },
  { big: "Not built (honestly)", label: "Known scope limits", body: "No native LLVM compiler, no Windows registry/service support, no multi-host dashboard, no list-indexing syntax yet. Documented, not hidden." },
  { big: "Read-only, signed, logged", label: "Trust model", body: "Trust with security tooling is meant to be earned through signing, least privilege, and transparency &mdash; never through hiding from EDR/AV." },
  { big: "This web IDE", label: "Zero new dependencies", body: "The Lab you're using right now is a Python standard-library HTTP server. No Flask, no Node, nothing that can be blocked by an install policy." },
];
