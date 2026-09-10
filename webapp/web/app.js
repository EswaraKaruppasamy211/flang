/* ============================================================
   FLANG Web IDE — app.js
   No framework, no build step. Content data lives in content.js.
   ============================================================ */
const API_BASE_URL = "https://flang-backend.onrender.com";
// ---------------- tab navigation ----------------

const tabButtons = document.querySelectorAll(".tab-btn");
const pages = document.querySelectorAll(".page");

tabButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    const target = btn.dataset.tab;
    if (target === "compiler-lang") {
      showCompilerAuth();
      return;
    }
    tabButtons.forEach((b) => b.classList.toggle("active", b === btn));
    pages.forEach((p) => p.classList.toggle("active", p.id === `page-${target}`));
    if (target === "lab" && typeof editor !== "undefined") {
      setTimeout(() => editor.refresh(), 10);
    }
  });
});

// ---------------- tiny FLANG token highlighter (for static code blocks) ----------------

const FLANG_KEYWORDS = new Set([
  "if", "elif", "else", "for", "in", "while", "function", "return",
  "true", "false", "and", "or", "not", "try", "catch", "break", "continue", "import", "from",
]);

function highlightFlang(source) {
  const escaped = source
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  const tokenPattern = /(#.*$)|("(?:[^"\\]|\\.)*")|(\b\d+(?:\.\d+)?\b)|(\b[a-zA-Z_][a-zA-Z0-9_]*\b)(?=\()|(\b[a-zA-Z_][a-zA-Z0-9_]*\b)/gm;

  return escaped.replace(tokenPattern, (match, comment, str, num, fnCall, ident) => {
    if (comment) return `<span class="tok-com">${comment}</span>`;
    if (str) return `<span class="tok-str">${str}</span>`;
    if (num) return `<span class="tok-num">${num}</span>`;
    if (fnCall) return `<span class="tok-fn">${fnCall}</span>`;
    if (ident && FLANG_KEYWORDS.has(ident)) return `<span class="tok-kw">${ident}</span>`;
    return match;
  });
}

// ---------------- Learn page ----------------

function renderLearn() {
  const toc = document.getElementById("learn-toc");
  const body = document.getElementById("learn-body");
  toc.innerHTML = "";
  body.innerHTML = "";

  LESSONS.forEach((lesson, i) => {
    const tocBtn = document.createElement("button");
    tocBtn.className = "learn-toc-item" + (i === 0 ? " active" : "");
    tocBtn.innerHTML = `<span class="lesson-num">${String(i + 1).padStart(2, "0")}</span>${lesson.title}`;
    tocBtn.addEventListener("click", () => showLesson(i));
    toc.appendChild(tocBtn);

    const section = document.createElement("div");
    section.className = "lesson" + (i === 0 ? " active" : "");
    section.id = `lesson-${i}`;
    section.innerHTML = `
      <span class="lesson-level">${lesson.level}</span>
      <h2>${lesson.title}</h2>
      ${lesson.body}
      ${lesson.code ? `<div class="code-block">${highlightFlang(lesson.code)}</div>` : ""}
      <div class="lesson-nav">
        <button data-dir="-1" ${i === 0 ? "disabled" : ""}>&larr; Previous</button>
        <button data-dir="1" ${i === LESSONS.length - 1 ? "disabled" : ""}>Next &rarr;</button>
      </div>
    `;
    section.querySelectorAll(".lesson-nav button").forEach((b) => {
      b.addEventListener("click", () => showLesson(i + parseInt(b.dataset.dir, 10)));
    });
    body.appendChild(section);
  });
}

function showLesson(index) {
  document.querySelectorAll(".learn-toc-item").forEach((el, i) => el.classList.toggle("active", i === index));
  document.querySelectorAll(".lesson").forEach((el, i) => el.classList.toggle("active", i === index));
}

// ---------------- Tips page ----------------

function renderTips() {
  const grid = document.getElementById("tips-grid");
  grid.innerHTML = TIPS.map((tip) => `
    <div class="tip-card">
      <span class="tip-kicker">${tip.kicker}</span>
      <h3>${tip.title}</h3>
      <p>${tip.body}</p>
    </div>
  `).join("");
}

// ---------------- Applications page ----------------

function renderApplications() {
  const grid = document.getElementById("apps-grid");
  grid.innerHTML = APPLICATIONS.map((app, i) => `
    <div class="app-card">
      <span class="app-num">${String(i + 1).padStart(2, "0")}</span>
      <h3>${app.title}</h3>
      <p>${app.body}</p>
      <div class="app-namespaces">
        ${app.ns.map((n) => `<span class="ns-chip">${n}</span>`).join("")}
      </div>
    </div>
  `).join("");
}

// ---------------- Facts page ----------------

function renderFacts() {
  const layout = document.getElementById("facts-layout");
  layout.innerHTML = FACTS.map((fact) => `
    <div class="fact-card">
      <span class="fact-label">${fact.label}</span>
      <div class="fact-big">${fact.big}</div>
      <p>${fact.body}</p>
    </div>
  `).join("");
}

renderLearn();
renderTips();
renderApplications();
renderFacts();

// ---------------- Lab: CodeMirror editor ----------------

const DEFAULT_SCRIPT = `# Welcome to the FLANG Lab.
# Press Run to execute this script against the machine running the
# web server, with a live audit trail.

info := system.info();
print(f"Host: {get(info, \\"hostname\\")} ({get(info, \\"os\\")})");

x := 21;
y := 21;
print(f"x + y = {to_string(x + y)}");

who := security.whoami();
print(f"Running as {get(who, \\"investigator\\")} ({get(who, \\"role\\")})");
`;

const editor = CodeMirror(document.getElementById("editor-host"), {
  value: DEFAULT_SCRIPT,
  mode: "javascript",       // closest built-in approximation to FLANG's C-family syntax
  theme: "default",
  lineNumbers: true,
  indentUnit: 4,
  tabSize: 4,
  matchBrackets: true,
  lineWrapping: true,
});

// ---------------- Lab: New / Open / Save (your own scripts, from disk) ----------------

const editorFilenameEl = document.getElementById("editor-filename");
const dirtyDot = document.getElementById("dirty-dot");
const fileInput = document.getElementById("file-input");

let currentFilename = "untitled.flang";
let isDirty = false;

function setFilename(name) {
  currentFilename = name;
  const label = document.getElementById("filename-label");
  if (label) {
    label.textContent = name;
  } else if (editorFilenameEl && editorFilenameEl.childNodes[0]) {
    editorFilenameEl.childNodes[0].nodeValue = name + " ";
  }
}

function markDirty(dirty) {
  isDirty = dirty;
  dirtyDot.classList.toggle("hidden", !dirty);
}

editor.on("change", () => markDirty(true));

function confirmDiscardIfDirty(actionLabel) {
  if (!isDirty) return true;
  return window.confirm(`You have unsaved changes in ${currentFilename}. ${actionLabel} anyway and lose them?`);
}

document.getElementById("new-btn").addEventListener("click", () => {
  if (!confirmDiscardIfDirty("Start a new blank script")) return;
  editor.setValue("# New FLANG script\n\n");
  setFilename("untitled.flang");
  markDirty(false);
});

document.getElementById("open-btn").addEventListener("click", () => {
  if (!confirmDiscardIfDirty("Open a different file")) return;
  fileInput.click();
});

fileInput.addEventListener("change", () => {
  const file = fileInput.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    editor.setValue(reader.result);
    setFilename(file.name);
    markDirty(false);
  };
  reader.onerror = () => {
    alert(`Could not read ${file.name}: ${reader.error}`);
  };
  reader.readAsText(file);
  fileInput.value = "";  // allow re-opening the same file later
});

document.getElementById("save-btn").addEventListener("click", () => {
  let name = currentFilename;
  if (name === "untitled.flang") {
    const entered = window.prompt("Save as (filename):", "my_script.flang");
    if (!entered) return;
    name = entered.endsWith(".flang") ? entered : `${entered}.flang`;
  }
  const blob = new Blob([editor.getValue()], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  setFilename(name);
  markDirty(false);
});

// ---------------- Lab: load bundled examples ----------------

const examplePicker = document.getElementById("example-picker");

fetch(`${API_BASE_URL}/api/examples`)
  .then((r) => r.json())
  .then((data) => {
    (data.examples || []).forEach((ex) => {
      const opt = document.createElement("option");
      opt.value = ex.name;
      opt.textContent = ex.name;
      opt.dataset.source = ex.source;
      examplePicker.appendChild(opt);
    });
  })
  .catch(() => {
    // examples endpoint unreachable -- Lab still works for hand-written scripts
  });

examplePicker.addEventListener("change", () => {
  const opt = examplePicker.selectedOptions[0];
  if (opt && opt.dataset.source !== undefined) {
    if (!confirmDiscardIfDirty("Load this example")) {
      examplePicker.value = "";
      return;
    }
    editor.setValue(opt.dataset.source);
    setFilename(opt.value);
    markDirty(false);
  }
});

// ---------------- Lab: run ----------------

const runBtn = document.getElementById("run-btn");
const consoleOutput = document.getElementById("console-output");
const runStatusTag = document.getElementById("run-status-tag");
const auditStrip = document.getElementById("audit-strip");
const auditChainValue = document.getElementById("audit-chain-value");
const auditEvidenceValue = document.getElementById("audit-evidence-value");
const auditHashValue = document.getElementById("audit-hash-value");

function setStatusTag(text, kind) {
  runStatusTag.textContent = text;
  runStatusTag.className = "evidence-tag" + (kind ? ` ${kind}` : "");
}

runBtn.addEventListener("click", async () => {
  const source = editor.getValue();
  const caseId = document.getElementById("field-case").value || "WEB-SESSION";
  const investigator = document.getElementById("field-investigator").value || "web-user";
  const role = document.getElementById("field-role").value;

  runBtn.disabled = true;
  runBtn.textContent = "Running…";
  consoleOutput.className = "console-output";
  consoleOutput.textContent = "Running…";
  setStatusTag("running", "");
  auditStrip.classList.add("hidden");

  try {
    const res = await fetch(`${API_BASE_URL}/api/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source, case_id: caseId, investigator, role }),
    });
    const data = await res.json();

    if (data.ok) {
      consoleOutput.textContent = data.stdout || "(script ran with no output)";
      setStatusTag("run ok", "ok");

      auditStrip.classList.remove("hidden");
      auditChainValue.textContent = data.audit.chain_intact ? "intact" : `broken at #${data.audit.broken_at}`;
      auditChainValue.className = "audit-value " + (data.audit.chain_intact ? "ok" : "fail");

      auditEvidenceValue.textContent = data.evidence.all_verified
        ? `verified (${data.evidence.item_count})`
        : "MISMATCH DETECTED";
      auditEvidenceValue.className = "audit-value " + (data.evidence.all_verified ? "ok" : "fail");

      auditHashValue.textContent = data.script_hash || "—";
    } else {
      consoleOutput.className = "console-output is-error";
      const kindLabel = { syntax: "Syntax error", runtime: "Runtime error", timeout: "Timed out", internal: "Internal error" }[data.error_kind] || "Error";
      consoleOutput.textContent = (data.stdout ? data.stdout + "\n\n" : "") + `${kindLabel}: ${data.error}`;
      setStatusTag(data.error_kind === "timeout" ? "timed out" : "failed", "fail");
    }
  } catch (err) {
    consoleOutput.className = "console-output is-error";
    consoleOutput.textContent = `Could not reach the FLANG backend (${err}). Is server.py still running?`;
    setStatusTag("no connection", "fail");
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "▶ Run";
  }
});
