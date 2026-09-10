"""
FLANG Web IDE — Backend
--------------------------
Deliberately zero third-party dependencies (standard library only:
http.server, json, threading). This project's own history has run
into pip / DLL / Application-Control-policy blockers more than once,
so the backend that makes the language usable without touching a
terminal every time must not add a new thing that can be blocked.
 
Run with:  python server.py
Then open: http://localhost:8765

This is a personal, local development tool -- it is not hardened for
being exposed on a network. It binds to localhost only.
"""

from __future__ import annotations
import io
import json
import os
import sys
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

# make the flang package importable regardless of where this script is launched from
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flang.lexer import tokenize, LexError
from flang.parser import parse, ParseError
from flang.interpreter import Interpreter, FlangRuntimeError

WEB_DIR = os.path.join(os.path.dirname(__file__), "web")
EXAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")
RUN_TIMEOUT_SECONDS = 10
PORT = 8765

# The interpreter changes the working directory (case files, report
# exports, etc. are written relative to cwd) and this is a single-user
# local tool, so runs are serialized rather than trying to make the
# whole interpreter thread-safe for concurrent cwd changes.
_run_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=1)


def _execute_flang_script(source: str, case_id: str, investigator: str, role: str) -> dict:
    """Runs one FLANG script and returns a JSON-serializable result dict.
    Never raises -- every failure mode (syntax error, runtime error,
    unexpected exception) is captured and returned as structured data
    instead of crashing the request handler."""

    result = {
        "ok": False,
        "stdout": "",
        "error": None,
        "error_kind": None,
        "audit": None,
        "evidence": None,
        "script_hash": None,
    }

    try:
        tokens = tokenize(source)
    except LexError as e:
        result["error"] = str(e)
        result["error_kind"] = "syntax"
        return result

    try:
        program = parse(tokens)
    except ParseError as e:
        result["error"] = str(e)
        result["error_kind"] = "syntax"
        return result

    # run inside the examples/ dir so bundled demo_evidence paths resolve,
    # exactly like running via the CLI from that directory.
    run_id = uuid.uuid4().hex[:8]
    old_cwd = os.getcwd()
    captured = io.StringIO()
    try:
        os.chdir(os.path.abspath(EXAMPLES_DIR))
        os.makedirs("output", exist_ok=True)

        # write the script to a temp file so script_hash / --audit-log
        # style behavior matches the CLI (the interpreter hashes the
        # script file, not the in-memory source, for the audit trail)
        script_path = os.path.join("output", f"_webrun_{run_id}.flang")
        with open(script_path, "w") as f:
            f.write(source)

        interp = Interpreter(
            case_id=case_id or "WEB-SESSION",
            investigator=investigator or "web-user",
            role=role or "LEAD_INVESTIGATOR",
            script_path=script_path,
        )

        old_stdout = sys.stdout
        sys.stdout = captured
        try:
            interp.run(program)
        finally:
            sys.stdout = old_stdout

        evidence_check = interp.evidence_mgr.verify_all()
        audit_check = interp.audit_log.verify()

        result["ok"] = True
        result["stdout"] = captured.getvalue()
        result["audit"] = {
            "entry_count": len(interp.audit_log.entries),
            "chain_intact": audit_check["ok"],
            "broken_at": audit_check["broken_at"],
        }
        result["evidence"] = {
            "item_count": len(evidence_check),
            "all_verified": all(evidence_check.values()) if evidence_check else True,
        }
        result["script_hash"] = interp.script_hash

    except FlangRuntimeError as e:
        sys.stdout = old_stdout if "old_stdout" in dir() else sys.__stdout__
        result["stdout"] = captured.getvalue()
        result["error"] = str(e)
        result["error_kind"] = "runtime"
    except Exception as e:
        sys.stdout = old_stdout if "old_stdout" in dir() else sys.__stdout__
        result["stdout"] = captured.getvalue()
        result["error"] = f"{type(e).__name__}: {e}"
        result["error_kind"] = "internal"
    finally:
        try:
            os.remove(script_path)
        except Exception:
            pass
        os.chdir(old_cwd)

    return result


def run_with_timeout(source: str, case_id: str, investigator: str, role: str) -> dict:
    with _run_lock:
        future = _executor.submit(_execute_flang_script, source, case_id, investigator, role)
        try:
            return future.result(timeout=RUN_TIMEOUT_SECONDS)
        except FutureTimeoutError:
            return {
                "ok": False,
                "stdout": "",
                "error": f"Script exceeded the {RUN_TIMEOUT_SECONDS}-second run limit for the "
                         f"web Lab (the CLI has no such limit). This usually means an "
                         f"unbounded while-loop -- check the loop condition.",
                "error_kind": "timeout",
                "audit": None, "evidence": None, "script_hash": None,
            }


CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".flang": "text/plain; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "FlangWebIDE/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[flang-web] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, payload: dict, status: int = 200):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str):
        if not os.path.isfile(path):
            self.send_error(404, "Not found")
            return
        ext = os.path.splitext(path)[1]
        content_type = CONTENT_TYPES.get(ext, "application/octet-stream")
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # This is a local development server: always pick up edited
        # certificate and web assets instead of serving a browser cache.
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        request_path = urlsplit(self.path).path

        if request_path == "/" or request_path == "":
            self._send_file(os.path.join(WEB_DIR, "index.html"))
            return

        if request_path == "/api/examples":
            examples = []
            try:
                for name in sorted(os.listdir(EXAMPLES_DIR)):
                    if name.endswith(".flang"):
                        with open(os.path.join(EXAMPLES_DIR, name)) as f:
                            examples.append({"name": name, "source": f.read()})
            except OSError:
                pass
            self._send_json({"examples": examples})
            return

        # static files under web/ -- prevent path traversal outside WEB_DIR
        requested = os.path.normpath(os.path.join(WEB_DIR, request_path.lstrip("/")))
        if not requested.startswith(os.path.normpath(WEB_DIR)):
            self.send_error(403, "Forbidden")
            return
        self._send_file(requested)

    def do_POST(self):
        if self.path != "/api/run":
            self.send_error(404, "Not found")
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            payload = json.loads(body.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            self._send_json({"ok": False, "error": "Malformed request body"}, status=400)
            return

        source = payload.get("source", "")
        case_id = payload.get("case_id", "WEB-SESSION")
        investigator = payload.get("investigator", "web-user")
        role = payload.get("role", "LEAD_INVESTIGATOR")

        result = run_with_timeout(source, case_id, investigator, role)
        self._send_json(result)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"FLANG Web IDE running at http://localhost:{PORT}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
        server.shutdown()


if __name__ == "__main__":
    main()
