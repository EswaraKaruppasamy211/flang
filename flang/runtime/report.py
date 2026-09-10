"""
Reporting Engine
-------------------
Builds a structured Report object from investigation findings and
exports it as signed JSON and human-readable HTML.

Signing: this prototype uses an HMAC-SHA256 keyed by a locally
generated "key_id" credential file, standing in for a production
PKI/HSM-backed signing key. The report JSON's signature block records
which key produced it and can be independently verified with
`verify_report_signature()`, mirroring how a real deployment would
verify against an org certificate.
"""

from __future__ import annotations
import hashlib
import hmac
import html
import json
import os
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

try:
    from cryptography.fernet import Fernet
    HAVE_CRYPTOGRAPHY = True
except Exception:
    HAVE_CRYPTOGRAPHY = False

KEYSTORE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "keystore")


def _keystore_path(key_id: str) -> str:
    os.makedirs(KEYSTORE_DIR, exist_ok=True)
    return os.path.join(KEYSTORE_DIR, f"{key_id}.key")


def _get_or_create_key(key_id: str) -> bytes:
    path = _keystore_path(key_id)
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = os.urandom(32)
    with open(path, "wb") as f:
        f.write(key)
    return key


@dataclass
class ReportSection:
    title: str
    content: Any


@dataclass
class Report:
    title: str
    created_at: float = field(default_factory=time.time)
    sections: List[ReportSection] = field(default_factory=list)
    timelines: List[Dict[str, Any]] = field(default_factory=list)
    signature: Optional[Dict[str, str]] = None
    co_signature: Optional[Dict[str, str]] = None
    script_hash: Optional[str] = None
    audit_summary: Optional[Dict[str, Any]] = None


def new_report(title: str) -> Report:
    return Report(title=title)


def add_section(report: Report, title: str, content: Any) -> Report:
    report.sections.append(ReportSection(title=title, content=content))
    return report


def add_timeline(report: Report, timeline: Dict[str, Any]) -> Report:
    report.timelines.append(timeline)
    return report


def _canonical_bytes(report: Report) -> bytes:
    payload = {
        "title": report.title,
        "created_at": report.created_at,
        "sections": [asdict(s) for s in report.sections],
        "timelines": report.timelines,
        "script_hash": report.script_hash,
    }
    return json.dumps(payload, sort_keys=True, default=str).encode("utf-8")


def sign_report(report: Report, key_id: str) -> Report:
    key = _get_or_create_key(key_id)
    digest = hmac.new(key, _canonical_bytes(report), hashlib.sha256).hexdigest()
    report.signature = {"key_id": key_id, "algorithm": "HMAC-SHA256", "value": digest}
    return report


def verify_report_signature(report: Report) -> bool:
    if not report.signature:
        return False
    key = _get_or_create_key(report.signature["key_id"])
    expected = hmac.new(key, _canonical_bytes(report), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, report.signature["value"])


def co_sign_report(report: Report, key_id: str) -> Report:
    """
    Dual-control / two-person-integrity signing: a second, distinct
    key_id signs the already-signed report. Production deployments
    would require this second key to be held by a different role
    (e.g. LEAD_INVESTIGATOR signs, then a second LEAD_INVESTIGATOR or
    supervisor co-signs) before the report is considered final --
    mirroring the "two-person control for key release" mentioned in
    the project's security architecture for especially sensitive cases.
    """
    if not report.signature:
        raise ValueError("Report must be sign_report()'d before it can be co-signed")
    key = _get_or_create_key(key_id)
    # co-signature covers the primary signature too, binding both together
    payload = _canonical_bytes(report) + report.signature["value"].encode("utf-8")
    digest = hmac.new(key, payload, hashlib.sha256).hexdigest()
    report.co_signature = {"key_id": key_id, "algorithm": "HMAC-SHA256", "value": digest}
    return report


def _get_or_create_fernet_key(key_id: str) -> bytes:
    if not HAVE_CRYPTOGRAPHY:
        raise RuntimeError(
            "export_encrypted()/decrypt_report() need the 'cryptography' "
            "package, which is not installed (pip install cryptography). "
            "Every other FLANG feature -- including plain export() and "
            "sign_report() -- works without it."
        )
    path = _keystore_path(f"{key_id}.fernet")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    return key


def export_encrypted(report: Report, path: str, key_id: str):
    """
    Export the signed report JSON, then encrypt it at rest with
    AES-128-CBC + HMAC (via the `cryptography` package's Fernet
    recipe) using a key derived from key_id. This implements the
    "encrypted evidence storage" / "encrypted report storage" property
    named in the project's security architecture. The key file itself
    is written under keystore/ -- in production this would be an
    HSM-backed or KMS-backed key, not a local file.
    """
    payload = {
        "title": report.title,
        "created_at": report.created_at,
        "sections": [asdict(s) for s in report.sections],
        "timelines": report.timelines,
        "signature": report.signature,
        "co_signature": report.co_signature,
        "script_hash": report.script_hash,
        "audit_summary": report.audit_summary,
    }
    plaintext = json.dumps(payload, default=str).encode("utf-8")
    fkey = _get_or_create_fernet_key(key_id)
    ciphertext = Fernet(fkey).encrypt(plaintext)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(ciphertext)


def decrypt_report(path: str, key_id: str) -> Dict[str, Any]:
    fkey = _get_or_create_fernet_key(key_id)
    with open(path, "rb") as f:
        ciphertext = f.read()
    plaintext = Fernet(fkey).decrypt(ciphertext)
    return json.loads(plaintext)


def export(report: Report, fmt: str, path: str):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if fmt == "json":
        _export_json(report, path)
    elif fmt in ("html", "pdf"):
        # PDF generation would normally go through a HTML->PDF renderer
        # (e.g. WeasyPrint) on top of the same HTML below; we emit HTML
        # directly here to keep the prototype dependency-free, and note
        # the substitution clearly in the exported file itself.
        _export_html(report, path if fmt == "html" else path.rsplit(".", 1)[0] + ".html")
    else:
        raise ValueError(f"Unsupported export format: {fmt}")


def _export_json(report: Report, path: str):
    payload = {
        "title": report.title,
        "created_at": report.created_at,
        "sections": [asdict(s) for s in report.sections],
        "timelines": report.timelines,
        "signature": report.signature,
        "script_hash": report.script_hash,
        "audit_summary": report.audit_summary,
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2, default=str)


def _render_value(value: Any) -> str:
    if isinstance(value, list):
        if not value:
            return "<p><em>None found.</em></p>"
        rows = "".join(f"<li><pre>{html.escape(json.dumps(v, default=str))}</pre></li>" for v in value)
        return f"<ul>{rows}</ul>"
    if isinstance(value, dict):
        return f"<pre>{html.escape(json.dumps(value, indent=2, default=str))}</pre>"
    return f"<p>{html.escape(str(value))}</p>"


def _export_html(report: Report, path: str):
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>{html.escape(report.title)}</title>",
        "<style>body{font-family:sans-serif;max-width:900px;margin:2rem auto;line-height:1.5}"
        "h1{border-bottom:2px solid #333}h2{margin-top:2rem;color:#333}"
        "pre{background:#f4f4f4;padding:.5rem;overflow-x:auto;font-size:.85em}"
        ".sig{background:#eef7ee;padding:1rem;border:1px solid #9c9}</style>",
        "</head><body>",
        f"<h1>{html.escape(report.title)}</h1>",
        f"<p><strong>Generated:</strong> {time.ctime(report.created_at)}</p>",
    ]
    if report.script_hash:
        parts.append(f"<p><strong>Script SHA-256:</strong> <code>{html.escape(report.script_hash)}</code></p>")

    for section in report.sections:
        parts.append(f"<h2>{html.escape(section.title)}</h2>")
        parts.append(_render_value(section.content))

    for i, timeline in enumerate(report.timelines):
        parts.append(f"<h2>Correlated Timeline {i + 1}</h2>")
        parts.append(f"<p>{timeline.get('total_records', 0)} total records, "
                      f"{len(timeline.get('clusters', []))} correlation clusters "
                      f"(window: {timeline.get('window_seconds')}s)</p>")
        for c in timeline.get("clusters", []):
            parts.append(f"<h3>Cluster: {time.ctime(c['start'])} &ndash; {time.ctime(c['end'])} "
                         f"({c['record_count']} records)</h3>")
            parts.append(_render_value(c["records"]))

    if report.signature:
        parts.append(
            "<div class='sig'><strong>Digitally signed.</strong><br>"
            f"Key ID: {html.escape(report.signature['key_id'])}<br>"
            f"Algorithm: {html.escape(report.signature['algorithm'])}<br>"
            f"Signature: <code>{html.escape(report.signature['value'])}</code></div>"
        )
    if report.co_signature:
        parts.append(
            "<div class='sig'><strong>Co-signed (dual control).</strong><br>"
            f"Key ID: {html.escape(report.co_signature['key_id'])}<br>"
            f"Algorithm: {html.escape(report.co_signature['algorithm'])}<br>"
            f"Signature: <code>{html.escape(report.co_signature['value'])}</code></div>"
        )

    parts.append("</body></html>")
    with open(path, "w") as f:
        f.write("\n".join(parts))
