"""
FLANG CLI
-----------
Usage:
    python -m flang.cli run script.flang --case CASE-2026-0417 \\
        --investigator "j.doe" --role TIER2_ANALYST \\
        --audit-log /cases/CASE-2026-0417/audit.log

    python -m flang.cli verify-audit /cases/CASE-2026-0417/audit.log
"""

from __future__ import annotations
import argparse
import os
import sys

from .lexer import tokenize, LexError
from .parser import parse, ParseError
from .interpreter import Interpreter, FlangRuntimeError
from .runtime.audit import AuditLog


def cmd_run(args):
    with open(args.script, "r") as f:
        source = f.read()

    try:
        tokens = tokenize(source)
        program = parse(tokens)
    except (LexError, ParseError) as e:
        print(f"[FLANG] Syntax error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.audit_log:
        os.makedirs(os.path.dirname(args.audit_log) or ".", exist_ok=True)

    interp = Interpreter(
        case_id=args.case,
        investigator=args.investigator,
        role=args.role,
        audit_log_path=args.audit_log,
        script_path=args.script,
    )

    print(f"[FLANG] Running '{args.script}' as {args.investigator} "
          f"(role={args.role}, case={args.case})")

    try:
        interp.run(program)
    except FlangRuntimeError as e:
        print(f"[FLANG] Runtime error: {e}", file=sys.stderr)
        sys.exit(1)

    verify = interp.evidence_mgr.verify_all()
    all_ok = all(verify.values()) if verify else True
    audit_check = interp.audit_log.verify()

    print(f"[FLANG] Evidence integrity check: "
          f"{'PASS' if all_ok else 'FAIL'} ({len(verify)} item(s))")
    print(f"[FLANG] Audit log integrity check: "
          f"{'PASS' if audit_check['ok'] else 'FAIL'} "
          f"({audit_check['checked']} entries)")
    print(f"[FLANG] Script SHA-256: {interp.script_hash}")


def cmd_verify_audit(args):
    entries = []
    import json
    with open(args.log_path) as f:
        for line in f:
            entries.append(json.loads(line))

    log = AuditLog()
    from .runtime.audit import AuditEntry
    log.entries = [AuditEntry(**e) for e in entries]
    result = log.verify()
    if result["ok"]:
        print(f"[FLANG] Audit log OK -- {result['checked']} entries, chain intact.")
    else:
        print(f"[FLANG] TAMPER DETECTED at entry {result['broken_at']} "
              f"(verified {result['checked']} entries before break).")
        sys.exit(2)


def main():
    parser = argparse.ArgumentParser(prog="flang")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Execute a FLANG investigation script")
    run_p.add_argument("script", help="Path to .flang script")
    run_p.add_argument("--case", required=True, help="Case ID")
    run_p.add_argument("--investigator", required=True, help="Investigator identity")
    run_p.add_argument("--role", required=True,
                        choices=["TIER1_TRIAGE", "TIER2_ANALYST", "LEAD_INVESTIGATOR", "ADMIN",
                                 # added: optional alternate role names (SecurityContext maps
                                 # these onto the same four ranks above -- see runtime/security.py)
                                 "Viewer", "Analyst", "Reviewer", "Investigator", "Administrator"])
    run_p.add_argument("--audit-log", default=None, help="Path to append-only audit log file")
    run_p.set_defaults(func=cmd_run)

    verify_p = sub.add_parser("verify-audit", help="Independently verify an audit log's hash chain")
    verify_p.add_argument("log_path", help="Path to the audit log file")
    verify_p.set_defaults(func=cmd_verify_audit)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
