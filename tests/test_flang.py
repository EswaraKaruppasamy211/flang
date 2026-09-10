"""
Basic automated tests for the FLANG prototype.
Run with:  PYTHONPATH=.. python3 -m pytest tests/  (or just: python3 tests/test_flang.py)
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flang.lexer import tokenize
from flang.parser import parse
from flang.interpreter import Interpreter, FlangRuntimeError
from flang.runtime.audit import AuditLog, AuditEntry
from flang.runtime.security import AuthorizationError


class TestLexerParser(unittest.TestCase):
    def test_tokenize_basic(self):
        tokens = tokenize('x := sha256(disk);')
        kinds = [t.kind for t in tokens]
        self.assertIn("IDENT", kinds)
        self.assertIn("SYMBOL", kinds)

    def test_parse_assignment_and_call(self):
        tokens = tokenize('x := length([1,2,3]);')
        program = parse(tokens)
        self.assertEqual(len(program.statements), 1)


class TestInterpreterCore(unittest.TestCase):
    def run_script(self, source: str, role="LEAD_INVESTIGATOR", investigator="tester", case="TEST-CASE"):
        tokens = tokenize(source)
        program = parse(tokens)
        interp = Interpreter(case_id=case, investigator=investigator, role=role)
        interp.run(program)
        return interp

    def test_variables_and_arithmetic(self):
        interp = self.run_script("x := 2 + 3; y := x * 4;")
        self.assertEqual(interp.global_env.get("x"), 5)
        self.assertEqual(interp.global_env.get("y"), 20)

    def test_if_else_and_scope_leak_is_intentional(self):
        interp = self.run_script('''
            n := 10;
            if n > 5 {
                verdict := "big";
            } else {
                verdict := "small";
            }
        ''')
        self.assertEqual(interp.global_env.get("verdict"), "big")

    def test_for_loop_and_list_literal(self):
        interp = self.run_script('''
            total := 0;
            for x in [1, 2, 3] {
                total := total + x;
            }
        ''')
        self.assertEqual(interp.global_env.get("total"), 6)

    def test_fstring_interpolation(self):
        interp = self.run_script('name := "world"; msg := f"hello {name}";')
        self.assertEqual(interp.global_env.get("msg"), "hello world")

    def test_length_builtin(self):
        interp = self.run_script('n := length([1,2,3,4]);')
        self.assertEqual(interp.global_env.get("n"), 4.0)


class TestRBAC(unittest.TestCase):
    def test_low_role_blocked_from_high_role_function(self):
        source = 'r := new_report("t"); r := sign_report(r, key_id: "k");'
        tokens = tokenize(source)
        program = parse(tokens)
        interp = Interpreter(case_id="TEST-CASE", investigator="trainee", role="TIER1_TRIAGE")
        with self.assertRaises(FlangRuntimeError):
            interp.run(program)

    def test_high_role_permitted(self):
        source = 'r := new_report("t"); r := sign_report(r, key_id: "k_test_high_role");'
        tokens = tokenize(source)
        program = parse(tokens)
        interp = Interpreter(case_id="TEST-CASE", investigator="lead", role="LEAD_INVESTIGATOR")
        interp.run(program)  # should not raise


class TestEvidenceIntegrity(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.disk_dir = os.path.join(self.tmpdir, "disk")
        os.makedirs(self.disk_dir)
        with open(os.path.join(self.disk_dir, "file1.txt"), "w") as f:
            f.write("hello evidence")

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_disk_hash_changes_if_evidence_modified(self):
        source = f'd := load_disk_image("{self.disk_dir}"); h := sha256(d);'
        tokens = tokenize(source)
        program = parse(tokens)
        interp = Interpreter(case_id="TEST-CASE", investigator="tester", role="LEAD_INVESTIGATOR")
        interp.run(program)
        original_hash = interp.global_env.get("h")

        # mutate evidence out-of-band (simulating tampering) and verify detection
        with open(os.path.join(self.disk_dir, "file1.txt"), "a") as f:
            f.write(" -- tampered")
        ok = interp.evidence_mgr.verify_all()
        self.assertFalse(all(ok.values()))


class TestAuditChain(unittest.TestCase):
    def test_tamper_detected(self):
        log = AuditLog()
        log.record("A", "tester", "CASE", {"x": 1})
        log.record("B", "tester", "CASE", {"x": 2})
        log.record("C", "tester", "CASE", {"x": 3})

        result = log.verify()
        self.assertTrue(result["ok"])

        # tamper with entry 1's detail without recomputing its hash
        log.entries[1].detail = {"x": 999}
        result = log.verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["broken_at"], 1)


# ======================================================================
# Added in this revision: tests for the new forensic-subsystem namespaces
# (timeline, case, evidence, correlation, audit, security, forensics,
# simulation, filesystem alias, reporting alias, SHA-512, role aliases).
# None of the classes/tests above this line were modified.
# ======================================================================

class TestRoleAliases(unittest.TestCase):
    def test_new_role_names_map_to_same_ranks_as_existing_ones(self):
        from flang.runtime.security import SecurityContext
        admin_via_alias = SecurityContext("tester", "Administrator", "CASE")
        self.assertEqual(admin_via_alias.role, "ADMIN")
        investigator_via_alias = SecurityContext("tester", "Investigator", "CASE")
        self.assertEqual(investigator_via_alias.role, "LEAD_INVESTIGATOR")
        # existing canonical names still work completely unchanged
        still_works = SecurityContext("tester", "TIER1_TRIAGE", "CASE")
        self.assertEqual(still_works.role, "TIER1_TRIAGE")


class TestSHA512(unittest.TestCase):
    def test_sha512_file_matches_known_value(self):
        import hashlib
        from flang.runtime.evidence import sha512_file
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "f.txt")
            with open(path, "wb") as f:
                f.write(b"hello")
            self.assertEqual(sha512_file(path), hashlib.sha512(b"hello").hexdigest())
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestNamespacedForensicModules(unittest.TestCase):
    def run_script(self, source: str, role="LEAD_INVESTIGATOR"):
        tokens = tokenize(source)
        program = parse(tokens)
        interp = Interpreter(case_id="TEST-CASE", investigator="tester", role=role)
        interp.run(program)
        return interp

    def test_hash_namespace_sha512(self):
        interp = self.run_script('h := hash.sha512("hello");')
        import hashlib
        self.assertEqual(interp.global_env.get("h"), hashlib.sha512(b"hello").hexdigest())

    def test_reporting_is_alias_for_report(self):
        interp = self.run_script('r := report.create("t"); r2 := reporting.add(r, "s", "c");')
        # both calls must have operated on the same underlying namespace
        self.assertEqual(len(interp.global_env.get("r2").sections), 1)

    def test_timeline_operations(self):
        interp = self.run_script('''
            events := simulation.scenario(["process", "dns"], 4);
            t := correlation.correlate([events], window_seconds: 3600);
            sorted_events := timeline.sort(t);
            grouped := timeline.group_by(t, "type");
        ''')
        self.assertEqual(len(interp.global_env.get("sorted_events")), 4)
        self.assertGreaterEqual(len(interp.global_env.get("grouped")), 1)

    def test_correlation_link_and_graph(self):
        interp = self.run_script('''
            a := simulation.process_event();
            b := simulation.network_event();
            edge := correlation.link(a, b, "test reason");
            graph := correlation.build_graph([edge]);
        ''')
        graph = interp.global_env.get("graph")
        self.assertEqual(graph["edge_count"], 1)

    def test_case_management_roundtrip(self):
        tmpdir = tempfile.mkdtemp()
        old_cwd = os.getcwd()
        try:
            os.chdir(tmpdir)
            interp = self.run_script('''
                case.create("T-1", "Test case", "tester");
                case.add_note("T-1", "a note", "tester");
                n := length(case.list_evidence("T-1"));
            ''')
            self.assertEqual(interp.global_env.get("n"), 0.0)
        finally:
            os.chdir(old_cwd)
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_evidence_manifest_has_both_hashes(self):
        tmpdir = tempfile.mkdtemp()
        try:
            path = os.path.join(tmpdir, "f.txt")
            with open(path, "w") as f:
                f.write("evidence content")
            interp = self.run_script(f'm := evidence.manifest("{path}", "tester");')
            manifest = interp.global_env.get("m")
            self.assertIn("sha256", manifest)
            self.assertIn("sha512", manifest)
            self.assertEqual(len(manifest["sha512"]), 128)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_simulation_events_are_marked_synthetic(self):
        interp = self.run_script('events := simulation.scenario(["process", "network"], 6);')
        for e in interp.global_env.get("events"):
            self.assertTrue(e["synthetic"])

    def test_audit_namespace_summary(self):
        interp = self.run_script('s := audit.summary();')
        summary = interp.global_env.get("s")
        self.assertEqual(summary["case_id"], "TEST-CASE")
        self.assertTrue(summary["chain_verified"]["ok"])

    def test_security_whoami(self):
        interp = self.run_script('w := security.whoami();', role="TIER2_ANALYST")
        who = interp.global_env.get("w")
        self.assertEqual(who["role"], "TIER2_ANALYST")

    def test_namespace_shadowing_is_rejected(self):
        with self.assertRaises(FlangRuntimeError):
            self.run_script('timeline := 5;')
        with self.assertRaises(FlangRuntimeError):
            self.run_script('case := "oops";')

    def test_existing_namespaces_still_work_unchanged(self):
        # regression guard: the ORIGINAL namespaces from the prior
        # revision must still behave identically after this revision's
        # additions.
        interp = self.run_script('info := system.info(); procs := process.list();')
        self.assertIn("hostname", interp.global_env.get("info"))
        self.assertIsInstance(interp.global_env.get("procs"), list)


if __name__ == "__main__":
    unittest.main()
