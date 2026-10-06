"""Synthetic tests only: never invoke a native broker or mutate system policy."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("startup_fixture", Path(__file__).with_name("fixture.py"))
f = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f)


def report(refusal=None, persisted=False):
    checks = []
    for i, name in enumerate(f.IDS):
        status, reason = "pass", "satisfied"
        if i == refusal:
            status, reason = "not_checked" if persisted else "refused", f.REASONS[i]
        elif refusal is not None and i > refusal:
            status, reason = "not_checked", "prerequisite_refused"
        checks.append({"id": name, "status": status, "reason": reason})
    return {"schema_version": 1, "scope": "native_linux_broker_startup_admission", "platform": "linux", "supported": refusal is None, "read_only": True, "checks": checks, "restrictions": list(f.RESTRICTIONS)}


class StartupFixtureTests(unittest.TestCase):
    def test_fixed_report_order_reasons_and_typed_envelope(self):
        for refusal in [None, *range(9)]:
            value = report(refusal)
            self.assertEqual(f.validate_startup(value, refusal), value)
        self.assertEqual(f.validate_startup(report(8, True), 8, True)["checks"][8]["status"], "not_checked")
        for mutate in [lambda x: x.update(schema_version=True), lambda x: x.update(read_only=1), lambda x: x.update(supported=1), lambda x: x["checks"].reverse(), lambda x: x.update(path="private"), lambda x: x["checks"][6].update(reason="wrong"), lambda x: x["restrictions"].pop()]:
            value = report(5)
            mutate(value)
            with self.assertRaises(AssertionError): f.validate_startup(value, 5)

    def test_nss_redaction_actions_and_row_count(self):
        raw = b"passwd: sss files systemd\nshadow: files sss [SUCCESS=return]\ngroup: private_provider files\ngroup: compat\n"
        values = f.nss_profiles(raw)
        self.assertEqual(values[0], {"id": "passwd", "row_count": 1, "providers": ["sss", "files", "systemd"], "actions_present": False, "unknown_provider": False})
        self.assertEqual(values[1]["providers"], ["unknown", "files", "compat"])
        self.assertEqual(values[1]["row_count"], 2)
        self.assertTrue(values[1]["unknown_provider"])
        self.assertTrue(values[2]["actions_present"])
        self.assertNotIn("private_provider", json.dumps(values))
        self.assertNotIn("SUCCESS", json.dumps(values))
        with self.assertRaises(AssertionError): f.nss_profiles(b"passwd: files\0")

    def test_duplicate_json_keys_and_trailing_payload(self):
        for raw in ['{"a":1,"a":2}', '{"a":{"x":1,"x":2}}', '{"a":NaN}', '{}{}']:
            with self.assertRaises((AssertionError, ValueError)): f.strict_json(raw)

    def test_probe_readonly_snapshot_and_exact_command(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            before = f.owned_snapshot(parent)
            calls = []
            def run(argv, **options):
                calls.append(argv)
                self.assertEqual(options, {"timeout": 10, "limit": 8192})
                return {"exit_code": 0, "stdout": json.dumps(report()).encode(), "stderr": b"", "owned_child_exited": True}
            with patch.object(f, "run_child", run):
                value = f.startup_observation(Path("owned-broker"), parent)
            self.assertEqual(value["before_sha256"], before)
            self.assertEqual(value["after_sha256"], before)
            self.assertEqual(value["missing_paths"], ["state", "homes", "socket_parent", "socket"])
            self.assertEqual(calls[0][1], "--check-startup")
            self.assertEqual(calls[0][-2:], ["--controller-uid", "65534"])

    def test_probe_rejects_added_paths_wrong_exit_and_private_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            def mutate(argv, **options):
                (parent / "unexpected").write_bytes(b"fixture")
                return {"exit_code": 0, "stdout": json.dumps(report()).encode(), "stderr": b"", "owned_child_exited": True}
            with patch.object(f, "run_child", mutate), self.assertRaises(AssertionError):
                f.startup_observation(Path("owned-broker"), parent)
            (parent / "unexpected").unlink()
            for stdout, stderr, code in [(b"{}", b"private", 1), (json.dumps(report()).encode(), b"", 1)]:
                with patch.object(f, "run_child", return_value={"exit_code": code, "stdout": stdout, "stderr": stderr, "owned_child_exited": True}), self.assertRaises(AssertionError):
                    f.startup_observation(Path("owned-broker"), parent)

    def test_invalid_grammar_has_no_json_and_no_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            good = {"exit_code": 2, "stdout": b"", "stderr": b"Invalid native broker configuration\n", "owned_child_exited": True}
            with patch.object(f, "run_child", return_value=good):
                self.assertIsNone(f.startup_observation(Path("broker"), parent, uid=0)["report"])
                self.assertIsNone(f.startup_observation(Path("broker"), parent, invalid=["--unknown", "/private/value"])["report"])
            for bad in [dict(good, stdout=b"{}"), dict(good, stderr=b"private path"), dict(good, exit_code=1)]:
                with patch.object(f, "run_child", return_value=bad), self.assertRaises(AssertionError):
                    f.startup_observation(Path("broker"), parent, uid=0)

    def test_only_declared_nss_leaf_adapted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "etc").mkdir()
            (root / "etc/nsswitch.conf").write_bytes(b"passwd: sss\n")
            (root / "etc/defaults").write_bytes(b"unchanged")
            if os.name == "nt":
                real_open = f.os.open
                # Model Linux descriptor/mode APIs only for this Windows
                # synthetic test; native producer keeps actual root checks.
                with patch.object(f.os, "geteuid", return_value=0, create=True), patch.object(f.os, "fchmod", create=True), patch.object(f.stat, "S_IMODE", return_value=0o644), patch.object(f.os, "open", side_effect=lambda target, flags, mode: real_open(target, flags | getattr(f.os, "O_BINARY", 0), mode)):
                    f.adapt_nss("b" * 32, root)
            else:
                f.adapt_nss("b" * 32, root)
            self.assertEqual((root / "etc/nsswitch.conf").read_bytes(), f.NSS_BYTES)
            self.assertEqual(len(f.NSS_BYTES), 54)
            self.assertEqual((root / "etc/defaults").read_bytes(), b"unchanged")
            self.assertEqual(sorted(x.name for x in (root / "etc").iterdir()), ["defaults", "nsswitch.conf"])

    def test_bounded_child_timeout_output_and_cleanup(self):
        for code, timeout, limit in [("import time;time.sleep(10)", .1, 1024), ("print('x'*100000)", 5, 10)]:
            with self.assertRaises(AssertionError): f.run_child([sys.executable, "-I", "-B", "-c", code], timeout=timeout, limit=limit)
        result = f.run_child([sys.executable, "-I", "-B", "-c", "print('safe')"], timeout=5)
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["owned_child_exited"])

    def test_native_tests_must_run_all_names_without_skips(self):
        names = ["TestAlpha", "TestBeta"]
        good = b"--- PASS: TestAlpha (0.00s)\n--- PASS: TestBeta (0.00s)\nPASS\n"
        for raw in [good.replace(b"PASS: TestBeta", b"SKIP: TestBeta"), good.replace(b"TestBeta", b"Foreign"), b"testing: warning: no tests to run\nPASS\n"]:
            with patch.object(f, "run_child", return_value={"exit_code": 0, "stdout": raw, "stderr": b""}), self.assertRaises(AssertionError): f.execute_tests(Path("owned.test"), names)
        with patch.object(f, "run_child", return_value={"exit_code": 0, "stdout": good, "stderr": b""}): self.assertEqual(f.execute_tests(Path("owned.test"), names)["test_names"], names)


if __name__ == "__main__":
    unittest.main()
