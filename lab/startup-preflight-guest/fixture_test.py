"""Synthetic tests only: never invoke a native broker or mutate system policy."""
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import io
import base64
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock
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
        with tempfile.TemporaryDirectory() as directory, patch.object(f, "admit_socket_path"):
            # Windows temporary paths model filesystem snapshots; native Linux
            # socket admission is tested separately against actual planned paths.
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
        with tempfile.TemporaryDirectory() as directory, patch.object(f, "admit_socket_path"):
            # Windows temporary paths model filesystem snapshots; native Linux
            # socket admission is tested separately against actual planned paths.
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
        with tempfile.TemporaryDirectory() as directory, patch.object(f, "admit_socket_path"):
            # Windows temporary paths model filesystem snapshots; native Linux
            # socket admission is tested separately against actual planned paths.
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
            with patch.object(f, "run_child", return_value={"exit_code": 0, "stdout": raw, "stderr": b""}), self.assertRaises(AssertionError): f.execute_tests(Path("owned.test"), names, Path("owned-test-temp"), "b" * 32, "core")
        with patch.object(f, "run_child", return_value={"exit_code": 0, "stdout": good, "stderr": b""}) as run:
            self.assertEqual(f.execute_tests(Path("owned.test"), names, Path("owned-test-temp"), "b" * 32, "core")["test_names"], names)
            self.assertEqual(run.call_args.kwargs["test_temp"], Path("owned-test-temp"))

    def test_test_temp_rejects_owner_mode_link_and_inode_drift(self):
        good = SimpleNamespace(st_mode=f.stat.S_IFDIR | 0o700, st_uid=0, st_ino=10, st_dev=1)
        for mode, uid in [(f.stat.S_IFDIR | 0o777, 0), (f.stat.S_IFDIR | 0o755, 0), (f.stat.S_IFDIR | 0o700, 65534), (f.stat.S_IFLNK | 0o700, 0), (f.stat.S_IFREG | 0o700, 0)]:
            with self.assertRaises(AssertionError): f.test_directory_info(SimpleNamespace(st_mode=mode, st_uid=uid), True)
        for mode in (0o1755, 0o2755, 0o4755):
            with self.assertRaises(AssertionError): f.test_directory_info(SimpleNamespace(st_mode=f.stat.S_IFDIR | mode, st_uid=0))
        target = MagicMock()
        target.__str__.return_value = "/run/cbbbbbb"
        target.is_absolute.return_value = True
        target.parents = []
        target.lstat.return_value = good
        with patch.object(f, "Path", return_value=target), patch.object(f.os, "O_DIRECTORY", 0x10000, create=True), patch.object(f.os, "O_NOFOLLOW", 0x20000, create=True), patch.object(f.os, "open", return_value=19) as opened, patch.object(f.os, "close") as closed, patch.object(f.os, "fstat", return_value=good):
            self.assertIs(f.trusted_test_temp(target), target)
            self.assertEqual(opened.call_args.args[1] & 0x30000, 0x30000)
            closed.assert_called_once_with(19)

        changed = SimpleNamespace(st_mode=good.st_mode, st_uid=0, st_ino=11, st_dev=1)
        with patch.object(f, "Path", return_value=target), patch.object(f.os, "O_DIRECTORY", 0x10000, create=True), patch.object(f.os, "O_NOFOLLOW", 0x20000, create=True), patch.object(f.os, "open", return_value=19), patch.object(f.os, "close") as closed, patch.object(f.os, "fstat", return_value=changed), self.assertRaises(AssertionError):
            f.trusted_test_temp(target)
        closed.assert_called_once_with(19)
        target.__str__.return_value = "/tmp"
        with patch.object(f, "Path", return_value=target), self.assertRaises(AssertionError): f.trusted_test_temp(target)

    def test_test_directory_setup_separates_core_and_review_with_exact_modes(self):
        info = SimpleNamespace(st_mode=f.stat.S_IFDIR | 0o755, st_uid=0, st_ino=10, st_dev=1)
        with patch.object(f.sys, "platform", "linux"), patch.object(f.os, "geteuid", return_value=0, create=True), patch.object(Path, "lstat", return_value=info), patch.object(f.os, "O_DIRECTORY", 0x10000, create=True), patch.object(f.os, "O_NOFOLLOW", 0x20000, create=True), patch.object(f.os, "open", return_value=19), patch.object(f.os, "fstat", return_value=info), patch.object(f.os, "close") as closed, patch.object(f.os, "mkdir") as mkdir, patch.object(f, "trusted_test_temp", side_effect=lambda path: path) as trusted:
            result = f.create_test_temps("b" * 32)
        self.assertEqual([(call.args, call.kwargs) for call in mkdir.call_args_list], [(("cbbbbbb", 0o700), {"dir_fd": 19}), (("rbbbbbb", 0o700), {"dir_fd": 19})])
        self.assertEqual(set(result), {"core", "review"})
        self.assertNotEqual(result["core"], result["review"])
        self.assertEqual(trusted.call_count, 2)
        closed.assert_called_once_with(19)

    def test_exclusive_test_directory_creation_never_adopts_existing_parent(self):
        good = SimpleNamespace(st_mode=f.stat.S_IFDIR | 0o755, st_uid=0, st_ino=10, st_dev=1)
        with patch.object(f.sys, "platform", "linux"), patch.object(f.os, "geteuid", return_value=0, create=True), patch.object(Path, "lstat", return_value=good), patch.object(f.os, "O_DIRECTORY", 0x10000, create=True), patch.object(f.os, "O_NOFOLLOW", 0x20000, create=True), patch.object(f.os, "open", return_value=19), patch.object(f.os, "fstat", return_value=good), patch.object(f.os, "close") as closed, patch.object(f.os, "mkdir", side_effect=FileExistsError) as mkdir, patch.object(f, "trusted_test_temp") as trusted:
            with self.assertRaises(FileExistsError): f.create_test_temps("b" * 32)
            mkdir.assert_called_once_with("cbbbbbb", 0o700, dir_fd=19)
            trusted.assert_not_called()
            closed.assert_called_once_with(19)

    def test_only_test_child_receives_explicit_verified_tmpdir(self):
        real_popen = subprocess.Popen
        calls = []
        def capture(argv, **options):
            calls.append(dict(options["env"]))
            return real_popen(argv, **options)
        owned = Path("owned-test-temp")
        with patch.object(f, "trusted_test_temp", return_value=owned) as trusted, patch.object(f.subprocess, "Popen", side_effect=capture):
            f.run_child([sys.executable, "-I", "-B", "-c", "print('test')"], timeout=5, test_temp=owned)
            f.run_child([sys.executable, "-I", "-B", "-c", "print('diagnostic')"], timeout=5)
            trusted.assert_called_once_with(owned)
        fixed = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
        self.assertEqual(calls, [dict(fixed, TMPDIR=str(owned)), fixed])
        with patch.object(f, "trusted_test_temp", side_effect=AssertionError("test_temp_authority")), patch.object(f.subprocess, "Popen") as popen, self.assertRaises(AssertionError):
            f.run_child(["native-test"], test_temp=owned)
        popen.assert_not_called()

    def test_indexed_native_paths_preserve_labels_and_existing_100_byte_cap(self):
        nonce = "b" * 32
        planned = f.planned_socket_paths(nonce)
        self.assertEqual(list(planned), ["stock", "adapted", *f.CASE_LABELS, "broker_smoke"])
        self.assertEqual(len(planned), 16)
        for index, label in enumerate(f.CASE_LABELS):
            self.assertEqual(planned[label].parts[-3], "c%02d" % index)
        for endpoint in planned.values():
            f.admit_socket_path(endpoint)
            self.assertLessEqual(len(endpoint.as_posix().encode()), 100)
        old = f.startup_paths(PurePosixPath("/run/sp-cases-" + nonce) / "ancestor_untrusted_nontraversable")[3]
        self.assertEqual(len(old.as_posix().encode()), 106)
        with self.assertRaisesRegex(AssertionError, "socket_path_admission"): f.admit_socket_path(old)
        f.admit_socket_path(PurePosixPath("/" + "x" * 99))
        for value in ["/" + "x" * 100, "/" + "é" * 50, "/run/../private", "//run/socket", "/run/bad\nname"]:
            with self.assertRaisesRegex(AssertionError, "socket_path_admission"): f.admit_socket_path(PurePosixPath(value))

    def test_overlength_broker_path_never_spawns_a_child(self):
        parent = PurePosixPath("/run/sp-cases-" + "b" * 32) / "ancestor_untrusted_nontraversable"
        with patch.object(f.subprocess, "Popen") as popen, self.assertRaisesRegex(AssertionError, "socket_path_admission"):
            f.OwnedBroker(PurePosixPath("/owned/broker"), parent)
        popen.assert_not_called()
        with patch.object(f.subprocess, "Popen") as popen, patch.object(f, "owned_snapshot", return_value="a" * 64), self.assertRaisesRegex(AssertionError, "socket_path_admission"):
            f.startup_observation(PurePosixPath("/owned/broker"), parent)
        popen.assert_not_called()

    def test_fixed_failure_context_reports_only_allowlisted_phase_and_check(self):
        value = report(0)
        with self.assertRaises(f.PhaseFailure) as caught:
            f.run_phase("ancestor_untrusted_nontraversable", lambda: f.validate_startup(value, 7))
        self.assertEqual(caught.exception.diagnostic, {"phase": "ancestor_untrusted_nontraversable", "check_index": 0, "status": "refused", "reason": f.REASONS[0]})
        value = report(0)
        value["checks"][0].update(status="/private/status", reason="private credential-like value")
        with self.assertRaises(f.PhaseFailure) as caught:
            f.run_phase("stock", lambda: f.validate_startup(value, 7))
        self.assertEqual(caught.exception.diagnostic, {"phase": "stock", "check_index": 0, "status": "unknown", "reason": "unknown"})
        self.assertNotIn("private", json.dumps(caught.exception.diagnostic))
        with self.assertRaisesRegex(AssertionError, "phase_label"):
            f.run_phase("/private/phase", lambda: None)
        with self.assertRaises(f.PhaseFailure) as caught:
            f.run_phase("core_tests", lambda: (_ for _ in ()).throw(ValueError("private raw error")))
        self.assertEqual(str(caught.exception), "fixture_observation_failed")
        self.assertEqual(caught.exception.diagnostic, {"phase": "core_tests", "check_index": None, "status": None, "reason": None})
        with self.assertRaises(f.PhaseFailure) as caught:
            f.run_phase("core_tests", lambda: (_ for _ in ()).throw(AssertionError("private_secret")))
        self.assertEqual(str(caught.exception), "fixture_observation_failed")

    def test_main_emits_separate_failure_metadata_without_success_schema_change(self):
        argv = ["fixture.py", "--disposable-startup-preflight", "--nonce", "b" * 32]
        for name in ("baseline", "candidate", "fixture", "core-test", "review-test"):
            argv.extend(["--" + name + "-sha", "a" * 64])
        argv.extend(["--core-test-names", "TestCore", "--review-test-names", "TestReview"])
        error = f.PhaseFailure("startup_order_reason", "state_file", 7, "refused", f.REASONS[7])
        output = io.StringIO()
        with patch.object(f.sys, "argv", argv), patch.object(f.sys, "stdout", output), patch.object(f, "observe", side_effect=error):
            self.assertEqual(f.main(), 1)
        value = json.loads(output.getvalue())
        self.assertEqual(set(value), {"schema_version", "scope", "nonce", "passed", "failure", "diagnostic"})
        self.assertFalse(value["passed"])
        self.assertEqual(value["diagnostic"], error.diagnostic)

    def test_pinned_go_tempdir_expansion_fits_all_ten_private_cases(self):
        root = PurePosixPath("/run/rbbbbbb")
        values = f.private_go_socket_paths(root)
        self.assertEqual(list(values), f.PRIVATE_SUBCASES)
        self.assertEqual(len(values), 10)
        for value in values.values():
            f.admit_socket_path(value)
        self.assertEqual(max(len(value.as_posix().encode()) for value in values.values()), 99)
        self.assertEqual(len(values["controller_duplicate"].as_posix().encode()), 99)
        old = PurePosixPath("/run/sp-tests-" + "b" * 32 + "/review")
        for name in f.PRIVATE_SUBCASES:
            pattern = ("TestIndependentStartupFreshAuthority/" + name)[:64].replace("/", "")
            for random in ("0", "4294967295"):
                endpoint = old / (pattern + random) / "001/run/broker.sock"
                with self.assertRaisesRegex(AssertionError, "socket_path_admission"): f.admit_socket_path(endpoint)
        with patch.object(f, "private_go_socket_paths", return_value={"missing": old / ("x" * 64) / "001/run/broker.sock"}), patch.object(f, "run_child") as child, self.assertRaisesRegex(AssertionError, "socket_path_admission"):
            f.execute_tests(Path("owned.test"), ["TestIndependentStartupFreshAuthority"], root, "b" * 32, "review")
        child.assert_not_called()

    def test_private_native_child_capture_is_bounded_encoded_and_nonce_bound(self):
        output = io.StringIO()
        marker = "SIFRUNO_STARTUP_REPORT_BEGIN_" + "b" * 32
        code = "import sys;print(" + repr(marker) + ");sys.stderr.write('private diagnostic');sys.exit(1)"
        with patch.object(f, "trusted_test_temp", return_value=Path("owned-test-temp")), patch.object(f.sys, "stderr", output):
            result = f.run_child([sys.executable, "-I", "-B", "-c", code], timeout=5, limit=65536, test_temp=Path("owned-test-temp"), private_test_log=("b" * 32, "core"))
        lines = output.getvalue().splitlines()
        self.assertEqual(lines[0], "SIFRUNO_NATIVE_LOG_BEGIN_" + "b" * 32 + "_core")
        self.assertEqual(lines[2], "SIFRUNO_NATIVE_LOG_END_" + "b" * 32 + "_core")
        self.assertNotIn(marker, output.getvalue())
        self.assertNotIn("private diagnostic", output.getvalue())
        packet = json.loads(base64.b64decode(lines[1]))
        self.assertEqual(packet["exit_code"], 1)
        self.assertEqual(base64.b64decode(packet["stdout_base64"]), result["stdout"])
        self.assertEqual(base64.b64decode(packet["stderr_base64"]), result["stderr"])
        self.assertEqual(packet["stdout_sha256"], f.sha(result["stdout"]))
        self.assertEqual(packet["stderr_sha256"], f.sha(result["stderr"]))
        self.assertLessEqual(packet["stdout_bytes"] + packet["stderr_bytes"], 65536)
        output = io.StringIO()
        with patch.object(f, "trusted_test_temp", return_value=Path("owned-test-temp")), patch.object(f.sys, "stderr", output), self.assertRaisesRegex(AssertionError, "child_timeout"):
            f.run_child([sys.executable, "-I", "-B", "-c", "import time;time.sleep(10)"], timeout=.1, limit=65536, test_temp=Path("owned-test-temp"), private_test_log=("b" * 32, "core"))
        packet = json.loads(base64.b64decode(output.getvalue().splitlines()[1]))
        self.assertTrue(packet["timed_out"])


if __name__ == "__main__":
    unittest.main()
