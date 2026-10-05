"""Import-safe contract tests. No guest launch/accounts/mounts/policy writes."""
import copy
import importlib.util
import json
import io
from pathlib import Path
import unittest
import time
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("serving_guest_contract", Path(__file__).with_name("serving_guest.py"))
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)


def admission():
    return {"schema_version": 1, "kind": "trusted-disposable-alma9-runtime-serving", "nonce": "a" * 24, "prepared_image_sha256": "1" * 64, "fixture_sha256": "2" * 64, "helper_sha256": g.HELPER_SHA, "source_catalog_sha256": g.SOURCE_CATALOG_SHA, "package_report_sha256": "4" * 64, "driver_sha256": g.DRIVER_SHA, "test_sha256": g.TEST_SHA, "zero_external_nics": True}


def packages():
    return {"schema_version": 1, "kind": "alma9-prepared-web-packages", "packages": [{"name": name, "nevra": name + "-0:1.0-1.el9.x86_64", "filename": name + "-1.0-1.el9.x86_64.rpm", "sha256": "a" * 64, "bytes": 100} for name in sorted(g.PACKAGE_NAMES)]}


def driver():
    p, snapshots = g.expected_digests()
    identities = [{"generation_id": gen, "profile_sha256": p, "snapshot_sha256": snapshots[0 if i < 2 else 1], "bundle_sha256": str(i + 1) * 64, "denied": i != 1} for i, gen in enumerate(("", "c" * 32, "d" * 32))]
    stages = (("bootstrap", 0), ("active_before_requests", 1), ("active_after_php_webalpha", 1), ("active_after_worker_webalpha", 1), ("active_after_php_webbravo", 1), ("active_after_worker_webbravo", 1), ("active_after_all_workers", 1), ("suspended_denied", 2), ("suspended_after_requests", 2))
    r = {"schema_version": 1, "fixture_only": True, "execution_kind": "native-linux-driver", "run_id": g.driver_run_id("a" * 24), "nonce": "e" * 32, "driver_sha256": g.DRIVER_SHA, "runtime_manifest_sha256": g.RUNTIME_SHA, "input_sha256": "f" * 64, "profile_sha256": p, "intended_generations": identities, "observations": [{"stage": stage, "identity": copy.deepcopy(identities[i])} for stage, i in stages], "probes": [], "workers": [], "prerequisites": {"selinux_enforce": "1", "network_admin_raw_absent": "true", "NoNewPrivs": "0", "kernel_release": "test-only", **{key: "0000000000000000" for key in ("CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh")}}, "stage": "complete", "passed": True, "shutdown_passed": True, "close_passed": True, "listeners_extinct": True, "input_stable": True, "selinux_stable": True}
    for i, a in enumerate(g.accounts()):
        body = f"SIFRUNO_STATIC_{a['username']}\n".encode()
        r["probes"].append({"account_id": a["id"], "kind": "static", "status": 200, "bytes": len(body), "sha256": g.digest(body), "contract_passed": True})
        body = f"SIFRUNO_PHP_{a['username']}\nSELF=readable\nHOST=denied\nSIBLING=denied\nPID=7\n".encode()
        r["probes"].append({"account_id": a["id"], "kind": "php", "status": 200, "bytes": len(body), "sha256": g.digest(body), "contract_passed": True})
        r["workers"].append({"account_id": a["id"], "host_pid": 200 + i, "namespace_pid": 7, "namespace": 123 + i, "uid": [a["uid"]] * 4, "gid": [a["gid"]] * 4, "groups": [a["gid"]], "capabilities": {key: "0000000000000000" for key in ("CapEff", "CapPrm", "CapInh", "CapAmb")}, "root": (g.ROOT / "backend-jails" / a["id"]).as_posix(), "start": "321"})
    for host in ("alpha.test", "bravo.test", "foreign.test"):
        r["probes"].append({"account_id": "", "kind": "denied_" + host, "status": 403, "bytes": 1, "sha256": "0" * 64, "contract_passed": True})
    return r


class ContractTests(unittest.TestCase):
    def test_admission_exact_nonce_and_pins(self):
        self.assertEqual(g.validate_admission(admission()), admission())
        for field, value in (("nonce", "x" * 24), ("nonce", "a" * 32), ("driver_sha256", "a" * 64), ("helper_sha256", "a" * 64), ("zero_external_nics", 1), ("schema_version", True)):
            v = admission(); v[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(g.Failure):
                g.validate_admission(v)
        v = admission(); v["path"] = "/etc/shadow"
        with self.assertRaises(g.Failure): g.validate_admission(v)

    def test_json_duplicates_nonfinite_and_bound(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{} {}', b'\xff', b' ' * (g.MAX_JSON + 1)):
            with self.assertRaises(g.Failure): g.strict_json(raw)

    def test_package_path_nevra_identity_and_storage(self):
        self.assertEqual(len(g.package_entries(packages())), 18)
        for field, value in (("filename", "../escaped.rpm"), ("nevra", "other-0:1-1.el9.x86_64"), ("name", "foreign"), ("bytes", True), ("bytes", g.MAX_RPM + 1), ("sha256", "a")):
            v = packages(); v["packages"][0][field] = value
            with self.subTest(field=field), self.assertRaises(g.Failure): g.package_entries(v)
        v = packages(); v["packages"][1] = v["packages"][0]
        with self.assertRaises(g.Failure): g.package_entries(v)
        v = packages()
        for p in v["packages"]: p["bytes"] = g.MAX_RPM
        with self.assertRaises(g.Failure): g.package_entries(v)

    def test_signature_requires_actual_expected_signature_line(self):
        good = b"Header V4 RSA/SHA256 Signature, key ID b86b3716: OK\nHeader SHA256 digest: OK\n"
        self.assertEqual(g.signature_ok(good, 0), "B86B3716")
        for output, code in ((good, 1), (b"SHA256 digest: OK\n", 0), (good.replace(b"b86b3716", b"deadbeef"), 0), (good + b"Payload digest: NOT OK\n", 0), (good + b"NOKEY\n", 0), (b"a" * 16385, 0)):
            with self.assertRaises(g.Failure): g.signature_ok(output, code)

    def test_php_core_exact_newline_and_real_paths(self):
        a, b = g.accounts()
        code = g.php_code(a, b)
        self.assertIn(b'getmypid()', code)
        self.assertNotIn(b'getmyuid', code)
        self.assertNotIn(b'posix_', code)
        self.assertIn(b'"SELF=".(is_readable(__FILE__)', code)
        self.assertIn((b["home"] + "/private.txt").encode(), code)
        self.assertIn((g.ROOT / "managed/controller-private-sentinel").as_posix().encode(), code)
        self.assertIn(b'"\\n"', code)

    def test_driver_strict_success_and_negative_receipts(self):
        self.assertIs(g.valid_driver(driver(), admission(), "f" * 64)["passed"], True)
        for key in ("passed", "shutdown_passed", "close_passed", "listeners_extinct", "input_stable", "selinux_stable"):
            r = driver(); r[key] = False
            with self.subTest(key=key), self.assertRaises(g.Failure): g.valid_driver(r, admission(), "f" * 64)
        for mutate in (lambda r: r["observations"].pop(), lambda r: r["observations"][0].update(stage="active"), lambda r: r["observations"][1]["identity"].update(snapshot_sha256="a" * 64), lambda r: r["probes"][0].update(status=302), lambda r: r["probes"][1].update(sha256="a" * 64), lambda r: r["workers"][0]["uid"].__setitem__(1, 0), lambda r: r["workers"][0].update(groups=[0]), lambda r: r["workers"][0]["capabilities"].update(CapEff="1"), lambda r: r["workers"][0].update(root="/"), lambda r: r.update(input_sha256="a" * 64)):
            r = driver(); mutate(r)
            with self.assertRaises(g.Failure): g.valid_driver(r, admission(), "f" * 64)

    def test_bound_failure_receipt_retains_stage_but_cannot_pass(self):
        r = driver(); r["passed"] = False; r["stage"] = "bootstrap:runtime_recovery_required"
        self.assertEqual(g.driver_header(r, admission(), "f" * 64)["stage"], r["stage"])
        with self.assertRaises(g.Failure): g.valid_driver(r, admission(), "f" * 64)
        r["private_key"] = "forbidden"
        with self.assertRaises(g.Failure): g.driver_header(r, admission(), "f" * 64)

    def test_cleanup_refuses_foreign_id_but_removes_other_owned(self):
        mounts = {"/owned/a": 2, "/owned/b": 3}
        calls = []
        class H:
            def unmount(self, path): calls.append(path.as_posix()); mounts.pop(path.as_posix())
        with patch.object(g, "mounted", side_effect=lambda: dict(mounts)):
            with self.assertRaises(g.Failure): g.cleanup_mounts(H(), [{"target": "/owned/a", "mount_id": 1}, {"target": "/owned/b", "mount_id": 3}])
        self.assertEqual(calls, ["/owned/b"])
        self.assertEqual(mounts, {"/owned/a": 2})

    def test_capture_pidfd_acquisition_failure_reaps_owned_child(self):
        class Child:
            pid, returncode = 1234, None
            stdout, stderr = io.BytesIO(), io.BytesIO()
            killed, waited = False, False
            def kill(self): self.killed = True
            def wait(self, timeout): self.waited = True; self.returncode = -9; return -9
        child = Child()
        with patch.object(g.os, "pidfd_open", side_effect=OSError("injected"), create=True):
            with self.assertRaises(OSError): g.capture_child(child, time.monotonic() + 1)
        self.assertTrue(child.killed and child.waited and child.stdout.closed and child.stderr.closed)

    def test_capture_registration_failure_uses_exact_pidfd_and_reaps(self):
        class Pipe(io.BytesIO):
            def fileno(self): return 8
        class Child:
            pid, returncode = 1234, None
            stdout, stderr = Pipe(), Pipe()
            waited = False
            def wait(self, timeout): self.waited = True; self.returncode = -9; return -9
        class Selector:
            closed = False
            def register(self, *args): raise OSError("injected_registration_failure")
            def close(self): self.closed = True
        child, selector, signals = Child(), Selector(), []
        with patch.object(g.os, "pidfd_open", return_value=42, create=True), patch.object(g.os, "set_blocking"), patch.object(g.os, "close") as close, patch.object(g.selectors, "DefaultSelector", return_value=selector), patch.object(g.signal, "SIGKILL", 9, create=True), patch.object(g.signal, "pidfd_send_signal", side_effect=lambda fd, sig: signals.append((fd, sig)), create=True):
            with self.assertRaises(OSError): g.capture_child(child, time.monotonic() + 1)
        self.assertEqual(signals, [(42, 9)])
        self.assertTrue(child.waited and selector.closed and child.stdout.closed and child.stderr.closed)
        close.assert_called_once_with(42)

    def test_driver_requires_policy_and_nested_field_admission(self):
        for mutate in (lambda r: r["prerequisites"].update(selinux_enforce="0"), lambda r: r["prerequisites"].update(CapBnd="0000000000001000"), lambda r: r["probes"][0].update(unknown=True), lambda r: r["workers"][0].update(unknown=True)):
            r = driver(); mutate(r)
            with self.assertRaises(g.Failure): g.valid_driver(r, admission(), "f" * 64)


if __name__ == "__main__": unittest.main()
