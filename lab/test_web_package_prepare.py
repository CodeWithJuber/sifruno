"""Import-safe regression checks; no guest admission, subprocess, or live state."""

import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("web_package_prepare", Path(__file__).with_name("web_package_prepare.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def package(name, version="8.3.30", epoch=0, release="1.el9_8", arch="x86_64"):
    return SimpleNamespace(name=name, version=version, epoch=epoch, release=release, arch=arch,
                           reponame="AppStream", downloadsize=42)


def php_packages(version="8.3.30"):
    return [package(name, version) for name in ("php-common", "php-fpm", "php-process")]


def dnf_modules(base, available=("8.3",), enable_error=False):
    class ModuleBase:
        def __init__(self, actual):
            if actual is not base:
                raise AssertionError("wrong DNF base")

        def get_modules(self, name):
            if name != "php":
                raise AssertionError("wrong module")
            return [SimpleNamespace(getName=lambda: "php", getStream=lambda value=value: value)
                    for value in available], None

        def enable(self, specs):
            if specs != ["php:8.3"]:
                raise AssertionError("wrong stream")
            base.enabled = True
            if enable_error:
                raise RuntimeError("partially changed sack")

    dnf = ModuleType("dnf")
    dnf.Base = lambda: base
    module = ModuleType("dnf.module")
    module_base = ModuleType("dnf.module.module_base")
    module_base.ModuleBase = ModuleBase
    return {"dnf": dnf, "dnf.module": module, "dnf.module.module_base": module_base}


class PackagePreparationTests(unittest.TestCase):
    def assert_failure(self, code, call):
        with self.assertRaisesRegex(helper.PreparationError, "^" + code + "$"):
            call()

    def test_dnf_diagnostic_preserves_actionable_stderr_and_stdout_fallback(self):
        diagnostic = helper.dnf_install_diagnostic(1, b"Transaction failed\n", b"Error: conflicting requests\n")
        self.assertEqual(diagnostic["command"], "dnf_offline_install")
        self.assertEqual(diagnostic["exit_code"], 1)
        self.assertEqual(diagnostic["stderr"], "Error: conflicting requests")
        self.assertEqual(diagnostic["stdout"], "Transaction failed")
        self.assertFalse(diagnostic["truncated"])
        self.assertEqual(helper.dnf_install_diagnostic(2, b"Error: missing dependency", b"")["stdout"], "Error: missing dependency")

    def test_dnf_diagnostic_bounds_combined_bytes_and_lines(self):
        for stdout, stderr in ((b"x" * 9000, b"y" * 9000), (b"summary\n" * 20, b"error\n" * 20)):
            with self.subTest(output_size=len(stderr)):
                diagnostic = helper.dnf_install_diagnostic(1, stdout, stderr)
                self.assertLessEqual(len(diagnostic["stdout"].encode()) + len(diagnostic["stderr"].encode()), 8192)
                self.assertLessEqual(len(diagnostic["stdout"].splitlines()) + len(diagnostic["stderr"].splitlines()), 16)
                self.assertTrue(diagnostic["truncated"])

    def test_dnf_diagnostic_strips_ansi_controls_and_redacts_sensitive_lines(self):
        raw = b"\x1b[31mError\x1b[0m\x00\x07\npassword=hunter2\nAuthorization: Bearer abc123\nhttps://user:pass@example.test/path\n"
        diagnostic = helper.dnf_install_diagnostic(1, b"", raw)
        text = diagnostic["stderr"]
        self.assertIn("Error", text)
        self.assertIn("https://[redacted]@example.test/path", text)
        for forbidden in ("hunter2", "abc123", "user:pass", "\x1b", "\x00", "\x07"):
            self.assertNotIn(forbidden, text)
        for raw in (b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nkeybytes", b"Traceback (most recent call last):\nprivate traceback data"):
            text = helper.dnf_install_diagnostic(1, b"", raw)["stderr"]
            self.assertNotIn("keybytes", text)
            self.assertNotIn("private traceback data", text)

    def test_only_fixed_dnf_failure_attaches_diagnostic_to_install_failure_report(self):
        failure = helper.DNFInstallFailure(1, b"", b"Error: local RPM dependency absent")
        with patch.object(helper, "args", return_value=SimpleNamespace(phase="install", report_path=Path("unused"))), \
                patch.object(helper, "require_root_and_admission"), \
                patch.object(helper, "require_readonly_cidata"), \
                patch.object(helper, "apply_process_limits"), \
                patch.object(helper, "install", side_effect=failure), \
                patch.object(helper, "write_report") as write:
            self.assert_failure("dnf_install_failed", helper.main)
        report = write.call_args.args[1]
        self.assertFalse(report["passed"])
        self.assertEqual(report["diagnostic"]["exit_code"], 1)
        self.assertEqual(report["diagnostic"]["stderr"], "Error: local RPM dependency absent")
        with patch.object(helper, "write_report") as write:
            helper.write_failure_report(Path("unused"), "install", "unexpected_failure", failure)
            self.assertNotIn("diagnostic", write.call_args.args[1])
            helper.write_failure_report(Path("unused"), "resolve", "dnf_install_failed", failure)
            self.assertNotIn("diagnostic", write.call_args.args[1])

    def test_phase_process_limits_sets_nnp_only_for_resolve(self):
        resource = SimpleNamespace(RLIMIT_FSIZE=1, RLIMIT_NOFILE=2, RLIMIT_NPROC=3, setrlimit=lambda *_: None)
        libc = SimpleNamespace(prctl=lambda *_: 0)
        with patch.object(helper, "resource", resource), patch.object(helper.os, "umask"), \
                patch.object(helper.ctypes, "CDLL", return_value=libc) as load, \
                patch.object(helper, "require_privilege_profile", return_value={}) as require:
            helper.apply_process_limits("resolve")
            self.assertEqual(load.call_count, 1)
            self.assertEqual(require.call_args.args, ("resolve",))
            load.reset_mock()
            helper.apply_process_limits("install")
            load.assert_not_called()
            self.assertEqual(require.call_args.args, ("install",))

    def test_installer_rejects_inherited_nnp_without_attempting_unset(self):
        observed = {"no_new_privs": 1, "selinux_enforce": 1, "network_capabilities_present": []}
        with patch.object(helper, "privilege_profile", return_value=observed), patch.object(helper.ctypes, "CDLL") as load:
            self.assert_failure("installer_parent_no_new_privs", lambda: helper.apply_process_limits("install"))
        load.assert_not_called()

    def test_privilege_observation_and_enforcing_network_guards(self):
        def text(path, **_):
            return "NoNewPrivs:\t0\nCapEff:\t0000000000000000\n" if path.as_posix() == "/proc/self/status" else "1\n"
        with patch.object(helper.Path, "read_text", text):
            observed = helper.require_privilege_profile("install")
        self.assertEqual(observed["profile"], "install_stock_nnp0_signed_pinned_rpms")
        self.assertEqual(observed["no_new_privs"], 0)
        self.assertEqual(observed["selinux_enforce"], 1)
        with patch.object(helper, "privilege_profile", return_value={**observed, "selinux_enforce": 0}):
            self.assert_failure("selinux_not_enforcing", lambda: helper.require_privilege_profile("install"))
        with patch.object(helper, "privilege_profile", return_value={**observed, "network_capabilities_present": ["CAP_NET_ADMIN"]}):
            self.assert_failure("network_capability_present", lambda: helper.require_privilege_profile("install"))

    def test_failure_report_records_observed_privilege_profile(self):
        observed = {"profile": "install_stock_nnp0_signed_pinned_rpms", "no_new_privs": 1, "selinux_enforce": 1, "network_capabilities_present": []}
        with patch.object(helper, "privilege_profile", return_value=observed), patch.object(helper, "write_report") as write:
            helper.write_failure_report(Path("unused"), "install", "installer_parent_no_new_privs")
        self.assertEqual(write.call_args.args[1]["privilege_profile"], observed)

    def test_avc_evidence_keeps_only_fresh_process_transition_fields(self):
        line = 'type=AVC msg=audit(1000.250:12): avc: denied { nnp_transition } for pid=999 comm="secret-path" path="/private/customer" scontext=system_u:system_r:rpm_t:s0 tcontext=system_u:system_r:rpm_script_t:s0 tclass=process permissive=0'
        records = helper.transition_avcs(line, 1000.0)
        self.assertEqual(records, [{"event": "1000.250:12", "denied": ["nnp_transition"], "source_type": "rpm_t", "target_type": "rpm_script_t", "class": "process", "permissive": 0}])
        self.assertNotIn("customer", str(records))
        self.assertNotIn("secret-path", str(records))
        for excluded in (line.replace("1000.250", "999.250"), line.replace("nnp_transition", "read"),
                         line.replace("tclass=process", "tclass=file"), line.replace("type=AVC", "type=SYSCALL")):
            self.assertEqual(helper.transition_avcs(excluded, 1000.0), [])
        self.assertEqual(len(helper.transition_avcs("\n".join([line] * 30), 1000.0)), 8)

    def test_audit_unavailable_is_explicit_and_does_not_attach_raw_errors(self):
        with patch.object(helper.os, "open", side_effect=OSError("sensitive error details")):
            evidence = helper.audit_transition_evidence(1000.0)
        self.assertEqual(evidence, {"scope": "current_offline_dnf_install_transition_denials", "records": [], "available": False, "reason": "audit_log_unavailable"})

    def test_signature_only_accepts_expected_key_ok_and_success_status(self):
        short = helper.ALMA_KEY_FINGERPRINT[-8:]
        long = helper.ALMA_KEY_FINGERPRINT[-16:]
        for key in (short, long):
            with self.subTest(key=key):
                self.assertEqual(helper.signature_verified(f"Header V4 RSA/SHA256 Signature, key ID {key}: OK\n", 0), key)
        bad = (f"Header Signature, key ID {short}: NOKEY", "Header Signature, key ID deadbeef: OK",
               f"Header SHA256 digest, key ID {short}: OK", f"Header Signature, key ID {short}: BAD\nSHA256 digest: OK")
        for output in bad:
            with self.subTest(output=output):
                self.assertIsNone(helper.signature_verified(output, 0))
        self.assertIsNone(helper.signature_verified(f"Header Signature, key ID {short}: OK", 1))

    def test_signature_wrapper_rejects_invalid_command_output(self):
        with patch.object(helper, "command", return_value=(0, b"SHA256 digest: OK", b"")):
            self.assert_failure("rpm_signature_invalid", lambda: helper.check_signature(Path("unused.rpm")))

    def test_nevra_keeps_explicit_epoch_and_hyphenated_name(self):
        self.assertEqual(helper.package_nevra(package("php-common", epoch=0)), "php-common-0:8.3.30-1.el9_8.x86_64")
        self.assertEqual(helper.package_nevra(package("php-common", epoch=2)), "php-common-2:8.3.30-1.el9_8.x86_64")
        self.assert_failure("dnf_package_nevra_missing", lambda: helper.package_nevra(SimpleNamespace(name="php-fpm")))

    def test_actual_php_versions_are_independent_of_default_intent(self):
        observed = helper.resolved_php_packages(php_packages("8.0.30"), "distribution-default")
        self.assertEqual([item["name"] for item in observed], ["php-common", "php-fpm", "php-process"])
        self.assertEqual({item["version"] for item in observed}, {"8.0.30"})

    def test_selected_stream_requires_matching_actual_php_version(self):
        self.assert_failure("dnf_php_stream_version_mismatch", lambda: helper.resolved_php_packages(php_packages("8.0.30"), "8.3"))
        self.assertEqual(len(helper.resolved_php_packages(php_packages(), "8.3")), 3)

    def test_php_set_rejects_missing_duplicate_mixed_or_malformed_versions(self):
        cases = [(php_packages()[:2], "dnf_php_package_set_invalid"),
                 (php_packages() + [package("php-fpm")], "dnf_php_package_version_invalid"),
                 ([package("php-common", "8.0.30"), *php_packages()[1:]], "dnf_php_package_set_invalid"),
                 (php_packages("8.3.fake"), "dnf_php_package_version_invalid")]
        for packages, code in cases:
            with self.subTest(code=code):
                self.assert_failure(code, lambda: helper.resolved_php_packages(packages, "distribution-default"))

    def test_stream_enable_error_fails_after_partial_state_change(self):
        base = SimpleNamespace(enabled=False)
        with patch.dict(sys.modules, dnf_modules(base, enable_error=True)):
            self.assert_failure("dnf_php_stream_enable_failed", lambda: helper.select_php_stream(base))
        self.assertTrue(base.enabled)

    def test_unavailable_stream_uses_clean_distribution_default(self):
        base = SimpleNamespace(enabled=False)
        with patch.dict(sys.modules, dnf_modules(base, available=("8.1",))):
            self.assertEqual(helper.select_php_stream(base)["selected"], "distribution-default")
        self.assertFalse(base.enabled)

    def test_resolve_does_not_refill_sack_after_enabling(self):
        class Base:
            def __init__(self):
                self.conf = SimpleNamespace()
                self.repos = SimpleNamespace(add_new_repo=lambda *_: SimpleNamespace())
                self.transaction = SimpleNamespace(install_set=php_packages())
                self.enabled = False
                self.fills = 0
                self.goals = []

            def fill_sack(self, **_):
                self.fills += 1
                self.enabled = False

            def install(self, name):
                self.goals.append(name)
                if not self.enabled:
                    raise AssertionError("stream selection discarded")

            def resolve(self):
                return True

        base = Base()
        with patch.dict(sys.modules, dnf_modules(base)), \
                patch.object(helper, "repository_manifest", return_value={}), \
                patch.object(helper, "rpm_baseline", return_value=[]), \
                patch.object(helper, "package_location", side_effect=lambda pkg, _: f"Packages/p/{pkg.name}.rpm"), \
                patch.object(helper, "package_checksum", return_value="a" * 64), \
                patch.object(helper, "require_privilege_profile", return_value={"no_new_privs": 1, "selinux_enforce": 1}), \
                patch.object(helper, "digest", return_value="b" * 64), \
                patch.object(helper, "write_report") as write:
            helper.resolve(Path("unused"))
        self.assertEqual(base.fills, 1)
        self.assertEqual(base.goals, list(helper.GOAL))
        report = write.call_args.args[1]
        self.assertEqual(report["php_stream"]["selected"], "8.3")
        self.assertEqual({item["version"] for item in report["resolved_php_packages"]}, {"8.3.30"})

    def test_installed_versions_normalizes_absent_epoch(self):
        with patch.object(helper, "command", return_value=(0, b"php-fpm\tphp-fpm-(none):8.0.30-8.el9_8.x86_64\n", b"")) as command:
            observed = helper.installed_versions(["php-fpm.x86_64"])
        self.assertEqual(command.call_args.args[0][-1], "php-fpm.x86_64")
        self.assertEqual(observed, [{"name": "php-fpm", "nevra": "php-fpm-0:8.0.30-8.el9_8.x86_64"}])

    def test_install_queries_name_arch_and_compares_exact_admitted_nevras(self):
        packages = [{"repository": "AppStream", "nevra": helper.package_nevra(pkg),
                     "relative_path": f"Packages/p/{pkg.name}.rpm", "checksum_sha256": "a" * 64,
                     "size": 42, "file": f"packages/{pkg.name}.rpm"} for pkg in php_packages("8.0.30")]
        installed = [{"name": pkg.name, "nevra": helper.package_nevra(pkg)} for pkg in php_packages("8.0.30")]
        with patch.object(helper, "resolve_report", return_value={"packages": packages}), \
                patch.object(helper, "package_manifest", return_value={"packages": packages}), \
                patch.object(helper, "key_fingerprint"), \
                patch.object(helper, "require_privilege_profile", return_value={"no_new_privs": 0, "selinux_enforce": 1}), \
                patch.object(helper, "confined", side_effect=lambda _, name, label: Path(name)), \
                patch.object(helper, "check_signature", return_value={"verification": "ok"}), \
                patch.object(helper, "command", return_value=(0, b"", b"")) as run, \
                patch.object(helper, "installed_versions", return_value=installed) as query, \
                patch.object(helper, "observations", return_value={}), \
                patch.object(helper, "write_report"):
            helper.install(Path("unused"))
            self.assertEqual(query.call_args.args[0], ["php-common.x86_64", "php-fpm.x86_64", "php-process.x86_64"])
            query.return_value = [{**item, "nevra": item["nevra"].replace("8.0.30", "8.0.31")} for item in installed]
            self.assert_failure("installed_nevra_mismatch", lambda: helper.install(Path("unused")))
            run.return_value = (1, b"DNF summary", b"Error: dependency absent")
            with self.assertRaises(helper.DNFInstallFailure) as caught:
                helper.install(Path("unused"))
            self.assertEqual(caught.exception.diagnostic["stderr"], "Error: dependency absent")
            self.assertEqual(run.call_args.args[0][:5], ["dnf", "--assumeyes", "--disablerepo=*", "--setopt=localpkg_gpgcheck=1", "install"])


if __name__ == "__main__":
    unittest.main()
