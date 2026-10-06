"""Synthetic TempDir/owned-child tests; these are not native guest evidence."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("stock_fixture", Path(__file__).with_name("fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class SyntheticContracts(unittest.TestCase):
    def test_unique_existing_numeric_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "passwd"
            path.write_text("root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/sbin/nologin\n")
            self.assertEqual(fixture.unique_uid(path, 65534)["matching_local_passwd_records"], 1)
            with self.assertRaisesRegex(AssertionError, "controller_not_unique"):
                fixture.unique_uid(path, 12345)
            path.write_text(path.read_text() + "alias:x:65534:65534::/:/sbin/nologin\n")
            with self.assertRaisesRegex(AssertionError, "controller_not_unique"):
                fixture.unique_uid(path, 65534)
            with self.assertRaisesRegex(AssertionError, "controller_uid"):
                fixture.unique_uid(path, 0)

    def test_duplicate_nested_and_truncated_json(self):
        for raw in ('{"checks":[{"id":"nss","id":"nss"}]}', '{"read_only":true,"read_only":true}', '{"checks":['):
            with self.assertRaises((AssertionError, json.JSONDecodeError)):
                fixture.strict_json(raw)

    def test_stock_dto_refuses_unknown_fields_and_false_admission(self):
        value = {"schema_version": 1, "scope": "native_linux_account_host_policy", "platform": "linux", "supported": False, "read_only": True, "checks": [{"id": "utilities", "status": "pass", "reason": "satisfied"}, {"id": "nss", "status": "refused", "reason": "files_only_nss_required"}, {"id": "useradd_defaults", "status": "refused", "reason": "mail_disabled_defaults_required"}], "restrictions": fixture.RESTRICTIONS.copy()}
        self.assertEqual(fixture.validate_check(value), value)
        for change in (lambda x: x.update(supported=True), lambda x: x.update(raw_path="private"), lambda x: x["checks"].reverse(), lambda x: x["checks"][1].update(reason="satisfied"), lambda x: x.update(schema_version=True)):
            copy = json.loads(json.dumps(value))
            change(copy)
            with self.assertRaises(AssertionError):
                fixture.validate_check(copy)

    def test_metadata_never_contains_policy_text_and_detects_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "etc/default/useradd"
            path.parent.mkdir(parents=True)
            path.write_text("synthetic_private_policy\n")
            before = fixture.policy_snapshot(root)
            self.assertNotIn("synthetic_private_policy", json.dumps(before))
            self.assertEqual(set(before[2]), {"id", "kind", "mode", "bytes", "sha256"})
            path.write_text("different_policy_bytes\n")
            self.assertNotEqual(before, fixture.policy_snapshot(root))

    def test_declared_path_admission_no_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory) / "existing"
            parent.mkdir()
            with self.assertRaisesRegex(AssertionError, "fixture_path_preexists"):
                fixture.observe_startup(Path("never-executed"), parent, 65534, False)
            self.assertEqual(list(parent.iterdir()), [])

    def test_owned_child_output_bound_and_timeout(self):
        okay = fixture.run_child([sys.executable, "-I", "-c", "print('synthetic')"])
        self.assertEqual(okay["exit_code"], 0)
        self.assertTrue(okay["owned_child_exited"])
        with self.assertRaisesRegex(AssertionError, "child_output_limit"):
            fixture.run_child([sys.executable, "-I", "-c", "print('x'*100000)"] , limit=64)
        with self.assertRaisesRegex(AssertionError, "child_timeout"):
            fixture.run_child([sys.executable, "-I", "-c", "import time; time.sleep(5)"], timeout=0.1)


if __name__ == "__main__":
    unittest.main()
