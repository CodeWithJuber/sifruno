"""Synthetic TempDir fixtures only; not actual Linux broker qualification."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("broker_fixture", Path(__file__).with_name("fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
owned = Path(__file__).resolve().parents[2]
scratch = owned / ".cache" / "broker-paths-tests"
for parent in (scratch.parent, scratch):
    if not parent.exists():
        parent.mkdir()
    assert parent.resolve() == parent and not parent.is_symlink()


class SyntheticContracts(unittest.TestCase):
    def test_controller_must_be_existing_unique_nonroot(self):
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            path = Path(directory) / "passwd"
            path.write_text("root:x:0:0::/root:/bin/sh\nnobody:x:65534:65534::/:/sbin/nologin\n")
            self.assertEqual(fixture.unique_uid(path, 65534)["matching_local_passwd_records"], 1)
            with self.assertRaises(AssertionError):
                fixture.unique_uid(path, 0)
            path.write_text(path.read_text() + "alias:x:65534:65534::/:/sbin/nologin\n")
            with self.assertRaisesRegex(AssertionError, "controller_not_unique"):
                fixture.unique_uid(path, 65534)

    def test_duplicates_truncation_and_nonfinite_json(self):
        for raw in ('{"nested":{"id":1,"id":1}}', '{"passed":true,"passed":true}', '{"x":', '{"x":NaN}'):
            with self.assertRaises((AssertionError, json.JSONDecodeError)):
                fixture.strict_json(raw)

    def test_metadata_hash_preserves_sentinel_and_omits_contents(self):
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            path = Path(directory) / "sentinel"
            path.write_text("synthetic_conflict_content")
            before = fixture.tree_snapshot(Path(directory))
            self.assertNotIn("synthetic_conflict_content", json.dumps(before))
            self.assertEqual(before, fixture.tree_snapshot(Path(directory)))
            path.write_text("changed")
            self.assertNotEqual(before, fixture.tree_snapshot(Path(directory)))

    def test_preexisting_fixture_parent_refused_without_child(self):
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            with self.assertRaisesRegex(AssertionError, "case_admission"):
                fixture.prepare_case(Path(directory), "homes_file")
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_candidate_added_directory_is_never_accepted(self):
        before = [{"path": ".", "kind": "directory"}, {"path": "homes", "kind": "file", "sha256": "old"}]
        after = before + [{"path": "state", "kind": "directory"}]
        with patch.object(fixture, "prepare_case", return_value=before), patch.object(fixture, "tree_snapshot", return_value=after), patch.object(fixture, "run_child", return_value={"exit_code": 1, "stdout": b"", "stderr": b"Native broker unavailable or recovery required\n", "owned_child_exited": True}):
            with self.assertRaisesRegex(AssertionError, "candidate_conflict_mutation"):
                fixture.observe_conflict(Path("unused"), Path("unused"), 65534, "homes_file", False)

    def test_owned_child_bounds_and_cleanup(self):
        normal = fixture.run_child([sys.executable, "-I", "-c", "print('synthetic')"])
        self.assertTrue(normal["owned_child_exited"])
        with self.assertRaisesRegex(AssertionError, "child_output_limit"):
            fixture.run_child([sys.executable, "-I", "-c", "print('x'*100000)"], limit=64)
        with self.assertRaisesRegex(AssertionError, "child_timeout"):
            fixture.run_child([sys.executable, "-I", "-c", "import time;time.sleep(5)"], timeout=0.1)


if __name__ == "__main__":
    unittest.main()
