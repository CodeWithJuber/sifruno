"""Temporary stdlib admission challenges, independent of product execution."""
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("prepare_review", pathlib.Path(__file__).with_name("prepare.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


class OutputAdmission(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="sifruno-preview-helper-")
        self.addCleanup(self.temp.cleanup)
        self.base = pathlib.Path(self.temp.name).resolve()
        self.own, self.candidate = self.base / "own", self.base / "candidate"
        self.own.mkdir()
        self.candidate.mkdir()
        entries = []
        for relative in ["go.mod", "go.sum"] + [f"internal/fixture/p{i:02}.go" for i in range(81)]:
            raw = ("synthetic helper admission: " + relative + "\n").encode()
            target = self.candidate / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            entries.append({"path": relative, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            if relative in ("go.mod", "go.sum"):
                (self.own / relative).write_bytes(raw)
        self.lab = self.own / "lab/native-restore-preview-review"
        self.lab.mkdir(parents=True)
        (self.lab / "source-catalog.json").write_text(json.dumps({"schema": 1, "kind": "independent-native-restore-preview-source-freeze", "inputs": entries}))

    def link(self, path):
        outside = self.base / "outside"
        outside.mkdir()
        if os.name == "nt":
            # Local TempDir-only junction; explicit removal before temp cleanup.
            result = subprocess.run(["cmd", "/c", "mklink", "/J", str(path), str(outside)], capture_output=True)
            self.assertEqual(result.returncode, 0, "temporary junction creation failed")
            self.addCleanup(lambda: os.rmdir(path))
        else:
            path.symlink_to(outside, target_is_directory=True)
            self.addCleanup(path.unlink)
        return outside

    def test_normal_83_admission_preserves_candidate_bytes(self):
        before = {p.relative_to(self.candidate).as_posix(): p.read_bytes() for p in self.candidate.rglob("*") if p.is_file()}
        result = helper.prepare(self.own, self.candidate)
        self.assertEqual(result["admitted_inputs"], 83)
        self.assertEqual(result["production_go_overlays"], 81)
        overlay = json.loads((self.own / ".cache/native-restore-preview-review/prepared/overlay.json").read_text())
        self.assertEqual(len(overlay["Replace"]), 81)
        for destination in overlay["Replace"].values():
            self.assertTrue(pathlib.Path(destination).resolve().is_relative_to(self.own))
        after = {p.relative_to(self.candidate).as_posix(): p.read_bytes() for p in self.candidate.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_escaping_cache_refused_before_outside_directory_creation(self):
        outside = self.link(self.own / ".cache")
        with self.assertRaises(SystemExit):
            helper.prepare(self.own, self.candidate)
        self.assertEqual(list(outside.iterdir()), [])

    def test_deeper_output_parent_refused_before_any_new_output(self):
        source = self.own / ".cache/native-restore-preview-review/prepared/source"
        source.mkdir(parents=True)
        outside = self.link(source / "internal")
        with self.assertRaises(SystemExit):
            helper.prepare(self.own, self.candidate)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((source / "go.mod").exists())
        self.assertFalse((source.parent / "overlay.json").exists())

    def test_hardlinked_overlay_file_refused_before_any_copy(self):
        out = self.own / ".cache/native-restore-preview-review/prepared"
        out.mkdir(parents=True)
        outside = self.base / "outside-file"
        outside.write_bytes(b"preserved sentinel")
        os.link(outside, out / "overlay.json")
        with self.assertRaises(SystemExit):
            helper.prepare(self.own, self.candidate)
        self.assertEqual(outside.read_bytes(), b"preserved sentinel")
        self.assertFalse((out / "source").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
