"""Real ISO metadata regression checks on Windows; no Linux execution claim."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

HERE = Path(__file__).absolute().parent
OWNER = HERE.parents[1]
PRIMARY = OWNER.parent.parent if OWNER.parent.name == ".worktrees" else OWNER
pins = json.loads((HERE / "pins.json").read_text())
wheel = PRIMARY / pins["wheel"]["path"]
if hashlib.sha256(wheel.read_bytes()).hexdigest() != pins["wheel"]["sha256"]:
    raise RuntimeError("pinned wheel unavailable")
sys.path.insert(0, str(wheel))
import pycdlib
spec = importlib.util.spec_from_file_location("mechanics_iso", HERE / "make_iso.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ISOReadback(unittest.TestCase):
    def image(self, mode=0o100444, links=1, label="CIDATA", header=True):
        parent = OWNER / ".cache" / "hostwebruntime-mechanics-tests"
        parent.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="iso-", dir=parent))
        data = {"user-data": b"#cloud-config\nusers: []\n" if header else b"invalid\n",
                "meta-data": b"instance-id: mechanics-123-aaaaaaaaaaaaaaaaaaaaaaaa\nlocal-hostname: sifruno-mechanics\n",
                "network-config": b"version: 2\nethernets: {}\n"}
        names = ["guest.py", "pins.json", "worker.test", "review.test", "worker-manifest.json", "review-manifest.json", "review-overlay.json", "review-source-report.json"]
        data.update({name: ("fixture-only-" + name).encode() for name in names})
        entries = []
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, rock_ridge="1.09", vol_ident=label)
        for i, (name, value) in enumerate(data.items()):
            p = directory / name
            p.write_bytes(value)
            iso.add_file(str(p), iso_path=f"/F{i:06d}.BIN;1", rr_name=name, file_mode=mode)
            if links != 1:
                iso.get_record(rr_path="/" + name).rock_ridge.dr_entries.px_record.posix_file_links = links
            entries.append({"name": name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()})
        image = directory / "payload.iso"
        iso.write(str(image))
        iso.close()
        return image, entries

    def test_actual_all_fixed_names_types_links_modes_and_content(self):
        image, entries = self.image()
        records = builder.verify_iso(pycdlib, image, entries)
        self.assertEqual(len(records), 11)
        self.assertTrue(all(r["mode"] == "0o100444" and r["links"] == 1 for r in records))

    def test_original_0444_failure_is_reproduced_and_rejected(self):
        image, entries = self.image(mode=0o444)
        with self.assertRaisesRegex(ValueError, "type/mode/link"):
            builder.verify_iso(pycdlib, image, entries)

    def test_link_and_nocloud_essentials_rejected(self):
        for settings in [{"links": 2}, {"label": "WRONG"}, {"header": False}]:
            image, entries = self.image(**settings)
            with self.assertRaises(ValueError):
                builder.verify_iso(pycdlib, image, entries)

    def test_content_hash_cannot_be_inferred_from_source_plan(self):
        image, entries = self.image()
        entries[0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "content"):
            builder.verify_iso(pycdlib, image, entries)


if __name__ == "__main__":
    unittest.main()
