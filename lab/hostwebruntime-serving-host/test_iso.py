"""Actual ISO readback cases on Windows. No guest/native execution."""
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
spec = importlib.util.spec_from_file_location("serving_iso", HERE / "make_iso.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)
wheel = PRIMARY / ".tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl"
if hashlib.sha256(wheel.read_bytes()).hexdigest() != builder.WHEEL_SHA:
    raise RuntimeError("pinned wheel unavailable")
sys.path.insert(0, str(wheel))
import pycdlib


class ISOReadback(unittest.TestCase):
    def image(self, mode=0o100444, links=1, label="CIDATA", header=True, dirmode=0o40555, metadata=True, network=True):
        parent = OWNER / ".cache/hostwebruntime-serving-host-tests"
        parent.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="iso-", dir=parent))
        data = {"user-data": b"#cloud-config\nusers: []\n" if header else b"invalid\n",
                "meta-data": b"instance-id: serving-123-aaaaaaaaaaaaaaaaaaaaaaaa\nlocal-hostname: sifruno-runtime-serving\n" if metadata else b"instance-id: wrong\n",
                "network-config": b"version: 2\nethernets: {}\n" if network else b"version: 2\nethernets: {eth0: {dhcp4: true}}\n"}
        data.update({n: ("fixture-only-" + n).encode() for n in sorted(builder.FIXED - set(data))})
        data.update({f"packages/parser-only-{i}.rpm": f"parser-only-rpm-{i}".encode() for i in range(18)})
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, rock_ridge="1.09", vol_ident=label)
        iso.add_directory(iso_path="/PACKAGES", rr_name="packages", file_mode=dirmode)
        entries = []
        for i, (name, value) in enumerate(data.items()):
            p = directory / f"source-{i}"
            p.write_bytes(value)
            prefix = "/PACKAGES" if name.startswith("packages/") else ""
            iso.add_file(str(p), iso_path=f"{prefix}/F{i:06d}.BIN;1", rr_name=Path(name).name, file_mode=mode)
            if links != 1:
                iso.get_record(rr_path="/" + name).rock_ridge.dr_entries.px_record.posix_file_links = links
            entries.append({"name": name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()})
        image = directory / "payload.iso"
        iso.write(str(image)); iso.close()
        return image, entries

    def test_all28_regular_fixed_names_modes_links_exact_content(self):
        image, entries = self.image()
        records = builder.verify_iso(pycdlib, image, entries)
        self.assertEqual(len(records), 28)
        self.assertTrue(all(r["mode"] == "0o100444" and r["links"] == 1 for r in records))

    def test_original_nonregular_0444_and_writable_and_links_rejected(self):
        for settings in ({"mode": 0o444}, {"mode": 0o100666}, {"links": 2}, {"dirmode": 0o40777}):
            image, entries = self.image(**settings)
            with self.assertRaises(ValueError): builder.verify_iso(pycdlib, image, entries)

    def test_nocloud_label_header_metadata_network_rejected(self):
        for settings in ({"label": "WRONG"}, {"header": False}, {"metadata": False}, {"network": False}):
            image, entries = self.image(**settings)
            with self.assertRaises(ValueError): builder.verify_iso(pycdlib, image, entries)

    def test_measured_content_and_byte_count_not_inferred(self):
        for key, value in (("sha256", "0" * 64), ("bytes", 2)):
            image, entries = self.image(); entries[0][key] = value
            with self.assertRaises(ValueError): builder.verify_iso(pycdlib, image, entries)

    def test_plan_scope_and_rpm_inventory_fail_closed(self):
        image, entries = self.image()
        packages = {"schema_version": 1, "kind": "alma9-prepared-web-packages", "packages": [{"filename": f"parser-only-{i}.rpm"} for i in range(18)]}
        plan = {"schema_version": 1, "entries": entries}
        self.assertEqual(len(builder.inventory(plan, packages)), 28)
        for change in (lambda p: p["entries"].pop(), lambda p: p["entries"][0].update(name="../escape"), lambda p: p["entries"][0].update(bytes=True)):
            p = json.loads(json.dumps(plan)); change(p)
            with self.assertRaises(ValueError): builder.inventory(p, packages)


if __name__ == "__main__": unittest.main()
