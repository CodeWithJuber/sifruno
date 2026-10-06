"""Synthetic TempDir checks; no native account or policy observation."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("fixture", Path(__file__).with_name("fixture.py"))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
OWN = Path(__file__).resolve().parents[2]
TEMP = OWN / ".cache/service-accounts-tests"
for directory in (OWN / ".cache", TEMP):
    if directory.is_symlink() or directory.exists() and (not directory.is_dir() or directory.resolve() != directory):
        raise AssertionError("test_root_link")
    directory.mkdir(exist_ok=True)


class Contract(unittest.TestCase):
    def test_literal_nss_size_and_measured_last_change_day(self):
        self.assertEqual(len(fixture.NSS_BYTES), 54)
        first = fixture.date(2026, 10, 6)
        self.assertEqual(fixture.validate_last_change("Oct 06, 2026", first, first), "2026-10-06")
        epoch = fixture.date(1970, 1, 1)
        self.assertEqual(fixture.validate_last_change("never", epoch, epoch), "never")
        for value in ("never", "Oct 05, 2026", "Oct 07, 2026", "Feb 30, 2026", "2026-10-06", "Oct 06, 2026 extra"):
            with self.assertRaises((AssertionError, ValueError)):
                fixture.validate_last_change(value, first, first)

    def test_nss_only_adaptation_does_not_create_defaults(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as name:
            root = Path(name)
            (root / "etc").mkdir()
            (root / "etc/nsswitch.conf").write_bytes(b"synthetic old nss\n")
            # Synthetic Windows test supplies Linux ownership/mode APIs. The
            # native implementation still requires actual root authority.
            real_open = fixture.os.open
            # Windows CRT text writes would add CR bytes; model Linux binary
            # descriptor semantics without changing the native producer.
            with patch.object(fixture.os, "geteuid", return_value=0, create=True), patch.object(fixture.os, "fchmod", create=True), patch.object(fixture.stat, "S_IMODE", return_value=0o644), patch.object(fixture.os, "open", side_effect=lambda path, flags, mode: real_open(path, flags | getattr(fixture.os, "O_BINARY", 0), mode)):
                fixture.adapt_nss("a" * 32, root)
            self.assertEqual((root / "etc/nsswitch.conf").read_bytes(), fixture.NSS_BYTES)
            self.assertFalse((root / "etc/default").exists())
            self.assertEqual(sorted(path.name for path in (root / "etc").iterdir()), ["nsswitch.conf"])

    def test_uid_duplicate_and_root_refused(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as name:
            path = Path(name) / "passwd-metadata"
            path.write_text("nobody:x:65534:65534::/:/nologin\n", encoding="utf-8")
            self.assertEqual(fixture.unique_uid(path, 65534)["matching_local_passwd_records"], 1)
            path.write_text("nobody:x:65534:65534::/:/nologin\nalias:x:65534:65534::/:/nologin\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                fixture.unique_uid(path, 65534)
            with self.assertRaises(AssertionError):
                fixture.unique_uid(path, 0)

    def test_public_identity_duplicate_alias_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as name:
            path = Path(name) / "group-metadata"
            path.write_text("same:x:5:\nsame:x:6:\n", encoding="utf-8")
            with self.assertRaises(AssertionError):
                fixture.public_rows(path, 4)

    def test_json_duplicates_truncation_nonfinite(self):
        for raw in ('{"a":1,"a":2}', '{"a":', '{"a":NaN}', '{"nested":{"b":1,"b":2}}'):
            with self.assertRaises((AssertionError, ValueError)):
                fixture.strict_json(raw)

    def test_mail_owned_spool_and_unsafe_declaration(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as name:
            root = Path(name)
            (root / "etc").mkdir()
            (root / "etc/login.defs").write_text("MAIL_DIR /var/spool/mail\n", encoding="ascii")
            (root / "var/spool/mail").mkdir(parents=True)
            self.assertEqual(len(fixture.mail_snapshot("owned", root)), 3)
            (root / "var/spool/mail/owned").write_bytes(b"synthetic sentinel")
            with self.assertRaises(AssertionError):
                fixture.mail_snapshot("owned", root)
            (root / "etc/login.defs").write_text("MAIL_DIR /unexpected\n", encoding="ascii")
            with self.assertRaises(AssertionError):
                fixture.mail_snapshot("owned", root)

    def test_subordinate_allocation_rejected(self):
        with tempfile.TemporaryDirectory(dir=TEMP) as name:
            root = Path(name)
            (root / "etc").mkdir()
            (root / "etc/subuid").write_text("owned:100000:65536\n", encoding="ascii")
            with self.assertRaises(AssertionError):
                fixture.subid_snapshot("owned", root)

    def test_bounded_child_reaped_timeout_and_excess_output(self):
        for code, timeout, limit in (("import time;time.sleep(10)", 0.1, 1024), ("print('a'*10000)", 2, 100)):
            with self.assertRaises(AssertionError):
                fixture.run_child([sys.executable, "-I", "-B", "-c", code], timeout=timeout, limit=limit)


if __name__ == "__main__":
    unittest.main()
