"""Independent synthetic TAR producer for local migration-inspector qualification.

It generates test data with Python's standard tarfile/gzip SDK. Nothing here is
an authentic cPanel backup. No extraction, credentials or network are used.
"""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile


def main():
    root = Path(__file__).resolve().parents[1]
    if len(sys.argv) != 2:
        raise ValueError("fixture output required")
    destination = Path(sys.argv[1]).resolve()
    cache = root / ".cache" / "cpanel-backup-qualification"
    if not destination.is_relative_to(cache.resolve()) or destination.exists():
        raise ValueError("new isolated fixture directory required")
    cursor = root
    for part in destination.relative_to(root).parts:
        cursor = cursor / part
        if cursor.exists() and (cursor.is_symlink() or cursor.resolve() != cursor):
            raise ValueError("linked output rejected")
    destination.mkdir(parents=True, mode=0o700)
    secret = b"SIFRUNO_SYNTHETIC_PRIVATE_PAYLOAD_DO_NOT_PRINT_91f783"
    contents = {
        "cp/synthetic": b"USER=synthetic\nDNS=synthetic.test\n" + secret,
        "homedir/public_html/index.html": b"<p>Synthetic original-backup inspection fixture</p>\n",
        "homedir/public_html/wp-config.php": secret,
        "mysql/synthetic_db.sql": b"-- synthetic database payload\n" + secret,
        "dnszones/synthetic.test.db": b"; synthetic DNS only\n",
        "unknown_vendor/config.bin": secret,
        "homedir/" + "long-part-" * 22 + "/file.txt": b"synthetic long-name payload",
    }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        directory = tarfile.TarInfo("./")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o750
        archive.addfile(directory)
        for name, content in contents.items():
            member = tarfile.TarInfo("./" + name)
            member.uid, member.gid = 1234, 2345
            member.uname, member.gname = "synthetic", "synthetic-group"
            member.mode, member.mtime, member.size = 0o640, 1_700_000_000, len(content)
            member.pax_headers = {"SIFRUNO.synthetic": secret.decode("ascii")}
            archive.addfile(member, io.BytesIO(content))
        link = tarfile.TarInfo("./homedir/link-outside")
        link.type, link.linkname = tarfile.SYMTYPE, "../../../outside-synthetic"
        archive.addfile(link)
        hardlink = tarfile.TarInfo("./homedir/link-inside")
        hardlink.type, hardlink.linkname = tarfile.LNKTYPE, "./homedir/public_html/index.html"
        archive.addfile(hardlink)
        fifo = tarfile.TarInfo("./homedir/synthetic-pipe")
        fifo.type = tarfile.FIFOTYPE
        archive.addfile(fifo)
    plain = buffer.getvalue()
    compressed = gzip.compress(plain, mtime=0)
    bad_crc = bytearray(compressed)
    bad_crc[-8] ^= 1
    fixtures = {"synthetic.tar": plain, "synthetic.tar.gz": compressed,
                "bad-crc.tar.gz": bytes(bad_crc),
                "truncated.tar": plain[:600], "trailing.tar": plain + b"NONZERO_TRAILING_DATA"}
    for name, payload in fixtures.items():
        path = destination / name
        with path.open("xb") as output:
            output.write(payload)
        os.chmod(path, 0o600)
    expected = {"kind": "synthetic", "producer": "Python standard tarfile/gzip",
                "compatibility_certified": False,
                "entries": len(contents) + 4,
                "files": [{"name": "./" + name, "sha256": hashlib.sha256(value).hexdigest(),
                           "bytes": len(value)} for name, value in contents.items()],
                "source_sha256": {name: hashlib.sha256(value).hexdigest()
                                  for name, value in fixtures.items()},
                "forbidden_payload_sha256": hashlib.sha256(secret).hexdigest()}
    with (destination / "expected.json").open("x", encoding="utf-8") as output:
        json.dump(expected, output, indent=2)
        output.write("\n")
    print(json.dumps({"fixture_generated": True, "kind": "synthetic", "files": len(fixtures)}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Synthetic fixture generation failed without disclosing inputs", file=sys.stderr)
        sys.exit(1)
