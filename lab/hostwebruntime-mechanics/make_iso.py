"""Fixed CIDATA payload, pinned local wheel; no downloads or arbitrary inputs."""
import hashlib
import json
from pathlib import Path
import os
import stat
import sys
import io
import re


def verify_iso(pycdlib, image, entries):
    """Read actual RockRidge types/links/content, not the source-side plan alone."""
    iso = pycdlib.PyCdlib()
    iso.open(str(image))
    records = []
    try:
        if iso.pvd.volume_identifier.decode("ascii").strip() != "CIDATA":
            raise ValueError("NoCloud volume label mismatch")
        for entry in entries:
            record = iso.get_record(rr_path="/" + entry["name"])
            px = record.rock_ridge.dr_entries.px_record
            if not stat.S_ISREG(px.posix_file_mode) or px.posix_file_mode != 0o100444 or px.posix_file_links != 1:
                raise ValueError("ISO regular-file type/mode/link mismatch")
            stream = io.BytesIO()
            iso.get_file_from_iso_fp(stream, rr_path="/" + entry["name"])
            data = stream.getvalue()
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("ISO payload content mismatch")
            if entry["name"] == "user-data" and not data.startswith(b"#cloud-config\n"):
                raise ValueError("NoCloud user-data header missing")
            if entry["name"] == "meta-data" and not re.fullmatch(rb"instance-id: mechanics-[0-9]+-[a-f0-9]{24}\nlocal-hostname: sifruno-mechanics\n", data):
                raise ValueError("NoCloud instance metadata mismatch")
            if entry["name"] == "network-config" and data != b"version: 2\nethernets: {}\n":
                raise ValueError("NoCloud fixed network metadata mismatch")
            records.append({"name": entry["name"], "mode": oct(px.posix_file_mode), "links": px.posix_file_links,
                            "bytes": len(data), "sha256": entry["sha256"]})
    finally:
        iso.close()
    return records


def regular(p, maximum):
    s = p.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_nlink != 1 or not 0 < s.st_size <= maximum:
        raise ValueError("invalid regular input")
    for parent in (p, *p.parents):
        st = parent.lstat()
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & 0x400:
            raise ValueError("redirected input")
    if os.path.normcase(str(p.resolve())) != os.path.normcase(str(p)):
        raise ValueError("redirected input")
    return p.read_bytes()


def main():
    if len(sys.argv) != 3:
        raise ValueError("primary root and owned run required")
    primary, work = (Path(p).absolute() for p in sys.argv[1:])
    owner = Path(__file__).absolute().parents[2]
    if owner not in (primary, primary / ".worktrees" / "release-plan-sol") or work.parent != owner / ".cache" / "hostwebruntime-mechanics":
        raise ValueError("fixed output scope required")
    pins = json.loads(regular(Path(__file__).with_name("pins.json"), 32768))
    wheel = primary / pins["wheel"]["path"]
    if hashlib.sha256(regular(wheel, 1024 * 1024)).hexdigest() != pins["wheel"]["sha256"]:
        raise ValueError("wheel pin mismatch")
    sys.path.insert(0, str(wheel))
    import pycdlib
    plan = json.loads(regular(work / "payload-plan.json", 65536))
    names = {"user-data", "meta-data", "network-config", "guest.py", "pins.json", "worker.test", "review.test", "worker-manifest.json", "review-manifest.json", "review-overlay.json", "review-source-report.json"}
    if set(plan) != {"schema_version", "entries"} or plan["schema_version"] != 1 or {e["name"] for e in plan["entries"]} != names or len(plan["entries"]) != len(names):
        raise ValueError("fixed payload inventory required")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", vol_ident="CIDATA")
    total = 0
    try:
        for i, entry in enumerate(plan["entries"]):
            if set(entry) != {"name", "bytes", "sha256"}:
                raise ValueError("invalid entry")
            source = work / entry["name"]
            data = regular(source, 64 * 1024 * 1024)
            total += len(data)
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"] or total > 128 * 1024 * 1024:
                raise ValueError("payload pin mismatch")
            iso.add_file(str(source), iso_path=f"/F{i:06d}.BIN;1", rr_name=entry["name"], file_mode=0o100444)
        with (work / "payload.iso").open("xb") as target:
            iso.write_fp(target)
    finally:
        iso.close()
    for entry in plan["entries"]:
        if hashlib.sha256(regular(work / entry["name"], 64 * 1024 * 1024)).hexdigest() != entry["sha256"]:
            raise ValueError("payload changed")
    records = verify_iso(pycdlib, work / "payload.iso", plan["entries"])
    print(json.dumps({"entries": len(names), "bytes": total, "iso_readback": records}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("ISO admission failed", file=sys.stderr)
        raise SystemExit(1)
