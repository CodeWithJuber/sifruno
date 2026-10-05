"""Fixed crash CIDATA media with completed-ISO type/link/content readback."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys

FIXED = {"user-data", "meta-data", "network-config", "crash_guest.py", "serving_guest_library.py", "web_runtime_fixture.py",
         "qualification-driver", "serving-linux.test", "reaping-linux.test", "source_catalog.json", "prepared-packages.json", "admission.json"}
WHEEL_SHA = "1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e"


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


def inventory(plan, packages):
    if set(plan) != {"schema_version", "entries"} or type(plan["schema_version"]) is not int or plan["schema_version"] != 1:
        raise ValueError("fixed payload schema required")
    if packages.get("schema_version") != 1 or packages.get("kind") != "alma9-prepared-web-packages" or len(packages.get("packages", [])) != 18:
        raise ValueError("fixed18 packages required")
    filenames = [p["filename"] for p in packages["packages"]]
    if len(set(filenames)) != 18 or any(not re.fullmatch(r"[A-Za-z0-9_.+-]+\.rpm", p) for p in filenames):
        raise ValueError("fixed RPM basenames required")
    expected = FIXED | {"packages/" + p for p in filenames}
    if len(plan["entries"]) != 30 or {e["name"] for e in plan["entries"]} != expected:
        raise ValueError("fixed30 payload inventory required")
    for entry in plan["entries"]:
        if set(entry) != {"name", "bytes", "sha256"} or type(entry["bytes"]) is not int or not 0 < entry["bytes"] <= 64 * 1024 * 1024 or not re.fullmatch(r"[a-f0-9]{64}", entry["sha256"]):
            raise ValueError("invalid payload entry")
    return expected


def verify_iso(pycdlib, image, entries):
    names = [entry["name"] for entry in entries]
    if len(names) != 30 or len(set(names)) != 30 or not FIXED <= set(names) or any(not re.fullmatch(r"packages/[A-Za-z0-9_.+-]+\.rpm", name) for name in set(names) - FIXED):
        raise ValueError("ISO fixed30 inventory required")
    iso = pycdlib.PyCdlib()
    iso.open(str(image))
    records = []
    try:
        if iso.pvd.volume_identifier.decode("ascii").strip() != "CIDATA":
            raise ValueError("NoCloud CIDATA label mismatch")
        actual = []
        directories = []
        for dirname, dirs, files in iso.walk(rr_path="/"):
            directories.extend(dirname.rstrip("/") + "/" + name for name in dirs)
            actual.extend((dirname.rstrip("/") + "/" + name).lstrip("/") for name in files)
        if sorted(directories) != ["/packages"] or sorted(actual) != sorted(names):
            raise ValueError("ISO unexpected or missing inventory")
        directory = iso.get_record(rr_path="/packages")
        px = directory.rock_ridge.dr_entries.px_record
        if not stat.S_ISDIR(px.posix_file_mode) or px.posix_file_mode != 0o40555:
            raise ValueError("ISO RPM directory type/mode mismatch")
        for entry in entries:
            r = iso.get_record(rr_path="/" + entry["name"])
            px = r.rock_ridge.dr_entries.px_record
            if not stat.S_ISREG(px.posix_file_mode) or px.posix_file_mode != 0o100444 or px.posix_file_links != 1:
                raise ValueError("ISO regular-file type/mode/link mismatch")
            stream = io.BytesIO()
            iso.get_file_from_iso_fp(stream, rr_path="/" + entry["name"])
            data = stream.getvalue()
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                raise ValueError("ISO payload content mismatch")
            if entry["name"] == "user-data" and not data.startswith(b"#cloud-config\n"):
                raise ValueError("NoCloud user-data header missing")
            if entry["name"] == "meta-data" and not re.fullmatch(rb"instance-id: crash-[0-9]+-[a-f0-9]{24}\nlocal-hostname: sifruno-runtime-crash\n", data):
                raise ValueError("NoCloud instance metadata mismatch")
            if entry["name"] == "network-config" and data != b"version: 2\nethernets: {}\n":
                raise ValueError("NoCloud fixed network metadata mismatch")
            records.append({"name": entry["name"], "mode": oct(px.posix_file_mode), "links": px.posix_file_links,
                            "bytes": len(data), "sha256": entry["sha256"]})
    finally:
        iso.close()
    return records


def main():
    if len(sys.argv) != 3:
        raise ValueError("primary root and owned run required")
    primary, work = (Path(p).absolute() for p in sys.argv[1:])
    owner = Path(__file__).absolute().parents[2]
    if owner not in (primary, primary / ".worktrees" / "web-crash-integration") or work.parent != owner / ".cache" / "hostwebruntime-crash-host" or not re.fullmatch(r"crash-[0-9]+-[a-f0-9]{24}", work.name):
        raise ValueError("fixed output scope required")
    wheel = primary / ".tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl"
    if hashlib.sha256(regular(wheel, 1024 * 1024)).hexdigest() != WHEEL_SHA:
        raise ValueError("wheel pin mismatch")
    sys.path.insert(0, str(wheel))
    import pycdlib
    plan = json.loads(regular(work / "payload-plan.json", 65536))
    packages = json.loads(regular(work / "prepared-packages.json", 32768))
    inventory(plan, packages)
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", vol_ident="CIDATA")
    iso.add_directory(iso_path="/PACKAGES", rr_name="packages", file_mode=0o40555)
    total = 0
    try:
        for i, entry in enumerate(plan["entries"]):
            source = work / entry["name"]
            data = regular(source, 64 * 1024 * 1024)
            total += len(data)
            if len(data) != entry["bytes"] or hashlib.sha256(data).hexdigest() != entry["sha256"] or total > 128 * 1024 * 1024:
                raise ValueError("payload pin mismatch")
            directory = "/PACKAGES" if entry["name"].startswith("packages/") else ""
            iso.add_file(str(source), iso_path=f"{directory}/F{i:06d}.BIN;1", rr_name=Path(entry["name"]).name, file_mode=0o100444)
        with (work / "payload.iso").open("xb") as target:
            iso.write_fp(target)
    finally:
        iso.close()
    records = verify_iso(pycdlib, work / "payload.iso", plan["entries"])
    for entry in plan["entries"]:
        if hashlib.sha256(regular(work / entry["name"], 64 * 1024 * 1024)).hexdigest() != entry["sha256"]:
            raise ValueError("payload changed")
    print(json.dumps({"entries": 30, "bytes": total, "iso_readback": records}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Serving ISO admission failed", file=sys.stderr)
        raise SystemExit(1)
