"""Build only the credential-free, pinned qualification payload ISO."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

ROOT = Path(__file__).resolve().parent.parent
WHEEL = ROOT / ".tools/linuxguest/downloads/pycdlib-1.21.0-py3-none-any.whl"
WHEEL_SHA = "1a82cd735542921d0dd7bc40381e7b7b9cbc70bd4c03e4f67a0531d59d2f518e"
MAX_FILE = 128 * 1024 * 1024
MAX_PAYLOAD = 2 * 1024 * 1024 * 1024


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def independent(relative, directory=False):
    pure = PurePosixPath(relative)
    if not relative or pure.is_absolute() or "\\" in relative or any(x in (".", "..") for x in relative.split("/")):
        raise ValueError("Invalid workspace input")
    target = ROOT.joinpath(*pure.parts)
    if os.path.normcase(str(target.resolve())) != os.path.normcase(str(target)):
        raise ValueError("Linked workspace input")
    current = ROOT
    for component in pure.parts:
        current /= component
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise ValueError("Linked workspace input")
    info = target.lstat()
    if directory:
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("Directory required")
    elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_FILE:
        raise ValueError("Bounded independent file required")
    return target


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", required=True)
    args = parser.parse_args()
    if not args.plan.startswith(".cache/linux-qualification/") or not args.plan.endswith("/payload-plan.json"):
        raise ValueError("Invalid qualification plan")
    plan_file = independent(args.plan)
    if plan_file.stat().st_size > 256 * 1024:
        raise ValueError("Plan too large")
    plan = json.loads(plan_file.read_text("utf-8"))
    if set(plan) != {"schema_version", "entries", "output"} or plan["schema_version"] != 1:
        raise ValueError("Invalid qualification plan")
    if plan["output"] != args.plan.removesuffix("payload-plan.json") + "payload.iso":
        raise ValueError("Invalid ISO output")
    independent(str(WHEEL.relative_to(ROOT)).replace("\\", "/"))
    if digest(WHEEL) != WHEEL_SHA:
        raise ValueError("ISO helper checksum mismatch")
    sys.path.insert(0, str(WHEEL))
    import pycdlib

    entries = plan["entries"]
    if not isinstance(entries, list) or not 1 <= len(entries) <= 512:
        raise ValueError("Invalid payload entry count")
    admitted = []
    seen = set()
    total = 0
    for entry in entries:
        if set(entry) != {"source", "destination", "bytes", "sha256", "executable"}:
            raise ValueError("Invalid payload entry")
        name = entry["destination"]
        pure = PurePosixPath(name)
        if not isinstance(name, str) or not name.isascii() or "\\" in name or pure.is_absolute() or len(name) > 512 or any(x in ("", ".", "..") for x in name.split("/")) or name in seen:
            raise ValueError("Invalid payload destination")
        if pure.parts[0] not in ("bundle", "fixtures", "probe", "review", "BOOT.SH"):
            raise ValueError("Invalid payload destination")
        source_name = entry["source"]
        if not source_name.startswith((".cache/runtime-builds/", ".cache/cpanel-backup-qualification/", ".cache/linux-qualification/", ".worktrees/native-transfer-cli/.cache/", ".worktrees/native-transfer-review/.cache/")):
            raise ValueError("Invalid payload source")
        source = independent(source_name)
        info = source.stat()
        if info.st_size != entry["bytes"] or digest(source) != entry["sha256"] or not isinstance(entry["executable"], bool):
            raise ValueError("Payload checksum mismatch")
        total += info.st_size
        if total > MAX_PAYLOAD:
            raise ValueError("Payload too large")
        seen.add(name)
        admitted.append((entry, source))

    output = ROOT.joinpath(*PurePosixPath(plan["output"]).parts)
    independent(str(output.parent.relative_to(ROOT)).replace("\\", "/"), directory=True)
    if output.exists():
        raise ValueError("ISO output already exists")
    iso = pycdlib.PyCdlib()
    iso.new(interchange_level=3, rock_ridge="1.09", vol_ident="SIFRUNO_DATA")
    directories = {PurePosixPath("."): ""}
    parents = {p for entry, _ in admitted for p in PurePosixPath(entry["destination"]).parents if str(p) != "."}
    for index, parent in enumerate(sorted(parents, key=lambda x: (len(x.parts), str(x))), 1):
        iso_name = directories[parent.parent] + "/D%07d" % index
        iso.add_directory(iso_path=iso_name, rr_name=parent.name, file_mode=0o40555)
        directories[parent] = iso_name
    for index, (entry, source) in enumerate(admitted, 1):
        name = PurePosixPath(entry["destination"])
        iso.add_file(str(source), iso_path=directories[name.parent] + "/F%07d.BIN;1" % index, rr_name=name.name, file_mode=0o100555 if entry["executable"] else 0o100444)
    with output.open("xb") as target:
        iso.write_fp(target)
    iso.close()
    if output.stat().st_size > MAX_PAYLOAD:
        raise ValueError("ISO output too large")
    for entry, source in admitted:
        if digest(source) != entry["sha256"]:
            raise ValueError("Payload changed during ISO creation")
    print(json.dumps({"files": len(admitted), "input_bytes": total, "iso_bytes": output.stat().st_size, "iso_sha256": digest(output), "admitted_static_plan_only": True}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Qualification ISO creation failed", file=sys.stderr)
        raise SystemExit(1)
