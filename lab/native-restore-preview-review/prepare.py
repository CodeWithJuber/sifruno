"""Admit pinned inputs to an owned overlay; no candidate/dependency writes."""
import hashlib
import json
import pathlib
import stat
import sys


def inspect_output(own, path, directory=False):
    """Check every existing component before any mkdir/write is attempted."""
    if not path.is_relative_to(own) or not path.resolve().is_relative_to(own):
        raise SystemExit("Output escapes this checkout")
    current = own
    parts = path.relative_to(own).parts
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise SystemExit("Output symlink/reparse point refused")
        leaf = index == len(parts) - 1
        if not leaf or directory:
            if not stat.S_ISDIR(info.st_mode):
                raise SystemExit("Output parent is not a directory")
        elif not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SystemExit("Output is not an owned regular file")


def make_directory(own, path):
    inspect_output(own, path, directory=True)
    current = own
    for part in path.relative_to(own).parts:
        current = current / part
        inspect_output(own, current, directory=True)
        current.mkdir(exist_ok=True)
        inspect_output(own, current, directory=True)


def prepare(own, candidate):
    own = own.resolve(strict=True)
    candidate = candidate.resolve(strict=True)
    catalog_path = own / "lab/native-restore-preview-review/source-catalog.json"
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    if catalog.get("schema") != 1 or catalog.get("kind") != "independent-native-restore-preview-source-freeze":
        raise SystemExit("Unknown catalog")
    out = own / ".cache/native-restore-preview-review/prepared"
    inputs, replacement, seen = [], {}, set()
    # Admit the entire destination plan before creating even the cache root.
    inspect_output(own, out / "source", directory=True)
    inspect_output(own, out / "overlay.json")
    for entry in catalog["inputs"]:
        relative = pathlib.PurePosixPath(entry["path"])
        if relative.is_absolute() or ".." in relative.parts or "\\" in str(relative) or str(relative).lower() in seen:
            raise SystemExit("Invalid or aliased catalog path")
        seen.add(str(relative).lower())
        source = candidate / relative
        if source.is_symlink() or not source.is_file() or not source.resolve().is_relative_to(candidate):
            raise SystemExit("Input is not an admitted source file")
        raw = source.read_bytes()
        if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise SystemExit("Pinned candidate bytes differ: " + str(relative))
        if str(relative) in ("go.mod", "go.sum") and (own / relative).read_bytes() != raw:
            raise SystemExit("Module metadata differs")
        destination = out / "source" / relative
        inspect_output(own, destination)
        inputs.append((relative, destination, raw))
    make_directory(own, out / "source")
    for relative, destination, raw in inputs:
        make_directory(own, destination.parent)
        inspect_output(own, destination)
        destination.write_bytes(raw)
        if relative.parts[0] == "internal" and str(relative).endswith(".go"):
            replacement[str(own / relative)] = str(destination)
    inspect_output(own, out / "overlay.json")
    (out / "overlay.json").write_text(json.dumps({"Replace": replacement}, indent=2) + "\n", encoding="utf-8")
    return {"admitted_inputs": len(seen), "production_go_overlays": len(replacement), "catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest()}


if __name__ == "__main__":
    checkout = pathlib.Path(__file__).resolve().parents[2]
    if pathlib.Path.cwd().resolve() != checkout:
        raise SystemExit("Run from the checkout containing this lab")
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python lab/native-restore-preview-review/prepare.py CANDIDATE_ROOT")
    print(json.dumps(prepare(checkout, pathlib.Path(sys.argv[1]))))
