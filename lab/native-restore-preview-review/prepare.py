"""Admit the pinned source bytes into this checkout's ignored Go overlay.

Reads only the explicit catalog; never discovers credentials, changes candidate
source, installs inputs, or modifies the shared module/compilation caches.
"""
import hashlib
import json
import pathlib
import sys

own = pathlib.Path(__file__).resolve().parents[2]
if pathlib.Path.cwd().resolve() != own:
    raise SystemExit("Run from the checkout containing this lab")
if len(sys.argv) != 2:
    raise SystemExit("Usage: python lab/native-restore-preview-review/prepare.py CANDIDATE_ROOT")
candidate = pathlib.Path(sys.argv[1]).resolve(strict=True)
catalog_path = own / "lab/native-restore-preview-review/source-catalog.json"
catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
if catalog.get("schema") != 1 or catalog.get("kind") != "independent-native-restore-preview-source-freeze":
    raise SystemExit("Unknown catalog")
out = own / ".cache/native-restore-preview-review/prepared"
out.mkdir(parents=True, exist_ok=True)
if out.is_symlink() or not out.resolve().is_relative_to(own):
    raise SystemExit("Cache output escapes this checkout")
replacement = {}
seen = set()
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
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink() or not destination.resolve().is_relative_to(out.resolve()):
        raise SystemExit("Output escapes the owned cache")
    destination.write_bytes(raw)
    if relative.parts[0] == "internal" and str(relative).endswith(".go"):
        replacement[str(own / relative)] = str(destination)
overlay = out / "overlay.json"
overlay.write_text(json.dumps({"Replace": replacement}, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"admitted_inputs": len(seen), "production_go_overlays": len(replacement), "catalog_sha256": hashlib.sha256(catalog_path.read_bytes()).hexdigest()}))
