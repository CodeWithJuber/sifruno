#!/usr/bin/env python3
"""Read-only, local characterization on an explicitly authorized Linux lab.

This script has no network client, arbitrary-command option, license probe,
package installation, or host-configuration operation. Its output is private
observed evidence with operator attestations, not authenticated certification.
"""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import stat
import subprocess
import sys
import time

MAX_OUTPUT = 256 * 1024
MAX_BUNDLE = 4 * 1024 * 1024
MAX_ARTIFACT = 64 * 1024 * 1024
DISPOSABLE_CONFIRMATION = "I_HAVE_AUTHORIZED_THIS_DISPOSABLE_HOST"
LICENSE_CONFIRMATION = "I_VERIFIED_A_VALID_REFERENCE_LICENSE"
CPANEL = "/usr/local/cpanel/cpanel"
WHMAPI1 = "/usr/local/cpanel/bin/whmapi1"

# Fixed commands; additions require review. The invalid-function probe observes
# errors and cannot dispatch any defined account/service mutation.
COMMANDS = (
    ("cli.version", (CPANEL, "-V")),
    ("cli.whm-version", (WHMAPI1, "--output=jsonpretty", "version")),
    ("cli.invalid-function", (WHMAPI1, "--output=jsonpretty", "sifruno_invalid_function")),
)


def go_string(value):
    """Match encoding/json's UTF-8 and HTML escaping for evidence v1."""
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":"))
            .replace("&", "\\u0026").replace("<", "\\u003c")
            .replace(">", "\\u003e").replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029"))


def canonical(value):
    """Sifruno v1 lossless envelope canonicalization, matching Go Seal.

    Envelopes use integers only; response JSON is retained as exact stdout text.
    This is not RFC 8785. Never use this digest as an authenticity signature.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if value == 0:
            return "0"
        digits = str(abs(value))
        exponent = len(digits) - 1
        digits = digits.rstrip("0")
        coefficient = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
        return ("-" if value < 0 else "") + coefficient + "e" + str(exponent)
    if isinstance(value, str):
        return go_string(value)
    if isinstance(value, list):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(go_string(k) + ":" + canonical(value[k]) for k in sorted(value)) + "}"
    raise ValueError("Only exact integer envelope numbers are supported")


def seal(bundle):
    unsigned = {key: value for key, value in bundle.items() if key != "sha256"}
    data = canonical(unsigned).encode("utf-8", errors="strict")
    if len(data) > MAX_BUNDLE:
        raise ValueError("Capture exceeds bundle size limit")
    return dict(unsigned, sha256=hashlib.sha256(data).hexdigest())


def artifact(path, name):
    p = Path(path)
    info = p.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT:
        raise ValueError("Reference artifact is not a bounded regular file")
    digest = hashlib.sha256()
    total = 0
    with p.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            total += len(chunk)
            if total > MAX_ARTIFACT:
                raise ValueError("Reference artifact grew beyond the size limit")
            digest.update(chunk)
    return {"name": name, "path": path, "sha256": digest.hexdigest()}


def capture(argv, timeout=20):
    if tuple(argv) not in [command for _, command in COMMANDS]:
        raise ValueError("Command is outside the fixed read-only allowlist")
    # Strip inherited secrets and dynamic-loader overrides. cPanel's trusted
    # installation supplies its own runtime paths; no shell interprets argv.
    environment = {"PATH": "/usr/local/cpanel/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                   "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"}
    proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.DEVNULL, shell=False, cwd="/",
                            env=environment, start_new_session=True)
    selector = selectors.DefaultSelector()
    output = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    completed = False
    try:
        for pipe, label in ((proc.stdout, "stdout"), (proc.stderr, "stderr")):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError("Read-only command exceeded timeout; no capture written")
            for key, _ in selector.select(min(remaining, 0.2)):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                output[key.data].extend(chunk)
                if len(output[key.data]) > MAX_OUTPUT:
                    raise ValueError("Command output exceeded limit; no capture written")
        exit_code = proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        if not 0 <= exit_code <= 255:
            raise ValueError("Command ended by signal; no complete outcome available")
        result = {"exit_code": exit_code,
                  "stdout": bytes(output["stdout"]).decode("utf-8", errors="strict"),
                  "stderr": bytes(output["stderr"]).decode("utf-8", errors="strict")}
        completed = True
        return result
    finally:
        if not completed:
            # Kill the whole group on failure even when its parent exited but
            # descendants kept stdout/stderr open. No stray lab child remains.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if proc.poll() is None:
            proc.wait()
        selector.close()
        proc.stdout.close()
        proc.stderr.close()


def strict_json(text):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("Duplicate response JSON key")
            result[key] = value
        return result
    def constant(value):
        raise ValueError("Non-JSON numeric constant")
    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def build_bundle(role, capture_id, features):
    before = [artifact(CPANEL, "cpanel"), artifact(WHMAPI1, "whmapi1")]
    cases = []
    for operation_id, argv in COMMANDS:
        outcome = capture(argv)
        try:
            strict_json(outcome["stdout"])
            outcome["format"] = "json"
        except (ValueError, json.JSONDecodeError):
            outcome["format"] = "text"
        cases.append({"operation": {"id": operation_id, "obligation_id": "cli.whmapi1",
                                    "transport": "cli", "command": list(argv)},
                      "outcome": outcome})
    if cases[0]["outcome"]["exit_code"] != 0:
        raise ValueError("Exact-build version command failed")
    build = cases[0]["outcome"]["stdout"].strip()
    if not build or len(build) > 256 or "\n" in build or "\r" in build:
        raise ValueError("Version output is not an exact bounded build identity")
    after = [artifact(CPANEL, "cpanel"), artifact(WHMAPI1, "whmapi1")]
    if before != after:
        raise ValueError("Reference artifacts changed during capture")
    release = platform.freedesktop_os_release()
    os_identity = release.get("PRETTY_NAME", "")
    if not os_identity or len(os_identity) > 256:
        raise ValueError("Missing exact OS identity")
    return seal({"schema_version": 1, "id": capture_id, "kind": "observed", "role": role,
                 "provenance": {"product": "cPanel & WHM" if role == "reference" else "Sifruno",
                                "exact_build": build, "os": os_identity,
                                "arch": platform.machine(),
                                "captured_at": datetime.datetime.now(datetime.timezone.utc)
                                .isoformat(timespec="microseconds").replace("+00:00", "Z"),
                                "features": sorted(features), "artifacts": before,
                                "disposable_host_attested": True,
                                "licensed_reference_attested": role == "reference"},
                 "cases": cases})


def write_private(path, bundle):
    # Directory must already be an explicit, private lab export destination.
    # Refuse symlinks and overwrites; no recursive delete/chmod of host paths.
    destination = Path(path)
    parent = destination.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent.absolute():
        raise ValueError("Output parent must be an existing canonical directory without symlinks")
    info = parent.stat()
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Output directory must be owned by the current user and mode 0700")
    data = (json.dumps(bundle, ensure_ascii=False, indent=2) + "\n").encode("utf-8", errors="strict")
    if len(data) > MAX_BUNDLE:
        raise ValueError("Serialized capture exceeds size limit")
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--role", required=True, choices=("reference", "candidate"))
    parser.add_argument("--id", required=True, help="Lowercase capture identifier")
    parser.add_argument("--feature", action="append", required=True,
                        help="Enabled feature inventory declaration; repeat per feature")
    parser.add_argument("--out", required=True, help="New JSON file in an existing private directory")
    parser.add_argument("--disposable-confirm", required=True, choices=(DISPOSABLE_CONFIRMATION,))
    parser.add_argument("--licensed-reference-confirm", choices=(LICENSE_CONFIRMATION,))
    args = parser.parse_args(argv)
    import re
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,95}", args.id):
        parser.error("Invalid capture identifier")
    if len(args.feature) > 64 or len(set(args.feature)) != len(args.feature) or any(
            not f or len(f.encode("utf-8")) > 128 or f.strip() != f or any(ord(c) < 32 for c in f)
            for f in args.feature):
        parser.error("Features must be unique bounded labels")
    if args.role == "reference" and args.licensed_reference_confirm != LICENSE_CONFIRMATION:
        parser.error("Reference capture requires an independently verified valid-license attestation")
    if not sys.platform.startswith("linux") or not hasattr(os, "geteuid") or os.geteuid() != 0:
        parser.error("Run locally as root only on the authorized disposable Linux lab")
    try:
        bundle = build_bundle(args.role, args.id, args.feature)
        write_private(args.out, bundle)
    except (ValueError, OSError, UnicodeError, subprocess.SubprocessError):
        # Captured stdout/stderr and paths are deliberately not echoed on failure.
        print("Capture failed validation or execution; no complete evidence claim is made.", file=sys.stderr)
        return 1
    print("Saved 3 bounded read-only observations. Licensing and host identity remain operator attestations.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
