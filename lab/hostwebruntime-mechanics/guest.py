"""Trusted disposable Alma guest; synthetic test mechanics, never serving proof."""
import hashlib
import json
import os
from pathlib import Path
import platform
import selectors
import signal
import subprocess
import time
import re
import sys

MAX_OUTPUT = 512 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def results(output, spec):
    """Require actual complete top-level Go test results, not echoed PASS text."""
    lines = output.splitlines()
    runs = re.findall(r"^=== RUN   (Test\w+)$", output, re.M)
    done = re.findall(r"^--- (PASS|SKIP|FAIL): (Test\w+) \([0-9.]+s\)$", output, re.M)
    passes = [name for state, name in done if state == "PASS"]
    skips = [name for state, name in done if state == "SKIP"]
    expected = spec["required"] + spec["allowed_skips"]
    return {"passes": passes, "skips": skips,
            "passed": sorted(runs) == sorted(expected)
            and sorted(passes) == sorted(spec["required"])
            and sorted(skips) == sorted(spec["allowed_skips"])
            and len(done) == len(expected) and lines.count("PASS") == 1
            and not re.search(r"^\s*--- FAIL:|^FAIL$|^panic:", output, re.M)}


def execute(binary, spec, nonce):
    args = [str(binary), "-test.v", "-test.count=1", "-test.timeout=" + spec["timeout"]]
    if spec.get("run"):
        args += ["-test.run", spec["run"]]
    p = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, start_new_session=True,
                         env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C",
                              "SIFRUNO_NATIVE_RUNTIME_TEST": "1", "TMPDIR": "/tmp"})
    chunks, total, limited, timed = [], 0, False, False
    deadline = time.monotonic() + int(spec["timeout"][:-1]) + 5
    sel = selectors.DefaultSelector()
    sel.register(p.stdout, selectors.EVENT_READ)
    try:
        while sel.get_map():
            if time.monotonic() >= deadline:
                timed = True
                break
            for key, _ in sel.select(min(.2, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fileobj.fileno(), 16384)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                total += len(chunk)
                if total > MAX_OUTPUT:
                    limited = True
                    break
                chunks.append(chunk)
            if limited:
                break
        if timed or limited:
            os.killpg(p.pid, signal.SIGKILL)
        try:
            code = p.wait(timeout=max(.1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed = True
            os.killpg(p.pid, signal.SIGKILL)
            code = p.wait(timeout=3)
    finally:
        sel.close()
        p.stdout.close()
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGKILL)
            p.wait(timeout=3)
    data = b"".join(chunks)
    output = data.decode("utf-8", errors="strict")
    # Each test output appears once outside the nonce-bound JSON report.
    print(f"SIFRUNO_RUNTIME_TEST_BEGIN_{nonce}_{spec['id']}", flush=True)
    sys.stdout.write(output)
    sys.stdout.flush()
    print(f"SIFRUNO_RUNTIME_TEST_END_{nonce}_{spec['id']}", flush=True)
    result = results(output, spec)
    result.update(id=spec["id"], exit_code=code, elf_sha256=sha(binary.read_bytes()),
                  arguments=args[1:], output_sha256=sha(data), output_bytes=len(data),
                  timed_out=timed, output_limited=limited)
    result["passed"] = bool(result["passed"] and code == 0 and not timed and not limited)
    return result


def facts():
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in ["Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"]:
            status[key] = value.strip()
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            os_release[key] = value.strip('"')
    filesystems = []
    for target in ["/", "/tmp", "/opt/sifruno-runtime-mechanics"]:
        s = os.statvfs(target)
        probe = subprocess.run(["/usr/bin/findmnt", "-n", "-T", target, "-o", "FSTYPE,OPTIONS"],
                               capture_output=True, text=True, timeout=3, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
        if probe.returncode:
            raise RuntimeError("filesystem fact unavailable")
        filesystems.append({"path": target, "type_options": probe.stdout.strip(), "block_size": s.f_frsize,
                            "available_bytes": s.f_bavail * s.f_frsize})
    selinux = Path("/sys/fs/selinux/enforce")
    return {"os": os_release, "architecture": platform.machine(), "kernel": platform.release(),
            "uid": [int(v) for v in status["Uid"].split()], "gid": [int(v) for v in status["Gid"].split()],
            "process_status": status, "selinux_enforce": selinux.read_text().strip() if selinux.exists() else "not-mounted",
            "filesystems": filesystems, "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip()}


def main():
    root = Path("/opt/sifruno-runtime-mechanics")
    nonce = Path("/run/sifruno-runtime-admission").read_text().strip()
    if not re.fullmatch(r"[a-f0-9]{24}", nonce) or platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("disposable guest admission missing")
    pins = json.loads((root / "pins.json").read_text())
    report = {"schema_version": 1, "kind": pins["scope"], "nonce": nonce,
              "passed": False, "daemon_serving_qualified": False, "facts": {}, "tests": []}
    try:
        report["facts"] = facts()
        if report["facts"]["os"].get("ID") != "almalinux" or report["facts"]["os"].get("VERSION_ID") != "9.8":
            raise RuntimeError("OS admission mismatch")
        for spec in pins["tests"]:
            binary = root / (spec["id"] + ".test")
            if sha(binary.read_bytes()) != spec["sha256"]:
                raise RuntimeError("ELF hash mismatch")
            report["tests"].append(execute(binary, spec, nonce))
        report["passed"] = all(t["passed"] for t in report["tests"])
    except Exception as error:
        report["failure"] = type(error).__name__  # no credentials or uncontrolled diagnostics
    print(f"SIFRUNO_RUNTIME_REPORT_BEGIN_{nonce}", flush=True)
    print(json.dumps(report, separators=(",", ":")), flush=True)
    print(f"SIFRUNO_RUNTIME_REPORT_END_{nonce}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
