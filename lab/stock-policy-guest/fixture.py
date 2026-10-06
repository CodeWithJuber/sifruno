"""Read-only installed-policy observation in an admitted disposable Linux guest.

No account utilities, NSS/default edits, shadow/key reads or network clients.
Only the two bounded hostbroker children may create their declared fixture paths.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import threading
import time

HEX = re.compile(r"^[0-9a-f]{64}$")
POLICY = (
    ("nss", "/etc/nsswitch.conf"), ("nss_authselect", "/etc/authselect/nsswitch.conf"),
    ("useradd_defaults", "/etc/default/useradd"), ("login_defaults", "/etc/login.defs"),
    ("passwd_metadata", "/etc/passwd"), ("group_metadata", "/etc/group"),
    ("groupadd", "/usr/sbin/groupadd"), ("useradd", "/usr/sbin/useradd"),
    ("usermod", "/usr/sbin/usermod"), ("passwd_utility", "/usr/bin/passwd"),
    ("chage", "/usr/bin/chage"), ("nologin", "/usr/sbin/nologin"),
)
RESTRICTIONS = ["host_policy_only", "controller_paths_state_not_checked", "no_stock_host_or_cpanel_certification"]


def require(value, code):
    if not value:
        raise AssertionError(code)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def bounded_bytes(path, maximum=4 * 1024 * 1024):
    with open(path, "rb") as source:
        value = source.read(maximum + 1)
    require(len(value) <= maximum, "file_bound")
    return value


def metadata(path, label):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"id": label, "kind": "missing", "mode": "0000", "bytes": 0, "sha256": None}
    require(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), "file_kind")
    link = stat.S_ISLNK(info.st_mode)
    data = os.readlink(path).encode("utf-8") if link else bounded_bytes(path)
    require(info.st_size == len(data), "file_size_changed")
    return {"id": label, "kind": "symlink" if link else "file", "mode": format(stat.S_IMODE(info.st_mode), "04o"), "bytes": info.st_size, "sha256": sha(data)}


def policy_snapshot(root=Path("/")):
    return [metadata(root / name.lstrip("/"), label) for label, name in POLICY]


def unique_uid(path, uid):
    require(0 < uid < 2**32, "controller_uid")
    rows = bounded_bytes(path, 1024 * 1024).decode("utf-8").splitlines()
    counts = 0
    for row in rows:
        fields = row.split(":")
        require(len(fields) == 7 and fields[2].isascii() and fields[2].isdigit(), "passwd_metadata_invalid")
        if int(fields[2]) == uid:
            counts += 1
    require(counts == 1, "controller_not_unique")
    return {"uid": uid, "matching_local_passwd_records": counts, "account_created": False}


def strict_json(raw):
    def pairs(entries):
        result = {}
        for key, value in entries:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: require(False, "json_number"))


def validate_check(value):
    require(type(value) is dict and set(value) == {"schema_version", "scope", "platform", "supported", "read_only", "checks", "restrictions"}, "check_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == "native_linux_account_host_policy" and value["platform"] == "linux" and value["supported"] is False and value["read_only"] is True and value["restrictions"] == RESTRICTIONS, "check_identity")
    expected = [("utilities", "trusted_utilities_required"), ("nss", "files_only_nss_required"), ("useradd_defaults", "mail_disabled_defaults_required")]
    require(type(value["checks"]) is list and len(value["checks"]) == 3, "check_count")
    refused = False
    for check, (name, reason) in zip(value["checks"], expected):
        require(type(check) is dict and set(check) == {"id", "status", "reason"} and check["id"] == name, "check_order")
        require((check["status"], check["reason"]) in [("pass", "satisfied"), ("refused", reason)], "check_reason")
        refused |= check["status"] == "refused"
    require(refused, "stock_policy_not_refused")
    return value


def run_child(argv, timeout=20, limit=16384):
    """Concurrent bounded pipe readers also work in synthetic Windows tests."""
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=os.name != "nt")
    buffers = [bytearray(), bytearray()]
    lock = threading.Lock()
    exceeded = threading.Event()
    def drain(stream, index):
        try:
            while True:
                data = stream.read(1024)
                if not data:
                    break
                with lock:
                    if sum(map(len, buffers)) + len(data) > limit:
                        exceeded.set()
                        break
                    buffers[index].extend(data)
        finally:
            stream.close()
    readers = [threading.Thread(target=drain, args=(stream, index), daemon=True) for index, stream in enumerate((child.stdout, child.stderr))]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        deadline = time.monotonic() + timeout
        while child.poll() is None:
            if exceeded.is_set() or time.monotonic() >= deadline:
                timed_out = not exceeded.is_set()
                break
            time.sleep(0.02)
    finally:
        # The entire owned session is killed even if its leader exited early.
        if os.name != "nt":
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        require(not any(reader.is_alive() for reader in readers), "child_pipe_cleanup")
    require(not timed_out and not exceeded.is_set(), "child_timeout" if timed_out else "child_output_limit")
    return {"exit_code": child.returncode, "stdout": bytes(buffers[0]), "stderr": bytes(buffers[1]), "owned_child_exited": child.poll() is not None}


def startup_paths(parent):
    return [parent / "state", parent / "homes", parent / "socket-parent", parent / "socket-parent" / "broker.sock"]


def observe_startup(binary, parent, uid, baseline):
    require(not parent.exists(), "fixture_path_preexists")
    parent.mkdir(mode=0o700)
    targets = startup_paths(parent)
    require(not any(p.exists() or p.is_symlink() for p in targets), "declared_path_preexists")
    command = [str(binary), "--state", str(targets[0]), "--homes", str(targets[1]), "--socket", str(targets[3]), "--controller-uid", str(uid)]
    result = run_child(command)
    require(result["exit_code"] == 1 and result["stdout"] == b"" and result["stderr"] == b"Native broker unavailable or recovery required\n", "startup_refusal")
    exists = [p.exists() or p.is_symlink() for p in targets]
    require(exists == ([True, True, True, False] if baseline else [False] * 4), "startup_side_effects")
    modes = []
    for target in targets[:3]:
        if target.exists():
            require(target.is_dir() and not target.is_symlink() and list(target.iterdir()) == [], "unexpected_store_or_socket")
            modes.append(format(stat.S_IMODE(target.stat().st_mode), "04o"))
        else:
            modes.append(None)
    require(modes == (["0700", "0755", "0755"] if baseline else [None] * 3), "directory_modes")
    return {"exit_code": result["exit_code"], "declared_directory_exists": exists[:3], "declared_directory_modes": modes, "socket_exists": exists[3], "store_created": False, "owned_child_exited": result["owned_child_exited"]}


def listeners(root=Path("/proc/net")):
    rows = []
    for name in ("tcp", "tcp6"):
        for row in bounded_bytes(root / name, 1024 * 1024).decode("ascii").splitlines()[1:]:
            fields = row.split()
            if fields[3] == "0A":
                rows.append(name + ":" + fields[1])
    for row in bounded_bytes(root / "unix", 1024 * 1024).decode("utf-8").splitlines()[1:]:
        fields = row.split()
        if fields[3] == "00010000":
            rows.append("unix:" + (fields[7] if len(fields) > 7 else "unnamed"))
    return {"count": len(rows), "sha256": sha("\n".join(sorted(rows)).encode("utf-8"))}


def observe(args):
    require(sys.platform == "linux" and os.geteuid() == 0, "guest_platform")
    admission = Path("/run/sifruno-stock-policy-admission")
    info = admission.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and bounded_bytes(admission, 100) == (args.nonce + "\n").encode(), "guest_admission")
    root = Path("/opt/sifruno-stock-policy")
    for name, expected in (("baseline-hostbroker", args.baseline_sha), ("candidate-hostbroker", args.candidate_sha), ("fixture.py", args.fixture_sha)):
        require(sha(bounded_bytes(root / name, 64 * 1024 * 1024)) == expected, "guest_input_hash")
    os_data = {}
    for line in bounded_bytes(Path("/etc/os-release"), 16384).decode().splitlines():
        key, _, value = line.partition("=")
        if key in ("ID", "VERSION_ID"):
            os_data[key] = value.strip('"')
    require(os_data == {"ID": "almalinux", "VERSION_ID": "9.8"}, "guest_profile")
    kernel = platform.release()
    require(re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", kernel) is not None, "kernel_metadata")
    controller = unique_uid(Path("/etc/passwd"), 65534)
    before, sockets_before = policy_snapshot(), listeners()
    result = run_child([str(root / "candidate-hostbroker"), "--check-host"], limit=8192)
    require(result["exit_code"] == 1 and result["stderr"] == b"", "check_exit")
    check = validate_check(strict_json(result["stdout"].decode("utf-8")))
    require(policy_snapshot() == before and listeners() == sockets_before, "check_mutation")
    baseline = observe_startup(root / "baseline-hostbroker", Path("/root/sifruno-stock-baseline-" + args.nonce), controller["uid"], True)
    require(policy_snapshot() == before and listeners() == sockets_before, "baseline_policy_or_listener_mutation")
    candidate = observe_startup(root / "candidate-hostbroker", Path("/root/sifruno-stock-candidate-" + args.nonce), controller["uid"], False)
    after, sockets_after = policy_snapshot(), listeners()
    require(before == after and sockets_before == sockets_after, "candidate_policy_or_listener_mutation")
    for name, expected in (("baseline-hostbroker", args.baseline_sha), ("candidate-hostbroker", args.candidate_sha), ("fixture.py", args.fixture_sha)):
        require(sha(bounded_bytes(root / name, 64 * 1024 * 1024)) == expected, "guest_input_changed")
    return {"schema_version": 1, "scope": "disposable_stock_linux_policy_observation", "nonce": args.nonce, "passed": True, "profile": {"distribution": "almalinux", "version": "9.8", "kernel": kernel, "machine": platform.machine()}, "binary_sha256": {"baseline": args.baseline_sha, "candidate": args.candidate_sha, "fixture": args.fixture_sha}, "controller": controller, "policy_before": before, "policy_after": after, "check_host": check, "check_host_exit": 1, "baseline": baseline, "candidate": candidate, "listeners_before": sockets_before, "listeners_after": sockets_after, "policy_unchanged": True, "inputs_unchanged": True, "account_created": False, "policy_rewritten": False, "owned_children_exited": True}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-stock-policy", action="store_true", required=True)
    parser.add_argument("--nonce", required=True)
    for name in ("baseline", "candidate", "fixture"):
        parser.add_argument("--" + name + "-sha", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{32}", args.nonce) is not None and all(HEX.fullmatch(value) for value in (args.baseline_sha, args.candidate_sha, args.fixture_sha)), "argument_binding")
    try:
        report = observe(args)
    except Exception as error:
        code = str(error) if isinstance(error, AssertionError) and re.fullmatch(r"[a-z_]{1,64}", str(error)) else "fixture_observation_failed"
        report = {"schema_version": 1, "scope": "disposable_stock_linux_policy_observation", "nonce": args.nonce, "passed": False, "failure": code}
    print(json.dumps(report, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
