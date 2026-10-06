"""ADAPTED disposable Linux broker-path observations, never stock provisioning.

Only fixed NSS/useradd overlay policies are adapted. No account utilities,
shadow/key reads or external network clients. Children/state are fixture-owned.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
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


def validate_check(value, supported=False):
    require(type(value) is dict and set(value) == {"schema_version", "scope", "platform", "supported", "read_only", "checks", "restrictions"}, "check_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == "native_linux_account_host_policy" and value["platform"] == "linux" and value["supported"] is supported and value["read_only"] is True and value["restrictions"] == RESTRICTIONS, "check_identity")
    expected = [("utilities", "trusted_utilities_required"), ("nss", "files_only_nss_required"), ("useradd_defaults", "mail_disabled_defaults_required")]
    require(type(value["checks"]) is list and len(value["checks"]) == 3, "check_count")
    refused = False
    for check, (name, reason) in zip(value["checks"], expected):
        require(type(check) is dict and set(check) == {"id", "status", "reason"} and check["id"] == name, "check_order")
        require((check["status"], check["reason"]) in [("pass", "satisfied"), ("refused", reason)], "check_reason")
        refused |= check["status"] == "refused"
    require(refused is not supported, "policy_admission_mismatch")
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


CASES = ("homes_file", "homes_symlink", "homes_wrong_mode", "unsafe_socket_parent", "occupied_socket", "fresh_shared_homes")
CORE_NAMES = ["TestBrokerPathAdmission" + suffix for suffix in ("FreshHomesReadOnly", "InvalidAndCancelledReadOnly", "LateFailuresReadOnly", "MissingUnderSetgidParentReadOnly", "OccupiedSocketReadOnly", "PositiveReadOnly", "ReopenAndInterruptedBootstrap")] + ["TestDeclaredDirRejectsInheritedSetgidMode"]
POLICY_BYTES = {"nss": b"passwd: files\ngroup: files\nshadow: files\nhosts: files\n", "useradd_defaults": b"CREATE_MAIL_SPOOL=no\n"}


def adapt_policy(nonce, root=Path("/")):
    for label, name in (("nss", "/etc/nsswitch.conf"), ("useradd_defaults", "/etc/default/useradd")):
        target = root / name.lstrip("/")
        for parent in (target.parent, *target.parent.parents):
            if parent == root.parent:
                break
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0, "policy_parent_authority")
        original = target.lstat()
        require(stat.S_ISREG(original.st_mode) or stat.S_ISLNK(original.st_mode), "policy_leaf_kind")
        temporary = target.parent / (".sifruno-paths-policy-" + nonce)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        try:
            require(os.write(fd, POLICY_BYTES[label]) == len(POLICY_BYTES[label]), "policy_write")
            os.fchmod(fd, 0o644)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, target)  # Replaces the leaf, never follows an NSS link.
        current = target.lstat()
        require(stat.S_ISREG(current.st_mode) and current.st_uid == os.geteuid() and stat.S_IMODE(current.st_mode) == 0o644 and sha(bounded_bytes(target)) == sha(POLICY_BYTES[label]), "policy_adaptation")


def tree_snapshot(root):
    values = []
    def visit(target):
        info = target.lstat()
        label = "." if target == root else target.relative_to(root).as_posix()
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode) else "other"
        require(kind != "other" and len(values) < 32, "tree_kind_or_bound")
        digest = None if kind in ("directory", "socket") else sha(os.readlink(target).encode() if kind == "symlink" else bounded_bytes(target))
        values.append({"path": label, "kind": kind, "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino, "device": info.st_dev, "nlink": info.st_nlink, "bytes": info.st_size, "sha256": digest})
        if kind == "directory":
            for child in sorted(target.iterdir()):
                visit(child)
    visit(root)
    return sorted(values, key=lambda item: item["path"])


def prepare_case(parent, name):
    require(name in CASES and not parent.exists(), "case_admission")
    parent.mkdir(mode=0o700)
    state, homes, socket_parent, endpoint = startup_paths(parent)
    if name == "homes_file":
        homes.write_bytes(b"owned homes file sentinel\n")
    elif name == "homes_symlink":
        target = parent / "target"
        target.mkdir(mode=0o755)
        homes.symlink_to(target, target_is_directory=True)
    elif name == "homes_wrong_mode":
        homes.mkdir(mode=0o700)
    elif name == "unsafe_socket_parent":
        socket_parent.mkdir(mode=0o755)
        socket_parent.chmod(0o757)
    elif name == "occupied_socket":
        socket_parent.mkdir(mode=0o755)
        endpoint.write_bytes(b"owned occupied socket sentinel\n")
    elif name == "fresh_shared_homes":
        homes.mkdir(mode=0o755)
        shared = homes / "shared-home"
        shared.mkdir(mode=0o755)
        (shared / "sentinel").write_bytes(b"owned unrelated home sentinel\n")
    return tree_snapshot(parent)


def broker_command(binary, parent, uid):
    state, homes, _, endpoint = startup_paths(parent)
    return [str(binary), "--state", str(state), "--homes", str(homes), "--socket", str(endpoint), "--controller-uid", str(uid)]


def observe_conflict(binary, parent, uid, name, baseline):
    before = prepare_case(parent, name)
    result = run_child(broker_command(binary, parent, uid))
    require(result["exit_code"] == 1 and result["stdout"] == b"" and result["stderr"] == b"Native broker unavailable or recovery required\n", "conflict_refusal")
    after = tree_snapshot(parent)
    old = {item["path"]: item for item in before}
    new = {item["path"]: item for item in after}
    require(all(new.get(label) == item for label, item in old.items() if label != "."), "preexisting_conflict_changed")
    added = sorted(set(new) - set(old))
    if baseline:
        expected = ["state"] if name.startswith("homes_") else ["homes", "state"] if name in ("unsafe_socket_parent", "occupied_socket") else ["socket-parent", "state", "state/.sifruno-hostbroker", "state/.sifruno-state", "state/hostaccounts.db"]
        require(added == sorted(expected), "baseline_additions")
        for label in added:
            require(new[label]["kind"] == ("file" if "/" in label else "directory") and new[label]["mode"] == ("0600" if "/" in label else "0700" if label == "state" else "0755"), "baseline_addition_metadata")
    else:
        require(before == after and added == [], "candidate_conflict_mutation")
    return {"name": name, "role": "baseline" if baseline else "candidate", "adapted_policy": True, "exit_code": 1, "before": before, "after": after, "added_paths": added, "preexisting_preserved": True, "owned_child_exited": result["owned_child_exited"]}


def read_empty_inventory(nonce):
    require(sys.platform == "linux" and os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{32}", nonce), "inventory_child_admission")
    require(bounded_bytes(Path("/run/sifruno-broker-paths-admission"), 100) == (nonce + "\n").encode(), "inventory_nonce")
    endpoint = "/run/bp-h-" + nonce + "/socket-parent/broker.sock"
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(3)
    try:
        connection.connect(endpoint)
        connection.sendall(b"GET /v1/accounts HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n")
        chunks = bytearray()
        while True:
            value = connection.recv(4096)
            if not value:
                break
            chunks.extend(value)
            require(len(chunks) <= 8192, "inventory_output_bound")
    finally:
        connection.close()
    header, body = bytes(chunks).split(b"\r\n\r\n", 1)
    require(header.split(b"\r\n", 1)[0] == b"HTTP/1.1 200 OK" and strict_json(body.decode()) == {"items": []}, "inventory_not_empty")
    return {"http_status": 200, "account_count": 0, "peer_uid": os.geteuid(), "response_sha256": sha(body)}


def happy_broker(binary, parent, uid, nonce):
    # Read-only GET is sent by a separate owned child after dropping to the
    # already-existing UID; no account mutation endpoint is ever invoked.
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    child = subprocess.Popen(broker_command(binary, parent, uid), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
    buffers = [bytearray(), bytearray()]
    exceeded = threading.Event()
    lock = threading.Lock()
    def drain(stream, index):
        try:
            while True:
                data = stream.read(1024)
                if not data:
                    break
                with lock:
                    if sum(map(len, buffers)) + len(data) > 16384:
                        exceeded.set()
                        try:
                            os.killpg(child.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        break
                    buffers[index].extend(data)
        finally:
            stream.close()
    readers = [threading.Thread(target=drain, args=(stream, index), daemon=True) for index, stream in enumerate((child.stdout, child.stderr))]
    for reader in readers:
        reader.start()
    timed_out = threading.Event()
    def kill_owned():
        timed_out.set()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    timer = threading.Timer(20, kill_owned)
    timer.start()
    signalled = False
    inventory = None
    endpoint = startup_paths(parent)[3]
    try:
        deadline = time.monotonic() + 10
        while not endpoint.exists():
            require(child.poll() is None and time.monotonic() < deadline, "happy_startup")
            time.sleep(0.025)
        info = endpoint.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "happy_socket_authority")
        result = run_child([sys.executable, "-I", "-B", str(Path(__file__)), "--read-empty-inventory", nonce], timeout=5)
        require(result["exit_code"] == 0 and result["stderr"] == b"", "happy_inventory_child")
        inventory = strict_json(result["stdout"].decode())
        os.kill(child.pid, signal.SIGTERM)
        signalled = True
        child.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        require(not any(reader.is_alive() for reader in readers) and buffers == [bytearray(), bytearray()] and child.returncode == 0 and not timed_out.is_set() and not exceeded.is_set(), "happy_shutdown")
    finally:
        timer.cancel()
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        if child.poll() is None:
            child.wait(timeout=5)
        for reader in readers:
            reader.join(timeout=5)
        require(not any(reader.is_alive() for reader in readers), "happy_pipe_cleanup")
    require(not endpoint.exists() and list(startup_paths(parent)[1].iterdir()) == [], "happy_cleanup")
    return {"adapted_policy": True, "startup_socket_observed": True, "inventory": inventory, "sigterm_sent": signalled, "exit_code": child.returncode, "socket_removed": True, "homes_empty": True, "owned_children_exited": True, "state_after": tree_snapshot(startup_paths(parent)[0])}


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
    admission = Path("/run/sifruno-broker-paths-admission")
    info = admission.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and bounded_bytes(admission, 100) == (args.nonce + "\n").encode(), "guest_admission")
    root = Path("/opt/sifruno-broker-paths")
    binaries = (("baseline-hostbroker", args.baseline_sha), ("candidate-hostbroker", args.candidate_sha), ("fixture.py", args.fixture_sha), ("core.test", args.core_test_sha), ("authority.test", args.review_test_sha))
    for name, expected in binaries:
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
    stock_check = validate_check(strict_json(result["stdout"].decode("utf-8")))
    require(policy_snapshot() == before and listeners() == sockets_before, "check_mutation")
    adapt_policy(args.nonce)
    adapted = policy_snapshot()
    changed = [new["id"] for old, new in zip(before, adapted) if old != new]
    require(changed == ["nss", "useradd_defaults"], "adaptation_scope")
    result = run_child([str(root / "candidate-hostbroker"), "--check-host"], limit=8192)
    require(result["exit_code"] == 0 and result["stderr"] == b"", "adapted_check_exit")
    check = validate_check(strict_json(result["stdout"].decode("utf-8")), True)
    require(policy_snapshot() == adapted and listeners() == sockets_before, "adapted_check_mutation")
    conflicts = []
    for index, name in enumerate(CASES):
        for role in ("baseline", "candidate"):
            parent = Path("/root/bp-" + args.nonce + "-" + role[0] + "-" + str(index))
            conflicts.append(observe_conflict(root / (role + "-hostbroker"), parent, controller["uid"], name, role == "baseline"))
            require(policy_snapshot() == adapted and listeners() == sockets_before, "conflict_policy_or_listener_mutation")
    happy_parent = Path("/run/bp-h-" + args.nonce)
    require(not happy_parent.exists(), "happy_preexists")
    happy_parent.mkdir(mode=0o755)
    happy = [happy_broker(root / "candidate-hostbroker", happy_parent, controller["uid"], args.nonce) for _ in range(2)]
    require(policy_snapshot() == adapted and listeners() == sockets_before, "happy_policy_or_listener_mutation")
    core = run_child([str(root / "core.test"), "-test.v", "-test.timeout=20s", "-test.run=^(" + "|".join(CORE_NAMES) + ")$"], limit=65536)
    require(core["exit_code"] == 0 and core["stderr"] == b"", "core_tests_exit")
    raw = core["stdout"].decode("utf-8")
    require("--- SKIP:" not in raw and "[no tests to run]" not in raw and raw.rstrip().endswith("PASS"), "core_tests_skipped")
    test_names = sorted(re.findall(r"^--- PASS: ([A-Za-z0-9_]+) \(", raw, re.MULTILINE))
    require(test_names == CORE_NAMES, "core_tests_missing")
    core_result = {"exit_code": 0, "stdout_sha256": sha(core["stdout"]), "stdout_bytes": len(core["stdout"]), "test_names": test_names, "skipped": False, "owned_child_exited": core["owned_child_exited"]}
    review_names = args.review_test_names.split(",")
    review = run_child([str(root / "authority.test"), "-test.v", "-test.timeout=20s", "-test.run=^(" + "|".join(review_names) + ")$"], limit=65536)
    require(review["exit_code"] == 0 and review["stderr"] == b"", "review_tests_exit")
    raw = review["stdout"].decode("utf-8")
    require("--- SKIP:" not in raw and "[no tests to run]" not in raw and raw.rstrip().endswith("PASS"), "review_tests_skipped")
    test_names = sorted(re.findall(r"^--- PASS: ([A-Za-z0-9_]+) \(", raw, re.MULTILINE))
    require(test_names == review_names, "review_tests_missing")
    review_result = {"exit_code": 0, "stdout_sha256": sha(review["stdout"]), "stdout_bytes": len(review["stdout"]), "test_names": test_names, "skipped": False, "owned_child_exited": review["owned_child_exited"]}
    after, sockets_after = policy_snapshot(), listeners()
    require(adapted == after and sockets_before == sockets_after, "post_adaptation_policy_or_listener_mutation")
    for name, expected in binaries:
        require(sha(bounded_bytes(root / name, 64 * 1024 * 1024)) == expected, "guest_input_changed")
    return {"schema_version": 1, "scope": "ADAPTED_disposable_linux_broker_path_observation", "nonce": args.nonce, "passed": True, "profile": {"distribution": "almalinux", "version": "9.8", "kernel": kernel, "machine": platform.machine()}, "binary_sha256": {"baseline": args.baseline_sha, "candidate": args.candidate_sha, "fixture": args.fixture_sha, "core_test": args.core_test_sha, "review_test": args.review_test_sha}, "controller": controller, "policy_before": before, "policy_adapted": adapted, "policy_after": after, "adaptation": [{"id": label, "sha256": sha(POLICY_BYTES[label]), "mode": "0644", "root_owned_regular": True} for label in ("nss", "useradd_defaults")], "stock_check": stock_check, "adapted_check": check, "conflicts": conflicts, "happy_fresh_and_reopen": happy, "core_tests": core_result, "review_tests": review_result, "listeners_before": sockets_before, "listeners_after": sockets_after, "adapted_policy_unchanged": True, "inputs_unchanged": True, "account_created": False, "account_mutation_requests": 0, "stock_provisioning_qualified": False, "owned_children_exited": True}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--read-empty-inventory":
        try:
            print(json.dumps(read_empty_inventory(sys.argv[2]), separators=(",", ":")))
            return 0
        except Exception:
            print("Owned empty-inventory child failed", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-broker-paths", action="store_true", required=True)
    parser.add_argument("--nonce", required=True)
    for name in ("baseline", "candidate", "fixture", "core-test", "review-test"):
        parser.add_argument("--" + name + "-sha", required=True)
    parser.add_argument("--review-test-names", required=True)
    args = parser.parse_args()
    names = args.review_test_names.split(",")
    require(re.fullmatch(r"[0-9a-f]{32}", args.nonce) is not None and all(HEX.fullmatch(value) for value in (args.baseline_sha, args.candidate_sha, args.fixture_sha, args.core_test_sha, args.review_test_sha)) and 1 <= len(names) <= 16 and names == sorted(set(names)) and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,127}", name) for name in names), "argument_binding")
    try:
        report = observe(args)
    except Exception as error:
        code = str(error) if isinstance(error, AssertionError) and re.fullmatch(r"[a-z_]{1,64}", str(error)) else "fixture_observation_failed"
        report = {"schema_version": 1, "scope": "ADAPTED_disposable_linux_broker_path_observation", "nonce": args.nonce, "passed": False, "failure": code}
    print(json.dumps(report, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
