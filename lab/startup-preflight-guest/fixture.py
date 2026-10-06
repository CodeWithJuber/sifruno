"""Read-only startup observations in a nonce-admitted disposable offline guest."""
import argparse
from datetime import datetime, timezone, date
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
SCOPE = "read_only_stock_then_NSS_only_adapted_fresh_startup_admission"
NSS_BYTES = b"passwd: files\ngroup: files\nshadow: files\nhosts: files\n"
ADMISSION = Path("/run/sifruno-startup-preflight-admission")
BROKER_SECONDS = 60
IDS = ["configuration", "privilege", "controller", "utilities", "nss_file", "nss_policy", "useradd_defaults", "paths", "fresh_state"]
REASONS = ["dedicated_paths_and_nonroot_uid_required", "root_required", "unique_local_controller_uid_required", "trusted_utilities_required", "trusted_bounded_regular_nss_file_required", "files_only_nss_required", "supported_service_account_defaults_required", "dedicated_path_and_socket_admission_required", "persisted_state_recovery_not_checked"]
RESTRICTIONS = ["fresh_setup_admission_only", "host_snapshot_not_startup_grant", "persisted_state_recovery_not_checked", "no_stock_host_or_cpanel_certification"]
PROVIDERS = {"files", "sss", "systemd", "compat", "nis", "nisplus", "db", "ldap", "winbind"}
POLICY = (
    ("nss", "/etc/nsswitch.conf"), ("nss_authselect", "/etc/authselect/nsswitch.conf"),
    ("useradd_defaults", "/etc/default/useradd"), ("login_defaults", "/etc/login.defs"),
    ("passwd_metadata", "/etc/passwd"), ("group_metadata", "/etc/group"),
    ("groupadd", "/usr/sbin/groupadd"), ("useradd", "/usr/sbin/useradd"),
    ("usermod", "/usr/sbin/usermod"), ("passwd_utility", "/usr/bin/passwd"),
    ("chage", "/usr/bin/chage"), ("nologin", "/usr/sbin/nologin"),
)


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
        return {"id": label, "kind": "missing", "mode": "0000", "bytes": 0, "sha256": None, "uid": 0, "gid": 0, "inode": 0, "device": 0, "nlink": 0}
    require(stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode), "file_kind")
    link = stat.S_ISLNK(info.st_mode)
    data = os.readlink(path).encode("utf-8") if link else bounded_bytes(path)
    require(info.st_size == len(data), "file_size_changed")
    return {"id": label, "kind": "symlink" if link else "file", "mode": format(stat.S_IMODE(info.st_mode), "04o"), "bytes": info.st_size, "sha256": sha(data), "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino, "device": info.st_dev, "nlink": info.st_nlink}


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


def adapt_nss(nonce, root=Path("/")):
    target = root / "etc/nsswitch.conf"
    for parent in (target.parent, root):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0, "nss_parent_authority")
    require(stat.S_ISREG(target.lstat().st_mode) or stat.S_ISLNK(target.lstat().st_mode), "nss_leaf_kind")
    temporary = target.parent / (".sifruno-startup-nss-" + nonce)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    try:
        require(os.write(fd, NSS_BYTES) == len(NSS_BYTES), "nss_write")
        os.fchmod(fd, 0o644)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, target)  # Replace only the leaf; never its authselect target.
    current = target.lstat()
    require(stat.S_ISREG(current.st_mode) and current.st_uid == os.geteuid() and stat.S_IMODE(current.st_mode) == 0o644 and bounded_bytes(target) == NSS_BYTES, "nss_adaptation")


def public_rows(path, columns):
    rows = bounded_bytes(path, 1024 * 1024).decode("utf-8").splitlines()
    parsed = [row.split(":") for row in rows]
    require(all(len(row) == columns for row in parsed) and len({row[0] for row in parsed}) == len(parsed), "public_identity_rows")
    return parsed


def subid_snapshot(username, root=Path("/")):
    output = []
    for label in ("subuid", "subgid"):
        target = root / "etc" / label
        item = metadata(target, label)
        if item["kind"] != "missing":
            require(item["kind"] == "file", "subid_kind")
            rows = bounded_bytes(target).decode("ascii").splitlines()
            require(not any(row.split(":", 1)[0] == username for row in rows), "owned_subid_allocation")
        output.append(item)
    return output


def mail_snapshot(username, root=Path("/")):
    declarations = []
    for row in bounded_bytes(root / "etc/login.defs", 65536).decode("ascii").splitlines():
        line = row.split("#", 1)[0].strip().split()
        if line and line[0] == "MAIL_DIR":
            require(len(line) == 2, "mail_dir_declaration")
            declarations.append(line[1])
    require(len(declarations) == 1 and declarations[0] in ("/var/mail", "/var/spool/mail"), "mail_dir_authority")
    result = []
    for label, name in (("configured", declarations[0]), ("var_mail", "/var/mail"), ("var_spool_mail", "/var/spool/mail")):
        directory = root / name.lstrip("/")
        require(not (directory / username).exists() and not (directory / username).is_symlink(), "owned_mail_spool")
        if not directory.exists():
            result.append({"id": label, "kind": "missing", "entries": [], "own_spool_absent": True})
            continue
        resolved = directory.resolve(strict=True)
        require(resolved in (root / "var/mail", root / "var/spool/mail") and resolved.is_dir(), "mail_directory_alias")
        entries = []
        for entry in sorted(resolved.iterdir()):
            info = entry.lstat()
            require(len(entries) < 128 and not stat.S_ISDIR(info.st_mode), "mail_entries_bound")
            entries.append({"name_sha256": sha(entry.name.encode()), "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino, "device": info.st_dev, "bytes": info.st_size, "mtime_ns": str(info.st_mtime_ns)})
        result.append({"id": label, "kind": "directory", "entries": entries, "own_spool_absent": True})
    return result


def startup_paths(parent):
    return [parent / "state", parent / "homes", parent / "socket-parent", parent / "socket-parent/broker.sock"]


def broker_command(binary, parent):
    state, homes, _, endpoint = startup_paths(parent)
    return [str(binary), "--state", str(state), "--homes", str(homes), "--socket", str(endpoint), "--controller-uid", "65534"]


def listeners():
    rows = []
    for name in ("tcp", "tcp6"):
        for row in bounded_bytes(Path("/proc/net") / name, 1024 * 1024).decode("ascii").splitlines()[1:]:
            fields = row.split()
            if fields[3] == "0A":
                rows.append(name + ":" + fields[1])
    for row in bounded_bytes(Path("/proc/net/unix"), 1024 * 1024).decode().splitlines()[1:]:
        fields = row.split()
        if fields[3] == "00010000":
            rows.append("unix:" + (fields[7] if len(fields) > 7 else "unnamed"))
    return {"count": len(rows), "sha256": sha("\n".join(sorted(rows)).encode())}


def execute_tests(binary, names):
    result = run_child([str(binary), "-test.v", "-test.timeout=20s", "-test.run=^(" + "|".join(names) + ")$"], limit=65536)
    raw = result["stdout"].decode()
    require(result["exit_code"] == 0 and result["stderr"] == b"" and "--- SKIP:" not in raw and "[no tests to run]" not in raw and raw.rstrip().endswith("PASS") and sorted(re.findall(r"^--- PASS: ([A-Za-z0-9_]+) \(", raw, re.MULTILINE)) == names, "test_family_execution")
    return {"exit_code": 0, "stdout_sha256": sha(result["stdout"]), "stdout_bytes": len(result["stdout"]), "test_names": names, "skipped": False, "owned_child_exited": True}


class OwnedBroker:
    def __init__(self, binary, parent):
        self.child = subprocess.Popen(broker_command(binary, parent), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}, start_new_session=True)
        self.buffers, self.exceeded, self.timed_out = [bytearray(), bytearray()], threading.Event(), threading.Event()
        self.lock = threading.Lock()
        def drain(stream, index):
            try:
                while True:
                    data = stream.read(1024)
                    if not data:
                        break
                    with self.lock:
                        if sum(map(len, self.buffers)) + len(data) > 16384:
                            self.exceeded.set()
                            self.kill()
                            break
                        self.buffers[index].extend(data)
            finally:
                stream.close()
        self.readers = [threading.Thread(target=drain, args=(stream, index), daemon=True) for index, stream in enumerate((self.child.stdout, self.child.stderr))]
        for reader in self.readers:
            reader.start()
        def expire():
            self.timed_out.set()
            self.kill()
        self.timer = threading.Timer(BROKER_SECONDS, expire)
        self.timer.start()
        self.endpoint = startup_paths(parent)[3]

    def kill(self):
        try:
            os.killpg(self.child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def ready(self):
        deadline = time.monotonic() + 10
        while not self.endpoint.exists():
            require(self.child.poll() is None and time.monotonic() < deadline, "broker_startup")
            time.sleep(0.025)
        info = self.endpoint.lstat()
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 65534 and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "broker_socket")

    def close(self, graceful):
        try:
            if graceful:
                os.kill(self.child.pid, signal.SIGTERM)
                self.child.wait(timeout=5)
        finally:
            self.timer.cancel()
            self.kill()
            self.child.wait(timeout=5)
            for reader in self.readers:
                reader.join(timeout=5)
            require(not any(reader.is_alive() for reader in self.readers), "broker_pipe_cleanup")
        require(not graceful or self.child.returncode == 0 and not self.exceeded.is_set() and not self.timed_out.is_set() and self.buffers == [bytearray(), bytearray()] and not self.endpoint.exists(), "broker_shutdown")
        return {"sigterm_sent": graceful, "exit_code": self.child.returncode, "socket_removed": not self.endpoint.exists(), "owned_child_exited": self.child.poll() is not None}


def admitted_guest(nonce):
    require(sys.platform == "linux" and os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{32}", nonce), "guest_platform")
    info = ADMISSION.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and bounded_bytes(ADMISSION, 100) == (nonce + "\n").encode(), "guest_admission")


def nss_profiles(raw):
    require(type(raw) is bytes and len(raw) <= 4 * 1024 * 1024 and b"\0" not in raw, "nss_profile_bound")
    result = []
    rows = raw.decode("ascii").splitlines()
    for name in ("passwd", "group", "shadow"):
        found, providers, actions, unknown = 0, [], False, False
        for row in rows:
            line = row.split("#", 1)[0]
            key, separator, value = line.partition(":")
            if not separator or key.strip() != name:
                continue
            found += 1
            # Action clauses are observed, never treated as providers. Unknown
            # provider spelling is redacted to one fixed literal.
            actions |= "[" in value or "]" in value
            clean = re.sub(r"\[[^\]]*\]", " ", value)
            for token in clean.split():
                accepted = token in PROVIDERS
                providers.append(token if accepted else "unknown")
                unknown |= not accepted
        require(found <= 64 and len(providers) <= 64, "nss_profile_count")
        result.append({"id": name, "row_count": found, "providers": providers, "actions_present": actions, "unknown_provider": unknown})
    return result


def validate_startup(value, refusal=None, persisted=False):
    require(type(value) is dict and set(value) == {"schema_version", "scope", "platform", "supported", "read_only", "checks", "restrictions"}, "startup_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == "native_linux_broker_startup_admission" and value["platform"] == "linux" and value["read_only"] is True and value["supported"] is (refusal is None) and value["restrictions"] == RESTRICTIONS, "startup_identity")
    require(type(value["checks"]) is list and len(value["checks"]) == 9, "startup_count")
    for i, check in enumerate(value["checks"]):
        status, reason = "pass", "satisfied"
        if refusal is not None and i == refusal:
            status, reason = "not_checked" if persisted else "refused", REASONS[i]
        elif refusal is not None and i > refusal:
            status, reason = "not_checked", "prerequisite_refused"
        require(type(check) is dict and set(check) == {"id", "status", "reason"} and check == {"id": IDS[i], "status": status, "reason": reason}, "startup_order_reason")
    return value


def owned_snapshot(parent):
    entries = []
    def visit(target):
        info = target.lstat()
        require(len(entries) < 128, "owned_snapshot_bound")
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "symlink" if stat.S_ISLNK(info.st_mode) else "file" if stat.S_ISREG(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode) else "unknown"
        require(kind != "unknown", "owned_snapshot_kind")
        data = os.readlink(target).encode() if kind == "symlink" else bounded_bytes(target, 65536) if kind == "file" else b""
        entries.append({"name": target.relative_to(parent).as_posix(), "kind": kind, "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino, "device": info.st_dev, "nlink": info.st_nlink, "bytes": info.st_size, "mtime_ns": str(info.st_mtime_ns), "sha256": sha(data)})
        if kind == "directory":
            for child in sorted(target.iterdir()):
                visit(child)
    visit(parent)
    return sha(json.dumps(entries, separators=(",", ":"), sort_keys=True).encode())


def missing_startup(parent):
    return [name for name, target in zip(("state", "homes", "socket_parent", "socket"), startup_paths(parent)) if not target.exists() and not target.is_symlink()]


def startup_observation(binary, parent, refusal=None, persisted=False, uid=65534, invalid=None):
    before = owned_snapshot(parent)
    args = broker_command(binary, parent)
    args[args.index("--controller-uid") + 1] = str(uid)
    args.insert(1, "--check-startup")
    if invalid:
        args.extend(invalid)
    result = run_child(args, timeout=10, limit=8192)
    after = owned_snapshot(parent)
    require(after == before, "startup_added_or_changed_paths")
    if invalid or uid == 0:
        require(result["exit_code"] == 2 and result["stdout"] == b"" and result["stderr"] == b"Invalid native broker configuration\n", "startup_grammar")
        report = None
    else:
        require(result["stderr"] == b"" and result["exit_code"] == (0 if refusal is None else 1), "startup_exit")
        report = validate_startup(strict_json(result["stdout"].decode()), refusal, persisted)
    return {"exit_code": result["exit_code"], "report": report, "before_sha256": before, "after_sha256": after, "added_paths": [], "missing_paths": missing_startup(parent), "owned_child_exited": True}


def inventory_peer(nonce):
    admitted_guest(nonce)
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    try:
        connection.connect("/run/sp-smoke-" + nonce + "/socket-parent/broker.sock")
        connection.sendall(b"GET /v1/accounts HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n\r\n")
        data = bytearray()
        while True:
            part = connection.recv(4096)
            if not part:
                break
            require(len(data) + len(part) <= 16384, "inventory_bound")
            data.extend(part)
    finally:
        connection.close()
    head, separator, body = bytes(data).partition(b"\r\n\r\n")
    require(separator and re.fullmatch(rb"HTTP/1\.[01] 200 [^\r\n]{1,80}", head.split(b"\r\n")[0]) and b"transfer-encoding:" not in head.lower() and b"content-type: application/json" in head.lower(), "inventory_http")
    value = strict_json(body.decode())
    require(type(value) is dict and set(value) == {"items"} and value["items"] == [], "inventory_empty")
    return {"peer_uid": os.geteuid(), "http_status": 200, "account_count": 0, "body_sha256": sha(body)}


def broker_smoke(binary, nonce):
    parent = Path("/run/sp-smoke-" + nonce)
    parent.mkdir(mode=0o755)
    rounds, shutdowns = [], []
    for _ in range(2):
        broker = OwnedBroker(binary, parent)
        try:
            broker.ready()
            result = run_child([sys.executable, "-I", "-B", str(Path(__file__)), "--inventory-peer", nonce], timeout=10)
            require(result["exit_code"] == 0 and result["stderr"] == b"", "inventory_child")
            rounds.append(strict_json(result["stdout"].decode()))
        except Exception:
            broker.close(False)
            raise
        shutdowns.append(broker.close(True))
    persisted = startup_observation(binary, parent, refusal=8, persisted=True)
    return {"fixture_setup_owned": True, "inventory": rounds, "shutdowns": shutdowns, "persisted_admission": persisted, "account_mutation_requests": 0}


def observe(args):
    admitted_guest(args.nonce)
    root = Path("/opt/sifruno-startup-preflight")
    hashes = {name: getattr(args, name + "_sha") for name in ("baseline", "candidate", "fixture", "core_test", "review_test")}
    paths = {"baseline": "baseline-hostbroker", "candidate": "candidate-hostbroker", "fixture": "fixture.py", "core_test": "core.test", "review_test": "authority.test"}
    for name, leaf in paths.items():
        require(sha(bounded_bytes(root / leaf, 64 * 1024 * 1024)) == hashes[name], "input_binding")
    os_data = dict(line.split("=", 1) for line in bounded_bytes(Path("/etc/os-release"), 16384).decode().splitlines() if "=" in line)
    require(os_data.get("ID", "").strip('"') == "almalinux" and os_data.get("VERSION_ID", "").strip('"') == "9.8" and platform.machine() == "x86_64" and re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", platform.release()), "guest_profile")
    controller = unique_uid(Path("/etc/passwd"), 65534)
    require(not any(int(row[2]) == 60001 for row in public_rows(Path("/etc/passwd"), 7)), "negative_uid_present")
    username = "sp" + args.nonce[:12]
    before, listen_before = policy_snapshot(), listeners()
    require(before[0]["kind"] == "file" and before[0]["mode"] == "0644" and before[0]["bytes"] == 2124 and before[0]["sha256"] == "c1cc473688f64942669ee7eb72b262103db75498d9236356bdf25289828f5b46" and before[0]["uid"] == before[0]["gid"] == 0 and before[0]["nlink"] == 1 and before[1]["kind"] == "missing", "stock_nss_pin")
    profile_bytes = bounded_bytes(Path("/etc/nsswitch.conf"))
    require(sha(profile_bytes) == before[0]["sha256"], "nss_profile_hash_binding")
    profiles = nss_profiles(profile_bytes)
    mail_before, subids_before = mail_snapshot(username), subid_snapshot(username)
    owned = Path("/run/sp-cases-" + args.nonce)
    owned.mkdir(mode=0o755)
    parent = owned / "stock"
    parent.mkdir(mode=0o755)
    original = startup_observation(root / paths["candidate"], parent, refusal=5)
    require(missing_startup(parent) == ["state", "homes", "socket_parent", "socket"] and policy_snapshot() == before and mail_snapshot(username) == mail_before and subid_snapshot(username) == subids_before and listeners() == listen_before, "stock_readonly")
    adapt_nss(args.nonce)
    adapted = policy_snapshot()
    require([old["id"] for old, new in zip(before, adapted) if old != new] == ["nss"], "nss_only_change")
    parent = owned / "adapted"
    parent.mkdir(mode=0o755)
    fresh = startup_observation(root / paths["candidate"], parent)
    require(missing_startup(parent) == ["state", "homes", "socket_parent", "socket"], "fresh_paths_created")
    negatives = []
    cases = ["missing_uid", "root_uid", "state_file", "homes_file", "homes_symlink", "homes_dangling_symlink", "ancestor_untrusted_nontraversable", "setgid_parent", "socket_file", "socket_bound", "socket_dangling_symlink", "nonempty_state", "unknown_private_argument"]
    for name in cases:
        parent = owned / name
        parent.mkdir(mode=0o755)
        state, homes, socket_parent, endpoint = startup_paths(parent)
        ancestor = None
        if name == "state_file": state.write_bytes(b"owned fixture conflict\n")
        if name == "homes_file": homes.write_bytes(b"owned fixture conflict\n")
        if name == "homes_symlink":
            target = parent / "target"; target.mkdir(mode=0o755); homes.symlink_to(target)
        if name == "homes_dangling_symlink": homes.symlink_to(parent / "absent")
        if name == "ancestor_untrusted_nontraversable":
            os.chown(parent, 65534, 65534); os.chmod(parent, 0)
            info = parent.lstat()
            ancestor = {"uid": info.st_uid, "gid": info.st_gid, "mode": format(stat.S_IMODE(info.st_mode), "04o")}
            require(ancestor == {"uid": 65534, "gid": 65534, "mode": "0000"}, "ancestor_setup_metadata")
        if name == "setgid_parent": os.chmod(parent, 0o2755)
        conflict_socket = None
        if name in ("socket_file", "socket_bound", "socket_dangling_symlink"):
            socket_parent.mkdir(mode=0o755)
            if name == "socket_file": endpoint.write_bytes(b"owned socket conflict\n")
            elif name == "socket_bound":
                conflict_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                conflict_socket.bind(str(endpoint))
            else: endpoint.symlink_to(parent / "absent")
        if name == "nonempty_state":
            state.mkdir(mode=0o700); (state / "owned-marker").write_bytes(b"owned fixture state\n")
        refusal = 2 if name == "missing_uid" else 8 if name == "nonempty_state" else 7
        try:
            entry = startup_observation(root / paths["candidate"], parent, refusal=refusal, persisted=name == "nonempty_state", uid=60001 if name == "missing_uid" else 0 if name == "root_uid" else 65534, invalid=["--unknown", "/private/fixture-value"] if name == "unknown_private_argument" else None)
        finally:
            if conflict_socket is not None: conflict_socket.close()
        negatives.append({"case": name, "fixture_setup_owned": True, "ancestor": ancestor, "observation": entry})
    require(policy_snapshot() == adapted and mail_snapshot(username) == mail_before and subid_snapshot(username) == subids_before and listeners() == listen_before, "adapted_readonly")
    host_result = run_child([str(root / paths["candidate"]), "--check-host"], limit=8192)
    require(host_result["exit_code"] == 0 and host_result["stderr"] == b"", "host_policy_exit")
    host_check = strict_json(host_result["stdout"].decode())
    require(set(host_check) == {"schema_version", "scope", "platform", "supported", "read_only", "checks", "restrictions"} and host_check["scope"] == "native_linux_account_host_policy" and host_check["supported"] is True, "host_policy_unchanged")
    smoke = broker_smoke(root / paths["candidate"], args.nonce)
    core = execute_tests(root / paths["core_test"], args.core_test_names.split(","))
    review = execute_tests(root / paths["review_test"], args.review_test_names.split(","))
    after = policy_snapshot()
    require(after == adapted and mail_snapshot(username) == mail_before and subid_snapshot(username) == subids_before and listeners() == listen_before, "final_host_unchanged")
    unchanged = all(sha(bounded_bytes(root / leaf, 64 * 1024 * 1024)) == hashes[name] for name, leaf in paths.items())
    require(unchanged, "guest_inputs_changed")
    return {"schema_version": 1, "scope": SCOPE, "nonce": args.nonce, "passed": True, "profile": {"distribution": "almalinux", "version": "9.8", "kernel": platform.release(), "machine": "x86_64"}, "binary_sha256": hashes, "controller": controller, "original_nss_profiles": profiles, "policy_before": before, "policy_adapted": adapted, "policy_after": after, "original_check": original, "adapted_check": fresh, "negative_cases": negatives, "host_policy_check": host_check, "broker_smoke": smoke, "mail_before": mail_before, "mail_after": mail_snapshot(username), "subids_before": subids_before, "subids_after": subid_snapshot(username), "listeners_before": listen_before, "listeners_after": listeners(), "core_tests": core, "review_tests": review, "inputs_unchanged": unchanged, "account_mutation_requests": 0, "accepted_account_mutations": 0, "stock_provisioning_qualified": False, "owned_children_exited": True}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--inventory-peer":
        try:
            print(json.dumps(inventory_peer(sys.argv[2]), separators=(",", ":")))
            return 0
        except Exception:
            print("Owned inventory request failed", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-startup-preflight", action="store_true", required=True)
    parser.add_argument("--nonce", required=True)
    for name in ("baseline", "candidate", "fixture", "core-test", "review-test"):
        parser.add_argument("--" + name + "-sha", required=True)
    parser.add_argument("--core-test-names", required=True)
    parser.add_argument("--review-test-names", required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"[0-9a-f]{32}", args.nonce) and all(HEX.fullmatch(getattr(args, name + "_sha")) for name in ("baseline", "candidate", "fixture", "core_test", "review_test")), "argument_binding")
    for value in (args.core_test_names, args.review_test_names):
        names = value.split(",")
        require(1 <= len(names) <= 16 and names == sorted(set(names)) and all(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{1,127}", name) for name in names), "test_names_binding")
    try:
        report = observe(args)
    except Exception as error:
        code = str(error) if isinstance(error, AssertionError) and re.fullmatch(r"[a-z_]{1,64}", str(error)) else "fixture_observation_failed"
        report = {"schema_version": 1, "scope": SCOPE, "nonce": args.nonce, "passed": False, "failure": code}
    print(json.dumps(report, separators=(",", ":")))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
