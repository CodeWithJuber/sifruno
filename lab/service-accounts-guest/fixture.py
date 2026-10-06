"""NSS-only adapted disposable stock-mail service-account qualification."""
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


def validate_check(value, statuses, candidate=False):
    require(type(value) is dict and set(value) == {"schema_version", "scope", "platform", "supported", "read_only", "checks", "restrictions"}, "check_fields")
    supported = "refused" not in statuses
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == "native_linux_account_host_policy" and value["platform"] == "linux" and value["supported"] is supported and value["read_only"] is True and value["restrictions"] == RESTRICTIONS, "check_identity")
    expected = [("utilities", "trusted_utilities_required"), ("nss", "files_only_nss_required"), ("useradd_defaults", "supported_service_account_defaults_required" if candidate else "mail_disabled_defaults_required")]
    require(type(value["checks"]) is list and len(value["checks"]) == 3, "check_count")
    refused = False
    for check, (name, reason), status in zip(value["checks"], expected, statuses):
        require(type(check) is dict and set(check) == {"id", "status", "reason"} and check["id"] == name, "check_order")
        require(check["status"] == status and check["reason"] == ("satisfied" if status == "pass" else reason), "check_reason")
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


SCOPE = "NSS_ADAPTED_stock_mail_service_account_lifecycle"
NSS_BYTES = b"passwd: files\ngroup: files\nshadow: files\nhosts: files\n"
ADMISSION = Path("/run/sifruno-service-accounts-admission")


def admitted_guest(nonce):
    require(sys.platform == "linux" and os.geteuid() == 0 and re.fullmatch(r"[0-9a-f]{32}", nonce), "guest_platform")
    info = ADMISSION.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and bounded_bytes(ADMISSION, 100) == (nonce + "\n").encode(), "guest_admission")


def adapt_nss(nonce, root=Path("/")):
    target = root / "etc/nsswitch.conf"
    for parent in (target.parent, root):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) & 0o022 == 0, "nss_parent_authority")
    require(stat.S_ISREG(target.lstat().st_mode) or stat.S_ISLNK(target.lstat().st_mode), "nss_leaf_kind")
    temporary = target.parent / (".sifruno-service-nss-" + nonce)
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


def unrelated_identity_snapshot(username):
    values = []
    for label, path, count in (("passwd", "/etc/passwd", 7), ("group", "/etc/group", 4)):
        rows = public_rows(Path(path), count)
        retained = sorted(":".join(row) for row in rows if row[0] != username)
        values.append({"id": label, "count": len(retained), "sha256": sha("\n".join(retained).encode())})
    return values


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


def state_evidence(parent):
    entries = []
    root = parent / "state"
    def visit(path):
        info = path.lstat()
        require(len(entries) < 32 and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)), "owned_state_snapshot")
        entries.append({"path": path.relative_to(root).as_posix(), "mode": format(stat.S_IMODE(info.st_mode), "04o"), "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino, "device": info.st_dev, "nlink": info.st_nlink, "sha256": sha(bounded_bytes(path, 1024 * 1024)) if stat.S_ISREG(info.st_mode) else None})
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)
    visit(root)
    return sha(json.dumps(entries, separators=(",", ":"), sort_keys=True).encode())


def check(binary, statuses, candidate):
    result = run_child([str(binary), "--check-host"], limit=8192)
    require(result["exit_code"] == (1 if "refused" in statuses else 0) and result["stderr"] == b"", "check_exit")
    return validate_check(strict_json(result["stdout"].decode()), statuses, candidate)


def peer_request(nonce, operation, account_id="", revision=0):
    admitted_guest(nonce)
    require(operation in ("list", "create", "duplicate", "suspend", "stale", "activate"), "peer_operation")
    username = "sf" + nonce[:12]
    endpoint = "/run/sa-" + nonce + "/socket-parent/broker.sock"
    os.setgroups([])
    os.setgid(65534)
    os.setuid(65534)
    method, route, body = "GET", "/v1/accounts", b""
    if operation in ("create", "duplicate"):
        method, body = "POST", json.dumps({"input": {"username": username, "domain": username + ".invalid", "reason": "owned disposable qualification"}, "actor": "guest-fixture"}, separators=(",", ":")).encode()
    elif operation != "list":
        require(re.fullmatch(r"[0-9a-f]{32}", account_id) and 0 < revision < 2**53, "peer_state_binding")
        method, route = "POST", "/v1/accounts/" + account_id + "/state"
        body = json.dumps({"input": {"state": "suspended" if operation in ("suspend", "stale") else "active", "expected_revision": revision, "reason": "owned disposable qualification"}, "actor": "guest-fixture"}, separators=(",", ":")).encode()
    headers = method + " " + route + " HTTP/1.1\r\nHost: unix\r\nConnection: close\r\n"
    if body:
        headers += "Content-Type: application/json\r\nContent-Length: " + str(len(body)) + "\r\n"
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(5)
    try:
        connection.connect(endpoint)
        connection.sendall(headers.encode() + b"\r\n" + body)
        response = bytearray()
        while True:
            part = connection.recv(4096)
            if not part:
                break
            require(len(response) + len(part) <= 16384, "peer_response_bound")
            response.extend(part)
    finally:
        connection.close()
    head, separator, payload = bytes(response).partition(b"\r\n\r\n")
    require(separator and re.fullmatch(rb"HTTP/1\.[01] (200|409) [^\r\n]{1,80}", head.split(b"\r\n")[0]), "peer_http_status")
    # The fixed broker returns short Content-Length JSON, never chunked bodies.
    require(b"transfer-encoding:" not in head.lower() and b"content-type: application/json" in head.lower(), "peer_http_headers")
    return {"http_status": int(head.split(b" ")[1]), "peer_uid": os.geteuid(), "body": strict_json(payload.decode()), "body_sha256": sha(payload)}


def request(nonce, operation, account_id="", revision=0):
    result = run_child([sys.executable, "-I", "-B", str(Path(__file__)), "--peer-request", nonce, operation, account_id, str(revision)], timeout=8)
    require(result["exit_code"] == 0 and result["stderr"] == b"", "request_child")
    response = strict_json(result["stdout"].decode())
    require(response["peer_uid"] == 65534, "request_peer")
    return response


def validate_account(value, nonce, parent, state, revision, previous=None):
    require(type(value) is dict and set(value) == {"id", "username", "domain", "home", "public_html", "state", "uid", "gid", "revision", "created_at", "updated_at"}, "account_fields")
    username = "sf" + nonce[:12]
    require(re.fullmatch(r"[0-9a-f]{32}", value["id"]) and value["username"] == username and value["domain"] == username + ".invalid" and value["home"] == str(parent / "homes" / username) and value["public_html"] == value["home"] + "/public_html" and value["state"] == state and type(value["revision"]) is int and value["revision"] == revision and type(value["uid"]) is int and 20000 <= value["uid"] <= 60000 and value["gid"] == value["uid"], "account_binding")
    for field in ("created_at", "updated_at"):
        require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z", value[field]), "account_date")
    if previous:
        require(all(value[key] == previous[key] for key in ("id", "username", "domain", "home", "public_html", "uid", "gid", "created_at")), "account_identity_changed")
    return {key: value[key] for key in ("id", "uid", "gid", "state", "revision")}


def native_identity(account):
    name = account["username"]
    rows = [row for row in public_rows(Path("/etc/passwd"), 7) if row[0] == name or int(row[2]) == account["uid"]]
    groups = public_rows(Path("/etc/group"), 4)
    own = [row for row in groups if row[0] == name or int(row[2]) == account["gid"]]
    require(len(rows) == 1 and rows[0][0] == name and int(rows[0][2]) == account["uid"] and int(rows[0][3]) == account["gid"] and rows[0][5] == account["home"] and rows[0][6] == "/usr/sbin/nologin" and len(own) == 1 and own[0][0] == name and int(own[0][2]) == account["gid"] and own[0][3] == "" and not any(name in row[3].split(",") for row in groups), "native_identity")
    status = run_child(["/usr/bin/passwd", "--status", name], limit=4096)
    parts = status["stdout"].decode().split()
    require(status["exit_code"] == 0 and status["stderr"] == b"" and len(parts) >= 2 and parts[0] == name and parts[1] in ("L", "LK"), "password_lock")
    aging = run_child(["/usr/bin/chage", "--list", name], limit=4096)
    require(aging["exit_code"] == 0 and aging["stderr"] == b"", "aging_exit")
    fields = {}
    for line in aging["stdout"].decode().splitlines():
        key, separator, value = line.partition(":")
        require(separator and key.strip() not in fields, "aging_fields")
        fields[key.strip()] = value.strip()
    require(fields.get("Account expires") == ("never" if account["state"] == "active" else "Jan 02, 1970") and all(fields.get(key) == "never" for key in ("Last password change", "Password expires", "Password inactive")), "service_aging_or_expiry")
    require(fields.get("Maximum number of days between password change") == "-1" and fields.get("Minimum number of days between password change") in ("-1", "0") and fields.get("Number of days of warning before password expires") in ("-1", "0"), "service_aging_limits")
    directories = []
    for label, path in (("home", account["home"]), ("public_html", account["public_html"])):
        info = Path(path).lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == account["uid"] and info.st_gid == account["gid"] and stat.S_IMODE(info.st_mode) == 0o750, "managed_home_identity")
        directories.append({"id": label, "uid": info.st_uid, "gid": info.st_gid, "mode": "0750", "inode": info.st_ino, "device": info.st_dev})
    require(sorted(child.name for child in Path(account["home"]).iterdir()) == ["public_html"] and list(Path(account["public_html"]).iterdir()) == [], "empty_managed_home")
    return {"uid": account["uid"], "gid": account["gid"], "private_group": True, "supplementary_groups": 0, "password_locked": True, "shell": "nologin", "password_aging": "disabled", "account_expiry": "never" if account["state"] == "active" else "1970-01-02", "directories": directories, "status_sha256": sha(status["stdout"]), "aging_sha256": sha(aging["stdout"])}


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
        self.timer = threading.Timer(20, expire)
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


def observe(args):
    admitted_guest(args.nonce)
    root = Path("/opt/sifruno-service-accounts")
    hashes = {name: getattr(args, name + "_sha") for name in ("baseline", "candidate", "fixture", "core_test", "review_test")}
    paths = {"baseline": "baseline-hostbroker", "candidate": "candidate-hostbroker", "fixture": "fixture.py", "core_test": "core.test", "review_test": "authority.test"}
    for name, leaf in paths.items():
        require(sha(bounded_bytes(root / leaf, 64 * 1024 * 1024)) == hashes[name], "input_binding")
    os_data = dict(line.split("=", 1) for line in bounded_bytes(Path("/etc/os-release"), 16384).decode().splitlines() if "=" in line)
    require(os_data.get("ID", "").strip('"') == "almalinux" and os_data.get("VERSION_ID", "").strip('"') == "9.8" and platform.machine() == "x86_64" and re.fullmatch(r"[A-Za-z0-9._+\-]{1,128}", platform.release()), "guest_profile")
    controller = unique_uid(Path("/etc/passwd"), 65534)
    username = "sf" + args.nonce[:12]
    require(not any(row[0] == username for row in public_rows(Path("/etc/passwd"), 7)) and not any(row[0] == username for row in public_rows(Path("/etc/group"), 4)), "owned_name_preexists")
    before, listen_before = policy_snapshot(), listeners()
    defaults = bounded_bytes(Path("/etc/default/useradd"), 4096)
    require(defaults.splitlines().count(b"CREATE_MAIL_SPOOL=yes") == 1, "stock_mail_default_not_yes")
    identities_before, mail_before, subids_before = unrelated_identity_snapshot(username), mail_snapshot(username), subid_snapshot(username)
    original = {"baseline": check(root / paths["baseline"], ["pass", "refused", "refused"], False), "candidate": check(root / paths["candidate"], ["pass", "refused", "pass"], True)}
    require(policy_snapshot() == before and listeners() == listen_before, "original_probe_mutation")
    adapt_nss(args.nonce)
    adapted = policy_snapshot()
    require([new["id"] for old, new in zip(before, adapted) if old != new] == ["nss"], "adaptation_scope")
    after_nss = {"baseline": check(root / paths["baseline"], ["pass", "pass", "refused"], False), "candidate": check(root / paths["candidate"], ["pass", "pass", "pass"], True)}
    baseline_parent = Path("/run/sa-b-" + args.nonce)
    require(not baseline_parent.exists(), "baseline_path_preexists")
    baseline_parent.mkdir(mode=0o755)
    result = run_child(broker_command(root / paths["baseline"], baseline_parent))
    require(result["exit_code"] == 1 and result["stdout"] == b"" and result["stderr"] == b"Native broker unavailable or recovery required\n" and list(baseline_parent.iterdir()) == [], "baseline_startup_mutation")
    parent = Path("/run/sa-" + args.nonce)
    require(not parent.exists(), "candidate_path_preexists")
    parent.mkdir(mode=0o755)
    phases, shutdowns, refusals = [], [], []
    broker, account = OwnedBroker(root / paths["candidate"], parent), None
    try:
        broker.ready()
        initial = request(args.nonce, "list")
        require(initial["http_status"] == 200 and initial["body"] == {"items": []}, "initial_inventory")
        created = request(args.nonce, "create")
        require(created["http_status"] == 200, "create_http")  # Never retry an ambiguous creation.
        account = created["body"]
        phases.append({"operation": "create", "http_status": 200, "account": validate_account(account, args.nonce, parent, "active", 1), "native": native_identity(account)})
        before_refusal = state_evidence(parent)
        duplicate = request(args.nonce, "duplicate")
        require(duplicate["http_status"] == 409 and duplicate["body"] == {"error": "conflict"}, "duplicate_refusal")
        unchanged = request(args.nonce, "list")
        require(unchanged["body"] == {"items": [account]}, "duplicate_side_effect")
        after_refusal = state_evidence(parent)
        require(before_refusal == after_refusal, "duplicate_state_mutation")
        refusals.append({"operation": "duplicate", "before_sha256": before_refusal, "after_sha256": after_refusal, "account_revision": 1})
        phases.append({"operation": "duplicate", "http_status": 409, "account": validate_account(account, args.nonce, parent, "active", 1), "native": native_identity(account)})
        suspended = request(args.nonce, "suspend", account["id"], 1)
        require(suspended["http_status"] == 200, "suspend_http")
        previous, account = account, suspended["body"]
        phases.append({"operation": "suspend", "http_status": 200, "account": validate_account(account, args.nonce, parent, "suspended", 2, previous), "native": native_identity(account)})
        before_refusal = state_evidence(parent)
        stale = request(args.nonce, "stale", account["id"], 1)
        require(stale["http_status"] == 409 and stale["body"] == {"error": "conflict"} and request(args.nonce, "list")["body"] == {"items": [account]}, "stale_side_effect")
        after_refusal = state_evidence(parent)
        require(before_refusal == after_refusal, "stale_state_mutation")
        refusals.append({"operation": "stale", "before_sha256": before_refusal, "after_sha256": after_refusal, "account_revision": 2})
        phases.append({"operation": "stale", "http_status": 409, "account": validate_account(account, args.nonce, parent, "suspended", 2), "native": native_identity(account)})
        activated = request(args.nonce, "activate", account["id"], 2)
        require(activated["http_status"] == 200, "activate_http")
        previous, account = account, activated["body"]
        phases.append({"operation": "activate", "http_status": 200, "account": validate_account(account, args.nonce, parent, "active", 3, previous), "native": native_identity(account)})
    finally:
        shutdowns.append(broker.close(account is not None and len(phases) == 5))
    reopened = OwnedBroker(root / paths["candidate"], parent)
    try:
        reopened.ready()
        inventory = request(args.nonce, "list")
        require(inventory["http_status"] == 200 and inventory["body"] == {"items": [account]}, "reopen_identity")
        phases.append({"operation": "reopen", "http_status": 200, "account": validate_account(account, args.nonce, parent, "active", 3, account), "native": native_identity(account)})
    finally:
        shutdowns.append(reopened.close(len(phases) == 6))
    core = execute_tests(root / paths["core_test"], args.core_test_names.split(","))
    review = execute_tests(root / paths["review_test"], args.review_test_names.split(","))
    after = policy_snapshot()
    require(all(old == new for old, new in zip(adapted, after) if old["id"] not in ("passwd_metadata", "group_metadata")), "policy_invariant")
    require(identities_before == unrelated_identity_snapshot(username) and mail_before == mail_snapshot(username) and subids_before == subid_snapshot(username) and listeners() == listen_before, "unrelated_native_mutation")
    for name, leaf in paths.items():
        require(sha(bounded_bytes(root / leaf, 64 * 1024 * 1024)) == hashes[name], "input_changed")
    return {"schema_version": 1, "scope": SCOPE, "nonce": args.nonce, "passed": True, "profile": {"distribution": "almalinux", "version": "9.8", "kernel": platform.release(), "machine": platform.machine()}, "binary_sha256": hashes, "controller": controller, "policy_before": before, "policy_adapted": adapted, "policy_after": after, "adaptation": {"id": "nss", "sha256": sha(NSS_BYTES), "mode": "0644", "root_owned_regular": True}, "original_checks": original, "nss_adapted_checks": after_nss, "baseline_startup": {"exit_code": 1, "added_paths": [], "owned_child_exited": True}, "lifecycle": phases, "refusal_evidence": refusals, "shutdowns": shutdowns, "mail_before": mail_before, "mail_after": mail_snapshot(username), "subids_before": subids_before, "subids_after": subid_snapshot(username), "unrelated_identities_before": identities_before, "unrelated_identities_after": unrelated_identity_snapshot(username), "core_tests": core, "review_tests": review, "listeners_before": listen_before, "listeners_after": listeners(), "stock_mail_defaults_unchanged": True, "inputs_unchanged": True, "account_created": True, "account_mutation_requests": 5, "accepted_account_mutations": 3, "stock_provisioning_qualified": False, "owned_children_exited": True}


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "--peer-request":
        try:
            print(json.dumps(peer_request(sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])), separators=(",", ":")))
            return 0
        except Exception:
            print("Owned peer request failed", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-service-accounts", action="store_true", required=True)
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
