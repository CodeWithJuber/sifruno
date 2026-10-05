#!/usr/bin/env python3
"""Trusted, disposable AlmaLinux hostweb qualification.

This program is deliberately an orchestrator, not an installer.  It accepts
only a root-produced profile/bundle from the pinned hostweb CLI, installs the
bytes into a fresh guest scratch layout, and runs the staged Apache/PHP-FPM
processes with per-account bind mounts.  It never edits generated config
bytes, reads private key contents into Python, or touches a live host state.
"""

from __future__ import annotations

from dataclasses import dataclass

import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import posixpath
import re
import selectors
import signal
import socket
import ssl
import stat
import subprocess
import time
from urllib.parse import urlsplit


MAX_ACCOUNTS = 2
COMMAND_TIMEOUT = 45
TOTAL_TIMEOUT = 360
MAX_OUTPUT = 256 * 1024
MAX_RUNTIME_REPORT = 64 * 1024
UID_MIN, UID_MAX = 20000, 60000
ACCOUNT_ID = re.compile(r"^[a-f0-9]{32}$")
USERNAME = re.compile(r"^[a-z][a-z0-9_]{2,31}$")
DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
SAFE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,400}$")
HEX = re.compile(r"^[a-f0-9]{64}$")
RUN_DEADLINE: float | None = None


class FixtureError(RuntimeError):
    def __init__(self, code: str, observations: list[dict] | None = None):
        super().__init__(code)
        self.code = code
        self.observations = observations


def guard_deadline() -> None:
    if RUN_DEADLINE is not None and time.monotonic() >= RUN_DEADLINE:
        die("fixture_total_timeout")


def die(code: str) -> None:
    raise FixtureError(code)


def clean_env() -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "HOME": "/root",
        "TMPDIR": "/tmp",
    }


def run_cmd(argv: list[str], *, timeout: int = COMMAND_TIMEOUT, uid: int | None = None,
            gid: int | None = None, check: bool = True, cwd: Path | None = None,
            output_limit: int = MAX_OUTPUT, input_data: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    if not argv or any("\x00" in x for x in argv):
        die("invalid_command")
    command = list(argv)
    if uid is not None:
        if gid is None:
            gid = uid
        command = ["/usr/bin/setpriv", "--reuid", str(uid), "--regid", str(gid),
                   "--clear-groups", "--", *command]
    try:
        child = subprocess.Popen(command, cwd=str(cwd) if cwd else None,
                                 env=clean_env(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, start_new_session=True)
    except OSError:
        die("command_failed_or_timed_out")
    stdout = bytearray()
    stderr = bytearray()
    if input_data is not None and len(input_data) > 1 << 20:
        die("command_input_bound_exceeded")
    selector = selectors.DefaultSelector()
    assert child.stdin is not None and child.stdout is not None and child.stderr is not None
    pending_input: list[object] | None = None
    if input_data is not None:
        os.set_blocking(child.stdin.fileno(), False)
        pending_input = [input_data, 0]
        selector.register(child.stdin, selectors.EVENT_WRITE, pending_input)
    else:
        child.stdin.close()
    selector.register(child.stdout, selectors.EVENT_READ, stdout)
    selector.register(child.stderr, selectors.EVENT_READ, stderr)
    deadline = time.monotonic() + timeout
    if RUN_DEADLINE is not None:
        deadline = min(deadline, RUN_DEADLINE)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=3)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                die("command_failed_or_timed_out")
            for key, _ in selector.select(min(1.0, remaining)):
                if key.fileobj is child.stdin:
                    assert pending_input is not None
                    payload, offset = pending_input
                    try:
                        written = os.write(child.stdin.fileno(), payload[offset:])
                    except BrokenPipeError:
                        selector.unregister(child.stdin)
                        child.stdin.close()
                        pending_input = None
                        continue
                    except OSError:
                        die("command_input_failed")
                    pending_input[1] = offset + written
                    if pending_input[1] == len(payload):
                        selector.unregister(child.stdin)
                        child.stdin.close()
                        pending_input = None
                    continue
                data = key.fileobj.read1(8192) if hasattr(key.fileobj, "read1") else key.fileobj.read(8192)
                if not data:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                key.data.extend(data)
                if len(stdout) + len(stderr) > output_limit:
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                        child.wait(timeout=3)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                    die("command_output_bound_exceeded")
    finally:
        selector.close()
        if pending_input is not None:
            try:
                child.stdin.close()
            except OSError:
                pass
    returncode = child.wait(timeout=3)
    result = subprocess.CompletedProcess(command, returncode, bytes(stdout), bytes(stderr))
    if check and result.returncode != 0:
        die("command_failed")
    return result


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest()


def verify_root_binary(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        die("staged_binary_invalid")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        die("staged_binary_permissions_invalid")
    return sha256(path)


def verify_root_file(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        die("staged_input_invalid")
    info = path.stat()
    if info.st_uid != 0 or info.st_mode & 0o022:
        die("staged_input_permissions_invalid")
    return sha256(path)


def exclusive_path(path: Path, parent: Path) -> None:
    if not path.is_absolute() or path.parent != parent or path.exists() or path.is_symlink():
        die("report_path_not_exclusive")


def write_runtime_report(path: Path, parent: Path, result: dict) -> None:
    # Serialize and bound before exclusively creating the admitted output.
    exclusive_path(path, parent)
    data = (json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")
    if len(data) > MAX_RUNTIME_REPORT:
        die("runtime_report_bound_exceeded")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as output:
        if hasattr(os, "fchmod"):
            os.fchmod(output.fileno(), 0o600)
        else:
            os.chmod(path, 0o600)
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def read_json(path: Path, max_bytes: int = 2 << 20) -> object:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > max_bytes:
        die("json_input_invalid")
    try:
        with path.open("rb") as source:
            value = json.loads(source.read(max_bytes + 1))
    except (OSError, ValueError):
        die("json_input_invalid")
    return value


def required_object(value: object, keys: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        die("json_schema_invalid")
    return value


def safe_path(value: object) -> str:
    if not isinstance(value, str) or not SAFE_PATH.fullmatch(value):
        die("unsafe_posix_path")
    if value == "/" or value != posixpath.normpath(value) or "//" in value:
        die("unsafe_posix_path")
    if any(part in (".", "..") for part in value.split("/")):
        die("unsafe_posix_path")
    return value


def within(path: str, root: str) -> bool:
    return path.startswith(root.rstrip("/") + "/")


def profile_from(path: Path) -> dict:
    keys = {"Name", "ManagedRoot", "ManagedHomeRoot", "FrontChroot", "ApacheModuleRoot",
            "BackendChrootRoot", "RuntimeRoot", "ApacheBinary", "FPMBinary",
            "TLSRoot", "CAFile", "FrontendIP", "FrontendPort", "BackendPort",
            "FrontUID", "FrontGID", "ControllerUID"}
    value = read_json(path)
    profile = required_object(value, keys)
    if profile["Name"] != "restricted-chroot-v1":
        die("unknown_profile")
    roots = {key: safe_path(profile[key]) for key in
             ("ManagedRoot", "ManagedHomeRoot", "FrontChroot", "BackendChrootRoot",
              "RuntimeRoot", "TLSRoot")}
    ca_file = safe_path(profile["CAFile"])
    module_root = safe_path(profile["ApacheModuleRoot"])
    if not safe_path(profile["ApacheBinary"]) or not safe_path(profile["FPMBinary"]):
        die("unsafe_binary_path")
    if profile["FrontendIP"] != "127.0.0.1" or not isinstance(profile["FrontendPort"], int):
        die("invalid_listener")
    if not isinstance(profile["BackendPort"], int) or profile["BackendPort"] != 18443:
        die("invalid_listener")
    if not (1 <= profile["FrontendPort"] <= 65535):
        die("invalid_listener")
    if (profile["FrontUID"], profile["FrontGID"], profile["ControllerUID"]) != (48, 48, 2000):
        die("front_identity_invalid")
    if module_root in roots.values() or any(within(module_root, root) or within(root, module_root) for root in roots.values()):
        die("profile_roots_overlap")
    for left_name, left in roots.items():
        for right_name, right in roots.items():
            if left_name >= right_name:
                continue
            if left == right or within(left, right) or within(right, left):
                die("profile_roots_overlap")
    if not within(ca_file, roots["TLSRoot"]):
        die("ca_outside_tls_root")
    return profile


def fixed_profile() -> dict:
    return {
        "Name": "restricted-chroot-v1",
        "ManagedRoot": "/var/lib/sifruno-web",
        "ManagedHomeRoot": "/home/sifruno-managed",
        "FrontChroot": "/srv/sifruno-web-front",
        "ApacheModuleRoot": "/usr/lib64/httpd/modules",
        "BackendChrootRoot": "/srv/sifruno-web-jails",
        "RuntimeRoot": "/run/sifruno-web-runtime",
        "ApacheBinary": "/usr/sbin/httpd",
        "FPMBinary": "/usr/sbin/php-fpm",
        "TLSRoot": "/etc/sifruno-web-tls",
        "CAFile": "/etc/sifruno-web-tls/ca.pem",
        "FrontendIP": "127.0.0.1",
        "FrontendPort": 18081,
        "BackendPort": 18443,
        "FrontUID": 48,
        "FrontGID": 48,
        "ControllerUID": 2000,
    }


def helper_profile(profile: dict) -> dict:
    return {"name": profile["Name"], "managedRoot": profile["ManagedRoot"],
            "managedHomeRoot": profile["ManagedHomeRoot"], "frontChroot": profile["FrontChroot"],
            "apacheModuleRoot": profile["ApacheModuleRoot"], "backendChrootRoot": profile["BackendChrootRoot"],
            "runtimeRoot": profile["RuntimeRoot"], "apacheBinary": profile["ApacheBinary"],
            "fpmBinary": profile["FPMBinary"], "tlsRoot": profile["TLSRoot"], "caFile": profile["CAFile"],
            "frontendIP": profile["FrontendIP"], "frontendPort": profile["FrontendPort"],
            "backendPort": profile["BackendPort"], "frontUID": profile["FrontUID"],
            "frontGID": profile["FrontGID"], "controllerUID": profile["ControllerUID"]}


def account_items(value: object, *, allow_raw_list: bool = False) -> list[dict]:
    if isinstance(value, dict):
        if set(value) not in ({"items"}, {"items", "$schema"}):
            die("account_list_schema_invalid")
        if "$schema" in value:
            schema = value["$schema"]
            if (not isinstance(schema, str) or not 1 <= len(schema) <= 2048 or
                    not schema.isascii() or any(not 33 <= ord(c) <= 126 for c in schema)):
                die("account_list_metadata_invalid")
            try:
                parsed = urlsplit(schema)
                port = parsed.port
                if (parsed.scheme not in ("http", "https") or not parsed.hostname or
                        parsed.username is not None or parsed.password is not None or
                        not parsed.path.endswith("/AccountListBody.json") or parsed.query or parsed.fragment or
                        (port is not None and not 1 <= port <= 65535)):
                    die("account_list_metadata_invalid")
            except ValueError:
                die("account_list_metadata_invalid")
            # Metadata is never fetched or passed into the strict Go helper.
        value = value["items"]
    elif not allow_raw_list:
        die("account_list_schema_invalid")
    if not isinstance(value, list) or not (1 <= len(value) <= MAX_ACCOUNTS):
        die("account_count_invalid")
    return value


def accounts_from(path: Path, profile: dict, allow_suspended: bool = False) -> list[dict]:
    value = account_items(read_json(path), allow_raw_list=True)
    keys = {"ID", "Username", "Domain", "Home", "PublicHTML", "State", "UID", "GID",
            "Revision", "CreatedAt", "UpdatedAt"}
    result: list[dict] = []
    seen: set[object] = set()
    for account in value:
        if isinstance(account, dict) and set(account) == {"id", "username", "domain", "home", "public_html", "state", "uid", "gid", "revision", "created_at", "updated_at"}:
            account = {
                "ID": account["id"], "Username": account["username"], "Domain": account["domain"],
                "Home": account["home"], "PublicHTML": account["public_html"], "State": account["state"],
                "UID": account["uid"], "GID": account["gid"], "Revision": account["revision"],
                "CreatedAt": account["created_at"], "UpdatedAt": account["updated_at"],
            }
        else:
            account = required_object(account, keys)
        if (not isinstance(account["ID"], str) or not ACCOUNT_ID.fullmatch(account["ID"]) or
                not isinstance(account["Username"], str) or not USERNAME.fullmatch(account["Username"]) or
                not isinstance(account["Domain"], str) or not DOMAIN.fullmatch(account["Domain"]) or
                account["State"] not in (("active", "suspended") if allow_suspended else ("active",)) or
                not isinstance(account["UID"], int) or not UID_MIN <= account["UID"] <= UID_MAX or
                account["GID"] != account["UID"] or not isinstance(account["Revision"], int) or
                account["Revision"] < 1):
            die("account_schema_invalid")
        home = safe_path(account["Home"])
        public = safe_path(account["PublicHTML"])
        if (home != posixpath.join(profile["ManagedHomeRoot"], account["Username"]) or
                public != posixpath.join(home, "public_html") or
                not within(home, profile["ManagedHomeRoot"]) or
                account["ID"] in seen or account["Username"] in seen or
                account["Domain"] in seen or account["UID"] in seen):
            die("account_identity_invalid")
        seen.update((account["ID"], account["Username"], account["Domain"], account["UID"]))
        result.append(account)
    return sorted(result, key=lambda a: a["ID"])


def bundle_from(path: Path, profile: dict, accounts: list[dict]) -> tuple[dict, dict[str, bytes]]:
    outer = required_object(read_json(path, 16 << 20), {"schemaVersion", "compatibility", "activation", "bundle"})
    if outer["schemaVersion"] != 1 or outer["compatibility"] is not False or outer["activation"] is not False:
        die("bundle_schema_invalid")
    bundle = required_object(outer["bundle"], {"profile", "files", "sha256"})
    if bundle["profile"] != profile["Name"] or not isinstance(bundle["files"], list) or not HEX.fullmatch(str(bundle["sha256"])):
        die("bundle_schema_invalid")
    files: dict[str, bytes] = {}
    last = ""
    digest = hashlib.sha256()
    for item in bundle["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "mode", "sha256", "config"}:
            die("bundle_schema_invalid")
        path_name = item["path"]
        if (not isinstance(path_name, str) or not path_name or path_name.startswith("/") or
                ".." in path_name or path_name <= last or path_name in files or
                item["mode"] != "0600" or not isinstance(item["sha256"], str) or not HEX.fullmatch(item["sha256"]) or
                not isinstance(item["config"], str) or len(item["config"].encode()) > 2 * 1024 * 1024):
            die("bundle_file_metadata_invalid")
        data = item["config"].encode()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            die("bundle_file_hash_invalid")
        files[path_name] = data
        last = path_name
        digest.update(path_name.encode() + b"\0" + b"600\0" + item["sha256"].encode() + b"\0")
    active = [account for account in accounts if account["State"] == "active"]
    if len(files) != 1 + len(active) * 2 or digest.hexdigest() != bundle["sha256"]:
        die("bundle_digest_or_count_invalid")
    expected = {"apache/front.conf"}
    for account in active:
        expected.update((f"apache/backends/{account['ID']}.conf", f"fpm/{account['ID']}.conf"))
    if set(files) != expected:
        die("bundle_inventory_invalid")
    check_config_bytes(files, profile, accounts)
    return bundle, files


def text(files: dict[str, bytes], name: str) -> str:
    try:
        return files[name].decode("ascii")
    except (KeyError, UnicodeDecodeError):
        die("config_encoding_invalid")


def check_config_bytes(files: dict[str, bytes], profile: dict, accounts: list[dict]) -> None:
    front = text(files, "apache/front.conf")
    active = [account for account in accounts if account["State"] == "active"]
    required_front = ("ProxyPreserveHost On", "User #48", "Group #48", "SSLProxyVerify require", "SSLProxyCheckPeerName on",
                      "SSLProxyCheckPeerExpire on", "SSLProxyCACertificateFile \"" + profile["CAFile"] + "\"")
    if any(item not in front for item in required_front) or "Require host " in front:
        die("front_tls_or_host_gate_missing")
    if any(account["Home"] in front or account["PublicHTML"] in front for account in accounts):
        die("front_tenant_read_path_present")
    for account in active:
        ip = f"127.73.{account['UID'] >> 8}.{account['UID'] & 255}"
        if f"https://{ip}:{profile['BackendPort']}/" not in front:
            die("front_backend_route_missing")
        backend = text(files, f"apache/backends/{account['ID']}.conf")
        fpm = text(files, f"fpm/{account['ID']}.conf")
        required_backend = (f"ChrootDir \"{profile['BackendChrootRoot']}/{account['ID']}\"",
                            f"User #{account['UID']}", f"Group #{account['GID']}",
                            f"Listen {ip}:{profile['BackendPort']}", f"DocumentRoot \"{account['PublicHTML']}\"",
                            f"{profile['RuntimeRoot']}/{account['ID']}/php-fpm.sock")
        required_fpm = (f"user = {account['UID']}", f"group = {account['GID']}",
                        f"chroot = {profile['BackendChrootRoot']}/{account['ID']}",
                        f"listen = {profile['RuntimeRoot']}/{account['ID']}/php-fpm.sock",
                        f"php_admin_value[session.save_path] = {account['Home']}/tmp")
        if any(item not in backend for item in required_backend) or any(item not in fpm for item in required_fpm):
            die("tenant_runtime_directive_missing")
        for other in active:
            if other["ID"] == account["ID"]:
                continue
            if any(path in backend or path in fpm for path in (other["Home"], other["PublicHTML"], other["ID"])):
                die("tenant_config_cross_reference")
    for account in accounts:
        if account["State"] == "suspended":
            if account["Domain"] not in front or "Require all denied" not in front:
                die("suspended_front_denial_missing")


def write_exact(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() or path.is_symlink():
        die("staged_path_not_fresh")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)


def replace_exact(path: Path, data: bytes, mode: int = 0o600) -> None:
    if not path.is_file() or path.is_symlink():
        die("staged_path_not_regular")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
        try:
            offset = 0
            while offset < len(data):
                offset += os.write(fd, data[offset:])
            os.fsync(fd)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)
    except OSError:
        die("staged_replace_failed")


def backend_tls_probe(account: dict, profile: dict, ca_file: Path) -> dict:
    ip = f"127.73.{account['UID'] >> 8}.{account['UID'] & 255}"
    context = ssl.create_default_context(cafile=str(ca_file))
    context.check_hostname = True
    connection = http.client.HTTPSConnection(ip, profile["BackendPort"], context=context, timeout=3)
    try:
        connection.request("GET", "/index.html", headers={"Host": account["Domain"], "Connection": "close"})
        response = connection.getresponse()
        body = response.read(128 * 1024 + 1)
        if len(body) > 128 * 1024:
            die("http_body_bound_exceeded")
    except (OSError, ssl.SSLError, http.client.HTTPException):
        die("backend_tls_identity_invalid")
    finally:
        connection.close()
    if response.status != 200 or f"SIFRUNO_STATIC_{account['Username']}".encode() not in body:
        die("backend_probe_invalid")
    return {"account_id": account["ID"], "status": response.status, "bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(), "expected_marker_observed": True}


def inspect_wrong_backend_certificate(proc: subprocess.Popen[bytes], account: dict,
                                      profile: dict, ca_file: Path, replacement_cert: Path,
                                      wrong_ip: str) -> None:
    """Prove a live backend serves the exact CA-valid wrong-SAN fixture leaf.

    Hostname checking is disabled only for this explicit inspection. The
    production front and backend_tls_probe keep their strict peer-name checks.
    """
    ip = f"127.73.{account['UID'] >> 8}.{account['UID'] & 255}"
    if wrong_ip != "127.73.255.254" or wrong_ip == ip:
        die("wrong_backend_fixture_ip_invalid")
    replacement_hash = verify_root_file(replacement_cert)
    if replacement_cert.stat().st_size > 64 * 1024:
        die("wrong_backend_fixture_certificate_invalid")
    try:
        expected_der = ssl.PEM_cert_to_DER_cert(replacement_cert.read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError):
        die("wrong_backend_fixture_certificate_invalid")
    context = ssl.create_default_context(cafile=str(ca_file))
    context.check_hostname = False  # Inspection only; chain validation stays required.
    context.verify_mode = ssl.CERT_REQUIRED
    deadline = time.monotonic() + 8
    while True:
        guard_deadline()
        if proc.poll() is not None:
            die("wrong_backend_process_exited")
        try:
            with socket.create_connection((ip, profile["BackendPort"]), timeout=2) as raw:
                with context.wrap_socket(raw, server_hostname=ip) as conn:
                    if conn.getpeercert(binary_form=True) != expected_der:
                        die("wrong_backend_presented_certificate_mismatch")
                    if conn.getpeercert().get("subjectAltName") != (
                            ("DNS", "wrong-backend.example.invalid"), ("IP Address", wrong_ip)):
                        die("wrong_backend_presented_san_invalid")
                    conn.sendall((f"GET /index.html HTTP/1.1\r\nHost: {account['Domain']}\r\nConnection: close\r\n\r\n").encode())
                    response = http.client.HTTPResponse(conn)
                    response.begin()
                    body = response.read(8193)
                    if response.status != 200 or body != f"SIFRUNO_STATIC_{account['Username']}\n".encode():
                        die("wrong_backend_static_probe_invalid")
            if proc.poll() is not None or sha256(replacement_cert) != replacement_hash:
                die("wrong_backend_fixture_changed")
            return
        except ssl.SSLCertVerificationError:
            die("wrong_backend_inspection_chain_invalid")
        except (OSError, ssl.SSLError, http.client.HTTPException):
            if time.monotonic() >= deadline:
                die("wrong_backend_inspection_not_ready")
            time.sleep(.1)


def replacement_startup_diagnostics(proc: subprocess.Popen[bytes]) -> list[str]:
    if proc.stderr is None:
        return []
    try:
        os.set_blocking(proc.stderr.fileno(), False)
        return diagnostic_lines(os.read(proc.stderr.fileno(), 4096))
    except OSError:
        return []


def guest_policy(path: Path, pattern: str, replacement: str, limit: int, code: str) -> tuple[str, str]:
    if not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > limit:
        die(code)
    original = path.read_bytes()
    try:
        text_value = original.decode("utf-8")
    except UnicodeDecodeError:
        die(code)
    updated = re.sub(pattern, replacement, text_value, flags=re.MULTILINE)
    return hashlib.sha256(original).hexdigest(), updated


def prepare_guest_policies(args: argparse.Namespace) -> dict[str, object]:
    if not args.qualification_files_only_nss or not args.qualification_no_mail_spool_default:
        die("guest_policy_adaptation_required")
    nss = Path("/etc/nsswitch.conf")
    nss_was_symlink = nss.is_symlink()
    nss_hash, nss_text = guest_policy(nss, r"^\s*(passwd|group|shadow)\s*:.*$", r"\1: files", 1 << 20, "nss_policy_invalid")
    for database in ("passwd", "group", "shadow"):
        if not re.search(r"^" + database + r": files$", nss_text, re.MULTILINE):
            nss_text += "\n" + database + ": files\n"
    temporary = nss.with_name(".sifruno-qualified-nss")
    if temporary.exists() or temporary.is_symlink():
        die("nss_policy_not_fresh")
    write_exact(temporary, nss_text.encode(), 0o644)
    os.replace(temporary, nss)

    defaults = Path("/etc/default/useradd")
    defaults_hash, defaults_text = guest_policy(defaults, r"^\s*CREATE_MAIL_SPOOL\s*=.*$", "CREATE_MAIL_SPOOL=no", 4096, "useradd_policy_invalid")
    if not re.search(r"^CREATE_MAIL_SPOOL=no$", defaults_text, re.MULTILINE):
        defaults_text += "\nCREATE_MAIL_SPOOL=no\n"
    temporary = defaults.with_name(".sifruno-qualified-useradd")
    if temporary.exists() or temporary.is_symlink():
        die("useradd_policy_not_fresh")
    write_exact(temporary, defaults_text.encode(), 0o644)
    os.replace(temporary, defaults)
    return {
        "guest_only_files_policy_declared": True,
        "original_sha256": nss_hash,
        "original_was_symlink": nss_was_symlink,
        "effective_identity_policy": ["passwd: files", "group: files", "shadow: files"],
        "stock_alma_nss_qualified": False,
        "guest_only_no_mail_spool_policy_declared": True,
        "useradd_original_sha256": defaults_hash,
        "effective_mail_spool": False,
        "stock_useradd_policy_qualified": False,
    }


def prepare_controller() -> dict[str, object]:
    for args in (("passwd", "2000"), ("group", "2000"), ("passwd", "sifrunocontrol")):
        if run_cmd(["/usr/bin/getent", *args], check=False).returncode == 0:
            die("controller_identity_not_fresh")
    run_cmd(["/usr/sbin/useradd", "--uid", "2000", "--user-group", "--groups", "",
             "--create-home", "--home-dir", "/home/sifruno-controller",
             "--shell", "/usr/sbin/nologin", "--password", "!", "sifrunocontrol"])
    home = Path("/home/sifruno-controller")
    info = home.stat()
    if info.st_uid != 2000 or info.st_gid != 2000 or home.is_symlink():
        die("controller_identity_invalid")
    passwd = run_cmd(["/usr/bin/getent", "passwd", "sifrunocontrol"]).stdout.decode("ascii").strip().split(":")
    if len(passwd) != 7 or passwd[2] != "2000" or passwd[3] != "2000" or passwd[5] != str(home) or passwd[6] != "/usr/sbin/nologin":
        die("controller_identity_invalid")
    if run_cmd(["/usr/bin/passwd", "--status", "sifrunocontrol"]).stdout.decode("ascii").split()[1] != "LK":
        die("controller_password_not_locked")
    if Path("/var/spool/mail/sifrunocontrol").exists():
        die("controller_mail_spool_created")
    return {"uid": 2000, "gid": 2000, "shell": "/usr/sbin/nologin", "password_locked": True,
            "supplementary_groups": False, "mail_spool": False}


def panel_ready_probe() -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        guard_deadline()
        connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=1)
        try:
            connection.request("GET", "/api/v1/status")
            response = connection.getresponse()
            body = response.read(32769)
            if response.status == 200 and len(body) <= 32768:
                value = json.loads(body)
                if isinstance(value, dict) and value.get("ready") is False:
                    return
        except (OSError, ValueError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(.1)
    die("panel_readiness_failed")


def process_context(pid: int) -> str:
    try:
        value = Path(f"/proc/{pid}/attr/current").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return "unavailable"
    return value[:256] if value else "empty"


def diagnostic_lines(stderr: bytes) -> list[str]:
    lines: list[str] = []
    for raw in stderr.decode("utf-8", "replace").splitlines():
        raw = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", raw)
        line = "".join(c for c in raw if c.isprintable())[:256]
        lowered = line.lower()
        if any(token in lowered for token in ("private key", "begin ", "end ", "traceback", "password", "token=", "secret=", "cookie", "authorization")):
            continue
        if (any(token in lowered for token in ("error", "syntax", "failed", "cannot", "denied", "unable", "could not", "invalid", "requires")) or
                re.search(r"\bAH[0-9]{5}\b", line) or line.startswith("Invalid command '")):
            lines.append(line)
    return lines[-4:]


def owned_log_diagnostics(path: Path) -> list[str]:
    # Paths come only from this fixture's exclusive stderr files or generated
    # fixed Apache/FPM log references. Never consume an arbitrary host log.
    try:
        if path.is_symlink():
            return []
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_uid", 0) != 0:
                return []
            source.seek(max(0, info.st_size - 4096))
            return diagnostic_lines(source.read(4096))
    except OSError:
        return []


def ensure_dir(path: Path, mode: int = 0o700) -> None:
    if path.exists() or path.is_symlink():
        die("runtime_root_not_fresh")
    path.mkdir(mode=mode, parents=True, exist_ok=False)
    os.chmod(path, mode)


def mount_bind(source: Path, target: Path) -> None:
    target.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_cmd(["/usr/bin/mount", "--bind", str(source), str(target)])
    run_cmd(["/usr/bin/mount", "--make-private", str(target)])


def unmount(path: Path) -> None:
    if run_cmd(["/usr/bin/umount", "-l", str(path)], timeout=15, check=False).returncode != 0:
        die("owned_mount_cleanup_failed")


def children(pid: int) -> list[int]:
    result: list[int] = []
    pending = [pid]
    while pending and len(result) < 128:
        current = pending.pop()
        child_file = Path(f"/proc/{current}/task/{current}/children")
        try:
            more = [int(item) for item in child_file.read_text().split()]
        except (OSError, ValueError):
            more = []
        for item in more:
            if item not in result:
                result.append(item)
                pending.append(item)
    return result


def parse_proc_identity(status: str, root: str) -> dict:
    wanted = ("Uid", "Gid", "Groups", "CapEff", "CapPrm", "CapAmb", "CapInh")
    values = {}
    if len(status.encode("ascii")) > 8192:
        raise ValueError("process status bound")
    for line in status.splitlines():
        key, _, value = line.partition(":")
        if key in wanted:
            if key in values:
                raise ValueError("duplicate process identity field")
            values[key] = value.strip()
    if set(values) != set(wanted):
        raise ValueError("missing process identity field")
    ids = {}
    for key in ("Uid", "Gid"):
        fields = values[key].split()
        if len(fields) != 4 or any(not field.isdecimal() for field in fields):
            raise ValueError("invalid process identity")
        ids[key] = [int(field) for field in fields]
        if any(value > 0xFFFFFFFE for value in ids[key]):
            raise ValueError("process identity bound")
    fields = values["Groups"].split()
    if len(fields) > 32 or any(not field.isdecimal() for field in fields):
        raise ValueError("invalid supplementary groups")
    groups = [int(field) for field in fields]
    if len(set(groups)) != len(groups) or any(value > 0xFFFFFFFE for value in groups):
        raise ValueError("supplementary groups bound")
    caps = {}
    for key, name in (("CapEff", "effective"), ("CapPrm", "permitted"), ("CapAmb", "ambient"), ("CapInh", "inheritable")):
        if not re.fullmatch(r"[0-9a-fA-F]{1,16}", values[key]):
            raise ValueError("invalid process capabilities")
        caps[name + "_capabilities"] = int(values[key], 16)
    return {"uid": ids["Uid"][0], "gid": ids["Gid"][0], "uids": ids["Uid"],
            "gids": ids["Gid"], "groups": groups, "root": root, **caps}


def process_identity(pid: int) -> dict:
    with Path(f"/proc/{pid}/status").open("r", encoding="ascii") as source:
        status = source.read(8193)
    return parse_proc_identity(status, os.path.realpath(f"/proc/{pid}/root"))


def worker_matches(identity: dict, uid: int, gid: int, root: str) -> bool:
    return (identity["uids"] == [uid] * 4 and identity["gids"] == [gid] * 4 and
            set(identity["groups"]).issubset({gid}) and identity["root"] == root and
            all(identity[name + "_capabilities"] == 0 for name in
                ("effective", "permitted", "ambient", "inheritable")))


def assert_worker(proc: subprocess.Popen[bytes], account: dict, jail: Path) -> None:
    deadline = time.monotonic() + 10
    observed = False
    while time.monotonic() < deadline:
        guard_deadline()
        if proc.poll() is not None:
            die("owned_daemon_exited_before_workers")
        pids = children(proc.pid)
        identities = []
        for pid in pids:
            try:
                identities.append(process_identity(pid))
            except (OSError, KeyError, ValueError, UnicodeError):
                pass
        observed = observed or bool(pids)
        if identities and len(identities) == len(pids) and all(
                worker_matches(identity, account["UID"], account["GID"], str(jail)) for identity in identities):
            return
        time.sleep(.1)
    raise FixtureError("worker_identity_or_chroot_invalid" if observed else "worker_not_observed",
                       observations=identities[:8])


def assert_front_has_no_tenant_worker(proc: subprocess.Popen[bytes], accounts: list[dict]) -> None:
    tenant_uids = {account["UID"] for account in accounts}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        guard_deadline()
        if proc.poll() is not None:
            die("owned_daemon_exited_before_workers")
        pids = children(proc.pid)
        identities = []
        for pid in pids:
            try:
                identity = process_identity(pid)
            except (OSError, KeyError, ValueError, UnicodeError):
                continue
            if set(identity["uids"]) & (tenant_uids | {2000}) or identity["root"] != "/":
                die("shared_front_tenant_authority")
            identities.append(identity)
        if identities and len(identities) == len(pids) and all(
                worker_matches(identity, 48, 48, "/") for identity in identities):
            return
        time.sleep(.1)
    raise FixtureError("shared_front_identity_not_apache", observations=identities[:8])


def linux_start_identity(pid: int) -> str | None:
    try:
        with Path(f"/proc/{pid}/stat").open("r", encoding="ascii") as source:
            value = source.read(8193)
    except FileNotFoundError:
        return None
    if len(value) > 8192:
        raise FixtureError("owned_process_identity_invalid")
    # comm is parenthesized and may contain spaces or ')'; split at its last ')'.
    close = value.rfind(")")
    if not value.startswith(f"{pid} (") or close < 0 or value[close:close+2] != ") ":
        raise FixtureError("owned_process_identity_invalid")
    fields = value[close + 2:].split()
    if len(fields) < 20 or not fields[19].isdecimal():
        raise FixtureError("owned_process_identity_invalid")
    return fields[19] # field22 starttime, relative to field3 state


@dataclass(frozen=True)
class OwnedProcess:
    process: subprocess.Popen
    pgid: int
    fixture_pgid: int
    start_identity: str

    def __getattr__(self, name):
        return getattr(self.process, name)


def owned_launch(argv, **kwargs) -> OwnedProcess:
    # Popen's POSIX start_new_session creates PGID=SID=PID before exec. No shell
    # or caller-supplied preexec_fn is admitted. All fixture daemons use this.
    if kwargs.get("start_new_session", True) is not True or kwargs.get("preexec_fn") is not None or kwargs.get("shell", False):
        raise FixtureError("owned_launch_contract_invalid")
    fixture_pgid = os.getpgrp()
    kwargs["start_new_session"] = True
    process = subprocess.Popen(argv, **kwargs)
    try:
        if process.pid <= 1 or process.pid == fixture_pgid:
            raise FixtureError("owned_process_group_invalid")
        identity = linux_start_identity(process.pid)
        if identity is None or os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
            raise FixtureError("owned_process_admission_failed")
        return OwnedProcess(process, process.pid, fixture_pgid, identity)
    except (OSError, FixtureError):
        # Admission failed: never signal an unproven/foreign process group.
        # Reap the exact Popen leader; disposable guest must be rejected.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        raise FixtureError("owned_process_admission_failed")


def stop_process(owned: OwnedProcess | None, *, term_timeout: float = 8,
                 kill_timeout: float = 3, poll_interval: float = .05) -> None:
    if owned is None:
        return
    if not isinstance(owned, OwnedProcess) or owned.pgid <= 1 or owned.pgid != owned.pid or owned.pgid in (owned.fixture_pgid, os.getpgrp()):
        raise FixtureError("owned_process_group_invalid")
    if not (0 < term_timeout <= 8 and 0 < kill_timeout <= 3 and 0 < poll_interval <= .1):
        raise FixtureError("owned_cleanup_bound_invalid")

    def check_identity():
        current = linux_start_identity(owned.pid)
        if current is not None and current != owned.start_identity:
            raise FixtureError("owned_process_identity_changed")
        if owned.poll() is None and (current is None or os.getpgid(owned.pid) != owned.pgid or os.getsid(owned.pid) != owned.pgid):
            raise FixtureError("owned_process_group_changed")

    def signal_group(sig) -> bool:
        check_identity()
        try:
            os.killpg(owned.pgid, sig)
            return True
        except ProcessLookupError:
            return False
        except OSError as error:
            raise FixtureError("owned_process_cleanup_failed") from error

    def wait_extinction(timeout):
        deadline = time.monotonic() + timeout
        while True:
            owned.poll() # reap leader so its zombie cannot keep the group alive
            if not signal_group(0):
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(min(poll_interval, max(0, deadline-time.monotonic())))

    # Cleanup has independent bounded grace periods even when the fixture's
    # global deadline/cancellation has fired. Never abandon owned children.
    if signal_group(0):
        if signal_group(signal.SIGTERM) and not wait_extinction(term_timeout):
            if signal_group(signal.SIGKILL) and not wait_extinction(kill_timeout):
                raise FixtureError("owned_process_cleanup_failed")
    try:
        owned.wait(timeout=kill_timeout)
    except subprocess.TimeoutExpired as error:
        raise FixtureError("owned_process_cleanup_failed") from error


def http_request(port: int, host: str, path: str) -> tuple[int, bytes]:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request("GET", path, headers={"Host": host, "Connection": "close"})
        response = connection.getresponse()
        body = response.read(128 * 1024 + 1)
        if len(body) > 128 * 1024:
            die("http_body_bound_exceeded")
        return response.status, body
    except (OSError, http.client.HTTPException):
        die("http_probe_failed")
    finally:
        connection.close()


def assert_traversal_denied(status: int, body: bytes) -> None:
    # Apache rejects malformed encoded dot segments as400 before routing. An
    # unavailable service/redirect cannot count as a successful isolation probe.
    if (type(status) is not int or status not in (400, 403, 404) or
            b"SIFRUNO_PRIVATE_SENTINEL" in body):
        die("sibling_path_not_denied")


def issue_backend_certificate(account: dict, cert: Path, key: Path, ca_cert: Path,
                              ca_key: Path, work: Path, ip: str, suffix: str,
                              peer_domain: str | None = None) -> None:
    ext = work / (account["ID"] + suffix + ".ext")
    # ProxyPreserveHost makes Apache use the original domain for peer-name/SNI;
    # direct loopback probes independently verify the account's IP identity.
    peer_domain = account["Domain"] if peer_domain is None else peer_domain
    if peer_domain not in (account["Domain"], "wrong-backend.example.invalid"):
        die("backend_certificate_domain_invalid")
    write_exact(ext, f"subjectAltName=DNS:{peer_domain},IP:{ip}\n".encode())
    csr = work / (account["ID"] + suffix + ".csr")
    serial = work / (account["ID"] + suffix + ".srl")
    run_cmd(["/usr/bin/openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={ip}", "-out", str(csr)])
    run_cmd(["/usr/bin/openssl", "x509", "-req", "-sha256", "-days", "1", "-in", str(csr), "-CA", str(ca_cert), "-CAkey", str(ca_key), "-CAserial", str(serial), "-CAcreateserial", "-extfile", str(ext), "-out", str(cert)])
    os.chmod(cert, 0o600)


def make_certificates(profile: dict, accounts: list[dict], work: Path) -> None:
    tls_root = Path(profile["TLSRoot"])
    tls_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    ca_key = work / "ca.key"
    ca_cert = Path(profile["CAFile"])
    ca_cert.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_cmd(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(ca_key)], output_limit=64 * 1024)
    os.chmod(ca_key, 0o600)
    run_cmd(["/usr/bin/openssl", "req", "-x509", "-new", "-sha256", "-days", "1", "-key", str(ca_key), "-subj", "/CN=Sifruno disposable hostweb CA", "-out", str(ca_cert)])
    os.chmod(ca_cert, 0o600)
    for account in accounts:
        directory = tls_root / account["ID"]
        directory.mkdir(mode=0o700, exist_ok=False)
        key = directory / "key.pem"
        cert = directory / "cert.pem"
        run_cmd(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)])
        os.chmod(key, 0o600)
        issue_backend_certificate(account, cert, key, ca_cert, ca_key, work,
                                  f"127.73.{account['UID'] >> 8}.{account['UID'] & 255}", "")


def main() -> int:
    global RUN_DEADLINE
    parser = argparse.ArgumentParser()
    parser.add_argument("--disposable-alma-guest", action="store_true", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--qualification-files-only-nss", action="store_true")
    parser.add_argument("--qualification-no-mail-spool-default", action="store_true")
    args = parser.parse_args()
    started = time.monotonic()
    RUN_DEADLINE = started + TOTAL_TIMEOUT
    report_path = Path(args.report)
    qualification_root = Path("/opt/sifruno-web-qualification")
    admission_path = Path("/run/sifruno-web-admission")
    run_root = qualification_root / "fixture-run"
    broker_binary = qualification_root / "hostbroker"
    panel_binary = qualification_root / "sifruno"
    panelctl_binary = qualification_root / "panelctl"
    web_render_binary = qualification_root / "web-render"
    ui_root = qualification_root / "ui"
    result: dict[str, object] = {
        "schema_version": 1, "evidence_kind": "synthetic", "passed": False,
        "complete": False, "fixture_kind": "trusted_networkless_alma_hostweb",
        "reference_observed": False, "compatibility_certified": False,
        "production_mutated": False, "reboot_durability_tested": False,
        "checks": [], "failure": None,
    }
    procs: list[subprocess.Popen[bytes]] = []
    mounts: list[Path] = []
    log_handles: list[object] = []
    daemon_logs: list[tuple[str, str | None, Path]] = []

    def daemon_stderr(role: str, account_id: str | None = None):
        path = run_root / (role + ("-" + account_id if account_id else "") + "-startup.log")
        handle = path.open("xb")
        os.chmod(path, 0o600)
        log_handles.append(handle)
        daemon_logs.append((role, account_id, path))
        return handle
    try:
        if os.geteuid() != 0 or not args.disposable_alma_guest:
            die("root_disposable_guest_required")
        for raw in (args.report, str(broker_binary), str(panel_binary), str(panelctl_binary),
                    str(web_render_binary), str(ui_root)):
            candidate = Path(raw)
            if not candidate.is_absolute() or candidate != Path(os.path.normpath(raw)) or "\x00" in raw:
                die("absolute_argument_required")
        admission = admission_path
        if (not admission.is_file() or admission.is_symlink() or admission.stat().st_uid != 0 or
                stat.S_IMODE(admission.stat().st_mode) != 0o600 or
                admission.read_text() != "trusted-disposable-alma9-web\n"):
            die("trusted_admission_missing")
        release = {}
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                release[key] = value.strip('"')
        if release.get("ID") != "almalinux" or not release.get("VERSION_ID", "").startswith("9."):
            die("alma9_only")
        if report_path.parent != qualification_root or report_path.exists() or report_path.is_symlink() or run_root.exists() or run_root.is_symlink():
            die("run_root_not_fresh")
        run_root.mkdir(mode=0o700, parents=False)
        if ui_root.exists() or ui_root.is_symlink():
            die("qualification_ui_not_fresh")
        ui_root.mkdir(mode=0o755)
        write_exact(ui_root / "index.html", b"Sifruno disposable qualification panel\n", 0o444)
        result["guest_policies"] = prepare_guest_policies(args)
        result["controller"] = prepare_controller()
        mounts_info = Path("/proc/mounts").read_text(encoding="ascii")[:1 << 20]
        root_fs = [row.split()[2] for row in mounts_info.splitlines() if len(row.split()) >= 3 and row.split()[1] == "/"]
        selinux_path = Path("/sys/fs/selinux/enforce")
        selinux_enforcing = selinux_path.is_file() and selinux_path.read_text(encoding="ascii").strip() == "1"
        package_versions = {}
        for package in ("httpd", "mod_ssl", "php-fpm"):
            package_versions[package] = run_cmd(["/usr/bin/rpm", "-q", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\\n", package]).stdout.decode("ascii", "replace").strip()[:160]
        result["environment"] = {"kernel": os.uname().release[:160], "architecture": os.uname().machine[:64],
                                  "root_filesystems": root_fs[:16], "selinux_enforcing": selinux_enforcing,
                                  "packages": package_versions, "confinement_certified": False}
        profile = fixed_profile()
        binaries = [Path(profile["ApacheBinary"]), Path(profile["FPMBinary"]),
                    broker_binary, panel_binary, panelctl_binary, web_render_binary]
        result["binaries"] = [{"name": path.name, "sha256": verify_root_binary(path)} for path in binaries]
        module_names = ("mod_mpm_event.so", "mod_unixd.so", "mod_ssl.so", "mod_proxy.so",
                        "mod_proxy_http.so", "mod_proxy_fcgi.so", "mod_authz_core.so",
                        "mod_authz_host.so", "mod_dir.so", "mod_mime.so", "mod_log_config.so")
        result["modules"] = [{"name": name, "sha256": verify_root_file(Path(profile["ApacheModuleRoot"]) / name)} for name in module_names]
        broker_state = Path("/var/lib/sifruno-hostbroker")
        panel_state = Path("/home/sifruno-controller/private")
        socket_path = Path("/run/sifruno-accounts/broker.sock")
        homes = Path(profile["ManagedHomeRoot"])
        for path in (broker_state, panel_state, socket_path.parent, homes, Path(profile["ManagedRoot"]),
                     Path(profile["FrontChroot"]), Path(profile["BackendChrootRoot"]),
                     Path(profile["RuntimeRoot"])):
            if path.exists() or path.is_symlink():
                die("profile_root_not_fresh")
        homes.mkdir(mode=0o755, parents=True)
        socket_path.parent.mkdir(mode=0o755, parents=False)
        logs = [run_root / "broker.log", run_root / "panel.log"]
        broker_log = logs[0].open("xb")
        panel_log = logs[1].open("xb")
        for log in logs:
            os.chmod(log, 0o600)
        log_handles.extend((broker_log, panel_log))
        broker = owned_launch([str(broker_binary), "--state", str(broker_state), "--socket", str(socket_path),
                                   "--homes", str(homes), "--controller-uid", "2000"], cwd=str(qualification_root),
                                  env=clean_env(), stdout=broker_log, stderr=broker_log, start_new_session=True)
        procs.append(broker)
        deadline = time.monotonic() + 20
        while not socket_path.exists() and broker.poll() is None and time.monotonic() < deadline:
            guard_deadline()
            time.sleep(.1)
        if not socket_path.exists() or broker.poll() is not None:
            die("broker_start_failed")
        panel = owned_launch(["/usr/bin/setpriv", "--reuid", "2000", "--regid", "2000", "--clear-groups", "--",
                                  str(panel_binary), "--listen", "127.0.0.1:18080", "--sites-listen", "", "--state", str(panel_state),
                                  "--ui", str(ui_root), "--accounts-socket", str(socket_path)], cwd=str(qualification_root), env=clean_env(),
                                 stdout=panel_log, stderr=panel_log, start_new_session=True)
        procs.append(panel)
        deadline = time.monotonic() + 25
        while not (panel_state / "operator/access.key").exists() and panel.poll() is None and time.monotonic() < deadline:
            guard_deadline()
            time.sleep(.1)
        if not (panel_state / "operator/access.key").exists() or panel.poll() is not None:
            die("panel_start_failed")
        panel_ready_probe()
        private_info = panel_state.stat()
        if private_info.st_uid != 2000 or private_info.st_gid != 2000 or stat.S_IMODE(private_info.st_mode) != 0o700:
            die("controller_private_state_permissions_invalid")
        apache_user = run_cmd(["/usr/bin/getent", "passwd", "apache"]).stdout.decode().split(":")
        apache_group = run_cmd(["/usr/bin/getent", "group", "apache"]).stdout.decode().split(":")
        if len(apache_user) < 4 or len(apache_group) < 3 or apache_user[2] != "48" or apache_group[2] != "48":
            die("signed_apache_identity_invalid")
        panelctl = [str(panelctl_binary), "--state", str(panel_state), "--panel-url", "http://127.0.0.1:18080"]
        capability = run_cmd([*panelctl, "accounts", "capability"], uid=2000)
        if b'"available":true' not in capability.stdout.replace(b" ", b""):
            die("broker_capability_unavailable")
        accounts_json = run_root / "accounts.json"
        rows = run_cmd([*panelctl, "accounts", "list"], uid=2000).stdout
        if len(rows) > MAX_OUTPUT:
            die("account_list_bound_exceeded")
        write_exact(accounts_json, rows)
        # Create exactly two fresh accounts; retries are forbidden after an unknown response.
        for username, domain in (("webalpha", "webalpha.example.test"), ("webbravo", "webbravo.example.test")):
            run_cmd([*panelctl, "accounts", "create", "--username", username, "--domain", domain,
                     "--reason", "Disposable hostweb qualification"], uid=2000)
        rows = run_cmd([*panelctl, "accounts", "list"], uid=2000).stdout
        replace_exact(accounts_json, rows)
        accounts = accounts_from(accounts_json, profile)
        account_rows = account_items(json.loads(rows))
        helper_input = json.dumps({"schemaVersion": 1, "compatibility": False, "activation": False,
                                   "profile": helper_profile(profile), "accounts": account_rows},
                                  separators=(",", ":")).encode() + b"\n"
        rendered = run_cmd([str(web_render_binary)], input_data=helper_input)
        bundle_path = run_root / "bundle.json"
        write_exact(bundle_path, rendered.stdout)
        bundle, files = bundle_from(bundle_path, profile, accounts)
        result["checks"].append("exact_bundle_admission")
        result["bundle_sha256"] = sha256(bundle_path)
        result["accounts"] = [{"id": a["ID"], "uid": a["UID"], "gid": a["GID"], "domain": a["Domain"]} for a in accounts]
        # The following steps deliberately require root-prepared, disjoint mounts.
        make_certificates(profile, accounts, run_root)
        for path in (Path(profile["ManagedRoot"]), Path(profile["FrontChroot"]),
                     Path(profile["BackendChrootRoot"]), Path(profile["RuntimeRoot"])):
            path.mkdir(mode=0o755, parents=True, exist_ok=False)
        # The compiler intentionally emits absolute metadata/log paths.  These
        # are prepared before any daemon starts; no generated config is edited.
        for path in (Path(profile["ManagedRoot"]) / "apache",
                     Path(profile["ManagedRoot"]) / "backend",
                     Path(profile["ManagedRoot"]) / "logs",
                     Path(profile["ManagedRoot"]) / "fpm",
                     Path(profile["ManagedRoot"]) / "front-mutex"):
            path.mkdir(mode=0o700, parents=False, exist_ok=False)
        write_exact(Path(profile["ManagedRoot"]) / "controller-private-sentinel", b"SIFRUNO_CONTROLLER_PRIVATE\n", 0o600)
        for rel, data in files.items():
            write_exact(Path(profile["ManagedRoot"]) / rel, data)
        for account in accounts:
            (Path(profile["ManagedRoot"]) / "backend" / (account["ID"] + "-mutex")).mkdir(
                mode=0o700, parents=False, exist_ok=False)
            home = Path(account["Home"])
            if not home.is_dir() or home.is_symlink() or home.stat().st_uid != account["UID"] or home.stat().st_gid != account["GID"]:
                die("broker_home_identity_invalid")
            public_html = Path(account["PublicHTML"])
            if (not public_html.is_dir() or public_html.is_symlink() or
                    public_html.stat().st_uid != account["UID"] or public_html.stat().st_gid != account["GID"]):
                die("broker_public_html_identity_invalid")
            tmp = home / "tmp"
            tmp.mkdir(mode=0o700, exist_ok=False)
            os.chown(tmp, account["UID"], account["GID"])
            jail = Path(profile["BackendChrootRoot"]) / account["ID"]
            runtime = Path(profile["RuntimeRoot"]) / account["ID"]
            jail.mkdir(mode=0o755, exist_ok=False)
            if jail.stat().st_uid != 0 or jail.stat().st_gid != 0 or stat.S_IMODE(jail.stat().st_mode) != 0o755:
                die("jail_root_not_immutable")
            # mod_mime's emitted TypesConfig is satisfied by this tiny
            # root-owned jail file; no host /etc is mounted or exposed.
            (jail / "etc").mkdir(mode=0o755)
            write_exact(jail / "etc/mime.types", b"text/html html htm\ntext/plain txt\n", 0o444)
            # Numeric Apache/FPM identities still need deterministic files-only
            # NSS if initgroups is attempted after chroot.  These files contain
            # no host users or secrets and are unreadable by the tenant UID.
            write_exact(jail / "etc/passwd", (
                f"root:x:0:0:root:/root:/usr/sbin/nologin\n"
                f"{account['Username']}:x:{account['UID']}:{account['GID']}::{account['Home']}:/usr/sbin/nologin\n"
            ).encode(), 0o400)
            write_exact(jail / "etc/group", (
                f"root:x:0:\n{account['Username']}:x:{account['GID']}:\n"
            ).encode(), 0o400)
            write_exact(jail / "etc/nsswitch.conf", b"passwd: files\ngroup: files\nshadow: files\n", 0o444)
            runtime.mkdir(mode=0o750, exist_ok=False)
            os.chown(runtime, account["UID"], account["GID"])
            home_target = jail / account["Home"].lstrip("/")
            runtime_target = jail / profile["RuntimeRoot"].lstrip("/") / account["ID"]
            mount_bind(home, home_target); mounts.append(home_target)
            mount_bind(runtime, runtime_target); mounts.append(runtime_target)
            marker = public_html / "index.html"
            write_exact(marker, f"SIFRUNO_STATIC_{account['Username']}\n".encode(), 0o640)
            os.chown(marker, account["UID"], account["GID"])
            php = public_html / "probe.php"
            other = next(candidate for candidate in accounts if candidate["ID"] != account["ID"])
            sibling_path = other["Home"] + "/private.txt"
            code = ("<?php header('Content-Type: text/plain'); "
                    f"echo 'SIFRUNO_PHP_{account['Username']}\\n'; "
                    f"echo 'SELF='.(is_readable('{account['PublicHTML']}/index.html')?'readable':'denied').'\\n'; "
                    "echo 'HOST='.(is_readable('/var/lib/sifruno-web/controller-private-sentinel')?'readable':'denied').'\\n'; "
                    + f"echo 'SIBLING='.(is_readable('{sibling_path}')?'readable':'denied').'\\n'; ?>")
            write_exact(php, code.encode(), 0o640)
            os.chown(php, account["UID"], account["GID"])
        # A sibling secret must never be readable through either jail.
        for account in accounts:
            sibling_secret = Path(account["Home"]) / "private.txt"
            write_exact(sibling_secret, b"SIFRUNO_PRIVATE_SENTINEL\n", 0o600)
            os.chown(sibling_secret, account["UID"], account["GID"])
        front_conf = Path(profile["ManagedRoot"]) / "apache/front.conf"
        fpm_procs: list[subprocess.Popen[bytes]] = []
        backend_procs: list[subprocess.Popen[bytes]] = []
        syntax = run_cmd([profile["ApacheBinary"], "-t", "-f", str(front_conf), "-d", str(profile["FrontChroot"])], check=False)
        if syntax.returncode != 0:
            result["diagnostics"] = {"kind": "front_config_syntax", "lines": diagnostic_lines(syntax.stderr)}
            die("front_config_syntax_invalid")
        for account in accounts:
            fpm_conf = Path(profile["ManagedRoot"]) / f"fpm/{account['ID']}.conf"
            backend_conf = Path(profile["ManagedRoot"]) / f"apache/backends/{account['ID']}.conf"
            syntax = run_cmd([profile["ApacheBinary"], "-t", "-f", str(backend_conf), "-d", str(Path(profile["BackendChrootRoot"]) / account["ID"])], check=False)
            if syntax.returncode != 0:
                result["diagnostics"] = {"kind": "backend_config_syntax", "account_id": account["ID"], "lines": diagnostic_lines(syntax.stderr)}
                die("backend_config_syntax_invalid")
            syntax = run_cmd([profile["FPMBinary"], "-y", str(fpm_conf), "-t"], check=False)
            if syntax.returncode != 0:
                result["diagnostics"] = {"kind": "fpm_config_syntax", "account_id": account["ID"], "lines": diagnostic_lines(syntax.stderr)}
                die("fpm_config_syntax_invalid")
            fpm = owned_launch([profile["FPMBinary"], "-y", str(fpm_conf), "-F"], env=clean_env(), stdout=subprocess.DEVNULL, stderr=daemon_stderr("fpm", account["ID"]), start_new_session=True)
            procs.append(fpm); fpm_procs.append(fpm)
            daemon_logs.append(("fpm", account["ID"], Path(profile["ManagedRoot"]) / "logs" / (account["ID"] + "-fpm.log")))
            backend = owned_launch([profile["ApacheBinary"], "-DFOREGROUND", "-f", str(backend_conf), "-d", str(Path(profile["BackendChrootRoot"]) / account["ID"])], env=clean_env(), stdout=subprocess.DEVNULL, stderr=daemon_stderr("backend", account["ID"]), start_new_session=True)
            procs.append(backend); backend_procs.append(backend)
            daemon_logs.append(("backend", account["ID"], Path(profile["ManagedRoot"]) / "logs" / (account["ID"] + "-apache.log")))
            assert_worker(backend, account, Path(profile["BackendChrootRoot"]) / account["ID"])
            result.setdefault("backend_probes", []).append(backend_tls_probe(account, profile, Path(profile["CAFile"])))
        front = owned_launch([profile["ApacheBinary"], "-DFOREGROUND", "-f", str(front_conf), "-d", str(profile["FrontChroot"])], env=clean_env(), stdout=subprocess.DEVNULL, stderr=daemon_stderr("front"), start_new_session=True)
        procs.append(front)
        daemon_logs.append(("front", None, Path(profile["ManagedRoot"]) / "front-error.log"))
        time.sleep(.5)
        assert_front_has_no_tenant_worker(front, accounts)
        private_probe = run_cmd(["/usr/bin/test", "-r", str(panel_state / "operator/access.key")], uid=48, check=False)
        if private_probe.returncode == 0:
            die("shared_front_can_read_controller_state")
        result["serving_probes"] = []
        for account, fpm in zip(accounts, fpm_procs):
            status, body = http_request(profile["FrontendPort"], account["Domain"], "/index.html")
            result["serving_probes"].append({"kind": "static", "account_id": account["ID"],
                "status": status, "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                "expected_marker_observed": f"SIFRUNO_STATIC_{account['Username']}".encode() in body})
            if status != 200 or f"SIFRUNO_STATIC_{account['Username']}".encode() not in body:
                result["http_probe"] = {"kind": "static", "account_id": account["ID"], "status": status,
                    "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                    "expected_marker_observed": f"SIFRUNO_STATIC_{account['Username']}".encode() in body}
                die("static_probe_failed")
            status, body = http_request(profile["FrontendPort"], account["Domain"], "/probe.php")
            result["serving_probes"].append({"kind": "php", "account_id": account["ID"],
                "status": status, "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                "expected_marker_observed": f"SIFRUNO_PHP_{account['Username']}".encode() in body,
                "self_readable": b"SELF=readable" in body, "host_denied": b"HOST=denied" in body,
                "sibling_denied": b"SIBLING=denied" in body})
            if (status != 200 or f"SIFRUNO_PHP_{account['Username']}".encode() not in body or
                    b"SELF=readable" not in body or b"HOST=denied" not in body or b"SIBLING=denied" not in body):
                result["http_probe"] = {"kind": "php", "account_id": account["ID"], "status": status,
                    "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                    "expected_marker_observed": f"SIFRUNO_PHP_{account['Username']}".encode() in body}
                die("php_isolation_probe_failed")
            assert_worker(fpm, account, Path(profile["BackendChrootRoot"]) / account["ID"])
        contexts: list[dict[str, object]] = []
        for role, process_list in (("front", [front]), ("backend", backend_procs), ("fpm", fpm_procs)):
            for process in process_list:
                for pid in [process.pid, *children(process.pid)][:8]:
                    try:
                        identity = process_identity(pid)
                    except (OSError, KeyError, ValueError, UnicodeError):
                        continue
                    contexts.append({"role": role, "pid": pid, **identity,
                                     "selinux_context": process_context(pid)})
        result["process_contexts"] = contexts[:32]
        status, _ = http_request(profile["FrontendPort"], "unknown.example.test", "/index.html")
        if status not in (400, 403, 421):
            die("unknown_host_not_denied")
        status, _ = http_request(profile["FrontendPort"], accounts[0]["Domain"], "/missing.html")
        if status != 404:
            die("missing_static_status_invalid")
        status, body = http_request(profile["FrontendPort"], accounts[0]["Domain"], f"/%2e%2e/{accounts[1]['Username']}/private.txt")
        result["traversal_probe"] = {"status": status, "bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "private_marker_observed": b"SIFRUNO_PRIVATE_SENTINEL" in body}
        assert_traversal_denied(status, body)
        status, body = http_request(profile["FrontendPort"], accounts[0]["Domain"],
                                    f"/{accounts[1]['Username']}/private.txt")
        result["sibling_mapping_probe"] = {"status": status, "bytes": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "private_marker_observed": b"SIFRUNO_PRIVATE_SENTINEL" in body}
        if status not in (403, 404) or b"SIFRUNO_PRIVATE_SENTINEL" in body:
            die("sibling_mapping_not_denied")
        # Replace one backend certificate with a CA-valid certificate for the wrong IP.
        # The front must reject the connection by required peer-name verification.
        wrong_cert = Path(profile["TLSRoot"]) / accounts[0]["ID"] / "cert.pem"
        issue_backend_certificate(accounts[0], wrong_cert, Path(profile["TLSRoot"]) / accounts[0]["ID"] / "key.pem",
                                  Path(profile["CAFile"]), run_root / "ca.key", run_root,
                                  "127.73.255.254", "-wrong", "wrong-backend.example.invalid")
        stop_process(backend_procs[0])
        backend_procs[0] = owned_launch([profile["ApacheBinary"], "-DFOREGROUND", "-f",
                                              str(Path(profile["ManagedRoot"]) / f"apache/backends/{accounts[0]['ID']}.conf"),
                                              "-d", str(Path(profile["BackendChrootRoot"]) / accounts[0]["ID"])],
                                             env=clean_env(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        procs.append(backend_procs[0])
        assert_worker(backend_procs[0], accounts[0], Path(profile["BackendChrootRoot"]) / accounts[0]["ID"])
        if backend_procs[0].stderr is not None:
            log_handles.append(backend_procs[0].stderr)
        try:
            inspect_wrong_backend_certificate(backend_procs[0], accounts[0], profile,
                                              Path(profile["CAFile"]), wrong_cert, "127.73.255.254")
        except FixtureError:
            result["diagnostics"] = {"kind": "wrong_backend_certificate_inspection",
                                     "lines": replacement_startup_diagnostics(backend_procs[0])}
            raise
        try:
            wrong_status, _ = http_request(profile["FrontendPort"], accounts[0]["Domain"], "/index.html")
        except FixtureError:
            die("wrong_backend_certificate_probe_failed")
        if backend_procs[0].poll() is not None:
            die("wrong_backend_process_exited")
        if not 500 <= wrong_status <= 599:
            die("wrong_backend_certificate_accepted")
        issue_backend_certificate(accounts[0], wrong_cert, Path(profile["TLSRoot"]) / accounts[0]["ID"] / "key.pem",
                                  Path(profile["CAFile"]), run_root / "ca.key", run_root,
                                  f"127.73.{accounts[0]['UID'] >> 8}.{accounts[0]['UID'] & 255}", "-restore")
        stop_process(backend_procs[0])
        backend_procs[0] = owned_launch([profile["ApacheBinary"], "-DFOREGROUND", "-f",
                                              str(Path(profile["ManagedRoot"]) / f"apache/backends/{accounts[0]['ID']}.conf"),
                                              "-d", str(Path(profile["BackendChrootRoot"]) / accounts[0]["ID"])],
                                             env=clean_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        procs.append(backend_procs[0])
        assert_worker(backend_procs[0], accounts[0], Path(profile["BackendChrootRoot"]) / accounts[0]["ID"])
        backend_tls_probe(accounts[0], profile, Path(profile["CAFile"]))
        result["checks"] = ["exact_bundle_admission", "front_proxy_backend_tls_peer_verification", "wrong_backend_certificate_refused", "static_and_php_results", "uid_gid_groups_capabilities_chroot_workers", "jail_files_only_nss", "unknown_missing_and_sibling_denial"]
        # Suspend the second account through the non-root controller, recompile,
        # and activate the exact new front bytes. Its backend is stopped first.
        updated_rows = run_cmd([*panelctl, "accounts", "list"], uid=2000).stdout
        updated_accounts = accounts_from(accounts_json, profile, allow_suspended=True)
        listed = {"items": account_items(json.loads(updated_rows))}
        write_json_rows = json.dumps(listed, separators=(",", ":")).encode()
        replace_exact(accounts_json, write_json_rows)
        updated_accounts = accounts_from(accounts_json, profile, allow_suspended=True)
        second = updated_accounts[1]
        run_cmd([*panelctl, "accounts", "state", "--id", second["ID"], "--state", "suspended",
                 "--revision", str(second["Revision"]), "--reason", "Disposable suspended-domain check"], uid=2000)
        replace_exact(accounts_json, run_cmd([*panelctl, "accounts", "list"], uid=2000).stdout)
        suspended_accounts = accounts_from(accounts_json, profile, allow_suspended=True)
        suspended_bundle_path = run_root / "bundle-suspended.json"
        account_rows = account_items(read_json(accounts_json))
        suspended_input = json.dumps({"schemaVersion": 1, "compatibility": False, "activation": False,
                                      "profile": helper_profile(profile), "accounts": account_rows},
                                     separators=(",", ":")).encode() + b"\n"
        write_exact(suspended_bundle_path, run_cmd([str(web_render_binary)], input_data=suspended_input).stdout)
        _suspended_bundle, suspended_files = bundle_from(suspended_bundle_path, profile, suspended_accounts)
        stop_process(backend_procs[1]); stop_process(fpm_procs[1])
        stop_process(front)
        replace_exact(front_conf, suspended_files["apache/front.conf"])
        front = owned_launch([profile["ApacheBinary"], "-DFOREGROUND", "-f", str(front_conf), "-d", str(profile["FrontChroot"])], env=clean_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        procs.append(front)
        assert_front_has_no_tenant_worker(front, accounts)
        status, _ = http_request(profile["FrontendPort"], second["Domain"], "/index.html")
        if status != 403:
            die("suspended_domain_not_denied")
        result["checks"].append("suspended_domain_denied_after_exact_recompile")
        # Malformed configuration must fail before a new process is admitted.
        malformed = run_root / "malformed.conf"
        write_exact(malformed, b"ServerRoot \"/invalid\"\nInclude \"unterminated\n")
        test = run_cmd([profile["ApacheBinary"], "-t", "-f", str(malformed), "-d", str(profile["FrontChroot"])], check=False)
        if test.returncode == 0:
            die("malformed_config_activated")
        result["checks"].append("malformed_config_fails_before_activation")
        result["execution_kind"] = "disposable_native_guest_with_fixture_data"
        result["passed"] = True
    except FixtureError as error:
        result["failure"] = error.code
        if error.observations is not None:
            result["worker_observations"] = error.observations
    except (OSError, ValueError, json.JSONDecodeError):
        result["failure"] = "fixture_io_or_validation_error"
    finally:
        for proc in reversed(procs):
            try:
                stop_process(proc)
            except FixtureError:
                result["failure"] = result["failure"] or "owned_process_cleanup_failed"
        for target in reversed(mounts):
            try:
                unmount(target)
            except FixtureError:
                result["failure"] = result["failure"] or "owned_mount_cleanup_failed"
                result["passed"] = False
        if result["failure"] is not None:
            startup = []
            for role, account_id, path in daemon_logs:
                lines = owned_log_diagnostics(path)
                if lines:
                    startup.append({"role": role, "account_id": account_id, "lines": lines})
                if len(startup) == 8:
                    break
            if startup:
                result["startup_diagnostics"] = startup
        for handle in log_handles:
            try:
                handle.close()
            except OSError:
                pass
        result["complete"] = True
        if result["failure"] is not None:
            result["passed"] = False
        result["duration_ms"] = int((time.monotonic() - started) * 1000)
        if run_root.exists():
            try:
                write_runtime_report(report_path, qualification_root, result)
            except (OSError, FixtureError, ValueError, TypeError):
                result["report_write_failure"] = "report_write_failed"
                result["failure"] = result["failure"] or "report_write_failed"
                result["passed"] = False
    summary = {key: result[key] for key in ("passed", "complete", "failure")}
    for key in ("report_write_failure", "diagnostics", "startup_diagnostics"):
        if key in result:
            summary[key] = result[key]
    print(json.dumps(summary))
    return 0 if result["passed"] and result["failure"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
