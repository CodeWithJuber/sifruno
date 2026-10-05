#!/usr/bin/env python3
"""Fixed, hash-admitted disposable Alma9 setup for the frozen Go executor.

Importing this module performs no guest operations. No caller paths/commands,
downloads, daemon lifecycle copies, or SELinux disabling are available.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

ROOT = Path("/opt/sifruno-runtime-fixture")
ADMISSION = Path("/run/sifruno-runtime-serving-admission")
DRIVER_SHA = "21b9b146674aa6e286cad0e8f180e263cb014bfa2d87efeb994ecc0cca7163f1"
TEST_SHA = "431e2717f0919591c864b23792381fd9d4f81ca92ca72e76bb78a953a497865d"
HELPER_SHA = "73ef86f95b34d255b4ab5c6145caae718ad1578efba7f1c0d24f5712c57fc9ed"
RUNTIME_SHA = "5fffdaada446ca5068258d43888ed34e15cb4492465bce4e9ffb1f27463f066c"
SOURCE_CATALOG_SHA = "74e6aab996033480ffbfb63b86a4a2c6b937d78e08ac6ff262909727ddbb8e35"
ALMA_FINGERPRINT = "BF18AC2876178908D6E71267D36CB86CB86B3716"
HEX = re.compile(r"^[a-f0-9]{64}$")
NONCE = re.compile(r"^[a-f0-9]{24}$")
ID = re.compile(r"^[a-f0-9]{32}$")
MAX_JSON = 64 << 10
MAX_RPM = 64 << 20
MAX_RPMS = 256 << 20
TOTAL_SECONDS = 330
PACKAGE_NAMES = frozenset(("almalinux-logos-httpd", "apr", "apr-util", "apr-util-bdb", "apr-util-openssl", "httpd", "httpd-core", "httpd-filesystem", "httpd-tools", "mod_http2", "mod_lua", "mod_ssl", "nginx-filesystem", "php-common", "php-fpm", "php-process", "sscg", "mailcap"))
TEST_NAMES = frozenset(("TestStrictInput", "TestCLIExact", "TestGenerationSnapshotAndCopy", "TestPHPCoreContract", "TestClientNoProxyRedirectBound", "TestClientActuallyRefusesRedirect", "TestOwnedInputRejectLinksModesAndEscape", "TestReportExclusiveBoundedJSON", "TestProcessStartIgnoresMutableCounters"))
DRIVER_FIELDS = {"schema_version", "fixture_only", "execution_kind", "run_id", "nonce", "driver_sha256", "runtime_manifest_sha256", "input_sha256", "profile_sha256", "intended_generations", "observations", "probes", "workers", "prerequisites", "stage", "passed", "shutdown_passed", "close_passed", "listeners_extinct", "input_stable", "selinux_stable"}
CHECKS = ("fixed_payload_admission", "alma9_enforcing_no_external_nics", "signed18_installed_exact_nevras", "guest_policy_adapted_declared", "two_fixture_accounts_and_private_receipts", "disjoint_jail_nss_and_exact_bind_mappings", "native_driver_negative_tests", "native_active_suspended_serving", "owned_driver_reaped_listeners_namespaces_extinct", "owned_mounts_removed", "input_source_package_policy_stable")


class Failure(RuntimeError):
    pass


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Failure(code)


def encoded(value: object) -> bytes:
    return (json.dumps(value, separators=(",", ":"), sort_keys=True, allow_nan=False) + "\n").encode("utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def strict_json(data: bytes, limit: int = MAX_JSON) -> object:
    require(0 < len(data) <= limit, "json_bound")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "json_duplicate_key")
            result[key] = value
        return result
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Failure("json_nonfinite")))
    except (UnicodeError, ValueError):
        raise Failure("json_invalid") from None


def object_keys(value: object, keys: set[str], code: str) -> dict:
    require(isinstance(value, dict) and set(value) == keys, code)
    return value


def root_file(path: Path, mode: int, limit: int) -> bytes:
    require(path.is_absolute(), "absolute_path_required")
    current = Path("/")
    for part in path.parts[1:-1]:
        current /= part
        s = current.lstat()
        require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and
                not s.st_mode & 0o022, "trusted_parent_required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        require(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and s.st_nlink == 1 and
                stat.S_IMODE(s.st_mode) == mode and 0 <= s.st_size <= limit, "root_file_invalid")
        data = bytearray()
        while len(data) <= limit:
            b = os.read(fd, min(65536, limit + 1 - len(data)))
            if not b:
                break
            data.extend(b)
        require(len(data) <= limit, "root_file_bound")
        return bytes(data)
    finally:
        os.close(fd)


def validate_admission(value: object) -> dict:
    keys = {"schema_version", "kind", "nonce", "prepared_image_sha256", "fixture_sha256", "helper_sha256", "source_catalog_sha256", "package_report_sha256", "driver_sha256", "test_sha256", "zero_external_nics"}
    a = object_keys(value, keys, "admission_fields")
    require(type(a["schema_version"]) is int and a["schema_version"] == 1 and
            a["kind"] == "trusted-disposable-alma9-runtime-serving" and
            isinstance(a["nonce"], str) and NONCE.fullmatch(a["nonce"]) is not None and
            a["zero_external_nics"] is True, "admission_invalid")
    for key in keys - {"schema_version", "kind", "nonce", "zero_external_nics"}:
        require(isinstance(a[key], str) and HEX.fullmatch(a[key]) is not None, "admission_digest")
    require(a["driver_sha256"] == DRIVER_SHA and a["test_sha256"] == TEST_SHA and a["helper_sha256"] == HELPER_SHA and a["source_catalog_sha256"] == SOURCE_CATALOG_SHA, "candidate_pin_mismatch")
    return a


def profile() -> dict:
    return {"Name": "restricted-chroot-v1", "ManagedRoot": (ROOT / "managed").as_posix(), "ManagedHomeRoot": (ROOT / "homes").as_posix(), "FrontChroot": (ROOT / "front-jail").as_posix(), "BackendChrootRoot": (ROOT / "backend-jails").as_posix(), "RuntimeRoot": (ROOT / "runtime").as_posix(), "TLSRoot": (ROOT / "tls").as_posix(), "CAFile": (ROOT / "tls/ca.pem").as_posix(), "ApacheModuleRoot": "/usr/lib64/httpd/modules", "ApacheBinary": "/usr/sbin/httpd", "FPMBinary": "/usr/sbin/php-fpm", "FrontendIP": "127.0.0.1", "FrontendPort": 18082, "BackendPort": 18443, "FrontUID": 48, "FrontGID": 48, "ControllerUID": 2000}


def accounts() -> list[dict]:
    return [{"id": letter * 32, "username": user, "domain": domain, "home": (ROOT / "homes" / user).as_posix(), "public_html": (ROOT / "homes" / user / "public_html").as_posix(), "state": "active", "uid": uid, "gid": uid, "revision": 1, "created_at": "2026-10-05T00:00:00Z", "updated_at": "2026-10-05T00:00:00Z"}
            for letter, user, domain, uid in (("a", "webalpha", "alpha.test", 20001), ("b", "webbravo", "bravo.test", 20002))]


def helper_accounts(items: list[dict]) -> list[dict]:
    names = {"id": "ID", "username": "Username", "domain": "Domain", "home": "Home", "public_html": "PublicHTML", "uid": "UID", "gid": "GID"}
    return [{target: a[source] for source, target in names.items()} for a in items]


def php_code(a: dict, other: dict) -> bytes:
    return ("<?php header('Content-Type: text/plain'); "
            f'echo "SIFRUNO_PHP_{a["username"]}\\n"; '
            'echo "SELF=".(is_readable(__FILE__)?"readable":"denied")."\\n"; '
            f'echo "HOST=".(is_readable("{ROOT.as_posix()}/managed/controller-private-sentinel")?"readable":"denied")."\\n"; '
            f'echo "SIBLING=".(is_readable("{other["home"]}/private.txt")?"readable":"denied")."\\n"; '
            'echo "PID=".getmypid()."\\n"; ?>').encode("ascii")


def load_helper(a: dict):
    path = ROOT / "web_runtime_fixture.py"
    require(digest(root_file(path, 0o600, 128 << 10)) == a["helper_sha256"], "helper_hash_mismatch")
    spec = importlib.util.spec_from_file_location("sifruno_runtime_serving_helpers", path)
    require(spec is not None and spec.loader is not None, "helper_load_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.RUN_DEADLINE = time.monotonic() + TOTAL_SECONDS
    return module


def package_entries(value: object) -> list[dict]:
    m = object_keys(value, {"schema_version", "kind", "packages"}, "package_manifest_fields")
    require(type(m["schema_version"]) is int and m["schema_version"] == 1 and m["kind"] == "alma9-prepared-web-packages" and isinstance(m["packages"], list) and len(m["packages"]) == 18, "package_manifest_invalid")
    names, files, nevras, total = set(), set(), set(), 0
    for item in m["packages"]:
        p = object_keys(item, {"name", "nevra", "filename", "sha256", "bytes"}, "package_entry_fields")
        require(p["name"] in PACKAGE_NAMES and p["name"] not in names and isinstance(p["filename"], str) and re.fullmatch(r"[A-Za-z0-9._+~-]{1,180}\.rpm", p["filename"]) is not None and p["filename"] not in files, "package_name_path_invalid")
        require(isinstance(p["nevra"], str) and re.fullmatch(re.escape(p["name"]) + r"-[0-9]+:[A-Za-z0-9._+~]+-[A-Za-z0-9._+~]+\.(?:x86_64|noarch)", p["nevra"]) is not None and p["nevra"] not in nevras, "package_nevra_invalid")
        require(isinstance(p["sha256"], str) and HEX.fullmatch(p["sha256"]) is not None and type(p["bytes"]) is int and 0 < p["bytes"] <= MAX_RPM, "package_digest_bound")
        names.add(p["name"]); files.add(p["filename"]); nevras.add(p["nevra"]); total += p["bytes"]
    require(names == PACKAGE_NAMES and total <= MAX_RPMS, "package_inventory_bound")
    return m["packages"]


def signature_ok(output: bytes, exit_code: int) -> str:
    require(exit_code == 0 and len(output) <= 16384, "rpm_signature_exit")
    text = output.decode("ascii", "strict").upper()
    require(not re.search(r"\b(?:NOKEY|BAD|UNSIGNED|NOTTRUSTED)\b|NOT\s+OK", text), "rpm_signature_rejected")
    for line in text.splitlines():
        if "SIGNATURE" in line and re.search(r":\s*OK\s*$", line):
            m = re.search(r"\bKEY\s+ID\s*:?[ \t]*([0-9A-F]{16}|[0-9A-F]{8})\b", line)
            if m and m[1] in {ALMA_FINGERPRINT[-8:], ALMA_FINGERPRINT[-16:]}:
                return m[1]
    raise Failure("rpm_signature_missing")


def verify_packages(h, entries: list[dict]) -> list[dict]:
    key = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9")
    root_file(key, 0o644, 128 << 10)
    h.ensure_dir(ROOT / "gpg-check")
    c = h.run_cmd(["/usr/bin/gpg", "--homedir", str(ROOT / "gpg-check"), "--batch", "--with-colons", "--show-keys", str(key)], output_limit=32768)
    fingerprints = [line.split(":")[9] for line in c.stdout.decode("ascii").splitlines() if line.startswith("fpr:") and len(line.split(":")) > 9]
    require(fingerprints and fingerprints[0] == ALMA_FINGERPRINT, "alma_key_fingerprint")
    require(set(p.name for p in (ROOT / "packages").iterdir()) == set(x["filename"] for x in entries), "rpm_directory_inventory")
    results = []
    for p in entries:
        path = ROOT / "packages" / p["filename"]
        data = root_file(path, 0o600, MAX_RPM)
        require(len(data) == p["bytes"] and digest(data) == p["sha256"], "rpm_hash_mismatch")
        c = h.run_cmd(["/usr/bin/rpm", "-Kv", str(path)], check=False, output_limit=16384)
        key_id = signature_ok(c.stdout + b"\n" + c.stderr, c.returncode)
        c = h.run_cmd(["/usr/bin/rpm", "-qp", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n", str(path)], output_limit=4096)
        require(c.stdout.decode("ascii").strip() == p["nevra"], "rpm_header_mismatch")
        query = p["name"] + "." + p["nevra"].rsplit(".", 1)[1]
        c = h.run_cmd(["/usr/bin/rpm", "-q", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n", query], output_limit=4096)
        require(c.stdout.decode("ascii").strip() == p["nevra"], "installed_nevra_mismatch")
        results.append({"name": p["name"], "nevra": p["nevra"], "rpm_sha256": p["sha256"], "signature_key_id": key_id, "signature_verified": True, "installed_exact": True})
    queries = [p["name"] + "." + p["nevra"].rsplit(".", 1)[1] for p in entries]
    c = h.run_cmd(["/usr/bin/rpm", "-V", "--noscripts", *queries], check=False, output_limit=32768)
    require(c.returncode == 0 and not c.stdout.strip(), "installed_rpm_verification_failed")
    return results


def system_inputs() -> list[dict]:
    names = ("mod_mpm_event.so", "mod_unixd.so", "mod_ssl.so", "mod_proxy.so", "mod_proxy_http.so", "mod_proxy_fcgi.so", "mod_authz_core.so", "mod_authz_host.so", "mod_dir.so", "mod_mime.so", "mod_log_config.so")
    paths = [Path("/usr/sbin/httpd"), Path("/usr/sbin/php-fpm")] + [Path("/usr/lib64/httpd/modules") / name for name in names]
    result = []
    for path in paths:
        s = path.lstat()
        require(not s.st_mode & 0o022, "system_input_writable")
        mode = stat.S_IMODE(s.st_mode)
        data = root_file(path, mode, 64 << 20)
        result.append({"path": str(path), "mode": mode, "bytes": len(data), "sha256": digest(data)})
    return result


def environment() -> dict:
    data = Path("/etc/os-release").read_bytes()
    require(len(data) <= 8192, "os_release_bound")
    release = dict(line.split("=", 1) for line in data.decode("ascii").splitlines() if "=" in line)
    release = {key: value.strip('"') for key, value in release.items()}
    require(release.get("ID") == "almalinux" and re.fullmatch(r"9\.[0-9]+", release.get("VERSION_ID", "")) is not None and os.uname().machine == "x86_64", "alma9_x86_64_required")
    require(Path("/sys/fs/selinux/enforce").read_text().strip() == "1", "selinux_enforcing_required")
    interfaces = sorted(p.name for p in Path("/sys/class/net").iterdir())
    require(interfaces == ["lo"], "external_nic_present")
    fields = dict((key, value.strip()) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line for key, value in [line.split(":", 1)])
    return {"os_id": "almalinux", "version_id": release["VERSION_ID"], "architecture": "x86_64", "kernel": os.uname().release[:128], "interfaces": interfaces, "selinux_enforce": 1, "parent_no_new_privs": fields["NoNewPrivs"], "parent_cap_eff": fields["CapEff"], "parent_cap_bnd": fields["CapBnd"], "os_release_sha256": digest(data)}


def mounted() -> dict[str, int]:
    data = Path("/proc/self/mountinfo").read_bytes()
    require(len(data) <= 1 << 20, "mountinfo_bound")
    result = {}
    for line in data.decode("ascii").splitlines():
        parts = line.split()
        require(len(parts) >= 10, "mountinfo_invalid")
        target = parts[4]
        if target == str(ROOT) or target.startswith(str(ROOT) + "/"):
            require("\\" not in target and target not in result, "mount_path_invalid")
            result[target] = int(parts[0])
    return result


def directory(h, path: Path, mode: int, uid: int = 0) -> None:
    h.ensure_dir(path, mode)
    os.chown(path, uid, uid)


def receipt(path: Path, expected: bytes, uid: int, mode: int) -> dict:
    s = path.lstat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == uid and s.st_gid == uid and s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == mode and path.read_bytes() == expected, "fixture_file_receipt_invalid")
    return {"path": str(path), "uid": s.st_uid, "gid": s.st_gid, "mode": oct(mode), "sha256": digest(expected), "root_read_verified": True}


def setup_accounts(h, items: list[dict]) -> list[dict]:
    result = []
    for a in items:
        for database, value in (("passwd", str(a["uid"])), ("group", str(a["gid"])), ("passwd", a["username"]), ("group", a["username"])):
            c = h.run_cmd(["/usr/bin/getent", database, value], check=False, output_limit=4096)
            require(c.returncode == 2, "fixture_identity_not_fresh")
        h.run_cmd(["/usr/sbin/groupadd", "--gid", str(a["gid"]), a["username"]])
        h.run_cmd(["/usr/sbin/useradd", "--uid", str(a["uid"]), "--gid", str(a["gid"]), "--groups", "", "--no-create-home", "--no-log-init", "--home-dir", a["home"], "--shell", "/usr/sbin/nologin", "--password", "!", a["username"]])
        c = h.run_cmd(["/usr/bin/getent", "passwd", a["username"]], output_limit=4096)
        fields = c.stdout.decode("ascii").strip().split(":")
        require(len(fields) == 7 and fields[2:4] == [str(a["uid"]), str(a["gid"])] and fields[5:] == [a["home"], "/usr/sbin/nologin"], "fixture_account_invalid")
        c = h.run_cmd(["/usr/bin/passwd", "--status", a["username"]], output_limit=4096)
        require(c.stdout.decode("ascii").split()[1] == "LK" and not Path("/var/spool/mail", a["username"]).exists(), "fixture_password_mail_invalid")
        home = Path(a["home"])
        directory(h, home, 0o750, a["uid"])
        directory(h, Path(a["public_html"]), 0o750, a["uid"])
        directory(h, home / "tmp", 0o700, a["uid"])
        result.append({"id": a["id"], "username": a["username"], "uid": a["uid"], "gid": a["gid"], "password_locked": True, "mail_spool": False, "shell": "/usr/sbin/nologin"})
    return result


def setup_jails(h, p: dict, items: list[dict], owned: list[dict]) -> list[dict]:
    proof = []
    for a in items:
        jail = Path(p["BackendChrootRoot"]) / a["id"]
        directory(h, jail, 0o755)
        directory(h, jail / "etc", 0o755)
        h.write_exact(jail / "etc/passwd", (f"root:x:0:0:root:/root:/usr/sbin/nologin\n{a['username']}:x:{a['uid']}:{a['gid']}::{a['home']}:/usr/sbin/nologin\n").encode(), 0o400)
        h.write_exact(jail / "etc/group", f"root:x:0:\n{a['username']}:x:{a['gid']}:\n".encode(), 0o400)
        h.write_exact(jail / "etc/nsswitch.conf", b"passwd: files\ngroup: files\nshadow: files\n", 0o444)
        h.write_exact(jail / "etc/mime.types", b"text/html html htm\ntext/plain txt\n", 0o444)
        directory(h, Path(p["RuntimeRoot"]) / a["id"], 0o750, a["uid"])
        for source in (Path(a["home"]), Path(p["RuntimeRoot"]) / a["id"]):
            target = jail / str(source).lstrip("/")
            # umask077 outside must not silently deny inside-jail traversal.
            current = jail
            for part in source.parts[1:-1]:
                current /= part
                if not current.exists():
                    directory(h, current, 0o755)
                s = current.lstat()
                require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o755, "jail_ancestor_invalid")
            owned.append({"target": str(target), "mount_id": None, "source": str(source)})
            try:
                h.mount_bind(source, target)
            finally:
                # A failure of --make-private after a successful bind still
                # leaves an owned mount to account for and remove.
                after = mounted()
                if str(target) in after:
                    x, y = source.stat(), target.stat()
                    require((x.st_dev, x.st_ino) == (y.st_dev, y.st_ino), "foreign_bind_refused")
                    owned[-1]["mount_id"] = after[str(target)]
            mounts = mounted()
            require(str(target) in mounts, "bind_not_observed")
            owned[-1]["mount_id"] = mounts[str(target)]
            x, y = source.stat(), target.stat()
            require((x.st_dev, x.st_ino, x.st_uid, x.st_gid) == (y.st_dev, y.st_ino, a["uid"], a["gid"]), "bind_identity_invalid")
            proof.append({"target": str(target), "mount_id": mounts[str(target)], "source_dev": x.st_dev, "source_ino": x.st_ino, "target_mode": oct(stat.S_IMODE(y.st_mode)), "jail_ancestors_mode": "0o755"})
        alias = jail / a["public_html"].lstrip("/")
        x, y = Path(a["public_html"]).stat(), alias.stat()
        require((x.st_dev, x.st_ino) == (y.st_dev, y.st_ino), "public_html_bind_identity_invalid")
    return proof


def cleanup_mounts(h, owned: list[dict]) -> bool:
    failed = False
    for row in reversed(owned):
        try:
            current = mounted()
            target = row["target"]
            if target not in current:
                continue
            require(row["mount_id"] is not None and current[target] == row["mount_id"], "foreign_mount_refused")
            h.unmount(Path(target))
            require(target not in mounted(), "mount_cleanup_not_observed")
        except Exception:
            failed = True
    require(not failed, "owned_mount_cleanup_failed")
    return not mounted()


def capture_child(child, deadline: float) -> tuple[dict, bytes]:
    # This guard starts immediately after Popen. If pidfd/selector setup fails,
    # the single-threaded parent still owns the unreaped child. Popen.kill()
    # checks returncode before signaling, and no competing wait/SIGCHLD handler
    # can reap/recycle that PID. This fallback is not a signal-group operation.
    pidfd, selector = None, None
    out, err = bytearray(), bytearray()
    timed_out, exceeded = False, False
    try:
        pidfd = os.pidfd_open(child.pid, 0)
        selector = selectors.DefaultSelector()
        require(child.stdout is not None and child.stderr is not None, "child_capture_missing")
        for pipe, target in ((child.stdout, out), (child.stderr, err)):
            os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, target)
        while selector.get_map():
            if time.monotonic() >= deadline:
                timed_out = True; break
            for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                data = os.read(key.fileobj.fileno(), 8192)
                if not data:
                    selector.unregister(key.fileobj); key.fileobj.close(); continue
                key.data.extend(data)
                if len(out) + len(err) > 128 << 10:
                    exceeded = True; break
            if exceeded:
                break
        if timed_out or exceeded:
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=6)
            except subprocess.TimeoutExpired:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                child.wait(timeout=3)
        else:
            child.wait(timeout=3)
    finally:
        try:
            if child.returncode is None:
                if pidfd is None:
                    child.kill()
                else:
                    try:
                        signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                child.wait(timeout=3)
        finally:
            if selector is not None:
                selector.close()
            if pidfd is not None:
                os.close(pidfd)
            for pipe in (child.stdout, child.stderr):
                if pipe is not None:
                    pipe.close()
    receipt = {"exit_code": child.returncode, "reaped": child.poll() is not None, "timed_out": timed_out, "output_bound_exceeded": exceeded, "stdout_sha256": digest(bytes(out)), "stderr_sha256": digest(bytes(err))}
    return receipt, bytes(out)


def execute(h, kind: str, nonce: str) -> tuple[dict, bytes]:
    require(kind in ("test", "driver") and signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL and len(threading.enumerate()) == 1, "exclusive_child_wait_required")
    name = "serving-linux.test" if kind == "test" else "qualification-driver"
    args = ["-test.v", "-test.count=1", "-test.timeout=60s"] if kind == "test" else ["--input", str(ROOT / "qualification-input.json")]
    argv = ["/usr/bin/setpriv", "--bounding-set=-net_admin,-net_raw,-net_bind_service,-net_broadcast", "--", str(ROOT / name), *args]
    env = h.clean_env(); env.update({"HOME": str(ROOT / "work"), "TMPDIR": str(ROOT / "test-tmp")})
    probe_fd = os.pidfd_open(os.getpid(), 0); os.close(probe_fd)
    deadline = min(h.RUN_DEADLINE, time.monotonic() + (70 if kind == "test" else 145))
    child = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    receipt, out = capture_child(child, deadline)
    if kind == "test":
        safe_output = len(out) <= 128 << 10 and all(b in (9, 10, 13) or 32 <= b <= 126 for b in out)
        print(f"SIFRUNO_RUNTIME_SERVING_TEST_BEGIN {nonce}", flush=True)
        if safe_output:
            sys.stdout.write(bytes(out).decode("ascii"))
            if out and not out.endswith(b"\n"):
                sys.stdout.write("\n")
        sys.stdout.flush()
        print(f"SIFRUNO_RUNTIME_SERVING_TEST_END {nonce}", flush=True)
        names = set(re.findall(r"^--- PASS: ([A-Za-z0-9_]+) \(", bytes(out).decode("ascii"), re.MULTILINE)) if safe_output else set()
        receipt["passed_names"] = sorted(names)
        receipt["contract_passed"] = safe_output and receipt["exit_code"] == 0 and not receipt["timed_out"] and not receipt["output_bound_exceeded"] and names == TEST_NAMES and "\nPASS\n" in bytes(out).decode("ascii")
    return receipt, bytes(out)


def valid_driver(value: object, a: dict, input_sha: str) -> dict:
    r = object_keys(value, DRIVER_FIELDS, "driver_report_fields")
    require(type(r["schema_version"]) is int and r["schema_version"] == 1 and r["fixture_only"] is True and r["execution_kind"] == "native-linux-driver" and r["run_id"] == driver_run_id(a["nonce"]) and isinstance(r["nonce"], str) and ID.fullmatch(r["nonce"]) is not None and r["driver_sha256"] == DRIVER_SHA and r["runtime_manifest_sha256"] == RUNTIME_SHA and r["input_sha256"] == input_sha, "driver_report_binding")
    for key in ("passed", "shutdown_passed", "close_passed", "listeners_extinct", "input_stable", "selinux_stable"):
        require(r[key] is True, "driver_or_cleanup_failed")
    pre = object_keys(r["prerequisites"], {"selinux_enforce", "NoNewPrivs", "CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh", "network_admin_raw_absent", "kernel_release"}, "driver_prerequisite_fields")
    require(pre["selinux_enforce"] == "1" and pre["network_admin_raw_absent"] == "true" and pre["NoNewPrivs"] in ("0", "1"), "driver_prerequisites_invalid")
    for key in ("CapEff", "CapPrm", "CapBnd", "CapAmb", "CapInh"):
        require(isinstance(pre[key], str) and re.fullmatch(r"[a-fA-F0-9]{16}", pre[key]) is not None and int(pre[key], 16) & ((1 << 12) | (1 << 13)) == 0, "driver_network_cap_present")
    require(r["stage"] == "complete" and all(isinstance(r[k], list) for k in ("intended_generations", "observations", "probes", "workers")) and len(r["intended_generations"]) == 3 and len(r["observations"]) == 9 and len(r["probes"]) == 7 and len(r["workers"]) == 2, "driver_proof_incomplete")
    identities = r["intended_generations"]
    expected_profile, expected_snapshots = expected_digests()
    for i, identity in enumerate(identities):
        object_keys(identity, {"generation_id", "profile_sha256", "snapshot_sha256", "bundle_sha256", "denied"}, "identity_fields")
        require(identity["generation_id"] == "" if i == 0 else isinstance(identity["generation_id"], str) and ID.fullmatch(identity["generation_id"]) is not None, "generation_id_invalid")
        require(identity["profile_sha256"] == expected_profile and identity["snapshot_sha256"] == expected_snapshots[0 if i < 2 else 1] and isinstance(identity["bundle_sha256"], str) and HEX.fullmatch(identity["bundle_sha256"]) is not None and identity["denied"] is (i != 1), "generation_identity_invalid")
    require(identities[1]["generation_id"] != identities[2]["generation_id"] and r["profile_sha256"] == expected_profile, "generation_identity_conflict")
    stages = (("bootstrap", 0), ("active_before_requests", 1), ("active_after_php_webalpha", 1), ("active_after_worker_webalpha", 1), ("active_after_php_webbravo", 1), ("active_after_worker_webbravo", 1), ("active_after_all_workers", 1), ("suspended_denied", 2), ("suspended_after_requests", 2))
    for observation, (stage, identity) in zip(r["observations"], stages):
        require(observation == {"stage": stage, "identity": identities[identity]}, "observed_identity_mismatch")
    expected_probes = [(account["id"], kind, 200) for account in accounts() for kind in ("static", "php")] + [("", "denied_" + host, 403) for host in ("alpha.test", "bravo.test", "foreign.test")]
    for probe, (account_id, kind, status) in zip(r["probes"], expected_probes):
        object_keys(probe, {"account_id", "kind", "status", "bytes", "sha256", "contract_passed"}, "driver_probe_fields")
        require(probe.get("contract_passed") is True and probe.get("status") == status and probe.get("account_id") == account_id and probe.get("kind") == kind and isinstance(probe.get("sha256"), str) and HEX.fullmatch(probe["sha256"]) is not None, "driver_probe_invalid")
    for worker, account in zip(r["workers"], accounts()):
        object_keys(worker, {"account_id", "host_pid", "namespace_pid", "namespace", "uid", "gid", "groups", "capabilities", "root", "start"}, "driver_worker_fields")
        require(worker["account_id"] == account["id"] and type(worker["host_pid"]) is int and worker["host_pid"] > 1 and type(worker["namespace_pid"]) is int and worker["namespace_pid"] > 1 and type(worker["namespace"]) is int and worker["namespace"] > 0 and isinstance(worker["start"], str) and re.fullmatch(r"[1-9][0-9]{0,19}", worker["start"]) is not None and worker["uid"] == [account["uid"]] * 4 and worker["gid"] == [account["gid"]] * 4 and worker["root"] == (ROOT / "backend-jails" / account["id"]).as_posix() and all(int(v, 16) == 0 for v in worker["capabilities"].values()) and set(worker["capabilities"]) == {"CapEff", "CapPrm", "CapInh", "CapAmb"} and set(worker["groups"] or []) <= {account["gid"]}, "driver_worker_invalid")
        expected_static = f"SIFRUNO_STATIC_{account['username']}\n".encode("ascii")
        expected_php = f"SIFRUNO_PHP_{account['username']}\nSELF=readable\nHOST=denied\nSIBLING=denied\nPID={worker['namespace_pid']}\n".encode("ascii")
        for kind, body in (("static", expected_static), ("php", expected_php)):
            probe = next(p for p in r["probes"] if p["account_id"] == account["id"] and p["kind"] == kind)
            require(probe["sha256"] == digest(body) and probe.get("bytes") == len(body), "driver_body_hash_mismatch")
    return r


def driver_header(value: object, a: dict, input_sha: str) -> dict:
    # Bind a bounded failure receipt before success validation, so an actual
    # native startup error is retained rather than replaced by a wrapper error.
    object_keys(value, DRIVER_FIELDS, "driver_report_fields")
    require(type(value.get("schema_version")) is int and value.get("schema_version") == 1 and
            value.get("fixture_only") is True and value.get("execution_kind") == "native-linux-driver" and
            value.get("run_id") == driver_run_id(a["nonce"]) and value.get("driver_sha256") == DRIVER_SHA and
            value.get("runtime_manifest_sha256") == RUNTIME_SHA and value.get("input_sha256") == input_sha and
            isinstance(value.get("stage"), str) and re.fullmatch(r"[a-z_]{1,80}(?::[a-z_]{1,80})?", value["stage"]) is not None,
            "driver_failure_receipt_unbound")
    return value


def expected_digests() -> tuple[str, list[str]]:
    # Go struct field order is part of its JSON digest contract, independent of
    # the sorted JSON input encoding used by this wrapper.
    p = profile()
    order = ("Name", "ManagedRoot", "ManagedHomeRoot", "FrontChroot", "ApacheModuleRoot", "BackendChrootRoot", "RuntimeRoot", "ApacheBinary", "FPMBinary", "TLSRoot", "CAFile", "FrontendIP", "FrontendPort", "BackendPort", "FrontUID", "FrontGID", "ControllerUID")
    go_encode = lambda v: json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    active = accounts()
    suspended = [{**item, "state": "suspended", "revision": 2, "updated_at": "2026-10-05T00:00:00.000000001Z"} for item in active]
    return digest(go_encode({key: p[key] for key in order})), [digest(go_encode(active)), digest(go_encode(suspended))]


def driver_run_id(nonce: str) -> str:
    return digest(("sifruno-serving:" + nonce).encode("ascii"))[:32]


def listener_extinction() -> bool:
    for ip, port in (("127.0.0.1", 18082), ("127.73.78.33", 18443), ("127.73.78.34", 18443)):
        with socket.socket() as sock:
            sock.settimeout(0.5)
            require(sock.connect_ex((ip, port)) == 111, "owned_listener_not_extinct")
    return True


def namespace_extinction(workers: list[dict]) -> bool:
    namespaces = {w["namespace"] for w in workers}
    names = list(Path("/proc").iterdir())
    require(len(names) <= 32768, "proc_inventory_bound")
    for name in names:
        if not name.name.isdigit():
            continue
        try:
            require((name / "ns/pid").stat().st_ino not in namespaces, "observed_worker_namespace_survived")
        except FileNotFoundError:
            pass
    return True


def main() -> int:
    require(len(sys.argv) == 1 and sys.platform == "linux" and os.geteuid() == 0 and os.getegid() == 0 and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "root_linux_pidfd_required")
    os.umask(0o077)
    a = validate_admission(strict_json(root_file(ADMISSION, 0o600, 4096)))
    s = ROOT.lstat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and s.st_gid == 0 and stat.S_IMODE(s.st_mode) == 0o700, "private_fixture_root_required")
    result = {"schema_version": 1, "kind": "alma9-runtime-serving-qualification", "nonce": a["nonce"], "driver_run_id": driver_run_id(a["nonce"]), "fixture_only": True, "passed": False, "failure_code": None, "checks": [], "cleanup": {"driver_reaped": False, "listeners_extinct": False, "observed_worker_namespaces_extinct": False, "mounts_removed": False}, "provenance": {}, "environment": {}, "policy_adaptations": {}, "packages": [], "system_inputs": [], "tls_public_inputs": [], "accounts": [], "sentinels": [], "binds": [], "tests": None, "driver": None}
    h, owned = None, []
    source_pins, package_pins = {}, []
    policy_hashes, driver_value = {}, None
    try:
        for name, field, mode, limit in (("serving_guest.py", "fixture_sha256", 0o600, 128 << 10), ("web_runtime_fixture.py", "helper_sha256", 0o600, 128 << 10), ("source_catalog.json", "source_catalog_sha256", 0o600, 256 << 10), ("prepared-packages.json", "package_report_sha256", 0o600, MAX_JSON), ("qualification-driver", "driver_sha256", 0o700, 32 << 20), ("serving-linux.test", "test_sha256", 0o700, 32 << 20)):
            data = root_file(ROOT / name, mode, limit)
            require(digest(data) == a[field], "payload_digest_mismatch")
            source_pins[name] = (digest(data), mode, limit)
        require(Path(__file__).absolute() == ROOT / "serving_guest.py", "fixed_entry_required")
        require(not mounted(), "fixture_mounts_not_fresh")
        for name in ("guest-report.json", "qualification-input.json", "qualification-report.json", "managed", "homes", "front-jail", "backend-jails", "runtime", "tls", "work", "test-tmp", "gpg-check"):
            require(not (ROOT / name).exists() and not (ROOT / name).is_symlink(), "fixture_layout_not_fresh")
        h = load_helper(a)
        result["provenance"] = {**{key: a[key] for key in a if key.endswith("sha256")}, "prepared_image_hash_admitted_not_guest_measured": True, "runtime_manifest_sha256": RUNTIME_SHA, "borrowed_helper_functions": ["clean_env", "run_cmd", "write_exact", "write_runtime_report", "ensure_dir", "mount_bind", "unmount", "prepare_guest_policies", "make_certificates"]}
        result["checks"].append(CHECKS[0]); result["environment"]["before"] = environment(); result["checks"].append(CHECKS[1])
        for name in ("work", "test-tmp", "managed", "homes", "front-jail", "backend-jails", "runtime"):
            directory(h, ROOT / name, 0o700 if name in ("work", "test-tmp", "managed") else 0o755)
        entries = package_entries(strict_json(root_file(ROOT / "prepared-packages.json", 0o600, MAX_JSON)))
        result["packages"] = verify_packages(h, entries); package_pins = entries; result["system_inputs"] = system_inputs(); result["checks"].append(CHECKS[2])
        result["policy_adaptations"] = h.prepare_guest_policies(SimpleNamespace(qualification_files_only_nss=True, qualification_no_mail_spool_default=True))
        policy_hashes = {str(path): digest(path.read_bytes()) for path in (Path("/etc/nsswitch.conf"), Path("/etc/default/useradd"))}
        result["policy_adaptations"]["effective_sha256"] = policy_hashes; result["checks"].append(CHECKS[3])
        items, p = accounts(), profile(); result["accounts"] = setup_accounts(h, items)
        sentinel = ROOT / "managed/controller-private-sentinel"; h.write_exact(sentinel, b"SIFRUNO_CONTROLLER_PRIVATE\n"); result["sentinels"].append(receipt(sentinel, b"SIFRUNO_CONTROLLER_PRIVATE\n", 0, 0o600))
        for arow in items:
            home = Path(arow["home"]); secret = home / "private.txt"; h.write_exact(secret, b"SIFRUNO_PRIVATE_SENTINEL\n"); os.chown(secret, arow["uid"], arow["gid"]); result["sentinels"].append(receipt(secret, b"SIFRUNO_PRIVATE_SENTINEL\n", arow["uid"], 0o600))
            for name, data in (("index.html", f"SIFRUNO_STATIC_{arow['username']}\n".encode()), ("probe.php", php_code(arow, next(other for other in items if other != arow)))):
                target = Path(arow["public_html"]) / name; h.write_exact(target, data, 0o640); os.chown(target, arow["uid"], arow["gid"])
        result["checks"].append(CHECKS[4]); result["binds"] = setup_jails(h, p, items, owned); h.make_certificates(p, helper_accounts(items), ROOT / "work")
        for path in [ROOT / "tls/ca.pem"] + [ROOT / "tls" / item["id"] / "cert.pem" for item in items]:
            data = root_file(path, 0o600, 16 << 10); result["tls_public_inputs"].append({"path": str(path), "sha256": digest(data)})
        result["checks"].append(CHECKS[5])
        value = {"schema_version": 1, "fixture_only": True, "run_id": driver_run_id(a["nonce"]), "root": str(ROOT), "profile": p, "accounts": items}
        input_bytes = encoded(value); h.write_exact(ROOT / "qualification-input.json", input_bytes); source_pins["qualification-input.json"] = (digest(input_bytes), 0o600, 32768)
        result["tests"], _ = execute(h, "test", a["nonce"]); require(result["tests"]["contract_passed"], "native_test_failed"); result["checks"].append(CHECKS[6])
        result["driver"], _ = execute(h, "driver", a["nonce"]); result["cleanup"]["driver_reaped"] = result["driver"]["reaped"]
        raw = root_file(ROOT / "qualification-report.json", 0o600, MAX_JSON); driver_value = driver_header(strict_json(raw), a, digest(input_bytes))
        print(f"SIFRUNO_RUNTIME_SERVING_DRIVER_BEGIN {a['nonce']}", flush=True); sys.stdout.write(raw.decode("utf-8") + "\n"); print(f"SIFRUNO_RUNTIME_SERVING_DRIVER_END {a['nonce']}", flush=True)
        result["driver"]["report_sha256"] = digest(raw); result["driver"]["passed"] = driver_value["passed"]
        driver_value = valid_driver(driver_value, a, digest(input_bytes))
        require(result["driver"]["exit_code"] == 0 and not result["driver"]["timed_out"] and not result["driver"]["output_bound_exceeded"], "driver_exit_failed")
        result["checks"].append(CHECKS[7]); result["cleanup"]["listeners_extinct"] = listener_extinction(); result["cleanup"]["observed_worker_namespaces_extinct"] = namespace_extinction(driver_value["workers"]); result["checks"].append(CHECKS[8])
    except Exception as error:
        code = str(error) if isinstance(error, (Failure, getattr(h, "FixtureError", Failure))) else "unexpected_fixture_failure"
        result["failure_code"] = code if re.fullmatch(r"[a-z0-9_]{1,80}", code) else "unexpected_fixture_failure"
    finally:
        try:
            if h is not None:
                h.RUN_DEADLINE = time.monotonic() + 45
                result["cleanup"]["mounts_removed"] = cleanup_mounts(h, owned)
                require(result["cleanup"]["mounts_removed"], "mount_cleanup_failed")
                result["checks"].append(CHECKS[9])
                for name, (sha, mode, limit) in source_pins.items():
                    require(digest(root_file(ROOT / name, mode, limit)) == sha, "source_input_changed")
                for entry in package_pins:
                    require(digest(root_file(ROOT / "packages" / entry["filename"], 0o600, MAX_RPM)) == entry["sha256"], "rpm_input_changed")
                for path, sha in policy_hashes.items():
                    require(digest(Path(path).read_bytes()) == sha, "effective_policy_changed")
                for row in result["system_inputs"]:
                    require(digest(root_file(Path(row["path"]), row["mode"], 64 << 20)) == row["sha256"], "system_input_changed")
                for row in result["tls_public_inputs"]:
                    require(digest(root_file(Path(row["path"]), 0o600, 16 << 10)) == row["sha256"], "public_tls_input_changed")
                result["environment"]["after"] = environment(); require(result["environment"]["after"]["os_release_sha256"] == result["environment"]["before"]["os_release_sha256"], "os_input_changed")
                result["checks"].append(CHECKS[10])
            require(result["failure_code"] is None and result["checks"] == list(CHECKS) and all(result["cleanup"].values()), "qualification_incomplete")
            result["passed"] = True
        except Exception as error:
            result["passed"] = False
            if result["failure_code"] is None:
                code = str(error) if isinstance(error, Failure) else "cleanup_or_stability_failed"
                result["failure_code"] = code if re.fullmatch(r"[a-z0-9_]{1,80}", code) else "cleanup_or_stability_failed"
        data = encoded(result); require(len(data) <= MAX_JSON, "guest_report_bound")
        if h is not None:
            h.write_runtime_report(ROOT / "guest-report.json", ROOT, result)
        print(f"SIFRUNO_RUNTIME_SERVING_BEGIN {a['nonce']}", flush=True); sys.stdout.write(data.decode("utf-8")); print(f"SIFRUNO_RUNTIME_SERVING_END {a['nonce']}", flush=True)
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("runtime_serving_fixture_failed", file=sys.stderr)
        raise SystemExit(1)
