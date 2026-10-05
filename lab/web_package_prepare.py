"""Fixed-input AlmaLinux web package resolver and installer.

The host stages official AlmaLinux 9.8 metadata and, after this helper's
resolve report is reviewed, the exact RPMs named by that report.  This helper
never mounts media, opens a network socket, selects an arbitrary repository, or
accepts a caller supplied install root.  The root QEMU wrapper mounts CIDATA
read-only at ``/mnt/sifruno-web-payload`` and creates the admission marker.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import selectors
import stat
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlparse

try:
    import resource
except ImportError:  # The helper is admitted only inside the Linux guest.
    resource = None  # type: ignore[assignment]


RELEASE = "9.8"
ARCHITECTURE = "x86_64"
PAYLOAD = Path("/mnt/sifruno-web-payload")
REPORT_ROOT = Path("/opt/sifruno-web-qualification")
ADMISSION = Path("/run/sifruno-web-admission")
ADMISSION_TEXT = b"trusted-disposable-alma9-web\n"
ALMA_KEY_FINGERPRINT = "BF18AC2876178908D6E71267D36CB86CB86B3716"
ALMA_KEY_FILE = Path("/etc/pki/rpm-gpg/RPM-GPG-KEY-AlmaLinux-9")
REPOSITORY_IDS = ("BaseOS", "AppStream")
REPOSITORY_BASE_URLS = {
    "BaseOS": "https://repo.almalinux.org/almalinux/9.8/BaseOS/x86_64/os/",
    "AppStream": "https://repo.almalinux.org/almalinux/9.8/AppStream/x86_64/os/",
}
GOAL = ("httpd", "mod_ssl", "php-fpm", "php-process")
MAX_JSON = 64 * 1024
MAX_PACKAGES = 200
MAX_FILE = 64 * 1024 * 1024
MAX_OUTPUT = 128 * 1024
NO_NETWORK_CAPS = {
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
}


class PreparationError(Exception):
    """An intentionally short, safe report code."""


class DNFInstallFailure(PreparationError):
    """Diagnostics only from the fixed, admitted offline install command."""

    def __init__(self, exit_code: int, stdout: bytes, stderr: bytes, since: float | None = None):
        super().__init__("dnf_install_failed")
        self.diagnostic = dnf_install_diagnostic(exit_code, stdout, stderr)
        self.audit_evidence = audit_transition_evidence(since) if since is not None else None


def transition_avcs(text: str, since: float) -> list[dict[str, Any]]:
    """Keep only fresh process NNP transition denials, never raw audit lines."""
    records = []
    for line in text.splitlines():
        if len(line) > 4096 or not re.search(r"\btype=AVC\b", line):
            continue
        event = re.search(r"\bmsg=audit\(([0-9]{1,12}\.[0-9]{1,6}):([0-9]{1,12})\)", line)
        denial = re.search(r"\bavc:\s+denied\s+\{\s*([a-z_ ]+)\s*\}", line)
        if event is None or denial is None or float(event.group(1)) < since:
            continue
        denied = denial.group(1).split()
        if not denied or not set(denied).issubset({"nnp_transition", "nosuid_transition"}):
            continue
        source = re.search(r"\bscontext=[A-Za-z0-9_]+:[A-Za-z0-9_]+:([a-z][a-z0-9_]{0,63}):", line)
        target = re.search(r"\btcontext=[A-Za-z0-9_]+:[A-Za-z0-9_]+:([a-z][a-z0-9_]{0,63}):", line)
        permissive = re.search(r"\bpermissive=([01])\b", line)
        if source is None or target is None or permissive is None or not re.search(r"\btclass=process\b", line):
            continue
        records.append({"event": ":".join(event.groups()), "denied": sorted(set(denied)),
                        "source_type": source.group(1), "target_type": target.group(1),
                        "class": "process", "permissive": int(permissive.group(1))})
        if len(records) == 8:
            break
    return records


def audit_transition_evidence(since: float) -> dict[str, Any]:
    result: dict[str, Any] = {"scope": "current_offline_dnf_install_transition_denials", "records": []}
    try:
        # Fresh admitted guest only; fixed root-owned audit tail, never all logs.
        descriptor = os.open("/var/log/audit/audit.log", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
                raise OSError("audit file not admitted")
            source.seek(max(0, info.st_size - 65536))
            text = source.read(65536).decode("ascii", "ignore")
        result.update({"available": True, "tail_limit_bytes": 65536, "records": transition_avcs(text, since)})
    except OSError:
        result.update({"available": False, "reason": "audit_log_unavailable"})
    return result


def dnf_install_diagnostic(exit_code: int, stdout: bytes, stderr: bytes) -> dict[str, Any]:
    remaining_bytes, remaining_lines = 8192, 16
    result: dict[str, Any] = {"command": "dnf_offline_install", "exit_code": exit_code, "truncated": False}
    # Prefer stderr; stdout retains DNF's summary when stderr is empty.
    for name, raw in (("stderr", stderr), ("stdout", stdout)):
        text = raw[:MAX_OUTPUT].decode("ascii", "ignore").replace("\r\n", "\n").replace("\r", "\n")
        text = re.sub(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))", "", text)
        text = "".join(char for char in text if char in "\n\t" or 32 <= ord(char) <= 126)
        if "-----BEGIN " in text:
            text = "[suppressed key material]"
        if "Traceback (most recent call last)" in text:
            text = "[suppressed traceback]"
        lines = []
        for line in text.splitlines():
            if re.search(r"\b(?:password|passwd|token|secret|authorization|api[_-]?key|bearer)\b", line, re.IGNORECASE):
                line = "[redacted credential-bearing line]"
            line = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/\s]*@", r"\1[redacted]@", line)
            if remaining_lines == 0 or remaining_bytes == 0:
                result["truncated"] = True
                break
            # Account for newline bytes in the combined output limit.
            cost = len(line) + bool(lines)
            if cost > remaining_bytes:
                line = line[:max(0, remaining_bytes - bool(lines))]
                result["truncated"] = True
                cost = len(line) + bool(lines)
            lines.append(line)
            remaining_bytes -= cost
            remaining_lines -= 1
        result[name] = "\n".join(lines)
        result["truncated"] = result["truncated"] or len(raw) > MAX_OUTPUT
    return result


def fail(code: str) -> None:
    raise PreparationError(code)


def regular(path: Path, label: str, max_bytes: int = MAX_FILE) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError:
        fail(f"{label}_missing")
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > max_bytes:
        fail(f"{label}_not_regular")
    if path.is_symlink():
        fail(f"{label}_symlink")
    return info


def safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        fail(f"{label}_path_invalid")
    if value.startswith("/") or "\\" in value or not re.fullmatch(r"[A-Za-z0-9._~+@/-]+", value):
        fail(f"{label}_path_invalid")
    parts = value.split("/")
    if any(part in ("", ".", "..") for part in parts):
        fail(f"{label}_path_invalid")
    return "/".join(parts)


def confined(base: Path, relative: str, label: str) -> Path:
    safe = safe_relative(relative, label)
    target = base.joinpath(*safe.split("/"))
    try:
        target.resolve(strict=False).relative_to(base.resolve())
    except ValueError:
        fail(f"{label}_escape")
    cursor = base
    try:
        if cursor.resolve() != cursor:
            fail(f"{label}_parent_invalid")
    except OSError:
        fail(f"{label}_parent_invalid")
    for part in Path(safe).parts[:-1]:
        cursor = cursor / part
        try:
            info = cursor.lstat()
            if not stat.S_ISDIR(info.st_mode) or cursor.is_symlink() or cursor.resolve() != cursor:
                fail(f"{label}_parent_invalid")
        except OSError:
            fail(f"{label}_parent_missing")
    return target


def read_json(path: Path, label: str) -> dict[str, Any]:
    regular(path, label, MAX_JSON)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        fail(f"{label}_json_invalid")
    if not isinstance(value, dict):
        fail(f"{label}_shape_invalid")
    return value


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def require_root_and_admission() -> None:
    if os.geteuid() != 0:
        fail("root_required")
    try:
        info = ADMISSION.lstat()
        content = ADMISSION.read_bytes()
    except OSError:
        fail("admission_missing")
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or content != ADMISSION_TEXT:
        fail("admission_invalid")


def require_readonly_cidata() -> None:
    if not PAYLOAD.is_dir() or PAYLOAD.is_symlink() or PAYLOAD.resolve() != PAYLOAD:
        fail("payload_mount_invalid")
    try:
        mounts = Path("/proc/mounts").read_text(encoding="ascii", errors="strict").splitlines()
    except OSError:
        fail("mount_table_unavailable")
    found = False
    for line in mounts:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == str(PAYLOAD):
            found = True
            if fields[2] != "iso9660" or "ro" not in fields[3].split(","):
                fail("payload_not_readonly_iso")
    if not found:
        fail("payload_mount_missing")


def privilege_profile(phase: str) -> dict[str, Any]:
    if phase not in ("resolve", "install"):
        fail("privilege_phase_invalid")
    try:
        status = Path("/proc/self/status").read_text(encoding="ascii", errors="strict")
        nnp = int(next(line.split(":", 1)[1].strip() for line in status.splitlines() if line.startswith("NoNewPrivs:")))
        cap_eff = int(next(line.split(":", 1)[1].strip() for line in status.splitlines() if line.startswith("CapEff:")), 16)
        enforce = Path("/sys/fs/selinux/enforce").read_text(encoding="ascii", errors="strict").strip()
        if nnp not in (0, 1) or enforce not in ("0", "1"):
            fail("privilege_state_unavailable")
    except (OSError, UnicodeError, StopIteration, ValueError):
        fail("privilege_state_unavailable")
    network_bits = {10: "CAP_NET_BIND_SERVICE", 11: "CAP_NET_BROADCAST", 12: "CAP_NET_ADMIN", 13: "CAP_NET_RAW"}
    return {"profile": "resolve_nnp1" if phase == "resolve" else "install_stock_nnp0_signed_pinned_rpms",
            "no_new_privs": nnp, "selinux_enforce": int(enforce),
            "network_capabilities_present": [name for bit, name in network_bits.items() if name in NO_NETWORK_CAPS and cap_eff & (1 << bit)]}


def require_privilege_profile(phase: str) -> dict[str, Any]:
    observed = privilege_profile(phase)
    if observed["selinux_enforce"] != 1:
        fail("selinux_not_enforcing")
    if observed["no_new_privs"] != (1 if phase == "resolve" else 0):
        fail("installer_parent_no_new_privs" if phase == "install" else "no_new_privs_unavailable")
    if observed["network_capabilities_present"]:
        fail("network_capability_present")
    return observed


def apply_process_limits(phase: str) -> None:
    if phase not in ("resolve", "install"):
        fail("privilege_phase_invalid")
    # NNP cannot be unset. The admitted install comparison keeps the stock
    # root installer domain for verified RPM scriptlets, failing inherited NNP.
    if phase == "install":
        require_privilege_profile(phase)
    if resource is None:
        fail("linux_resource_limits_unavailable")
    os.umask(0o077)
    for kind, limit in ((resource.RLIMIT_FSIZE, 512 * 1024 * 1024), (resource.RLIMIT_NOFILE, 256), (resource.RLIMIT_NPROC, 128)):
        try:
            resource.setrlimit(kind, (limit, limit))
        except (OSError, ValueError):
            fail("process_limits_unavailable")
    if phase == "resolve":
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
                fail("no_new_privs_unavailable")
        except (OSError, AttributeError):
            fail("no_new_privs_unavailable")
    require_privilege_profile(phase)


def clean_env() -> dict[str, str]:
    return {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "HOME": "/root"}


def command(argv: list[str], label: str, timeout: int = 120) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(argv, cwd="/", env=clean_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, close_fds=True)
    except OSError:
        fail(f"{label}_execution_failed")
    selector = selectors.DefaultSelector()
    assert process.stdout is not None and process.stderr is not None
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            if time.monotonic() > deadline:
                process.kill()
                process.wait()
                fail(f"{label}_timeout")
            for key, _ in selector.select(0.25):
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                buffer = buffers[key.data]
                if len(buffer) + len(chunk) > MAX_OUTPUT:
                    process.kill()
                    process.wait()
                    fail(f"{label}_output_limit")
                buffer.extend(chunk)
        returncode = process.wait(timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        process.kill()
        process.wait()
        fail(f"{label}_execution_failed")
    finally:
        selector.close()
    return returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"])


def repository_manifest() -> dict[str, Any]:
    manifest = read_json(PAYLOAD / "payload/repository-manifest.json", "repository_manifest")
    if manifest.get("schema_version") != 1 or manifest.get("kind") not in ("alma-web-repository-stage", "alma-web-offline-payload") or manifest.get("release") != RELEASE or manifest.get("architecture") != ARCHITECTURE:
        fail("repository_manifest_untrusted")
    repos = manifest.get("repositories")
    if not isinstance(repos, list) or len(repos) != 2:
        fail("repository_manifest_repositories_invalid")
    for repo in repos:
        if not isinstance(repo, dict) or repo.get("id") not in REPOSITORY_IDS:
            fail("repository_manifest_entry_invalid")
        repo_id = repo["id"]
        if repo.get("base_url") != REPOSITORY_BASE_URLS[repo_id]:
            fail("repository_manifest_base_url_invalid")
        files = repo.get("files")
        if not isinstance(files, list) or not files:
            fail("repository_manifest_files_invalid")
        seen: set[str] = set()
        for entry in files:
            if not isinstance(entry, dict):
                fail("repository_manifest_file_invalid")
            relative = safe_relative(entry.get("relative_path"), "metadata")
            if relative in seen or not relative.startswith("repodata/"):
                fail("repository_manifest_file_invalid")
            seen.add(relative)
            checksum = entry.get("checksum_sha256")
            size = entry.get("length")
            if not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum) or not isinstance(size, int) or size <= 0 or size > MAX_FILE:
                fail("repository_manifest_file_invalid")
            url = entry.get("url")
            parsed = urlparse(url) if isinstance(url, str) else None
            if parsed is None or parsed.scheme != "https" or parsed.hostname != "repo.almalinux.org" or parsed.query or parsed.fragment or not parsed.path.startswith(urlparse(REPOSITORY_BASE_URLS[repo_id]).path):
                fail("repository_manifest_url_invalid")
            file = confined(PAYLOAD / "repositories" / repo["id"], relative, "metadata")
            info = regular(file, "metadata")
            if info.st_size != size or digest(file) != checksum:
                fail("metadata_checksum_mismatch")
        required = {"primary", "filelists", "other"}
        if repo["id"] == "AppStream":
            required.add("modules")
        types = {entry.get("type") for entry in files}
        if not required.issubset(types):
            fail("repository_metadata_incomplete")
    return manifest


def rpm_baseline() -> list[str]:
    code, stdout, _ = command(["rpm", "-qa", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n"], "rpm_baseline")
    if code != 0:
        fail("rpm_baseline_failed")
    values = []
    for line in stdout.decode("ascii", "ignore").splitlines():
        if re.fullmatch(r"[A-Za-z0-9._+~-]+-(?:[0-9]+|\(none\)):[A-Za-z0-9._+~:-]+\.[A-Za-z0-9_]+", line):
            values.append(line)
    values.sort()
    encoded = json.dumps(values, separators=(",", ":")).encode()
    if len(encoded) > MAX_JSON:
        fail("rpm_baseline_too_large")
    return values


def package_checksum(pkg: Any) -> str:
    value = getattr(pkg, "chksum", None)
    if not isinstance(value, (tuple, list)) or len(value) != 2:
        fail("dnf_package_checksum_missing")
    try:
        import hawkey  # type: ignore
        sha256_type = hawkey.CHKSUM_SHA256
    except Exception:
        fail("dnf_checksum_api_missing")
    if value[0] == sha256_type:
        checksum = value[1]
    elif value[1] == sha256_type:
        checksum = value[0]
    else:
        fail("dnf_package_checksum_type_invalid")
    if isinstance(checksum, bytes) and len(checksum) == 32:
        return checksum.hex()
    if isinstance(checksum, str) and re.fullmatch(r"[a-fA-F0-9]{64}", checksum):
        return checksum.lower()
    fail("dnf_package_checksum_invalid")


def package_location(pkg: Any, repo_id: str) -> str:
    value = getattr(pkg, "location", None)
    if not isinstance(value, str) and hasattr(pkg, "remote_location"):
        value = pkg.remote_location(("file",))
    if not isinstance(value, str) or not value:
        fail("dnf_package_location_missing")
    parsed = urlparse(value)
    if parsed.scheme:
        if parsed.scheme != "file" or parsed.query or parsed.fragment:
            fail("dnf_package_location_external")
        value = parsed.path
    if value.startswith("/"):
        root = (PAYLOAD / "repositories" / repo_id).resolve()
        candidate = Path(value).resolve()
        try:
            value = candidate.relative_to(root).as_posix()
        except ValueError:
            fail("dnf_package_location_escape")
    relative = safe_relative(value, "package")
    if not relative.startswith("Packages/") or not relative.endswith(".rpm"):
        fail("dnf_package_location_invalid")
    return relative


def package_nevra(pkg: Any) -> str:
    name = getattr(pkg, "name", None)
    epoch = getattr(pkg, "epoch", None)
    version = getattr(pkg, "version", None)
    release = getattr(pkg, "release", None)
    arch = getattr(pkg, "arch", None)
    if not all(isinstance(value, (str, int)) and str(value) for value in (name, epoch, version, release, arch)):
        fail("dnf_package_nevra_missing")
    return f"{name}-{epoch}:{version}-{release}.{arch}"


def select_php_stream(base: Any) -> dict[str, str]:
    try:
        from dnf.module.module_base import ModuleBase  # type: ignore
        module_base = ModuleBase(base)
    except Exception:
        fail("dnf_module_api_missing")
    streams: set[str] = set()
    try:
        modules, _ = module_base.get_modules("php")
        for module in modules:
            name = module.getName()
            stream = module.getStream()
            if name == "php" and isinstance(stream, str):
                streams.add(stream)
    except Exception:
        fail("dnf_module_enumeration_failed")
    if "8.3" in streams:
        try:
            module_base.enable(["php:8.3"])
            return {"requested": "8.3", "selected": "8.3", "reason": "distribution_module_available_and_enabled"}
        except Exception:
            # Enabling may already have changed the sack. Never solve against
            # that partial state while claiming a clean default fallback.
            fail("dnf_php_stream_enable_failed")
    return {"requested": "8.3", "selected": "distribution-default", "reason": "8.3_unavailable_dnf_default_used"}


def resolved_php_packages(packages: list[Any], selected_stream: str) -> list[dict[str, str]]:
    """Record actual transaction versions independently of stream intent."""
    wanted = {"php-common", "php-fpm", "php-process"}
    observed: dict[str, dict[str, str]] = {}
    for pkg in packages:
        name = getattr(pkg, "name", None)
        if name not in wanted:
            continue
        version = getattr(pkg, "version", None)
        if name in observed or not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
            fail("dnf_php_package_version_invalid")
        observed[name] = {"name": name, "version": version, "nevra": package_nevra(pkg)}
    if set(observed) != wanted or len({item["version"] for item in observed.values()}) != 1:
        fail("dnf_php_package_set_invalid")
    if selected_stream == "8.3" and any(not item["version"].startswith("8.3.") for item in observed.values()):
        fail("dnf_php_stream_version_mismatch")
    if selected_stream not in ("8.3", "distribution-default"):
        fail("dnf_php_stream_invalid")
    return [observed[name] for name in sorted(observed)]


def resolve(report: Path) -> dict[str, Any]:
    manifest = repository_manifest()
    baseline = rpm_baseline()
    try:
        import dnf  # type: ignore
    except Exception:
        fail("dnf_python_unavailable")
    base = dnf.Base()
    try:
        base.conf.installroot = "/"
        base.conf.reposdir = []
        base.conf.cachedir = "/var/cache/sifruno-web-dnf"
        base.conf.persistdir = "/var/lib/sifruno-web-dnf"
        base.conf.gpgcheck = False
        for repo_id in REPOSITORY_IDS:
            repo = base.repos.add_new_repo(repo_id, base.conf)
            repo.baseurl = [f"file://{(PAYLOAD / 'repositories' / repo_id).resolve()}"]
            repo.enabled = True
            repo.skip_if_unavailable = False
            repo.metadata_expire = -1
        base.fill_sack(load_system_repo=True, load_available_repos=True)
        stream = select_php_stream(base)
        # ModuleBase.enable already updates modular filtering on this sack.
        # Refilling replaces it and discards the unpersisted stream selection.
        for spec in GOAL:
            base.install(spec)
        if not base.resolve():
            fail("dnf_solve_failed")
        transaction_packages = list(base.transaction.install_set)
        php_packages = resolved_php_packages(transaction_packages, stream["selected"])
        packages = []
        for pkg in transaction_packages:
            repo_obj = getattr(pkg, "repo", None)
            repo_id = getattr(pkg, "reponame", None) or getattr(repo_obj, "id", None)
            if repo_id not in REPOSITORY_IDS:
                fail("dnf_package_repo_untrusted")
            nevra = package_nevra(pkg)
            packages.append({
                "repository": repo_id,
                "nevra": nevra,
                "relative_path": package_location(pkg, repo_id),
                "checksum_sha256": package_checksum(pkg),
                "size": int(getattr(pkg, "downloadsize", 0)),
            })
    except PreparationError:
        raise
    except Exception:
        fail("dnf_resolve_failed")
    if not packages or len(packages) > MAX_PACKAGES or any(item["size"] <= 0 or item["size"] > MAX_FILE for item in packages):
        fail("dnf_package_set_invalid")
    packages.sort(key=lambda item: (item["repository"], item["nevra"], item["relative_path"]))
    result = {
        "schema_version": 1,
        "kind": "alma-web-package-resolve",
        "phase": "resolve",
        "passed": True,
        "release": RELEASE,
        "architecture": ARCHITECTURE,
        "repository_manifest_sha256": digest(PAYLOAD / "payload/repository-manifest.json"),
        "goal": list(GOAL),
        "php_stream": stream,
        "resolved_php_packages": php_packages,
        "privilege_profile": require_privilege_profile("resolve"),
        "installed_baseline": baseline,
        "packages": packages,
        "network": {"guest_external_nic": False, "external_network": False, "repositories": "file_only"},
        "global_install": False,
        "cpanel_compatibility_certified": False,
    }
    write_report(report, result)
    return {"phase": "resolve", "packages": len(packages), "report": str(report)}


def key_fingerprint() -> None:
    regular(ALMA_KEY_FILE, "alma_key", 128 * 1024)
    code, stdout, _ = command(["gpg", "--batch", "--with-colons", "--show-keys", str(ALMA_KEY_FILE)], "alma_key")
    if code != 0 or ALMA_KEY_FINGERPRINT not in stdout.decode("ascii", "ignore").upper():
        fail("alma_key_fingerprint_mismatch")


def package_manifest() -> dict[str, Any]:
    value = read_json(PAYLOAD / "payload/package-manifest.json", "package_manifest")
    if value.get("schema_version") != 1 or value.get("kind") != "alma-web-rpm-stage" or value.get("phase") != "download":
        fail("package_manifest_untrusted")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > MAX_PACKAGES:
        fail("package_manifest_packages_invalid")
    for item in packages:
        if not isinstance(item, dict) or item.get("repository") not in REPOSITORY_IDS or not isinstance(item.get("nevra"), str) or not re.fullmatch(r"[A-Za-z0-9._+~-]+", item["nevra"].replace(":", "_")):
            fail("package_manifest_entry_invalid")
        relative = safe_relative(item.get("relative_path"), "package")
        if not relative.startswith("Packages/") or not relative.endswith(".rpm"):
            fail("package_manifest_location_invalid")
        file = confined(PAYLOAD, item.get("file"), "package")
        if not str(file.relative_to(PAYLOAD)).startswith("packages/"):
            fail("package_manifest_file_invalid")
        checksum = item.get("checksum_sha256")
        size = item.get("size")
        if not isinstance(checksum, str) or not re.fullmatch(r"[a-f0-9]{64}", checksum) or not isinstance(size, int) or size <= 0 or size > MAX_FILE:
            fail("package_manifest_digest_invalid")
        info = regular(file, "rpm")
        if info.st_size != size or digest(file) != checksum:
            fail("rpm_checksum_mismatch")
    return value


def resolve_report() -> dict[str, Any]:
    value = read_json(PAYLOAD / "payload/resolve-report.json", "resolve_report")
    if value.get("schema_version") != 1 or value.get("kind") != "alma-web-package-resolve" or value.get("phase") != "resolve" or value.get("passed") is not True or value.get("release") != RELEASE or value.get("architecture") != ARCHITECTURE:
        fail("resolve_report_untrusted")
    expected_manifest = digest(PAYLOAD / "payload/repository-manifest.json")
    if value.get("repository_manifest_sha256") != expected_manifest:
        fail("resolve_report_manifest_mismatch")
    packages = value.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > MAX_PACKAGES:
        fail("resolve_report_packages_invalid")
    return value


def signature_key_ids(output: str) -> list[str]:
    key_ids = []
    for line in output.splitlines():
        if "SIGNATURE" not in line.upper():
            continue
        match = re.search(r"\bKEY\s+ID\s*:?[ \t]*([0-9A-F]{16}|[0-9A-F]{8})\b", line, re.IGNORECASE)
        if match:
            key_ids.append(match.group(1).upper())
    return key_ids


def signature_verified(output: str, returncode: int) -> str | None:
    if returncode != 0:
        return None
    expected = {ALMA_KEY_FINGERPRINT[-8:].upper(), ALMA_KEY_FINGERPRINT[-16:].upper()}
    for line in output.splitlines():
        if "SIGNATURE" in line.upper() and re.search(r":\s*OK(?:\s|$)", line, re.IGNORECASE):
            for key_id in signature_key_ids(line):
                if key_id in expected:
                    return key_id
    return None


def check_signature(path: Path) -> dict[str, str]:
    code, stdout, stderr = command(["rpm", "-Kv", str(path)], "rpm_signature")
    combined = (stdout + b"\n" + stderr).decode("ascii", "ignore").upper()
    key_id = signature_verified(combined, code)
    if key_id is None:
        fail("rpm_signature_invalid")
    return {"verification": "ok", "key_id": key_id}


def installed_versions(names: list[str]) -> list[dict[str, str]]:
    code, stdout, _ = command(["rpm", "-q", "--qf", "%{NAME}\\t%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\\n", *names], "rpm_installed_query")
    if code != 0:
        fail("rpm_installed_query_failed")
    result = []
    for line in stdout.decode("ascii", "ignore").splitlines():
        name, sep, nevra = line.partition("\t")
        nevra = nevra.replace("-(none):", "-0:", 1)
        if sep and re.fullmatch(r"[A-Za-z0-9._+~-]+", name) and re.fullmatch(r"[A-Za-z0-9._+~-]+-(?:[0-9]+):[A-Za-z0-9._+~:-]+\.[A-Za-z0-9_]+", nevra):
            result.append({"name": name, "nevra": nevra})
    if not result:
        fail("rpm_installed_empty")
    return result


def observations() -> dict[str, Any]:
    paths = {name: shutil.which(name, path=clean_env()["PATH"]) for name in ("httpd", "apachectl", "php", "php-fpm")}
    versions: dict[str, str] = {}
    for name in ("httpd", "php", "php-fpm"):
        if not paths.get(name):
            continue
        code, stdout, _ = command([str(paths[name]), "-v"], f"{name}_version", 30)
        if code == 0:
            first = stdout.decode("ascii", "ignore").splitlines()
            if first:
                match = re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)?)\b", first[0])
                if match:
                    versions[name] = match.group(1)
    modules: list[str] = []
    if paths.get("php"):
        code, stdout, _ = command([str(paths["php"]), "-m"], "php_modules", 30)
        if code == 0:
            modules = sorted(line.strip() for line in stdout.decode("ascii", "ignore").splitlines() if re.fullmatch(r"[A-Za-z0-9_+-]+", line.strip()))[:128]
    return {"daemon_paths": paths, "versions": versions, "php_modules": modules}


def install(report: Path) -> dict[str, Any]:
    resolve_value = resolve_report()
    rpm_value = package_manifest()
    key_fingerprint()
    by_key = {(item["repository"], item["nevra"], item["relative_path"], item["checksum_sha256"]): item for item in rpm_value["packages"]}
    selected = []
    signatures = []
    for item in resolve_value["packages"]:
        if not isinstance(item, dict) or item.get("repository") not in REPOSITORY_IDS or not isinstance(item.get("nevra"), str):
            fail("resolve_package_invalid")
        key = (item.get("repository"), item.get("nevra"), item.get("relative_path"), item.get("checksum_sha256"))
        admitted = by_key.get(key)
        if admitted is None or admitted.get("size") != item.get("size"):
            fail("rpm_not_admitted")
        file = confined(PAYLOAD, admitted.get("file"), "package")
        signatures.append({"nevra": item["nevra"], **check_signature(file)})
        selected.append(str(file))
    before_privilege = require_privilege_profile("install")
    install_started = time.time()
    code, stdout, stderr = command(["dnf", "--assumeyes", "--disablerepo=*", "--setopt=localpkg_gpgcheck=1", "install", *selected], "dnf_install", 300)
    if code != 0:
        raise DNFInstallFailure(code, stdout, stderr, install_started)
    after_privilege = require_privilege_profile("install")
    names = []
    for item in resolve_value["packages"]:
        match = re.fullmatch(r"([A-Za-z0-9._+~-]+)-[0-9]+:[A-Za-z0-9._+~:-]+\.([A-Za-z0-9_]+)", item["nevra"])
        if match is None:
            fail("resolve_package_nevra_invalid")
        query = match.group(1) + "." + match.group(2)
        if query not in names:
            names.append(query)
    installed = installed_versions(names)
    expected_nevra = sorted(item["nevra"] for item in resolve_value["packages"])
    observed_nevra = sorted(item["nevra"] for item in installed)
    if expected_nevra != observed_nevra:
        fail("installed_nevra_mismatch")
    result = {
        "schema_version": 1,
        "kind": "alma-web-package-install",
        "phase": "install",
        "passed": True,
        "release": RELEASE,
        "architecture": ARCHITECTURE,
        "resolved_packages": len(selected),
        "installed": installed,
        "signatures": signatures,
        "observed": observations(),
        "network": {"guest_external_nic": False, "external_network": False, "repositories": "disabled_local_rpms_only"},
        "global_install": False,
        "cpanel_compatibility_certified": False,
        "private_customer_data_read": False,
        "privilege_profile": {"before": before_privilege, "after": after_privilege},
    }
    write_report(report, result)
    return {"phase": "install", "packages": len(selected), "report": str(report)}


def write_report(path: Path, value: dict[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    if len(encoded) > MAX_JSON:
        fail("report_too_large")
    if path.parent != REPORT_ROOT or path.name not in ("resolve-report.json", "install-report.json"):
        fail("report_path_invalid")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        fail("report_create_failed")
    with os.fdopen(fd, "wb") as target:
        target.write(encoded)


def write_failure_report(path: Path, phase: str, code: str, dnf_failure: DNFInstallFailure | None = None) -> None:
    safe_code = code if re.fullmatch(r"[a-z0-9_]{1,80}", code) else "preparation_failed"
    try:
        value = {
            "schema_version": 1,
            "kind": f"alma-web-package-{phase}",
            "phase": phase,
            "passed": False,
            "failure_code": safe_code,
            "release": RELEASE,
            "architecture": ARCHITECTURE,
            "global_install": False,
            "cpanel_compatibility_certified": False,
            "private_customer_data_read": False,
        }
        if phase == "install" and safe_code == "dnf_install_failed" and isinstance(dnf_failure, DNFInstallFailure):
            value["diagnostic"] = dnf_failure.diagnostic
            if dnf_failure.audit_evidence is not None:
                value["audit_evidence"] = dnf_failure.audit_evidence
        try:
            value["privilege_profile"] = privilege_profile(phase)
        except PreparationError:
            value["privilege_profile"] = {"observed": False, "reason": "privilege_state_unavailable"}
        write_report(path, value)
    except Exception:
        pass


def args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--phase", required=True, choices=("resolve", "install"))
    parser.add_argument("--report", required=True)
    value = parser.parse_args()
    report = Path(value.report)
    if report.parent != REPORT_ROOT or report.name != f"{value.phase}-report.json":
        fail("report_path_invalid")
    value.report_path = report
    return value


def main() -> dict[str, Any]:
    options = args()
    require_root_and_admission()
    try:
        require_readonly_cidata()
        apply_process_limits(options.phase)
        if options.phase == "resolve":
            return resolve(options.report_path)
        return install(options.report_path)
    except PreparationError as error:
        write_failure_report(options.report_path, options.phase, str(error), error if isinstance(error, DNFInstallFailure) else None)
        raise
    except Exception:
        write_failure_report(options.report_path, options.phase, "unexpected_failure")
        raise PreparationError("unexpected_failure")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Alma web package preparation failed: fixed_precondition_failed", file=sys.stderr)
        raise SystemExit(1)
