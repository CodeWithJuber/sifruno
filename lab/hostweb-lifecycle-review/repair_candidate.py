"""Unintegrated Linux lifecycle helper candidate; no native proof from Windows."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import signal
import subprocess
import time


class LifecycleError(RuntimeError):
    pass


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


def worker_matches(identity: dict, uid: int, gid: int, root: str) -> bool:
    return (identity["uids"] == [uid] * 4 and identity["gids"] == [gid] * 4 and
            set(identity["groups"]).issubset({gid}) and identity["root"] == root and
            all(identity[name + "_capabilities"] == 0 for name in
                ("effective", "permitted", "ambient", "inheritable")))


def linux_start_identity(pid: int) -> str | None:
    try:
        with Path(f"/proc/{pid}/stat").open("r", encoding="ascii") as source:
            value = source.read(8193)
    except FileNotFoundError:
        return None
    if len(value) > 8192:
        raise LifecycleError("owned_process_identity_invalid")
    # comm is parenthesized and may contain spaces or ')'; split at its last ')'.
    close = value.rfind(")")
    if not value.startswith(f"{pid} (") or close < 0 or value[close:close+2] != ") ":
        raise LifecycleError("owned_process_identity_invalid")
    fields = value[close + 2:].split()
    if len(fields) < 20 or not fields[19].isdecimal():
        raise LifecycleError("owned_process_identity_invalid")
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
        raise LifecycleError("owned_launch_contract_invalid")
    fixture_pgid = os.getpgrp()
    kwargs["start_new_session"] = True
    process = subprocess.Popen(argv, **kwargs)
    try:
        if process.pid <= 1 or process.pid == fixture_pgid:
            raise LifecycleError("owned_process_group_invalid")
        identity = linux_start_identity(process.pid)
        if identity is None or os.getpgid(process.pid) != process.pid or os.getsid(process.pid) != process.pid:
            raise LifecycleError("owned_process_admission_failed")
        return OwnedProcess(process, process.pid, fixture_pgid, identity)
    except (OSError, LifecycleError):
        # Admission failed: never signal an unproven/foreign process group.
        # Reap the exact Popen leader; disposable guest must be rejected.
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        raise LifecycleError("owned_process_admission_failed")


def stop_process(owned: OwnedProcess | None, *, term_timeout: float = 8,
                 kill_timeout: float = 3, poll_interval: float = .05) -> None:
    if owned is None:
        return
    if not isinstance(owned, OwnedProcess) or owned.pgid <= 1 or owned.pgid != owned.pid or owned.pgid in (owned.fixture_pgid, os.getpgrp()):
        raise LifecycleError("owned_process_group_invalid")
    if not (0 < term_timeout <= 8 and 0 < kill_timeout <= 3 and 0 < poll_interval <= .1):
        raise LifecycleError("owned_cleanup_bound_invalid")

    def check_identity():
        current = linux_start_identity(owned.pid)
        if current is not None and current != owned.start_identity:
            raise LifecycleError("owned_process_identity_changed")
        if owned.poll() is None and (current is None or os.getpgid(owned.pid) != owned.pgid or os.getsid(owned.pid) != owned.pgid):
            raise LifecycleError("owned_process_group_changed")

    def signal_group(sig) -> bool:
        check_identity()
        try:
            os.killpg(owned.pgid, sig)
            return True
        except ProcessLookupError:
            return False
        except OSError as error:
            raise LifecycleError("owned_process_cleanup_failed") from error

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
                raise LifecycleError("owned_process_cleanup_failed")
    try:
        owned.wait(timeout=kill_timeout)
    except subprocess.TimeoutExpired as error:
        raise LifecycleError("owned_process_cleanup_failed") from error
