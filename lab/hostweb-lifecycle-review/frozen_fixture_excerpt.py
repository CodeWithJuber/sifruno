# Frozen verbatim canonical lifecycle excerpts for characterization only.
# Source SHA256: e8b1f00ec9199014cffe3dcf3df531fb53012742c61b1a10ef88d0363e09bb9b
from __future__ import annotations
import os
from pathlib import Path
import re
import signal
import subprocess
RUN_DEADLINE = None

class FixtureError(RuntimeError):
    def __init__(self, code: str, observations: list[dict] | None = None):
        super().__init__(code)
        self.code = code
        self.observations = observations


def die(code: str) -> None:
    raise FixtureError(code)


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
    values: dict[str, str] = {}
    if len(status.encode("ascii")) > 8192:
        raise ValueError("process status bound")
    for line in status.splitlines():
        key, _, value = line.partition(":")
        if key in ("Uid", "Gid", "Groups", "CapEff"):
            if key in values:
                raise ValueError("duplicate process identity field")
            values[key] = value.strip()
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
    if not re.fullmatch(r"[0-9a-fA-F]{1,16}", values["CapEff"]):
        raise ValueError("invalid effective capabilities")
    return {"uid": ids["Uid"][0], "gid": ids["Gid"][0], "uids": ids["Uid"],
            "gids": ids["Gid"], "groups": groups, "effective_capabilities": int(values["CapEff"], 16),
            "root": root}


def worker_matches(identity: dict, uid: int, gid: int, root: str) -> bool:
    return (identity["uids"] == [uid] * 4 and identity["gids"] == [gid] * 4 and
            set(identity["groups"]).issubset({gid}) and identity["effective_capabilities"] == 0 and
            identity["root"] == root)


def stop_process(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        try:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            die("owned_process_cleanup_failed")
