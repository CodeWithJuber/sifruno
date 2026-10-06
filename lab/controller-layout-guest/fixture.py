"""Fresh layout setup in an explicitly admitted, disposable offline Alma guest."""
import base64
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys

# Reuse the reviewed bounded process, policy snapshot and NSS fixture helpers.
import startup_helpers as helpers

ROLES = ["broker_state", "managed_homes", "socket_parent", "controller_state"]
ROOT_TESTS = ["TestControllerLayoutNativeFreshPreparation", "TestControllerLayoutNativeExistingNoAdoption", "TestControllerLayoutNativeRefusalNoAdditions", "TestControllerLayoutNativePartialCancellationPreserves", "TestControllerLayoutNativePinnedOwnership", "TestControllerLayoutNativeRestrictiveUmask"]


def require(value, code):
    if not value:
        raise AssertionError(code)


def validate_report(result, ready, read_only):
    require(result["exit_code"] == (0 if ready else 1) and result["stderr"] == b"", "cli_exit")
    value = helpers.strict_json(result["stdout"].decode("ascii"))
    require(set(value) == {"schema_version", "scope", "platform", "ready", "read_only", "checks", "directories", "restrictions"}, "report_fields")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1 and value["scope"] == "native_linux_controller_layout" and value["platform"] == "linux" and value["ready"] is ready and value["read_only"] is read_only, "report_identity")
    require(len(value["directories"]) == 4 and [entry["role"] for entry in value["directories"]] == ROLES, "directory_roles")
    for entry in value["directories"]:
        require(set(entry) == {"role", "action"} and entry["action"] in {"not_checked", "planned_create", "admitted_existing", "created", "refused"}, "directory_fields")
    require(type(value["checks"]) is list and 1 <= len(value["checks"]) <= 20 and len({c["id"] for c in value["checks"]}) == len(value["checks"]), "checks_bound")
    for check in value["checks"]:
        require(set(check) == {"id", "status", "reason"} and check["status"] in {"pass", "refused", "not_checked", "unknown"} and all(re.fullmatch(r"[a-z0-9_]{1,120}", check[k]) for k in ("id", "reason")), "checks_redacted")
    require(type(value["restrictions"]) is list and 1 <= len(value["restrictions"]) <= 20 and all(re.fullmatch(r"[a-z0-9_]{1,120}", r) for r in value["restrictions"]), "restrictions_redacted")
    return value


def observation(binary, parent, mode, ready, extra=None):
    before = helpers.owned_snapshot(parent)
    args = [str(binary), mode, "--state", str(parent / "state"), "--socket", str(parent / "run/broker.sock"), "--homes", str(parent / "homes"), "--controller-uid", "65534", "--controller-state", str(parent / "controller")]
    if extra:
        args.extend(extra)
    result = helpers.run_child(args, timeout=10, limit=16384)
    if extra:
        require(result["exit_code"] == 2 and result["stdout"] == b"" and b"secret-value" not in result["stderr"], "invalid_grammar")
        report = None
    else:
        report = validate_report(result, ready, mode == "--plan")
    after = helpers.owned_snapshot(parent)
    if mode == "--plan" or not ready or extra:
        require(before == after, "unexpected_layout_mutation")
    return {"mode": mode, "exit_code": result["exit_code"], "report": report, "before_sha256": before, "after_sha256": after, "owned_child_exited": result["owned_child_exited"]}


def run(nonce, expected):
    require(re.fullmatch(r"[0-9a-f]{32}", nonce) and sys.platform == "linux" and os.geteuid() == 0, "guest_admission")
    admission = Path("/run/sifruno-layout-admission")
    info = admission.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600 and admission.read_text() == nonce + "\n", "guest_admission")
    release = Path("/etc/os-release").read_text()
    require('ID="almalinux"' in release and 'VERSION_ID="9.8"' in release and platform.machine() == "x86_64", "guest_profile")
    own = Path(__file__).parent
    for leaf, digest in expected.items():
        require(helpers.sha(helpers.bounded_bytes(own / leaf, 64 * 1024 * 1024)) == digest, "guest_input_binding")
    require(helpers.unique_uid(Path("/etc/passwd"), 65534)["account_created"] is False, "controller_identity")
    os.umask(0o077)  # Real apply must establish modes on its own new leaves.
    parent = Path("/run") / ("l-" + nonce[:6])
    parent.mkdir(mode=0o755)
    parent.chmod(0o755)  # Fixture-owned exclusive parent, outside product setup.
    require(stat.S_IMODE(parent.stat().st_mode) == 0o755, "fixture_parent_mode")
    stock_before = helpers.policy_snapshot()
    stock = observation(own / "hostsetup", parent, "--apply", False)
    require(all(not (parent / leaf).exists() for leaf in ("state", "homes", "run", "controller")), "stock_added_paths")
    require(helpers.policy_snapshot() == stock_before, "stock_policy_mutation")
    helpers.adapt_nss(nonce)
    adapted = helpers.policy_snapshot()
    require(adapted[1:] == stock_before[1:] and adapted[0]["sha256"] == helpers.sha(helpers.NSS_BYTES), "nss_only_adaptation")
    plan = observation(own / "hostsetup", parent, "--plan", True)
    require(all(d["action"] == "planned_create" for d in plan["report"]["directories"]), "plan_actions")
    apply = observation(own / "hostsetup", parent, "--apply", True)
    require(all(d["action"] == "created" for d in apply["report"]["directories"]), "apply_actions")
    layout = []
    for role, leaf, uid, mode in zip(ROLES, ["state", "homes", "run", "controller"], [0, 0, 0, 65534], [0o700, 0o755, 0o755, 0o700]):
        target = parent / leaf
        info = target.lstat()
        require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == mode and info.st_uid == uid and list(target.iterdir()) == [], "prepared_metadata")
        layout.append({"role": role, "uid": uid, "mode": format(mode, "04o"), "empty": True})
    require(not (parent / "run/broker.sock").exists(), "setup_created_socket")
    repeat = observation(own / "hostsetup", parent, "--apply", True)
    require(repeat["before_sha256"] == repeat["after_sha256"] and all(d["action"] == "admitted_existing" for d in repeat["report"]["directories"]), "repeat_mutation")
    cases = []
    for case in ("controller_populated", "socket_parent_populated", "controller_wrong_mode", "controller_symlink", "socket_nontraversable_parent", "unknown_argument"):
        case_parent = parent / case
        case_parent.mkdir(mode=0o755)
        case_parent.chmod(0o755)
        if case == "controller_populated":
            (case_parent / "controller").mkdir(mode=0o700)
            os.chown(case_parent / "controller", 65534, -1)
            (case_parent / "controller/owned-data").write_bytes(b"retained")
        elif case == "socket_parent_populated":
            (case_parent / "run").mkdir(mode=0o755)
            (case_parent / "run").chmod(0o755)
            (case_parent / "run/owned-data").write_bytes(b"retained")
        elif case == "controller_wrong_mode":
            (case_parent / "controller").mkdir(mode=0o755)
            (case_parent / "controller").chmod(0o755)
            os.chown(case_parent / "controller", 65534, -1)
        elif case == "controller_symlink":
            (case_parent / "controller").symlink_to("absent")
        elif case == "socket_nontraversable_parent":
            case_parent.chmod(0o700)
        extra = ["--unknown", "secret-value"] if case == "unknown_argument" else None
        observed = observation(own / "hostsetup", case_parent, "--apply", False, extra)
        cases.append({"case": case, **observed})
    tested = helpers.run_child(["/usr/bin/env", "SIFRUNO_CONTROLLER_LAYOUT_GUEST=1", str(own / "core.test"), "-test.v", "-test.timeout=90s", "-test.run=^TestControllerLayoutNative"], timeout=100, limit=131072)
    test_text = tested["stdout"].decode("utf-8")
    require(tested["exit_code"] == 0 and tested["stderr"] == b"" and "--- SKIP:" not in test_text and all("--- PASS: " + name + " " in test_text for name in ROOT_TESTS), "native_test_execution")
    require(helpers.policy_snapshot() == adapted, "final_policy_mutation")
    for leaf, digest in expected.items():
        require(helpers.sha(helpers.bounded_bytes(own / leaf, 64 * 1024 * 1024)) == digest, "guest_input_drift")
    return {"schema_version": 1, "scope": "fresh_existing_controller_layout_NSS_only_adapted_Alma9_8", "nonce": nonce, "passed": True, "stock": stock, "plan": plan, "apply": apply, "prepared_directories": layout, "repeat": repeat, "conflicts": cases, "stock_policy_sha256": helpers.sha(json.dumps(stock_before, sort_keys=True).encode()), "adapted_policy_sha256": helpers.sha(json.dumps(adapted, sort_keys=True).encode()), "stock_mail_and_identities_unchanged": True, "account_created": False, "socket_created": False, "core_tests": {"required": ROOT_TESTS, "exit_code": 0, "skips": 0, "stdout_sha256": helpers.sha(tested["stdout"]), "stdout_base64": base64.b64encode(tested["stdout"]).decode("ascii")}, "kernel": platform.release(), "inputs_unchanged": True}


if __name__ == "__main__":
    try:
        require(len(sys.argv) == 3, "guest_arguments")
        expected = helpers.strict_json(Path(sys.argv[2]).read_text())
        print(json.dumps(run(sys.argv[1], expected), separators=(",", ":")))
    except Exception as error:
        code = str(error) if type(error) is AssertionError and re.fullmatch(r"[a-z0-9_]{1,80}", str(error)) else "fixture_observation_failed"
        print(json.dumps({"schema_version": 1, "scope": "fresh_existing_controller_layout_NSS_only_adapted_Alma9_8", "passed": False, "failure": code}, separators=(",", ":")))
        sys.exit(1)
