"""Independent frozen-source challenges; Windows is not Linux /proc proof.

Passing regression-characterization tests below mean the documented false
positives exist in the pinned fixture. They are not acceptance tests for repair.
"""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SOURCE = Path(__file__).with_name("frozen_fixture_excerpt.py")
spec = importlib.util.spec_from_file_location("frozen_lifecycle_fixture", SOURCE)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class IdentityFalsePositiveReview(unittest.TestCase):
    status = ("Uid: 20000 20000 20000 20000\nGid: 20000 20000 20000 20000\n"
              "Groups: 20000\nCapEff: 0000000000000000\n")

    def test_nonzero_permitted_and_ambient_are_currently_ignored(self):
        # These are Linux-format source inputs, not observations of Windows IDs.
        for field in ("CapPrm", "CapAmb", "CapInh"):
            with self.subTest(field=field):
                identity = fixture.parse_proc_identity(self.status + field + ": 0000000000000001\n", "/owned/jail")
                self.assertTrue(fixture.worker_matches(identity, 20000, 20000, "/owned/jail"),
                                "Frozen false positive changed; review repair instead")

    def test_all_four_uid_gid_slots_and_foreign_groups_are_rejected(self):
        for field in ("Uid", "Gid"):
            for slot in range(4):
                values = ["20000"] * 4
                values[slot] = "0"
                status = self.status.replace(field + ": 20000 20000 20000 20000", field + ": " + " ".join(values))
                self.assertFalse(fixture.worker_matches(fixture.parse_proc_identity(status, "/owned/jail"), 20000, 20000, "/owned/jail"))
        for groups in ("0", "20000 20001", "48", "2000"):
            status = self.status.replace("Groups: 20000", "Groups: " + groups)
            self.assertFalse(fixture.worker_matches(fixture.parse_proc_identity(status, "/owned/jail"), 20000, 20000, "/owned/jail"))

    def test_child_enumeration_ignores_children_of_secondary_threads(self):
        # A synthetic Linux /proc layout demonstrates traversal coverage only.
        # Windows cannot validate actual Linux task children semantics.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for task, child in ((77, "88"), (78, "99")):
                path = root / f"77/task/{task}/children"
                path.parent.mkdir(parents=True)
                path.write_text(child)
            with patch.object(fixture, "Path", side_effect=lambda value: root / str(value).removeprefix("/proc/")):
                self.assertEqual(fixture.children(77), [88])
            self.assertTrue((root / "77/task/78/children").exists())


class RealParentChildCleanupReview(unittest.TestCase):
    """Real Windows parent/child, bounded child lifetime, simulated killpg only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.heartbeat = self.root / "heartbeat"
        self.stop = self.root / "stop"
        self.done = self.root / "done"
        self._closed = False
        child_code = (
            "import os,sys,time; from pathlib import Path; "
            "heartbeat,stop,done=map(Path,sys.argv[1:]); "
            "parent=os.getppid(); deadline=time.monotonic()+15; "
            "\nwhile not stop.exists() and time.monotonic()<deadline:"
            "\n staged=heartbeat.with_suffix('.tmp'); staged.write_text(str(parent)+':'+str(time.monotonic())); staged.replace(heartbeat); time.sleep(.03)"
            "\ndone.write_text('child exited')"
        )
        parent_code = (
            "import subprocess,sys,json; "
            "p=subprocess.Popen([sys.executable,'-c',sys.argv[1],*sys.argv[2:]],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,"
            "creationflags=subprocess.CREATE_NO_WINDOW if sys.platform=='win32' else 0); "
            "print(json.dumps({'child':p.pid}),flush=True); sys.stdin.read()"
        )
        self.parent = subprocess.Popen(
            [sys.executable, "-c", parent_code, child_code, str(self.heartbeat), str(self.stop), str(self.done)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        self.addCleanup(self.tearDown) # also executes if later setup fails
        self.child_pid = json.loads(self.parent.stdout.readline())["child"]
        self.wait_for(lambda: self.heartbeat.exists())
        self.assertEqual(int(self.heartbeat.read_text().split(":")[0]), self.parent.pid,
                         "Child must report the actual spawned parent")

    def wait_for(self, predicate):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(.02)
        self.fail("bounded real-process fixture did not reach state")

    def child_still_runs(self):
        before = self.heartbeat.stat().st_mtime_ns
        self.wait_for(lambda: self.heartbeat.stat().st_mtime_ns > before)
        self.assertFalse(self.done.exists())

    def tearDown(self):
        if self._closed:
            return
        self._closed = True
        self.stop.write_text("stop owned child")
        if self.parent.poll() is None:
            self.parent.terminate()
        self.parent.wait(timeout=3)
        self.wait_for(self.done.exists)
        for stream in (self.parent.stdin, self.parent.stdout, self.parent.stderr):
            stream.close()
        self.tmp.cleanup()

    def test_exited_parent_skips_surviving_actual_child(self):
        self.parent.terminate()
        self.parent.wait(timeout=3)
        self.child_still_runs()
        with patch.object(fixture.os, "killpg", create=True) as killpg:
            fixture.stop_process(self.parent)
        self.assertEqual(killpg.call_count, 0)
        self.child_still_runs()

    def test_leader_exit_after_term_does_not_check_remaining_child(self):
        # Windows has no killpg: only this signal delivery is substituted. The
        # parent and surviving child are actual processes, not Popen mocks.
        with patch.object(fixture.os, "killpg", side_effect=lambda pid, sig: self.parent.terminate(), create=True) as killpg:
            fixture.stop_process(self.parent)
        self.assertEqual(killpg.call_count, 1, "No group extinction check/escalation occurred")
        self.assertIsNotNone(self.parent.poll())
        self.child_still_runs()


if __name__ == "__main__":
    unittest.main(verbosity=2)
