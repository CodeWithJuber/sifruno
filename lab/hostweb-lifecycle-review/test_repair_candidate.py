"""Candidate checks: Linux capability inputs and simulated group delivery only."""
from __future__ import annotations

import os
import signal
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import repair_candidate as candidate
import test_lifecycle_review as original_review


class CandidateCapabilityChecks(unittest.TestCase):
    status = original_review.IdentityFalsePositiveReview.status + (
        "CapPrm: 0000000000000000\nCapAmb: 0000000000000000\nCapInh: 0000000000000000\n")

    def test_all_four_sets_must_be_zero(self):
        self.assertTrue(candidate.worker_matches(candidate.parse_proc_identity(self.status, "/jail"), 20000, 20000, "/jail"))
        for field in ("CapEff", "CapPrm", "CapAmb", "CapInh"):
            with self.subTest(field=field):
                status = self.status.replace(field + ": 0000000000000000", field + ": 0000000000000001")
                self.assertFalse(candidate.worker_matches(candidate.parse_proc_identity(status, "/jail"), 20000, 20000, "/jail"))

    def test_missing_duplicate_malformed_sets_fail_closed(self):
        for status in (self.status.replace("CapPrm: 0000000000000000\n", ""),
                       self.status + "CapAmb: 0000000000000000\n",
                       self.status.replace("CapInh: 0000000000000000", "CapInh: invalid"),
                       self.status.replace("CapPrm: 0000000000000000", "CapPrm: " + "0"*17)):
            with self.assertRaises(ValueError):
                candidate.parse_proc_identity(status, "/jail")


class CandidateRealProcessChecks(unittest.TestCase):
    setUp = original_review.RealParentChildCleanupReview.setUp
    tearDown = original_review.RealParentChildCleanupReview.tearDown
    wait_for = original_review.RealParentChildCleanupReview.wait_for
    child_still_runs = original_review.RealParentChildCleanupReview.child_still_runs

    def owned(self):
        # Actual Windows Popen leader/child; Linux PGID/session/starttime are
        # deliberately simulated and labeled. This is not a Linux qualification.
        return candidate.OwnedProcess(self.parent, self.parent.pid, self.parent.pid+1000000, "pinned-start")

    def group_delivery(self, mode="normal"):
        calls = []
        def killpg(pgid, sig):
            self.assertEqual(pgid, self.parent.pid)
            calls.append(sig)
            if mode != "stubborn" and self.done.exists() and self.parent.poll() is not None:
                raise ProcessLookupError()
            if sig == signal.SIGTERM:
                if self.parent.poll() is None:
                    self.parent.terminate()
                if mode == "normal":
                    self.stop.write_text("TERM owned child")
            elif sig == 9 and mode != "stubborn": # simulated Linux SIGKILL on Windows
                self.stop.write_text("KILL owned child")
        return calls, killpg

    def patched(self, killpg, identity="pinned-start"):
        return [
            patch.object(candidate.os, "getpgrp", return_value=self.parent.pid+1000000, create=True),
            patch.object(candidate.os, "getpgid", return_value=self.parent.pid, create=True),
            patch.object(candidate.os, "getsid", return_value=self.parent.pid, create=True),
            patch.object(candidate, "linux_start_identity", return_value=identity),
            patch.object(candidate.os, "killpg", side_effect=killpg, create=True),
            patch.object(candidate.signal, "SIGKILL", 9, create=True),
        ]

    def invoke(self, owned, killpg, identity="pinned-start"):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for item in self.patched(killpg, identity):
                stack.enter_context(item)
            candidate.stop_process(owned, term_timeout=.08, kill_timeout=.2, poll_interval=.01)

    def test_exited_leader_still_signals_and_checks_child_extinction(self):
        self.parent.terminate(); self.parent.wait(timeout=3)
        self.child_still_runs()
        calls, delivery = self.group_delivery()
        self.invoke(self.owned(), delivery)
        self.assertIn(signal.SIGTERM, calls)
        self.assertTrue(self.done.exists())

    def test_term_survivor_is_killed_and_extinction_verified(self):
        calls, delivery = self.group_delivery("term-survivor")
        self.invoke(self.owned(), delivery)
        self.assertIn(signal.SIGTERM, calls)
        self.assertIn(9, calls)
        self.assertEqual(calls[-1], 0)
        self.assertTrue(self.done.exists())

    def test_stubborn_group_cannot_report_cleanup_success(self):
        calls, delivery = self.group_delivery("stubborn")
        with self.assertRaisesRegex(candidate.LifecycleError, "owned_process_cleanup_failed"):
            self.invoke(self.owned(), delivery)
        self.assertIn(9, calls)
        self.child_still_runs()

    def test_reused_identity_refuses_signaling(self):
        calls, delivery = self.group_delivery()
        with self.assertRaisesRegex(candidate.LifecycleError, "owned_process_identity_changed"):
            self.invoke(self.owned(), delivery, identity="new-process-start")
        self.assertEqual(calls, [])
        self.child_still_runs()

    def test_unadmitted_fixture_group_and_pid_one_refused(self):
        calls, delivery = self.group_delivery()
        for owned in (self.parent, candidate.OwnedProcess(self.parent, 1, 99, "pinned-start"),
                      candidate.OwnedProcess(self.parent, self.parent.pid, self.parent.pid, "pinned-start")):
            with self.assertRaisesRegex(candidate.LifecycleError, "owned_process_group_invalid"):
                self.invoke(owned, delivery)
        self.assertEqual(calls, [])

    def test_launch_contract_rejects_shell_and_shared_session_before_spawn(self):
        for options in ({"shell":True}, {"start_new_session":False}, {"preexec_fn":lambda:None}):
            with patch.object(candidate.subprocess, "Popen") as spawn:
                with self.assertRaisesRegex(candidate.LifecycleError, "owned_launch_contract_invalid"):
                    candidate.owned_launch(["unexecuted"], **options)
            spawn.assert_not_called()

    def test_owned_launch_admits_exact_spawned_leader_and_session_contract(self):
        from contextlib import ExitStack
        calls, delivery = self.group_delivery()
        with ExitStack() as stack:
            for item in self.patched(delivery):
                stack.enter_context(item)
            spawn = stack.enter_context(patch.object(candidate.subprocess, "Popen", return_value=self.parent))
            owned = candidate.owned_launch(["simulated-admission-argv"], stdout=None)
            self.assertEqual(owned.pid, self.parent.pid)
            self.assertEqual(owned.pgid, self.parent.pid)
            self.assertEqual(owned.start_identity, "pinned-start")
            self.assertIs(spawn.call_args.kwargs["start_new_session"], True)
            candidate.stop_process(owned, term_timeout=.08, kill_timeout=.2, poll_interval=.01)
        self.assertTrue(self.done.exists())

    def test_expired_fixture_deadline_does_not_abandon_cleanup(self):
        calls, delivery = self.group_delivery()
        with patch.object(original_review.fixture, "RUN_DEADLINE", 0):
            self.invoke(self.owned(), delivery)
        self.assertIn(signal.SIGTERM, calls)
        self.assertTrue(self.done.exists())

    def test_permission_error_cannot_report_group_extinction(self):
        def denied(pgid, sig):
            raise PermissionError("simulated Linux group permission failure")
        with self.assertRaisesRegex(candidate.LifecycleError, "owned_process_cleanup_failed"):
            self.invoke(self.owned(), denied)
        self.child_still_runs()


if __name__ == "__main__":
    unittest.main(verbosity=2)
