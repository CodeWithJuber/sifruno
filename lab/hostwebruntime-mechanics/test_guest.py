import importlib.util
from pathlib import Path
import json
import unittest

HERE = Path(__file__).absolute().parent
spec = importlib.util.spec_from_file_location("mechanics_guest", HERE / "guest.py")
guest = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guest)
PINS = json.loads((HERE / "pins.json").read_text())


def output(spec):
    lines = []
    for name in spec["required"]:
        lines += ["=== RUN   " + name, "--- PASS: " + name + " (0.01s)"]
    for name in spec["allowed_skips"]:
        lines += ["=== RUN   " + name, "--- SKIP: " + name + " (0.00s)"]
    return "\n".join(lines + ["PASS"]) + "\n"


class GuestParser(unittest.TestCase):
    def test_exact_worker_and_review_sets(self):
        for spec in PINS["tests"]:
            self.assertTrue(guest.results(output(spec), spec)["passed"])

    def test_echoed_pass_without_runs_denied(self):
        self.assertFalse(guest.results("PASS\n", PINS["tests"][0])["passed"])

    def test_opt_in_skip_denied(self):
        spec = PINS["tests"][0]
        name = "TestNamespaceRegistrationAndDescendantCleanup"
        self.assertFalse(guest.results(output(spec).replace("--- PASS: " + name, "--- SKIP: " + name), spec)["passed"])

    def test_root_filesystem_skip_denied(self):
        spec = PINS["tests"][1]
        self.assertFalse(guest.results(output(spec).replace("--- PASS: TestReviewOpenBelow", "--- SKIP: TestReviewOpenBelow"), spec)["passed"])

    def test_duplicate_missing_and_fail_denied(self):
        spec = PINS["tests"][1]
        good = output(spec)
        for broken in [good + good, good.replace("=== RUN   " + spec["required"][0] + "\n", ""), good.replace("--- PASS:", "--- FAIL:", 1), good + "panic: bad\n"]:
            self.assertFalse(guest.results(broken, spec)["passed"])

    def test_nested_subtests_do_not_replace_top_level(self):
        spec = PINS["tests"][1]
        good = output(spec)
        self.assertTrue(guest.results("=== RUN   TestReviewOptionsContainmentAndExposureRejected/nested\n    --- PASS: TestReviewOptionsContainmentAndExposureRejected/nested (0.00s)\n" + good, spec)["passed"])
        self.assertFalse(guest.results(good.replace("--- PASS: " + spec["required"][0], "    --- PASS: " + spec["required"][0] + "/child"), spec)["passed"])


if __name__ == "__main__":
    unittest.main()
