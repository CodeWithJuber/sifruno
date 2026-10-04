"""Regenerate interoperability fixtures. These are explicitly synthetic."""
import copy
import hashlib
import json
from pathlib import Path

from capture import seal


def fixtures():
    reference = {"schema_version": 1, "id": "synthetic-reference", "kind": "synthetic", "role": "reference",
                 "provenance": {"product": "Synthetic cPanel contract fixture", "exact_build": "fixture-1",
                                "os": "Synthetic AlmaLinux 9", "arch": "x86_64",
                                "captured_at": "2026-10-04T00:00:00Z", "features": ["synthetic-cli"],
                                "artifacts": [{"name": "fixture", "path": "/fixtures/not-a-real-cpanel-artifact",
                                               "sha256": hashlib.sha256(b"synthetic fixture only").hexdigest()}],
                                "disposable_host_attested": False, "licensed_reference_attested": False},
                 "cases": [{"operation": {"id": "cli.fixture-default", "obligation_id": "cli.whmapi1",
                                           "transport": "cli", "command": ["/fixtures/whmapi1", "fixture"]},
                            "outcome": {"format": "json", "exit_code": 0,
                                        "stdout": '{"data":{"default":1},"metadata":{"result":1}}', "stderr": ""}},
                           {"operation": {"id": "cli.fixture-error", "obligation_id": "cli.whmapi1",
                                           "transport": "cli", "command": ["/fixtures/whmapi1", "missing"]},
                            "outcome": {"format": "json", "exit_code": 0,
                                        "stdout": '{"metadata":{"result":0,"reason":"Unknown function"}}', "stderr": ""}}]}
    candidate = copy.deepcopy(reference)
    candidate.update(id="synthetic-candidate", role="candidate")
    candidate["provenance"]["product"] = "Synthetic Sifruno fixture"
    candidate["cases"][0]["outcome"]["stdout"] = '{"metadata":{"result":1.0},"data":{"default":1e0}}'
    candidate["cases"][1]["outcome"]["stderr"] = "Unexpected warning\n"
    return {"synthetic-reference": seal(reference), "synthetic-candidate": seal(candidate)}


if __name__ == "__main__":
    target = Path(__file__).parent / "fixtures"
    target.mkdir(exist_ok=True)
    for name, bundle in fixtures().items():
        (target / (name + ".json")).write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
