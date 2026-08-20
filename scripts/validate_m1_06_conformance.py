#!/usr/bin/env python3
"""Validate and execute the FMV3-M1-06 conformance inventory."""

from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "policy" / "m1-06-conformance.json"
BASE_SHA = "4f81cbeb6321e64fa51676ed6e375ce36b60d16d"
RED_SHA = "9d1235f9e5685e6b8b35c54b86d1d6e9d8365d49"
TEST_FILE = "runtime_acquisition_test.go"
REFERENCES = {
    "execution_guide": {
        "repository": "Project-Helianthus/helianthus-execution-plans",
        "path": "fronius-modbus-multivendor-v3-w29-26.implementing/plan.yaml",
        "node": "FMV3-M1-06",
    },
    "public_contract": {
        "repository": "Project-Helianthus/helianthus-docs-ebus",
        "contract_id": "OPAQUE_RUNTIME_ACQUISITION_V1",
        "contract_version": 1,
        "policy_path": "docs/platform/opaque-runtime-acquisition-v1.md",
        "manifest_path": "docs/platform/manifests/opaque-runtime-acquisition-v1.json",
    },
}
REQUIREMENTS = {
    "runtime_only_lossless_issuance": {
        "TestM106RuntimeOnlyIssuanceAndLosslessProvenance",
        "TestM106NonSuccessfulOutcomesNeverIssueCapabilities",
    },
    "coalesced_independence_copy_shared_claim": {
        "TestM106CoalescedCapabilitiesAreIndependentAndCopiesShareOneClaim",
        "TestM106ConcurrentRegistrationUsesDeclaredOrdinals",
    },
    "membership_close_late_registration": {
        "TestM106MembershipCloseRejectsLateRegistration"
    },
    "exact_instance_cancel_open_drain": {
        "TestM106CancelOpenUsesExactInstanceAndDrainsMembers",
        "TestM106CancelOpenAcceptsDrainedExactTerminalInstance",
        "TestM106CancelOpenDrainedInstanceLinearizesOnceAndStaysExact",
    },
    "bounded_sequences_reclamation_restart": {
        "TestM106BoundsExhaustionAndDeterministicTombstones",
        "TestM106RestartExportRetiresSourceAndPreservesSequenceUniqueness",
        "TestM106FailureAndExpiryReclaimSynchronously",
    },
    "opaque_private_state": {
        "TestM106PrivateCapabilityStateIsNotSerializableOrReconstructable"
    },
    "bounded_normalization_activation": {
        "TestM106NormalizationAndActivationBoundsFailClosed",
        "TestM106NormalizationExactSerializationBoundary",
        "TestM106NormalizationRequiredFieldsRejectNullAndWrongTypes",
        "TestM106NormalizationParseLinearizesWithRestartExport",
    },
}
CI_COMMANDS = (
    "./scripts/scope_gate.sh",
    "GOWORK=off go run ./scripts/read_only_surface .",
    "python3 scripts/validate_m1_02_acceptance.py",
    "python3 scripts/validate_m1_03_acceptance.py",
    "python3 scripts/validate_m1_04_acceptance.py",
    "python3 scripts/validate_m1_06_conformance.py",
    "python3 -m unittest discover -s tests -p 'test_*.py'",
    "GOWORK=off go vet ./...",
    "GOWORK=off go build ./...",
    "GOWORK=off GOOS=linux GOARCH=386 go test -c -o /dev/null .",
    "GOWORK=off go test -race -count=1 ./...",
    "GOWORK=off golangci-lint run ./...",
)
SCOPE_STOP = {
    "gateway": False,
    "vendor_profile": False,
    "detector": False,
    "live_device": False,
    "write": False,
    "private_binding": False,
    "canonical_semantics": False,
    "smoke_test_required": False,
}


class ConformanceError(RuntimeError):
    """Raised when conformance evidence is incomplete or changed."""


def run(*command: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "GOWORK": "off"},
        check=False,
        capture_output=True,
        text=True,
    )


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ConformanceError(f"cannot read {path.relative_to(ROOT)}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConformanceError(f"{path.relative_to(ROOT)} root is not an object")
    return value


def validate_artifact(artifact: dict[str, object]) -> set[str]:
    if set(artifact) != {
        "schema",
        "milestone",
        "references",
        "requirements",
        "gates",
        "scope_stop",
    }:
        raise ConformanceError("conformance top-level inventory differs")
    if artifact.get("schema") != (
        "helianthus.modbus.runtime-acquisition-conformance/v1"
    ) or artifact.get("milestone") != "FMV3-M1-06":
        raise ConformanceError("conformance identity differs")
    if artifact.get("references") != REFERENCES:
        raise ConformanceError("contract references differ")

    raw_requirements = artifact.get("requirements")
    if not isinstance(raw_requirements, list):
        raise ConformanceError("requirements are not a list")
    actual: dict[str, set[str]] = {}
    for requirement in raw_requirements:
        if not isinstance(requirement, dict) or set(requirement) != {"id", "tests"}:
            raise ConformanceError("requirement shape differs")
        identifier = requirement.get("id")
        tests = requirement.get("tests")
        if not isinstance(identifier, str) or not isinstance(tests, list) or not tests:
            raise ConformanceError("requirement identity or tests are invalid")
        if identifier in actual or not all(isinstance(test, str) for test in tests):
            raise ConformanceError("requirement duplicates or invalid test name")
        actual[identifier] = set(tests)
    if actual != REQUIREMENTS:
        raise ConformanceError("requirement-to-test map differs")

    gates = artifact.get("gates")
    if not isinstance(gates, dict) or set(gates) != {
        "TDD_RED",
        "pull_request",
        "CI",
        "doc_gate",
        "transport_gate",
    }:
        raise ConformanceError("gate inventory differs")
    red = gates.get("TDD_RED")
    if (
        not isinstance(red, dict)
        or set(red)
        != {
            "base_sha",
            "test_only_commit_sha",
            "test_file",
            "hosted_ci",
        }
        or red.get("base_sha") != BASE_SHA
        or red.get("test_only_commit_sha") != RED_SHA
        or red.get("test_file") != TEST_FILE
    ):
        raise ConformanceError("RED evidence identity differs")
    hosted = red.get("hosted_ci")
    if hosted != {
        "run_id": 31257996397,
        "run_url": (
            "https://github.com/Project-Helianthus/"
            "helianthus-modbus/actions/runs/31257996397"
        ),
        "checks_job_id": 93104267178,
        "lint_job_id": 93104267185,
        "conclusion": "failure",
        "reason": "typecheck_failed_on_absent_runtime_acquisition_api",
    }:
        raise ConformanceError("hosted RED evidence differs")
    if gates.get("pull_request") != {
        "repository": "Project-Helianthus/helianthus-modbus",
        "number": 16,
        "base": "main",
        "base_sha": BASE_SHA,
    }:
        raise ConformanceError("pull-request gate differs")
    if gates.get("CI") != {"commands": list(CI_COMMANDS)}:
        raise ConformanceError("CI command inventory differs")
    if gates.get("doc_gate") != {
        "applicable": False,
        "reason": (
            "public OPAQUE_RUNTIME_ACQUISITION_V1 contract already merged; "
            "no documentation change"
        ),
    }:
        raise ConformanceError("documentation gate differs")
    transport = gates.get("transport_gate")
    if not isinstance(transport, dict) or transport != {
        "applicable": True,
        "reason": (
            "successful TCP logical-view production carries source issuance authority"
        ),
        "matrix_path": "policy/m1-04-transport-matrix.json",
        "unexpected_fail": 0,
        "unexpected_pass": 0,
    }:
        raise ConformanceError("transport gate differs")
    if artifact.get("scope_stop") != SCOPE_STOP:
        raise ConformanceError("scope stop broadened beyond offline runtime work")
    return set().union(*REQUIREMENTS.values())


def validate_red_history() -> None:
    parent = run("git", "rev-parse", f"{RED_SHA}^")
    if parent.returncode != 0 or parent.stdout.strip() != BASE_SHA:
        raise ConformanceError("test-only RED parent differs from exact base")
    changed = run(
        "git",
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        RED_SHA,
    )
    if changed.returncode != 0 or changed.stdout.splitlines() != [TEST_FILE]:
        raise ConformanceError("RED commit is not test-only")
def validate_transport_matrix() -> None:
    path = ROOT / "policy" / "m1-04-transport-matrix.json"
    matrix = load_json(path)
    rows = matrix.get("rows")
    if (
        matrix.get("schema") != "helianthus.modbus.transport-gate/v1"
        or matrix.get("milestone") != "FMV3-M1-04"
        or not isinstance(rows, list)
        or len(rows) != 21
        or not all(
            isinstance(row, dict)
            and isinstance(row.get("id"), str)
            and isinstance(row.get("tests"), list)
            and bool(row["tests"])
            for row in rows
        )
    ):
        raise ConformanceError("transport matrix structure differs")


def execute_tests(expected: set[str]) -> None:
    listed = run("go", "test", "-list", "^TestM106", ".")
    if listed.returncode != 0:
        raise ConformanceError(f"cannot list M1-06 tests: {listed.stderr}")
    actual = {
        line.strip()
        for line in listed.stdout.splitlines()
        if line.startswith("TestM106")
    }
    if actual != expected:
        raise ConformanceError(
            f"M1-06 test inventory differs: actual={sorted(actual)}"
        )
    pattern = "^(?:" + "|".join(sorted(re.escape(test) for test in expected)) + ")$"
    result = run("go", "test", "-json", "-race", "-count=1", "-run", pattern, ".")
    if result.returncode != 0:
        raise ConformanceError(
            "M1-06 tests failed:\n" + result.stdout + result.stderr
        )
    passed: set[str] = set()
    for line in result.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ConformanceError("go test emitted invalid JSON") from exc
        if event.get("Action") == "skip" and event.get("Test") in expected:
            raise ConformanceError(f"mapped test skipped: {event.get('Test')}")
        if event.get("Action") == "pass" and event.get("Test") in expected:
            passed.add(str(event["Test"]))
    if passed != expected:
        raise ConformanceError(f"mapped tests did not all pass: {sorted(passed)}")


def main() -> int:
    try:
        artifact = load_json(ARTIFACT)
        expected = validate_artifact(artifact)
        validate_red_history()
        validate_transport_matrix()
        execute_tests(expected)
    except ConformanceError as exc:
        print(f"M1-06 conformance failed: {exc}")
        return 1
    print(f"M1-06 conformance passed: {len(expected)} tests")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
