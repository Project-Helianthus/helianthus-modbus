#!/usr/bin/env python3
"""Validate the offline FMV3-M1-04 transport-conformance milestone."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts" / "validate_m1_03_acceptance.py"
BASE_SPEC = importlib.util.spec_from_file_location(
    "validate_m1_03_acceptance",
    BASE_SCRIPT,
)
if BASE_SPEC is None or BASE_SPEC.loader is None:
    raise RuntimeError("cannot load M1-03 acceptance helpers")
previous = importlib.util.module_from_spec(BASE_SPEC)
BASE_SPEC.loader.exec_module(previous)
base = previous.base
AcceptanceError = previous.AcceptanceError

PLAN_SOURCE = {
    "repository": "Project-Helianthus/helianthus-execution-plans",
    "path": "fronius-modbus-multivendor-v3-w29-26.locked/plan.yaml",
    "node": "FMV3-M1-04",
}
COMPANION_SOURCE = {
    "repository": "Project-Helianthus/helianthus-docs-ebus",
    "contract_id": "HELIANTHUS_MODBUS_FOUNDATION_PROFILE_V1",
    "contract_version": 1,
    "manifest_path": (
        "docs/platform/manifests/"
        "modbus-foundation-profile-contract-v1.json"
    ),
    "policy_path": "docs/platform/modbus-foundation-profile-contract-v1.md",
}
RECOVERY_ROWS = (
    "tcp_provable_zero_no_abandonment",
    "tcp_partial_write_close_reconnect",
    "tcp_indeterminate_error_close_reconnect",
    "tcp_cancellation_race_close_reconnect",
    "tcp_ambiguous_completion_close_reconnect",
    "tcp_full_transmit_timeout_tombstone",
    "tcp_full_transmit_cancellation_tombstone",
    "tcp_same_socket_tombstone_reuse_rejected",
    "tcp_tombstone_exhaustion_controlled_rollover",
    "tcp_old_generation_late_frame_rejected",
    "rtu_provable_zero_no_abandonment",
    "rtu_partial_write_quarantine",
    "rtu_indeterminate_error_quarantine",
    "rtu_cancellation_race_quarantine",
    "rtu_ambiguous_completion_quarantine",
    "rtu_full_transmit_timeout_quarantine",
    "rtu_full_transmit_cancellation_quarantine",
    "rtu_late_same_shape_discarded",
    "rtu_quiescence_failure_endpoint_recovery",
)
IDENTITY_ROWS = (
    "tcp_fc2b_mei0e_device_identification",
    "rtu_fc2b_mei0e_device_identification",
)
OWNED_TESTS = {
    "TestRTUDeviceIDAccessADUFramingAndSegmentDecode",
    "TestRTUDeviceIDResponseRetainsExceptionAndMalformedRawFrame",
    "TestRTUDeviceIDEndpointDeliversSegmentWithWireProvenance",
    "TestRTUDeviceIDMalformedCandidateTerminalizesWithWireIdentity",
    "TestRTUEndFrameOperationTypeMismatchDoesNotConsumeFrame",
    "TestTCPDeviceIDTraversalAcrossTransportFrames",
    "TestRTUDeviceIDTraversalAcrossFixtureFrames",
    "TestTCPDeviceIDExceptionAndMalformedTransportResponses",
    "TestTCPEndpointDeviceIDTraversalPublishesOnlyCompleteAggregate",
    "TestTCPEndpointDeviceIDExceptionAndMalformedAreTerminal",
    "TestTCPEndpointDeviceIDQueuedCancellationReleasesScheduler",
    "TestTCPEndpointDeviceIDCancellationOwnsWriteBoundary",
    "TestTCPEndpointDeviceIDCancellationAfterWriteBeforeWaitingTombstones",
    "TestTCPEndpointDeviceIDWaitingCancellationDropsLateResponse",
    "TestTCPEndpointDeviceIDResponseAndCancellationLinearize",
    "TestTCPEndpointDeviceIDProvableZeroRetryRestartsTraversal",
    "TestTCPEndpointDeviceIDContinuationFailureRetryRestartsAtInitialCursor",
    "TestTCPEndpointDeviceIDMalformedContinuationReleasesCapacity",
    "TestRTUDeviceIDExceptionTerminalizesWithWireIdentity",
    "TestTCPRemainsAvailableWhenRTUCapabilityIsDisabled",
}
RED_REQUIRED_TESTS = {
    "TestRTUDeviceIDAccessADUFramingAndSegmentDecode",
    "TestRTUDeviceIDResponseRetainsExceptionAndMalformedRawFrame",
    "TestRTUDeviceIDEndpointDeliversSegmentWithWireProvenance",
    "TestRTUDeviceIDMalformedCandidateTerminalizesWithWireIdentity",
    "TestTCPEndpointDeviceIDTraversalPublishesOnlyCompleteAggregate",
}
EXPECTED_CI_COMMANDS = (
    "./scripts/scope_gate.sh",
    "GOWORK=off go run ./scripts/read_only_surface .",
    "python3 scripts/validate_m1_02_acceptance.py",
    "python3 scripts/validate_m1_03_acceptance.py",
    "python3 scripts/validate_m1_04_acceptance.py",
    "python3 -m unittest discover -s tests -p 'test_*.py'",
    "GOWORK=off go vet ./...",
    "GOWORK=off go build ./...",
    "GOWORK=off GOOS=linux GOARCH=386 go test -c -o /dev/null .",
    "GOWORK=off go test -race -count=1 ./...",
)


def validate_canonical_sources(
    document: dict[str, object],
) -> None:
    expected = {
        "plan": PLAN_SOURCE,
        "companion": COMPANION_SOURCE,
    }
    if document.get("canonical_sources") != expected:
        raise AcceptanceError("M1-04 canonical-source identity changed")


def validate_requirements(document: dict[str, object]) -> set[str]:
    requirements = document.get("requirements")
    if not isinstance(requirements, list) or len(requirements) != 5:
        raise AcceptanceError("M1-04 requirement inventory changed")
    expected_ids = (
        "closed_transport_recovery_matrix",
        "tcp_fc2b_mei0e_transport",
        "rtu_fc2b_mei0e_transport",
        "bounded_transport_stress",
        "fixture_only_rtu_independent_tcp",
    )
    actual_ids = tuple(
        item.get("id") if isinstance(item, dict) else None
        for item in requirements
    )
    if actual_ids != expected_ids:
        raise AcceptanceError("M1-04 requirement ordering changed")
    tests: set[str] = set()
    for requirement in requirements:
        if (
            not isinstance(requirement, dict)
            or not isinstance(requirement.get("source"), str)
            or not isinstance(requirement.get("tests"), list)
            or not requirement["tests"]
        ):
            raise AcceptanceError("M1-04 requirement mapping is malformed")
        tests.update(str(name) for name in requirement["tests"])
    return tests


def validate_transport_matrix(
    root: Path,
    document: dict[str, object],
) -> set[str]:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("M1-04 gates are missing")
    gate = gates.get("transport_gate")
    if gate != {
        "matrix_path": "policy/m1-04-transport-matrix.json",
        "matrix_sha256": (
            "e3265150a85be191c5eae7e942cc665edcf5b2ea68af980a5f482da1f1508ae3"
        ),
        "expected_rows": 21,
        "unexpected_fail": 0,
        "unexpected_pass": 0,
        "skipped": 0,
    }:
        raise AcceptanceError("M1-04 transport-gate declaration changed")
    path = root / str(gate["matrix_path"])
    if base.sha256(path.read_bytes()) != gate["matrix_sha256"]:
        raise AcceptanceError("M1-04 transport matrix content changed")
    matrix = json.loads(path.read_text(encoding="utf-8"))
    if (
        matrix.get("schema") != "helianthus.modbus.transport-gate/v1"
        or matrix.get("milestone") != "FMV3-M1-04"
        or matrix.get("disposition") != "FIXTURE_ONLY_NO_HARDWARE"
        or matrix.get("execution_surface") != "offline_fixture_only"
        or matrix.get("canonical_source")
        != {
            "repository": COMPANION_SOURCE["repository"],
            "contract_id": COMPANION_SOURCE["contract_id"],
            "contract_version": COMPANION_SOURCE["contract_version"],
            "manifest_path": COMPANION_SOURCE["manifest_path"],
            "recovery_field": "transport_recovery_rows",
        }
    ):
        raise AcceptanceError("M1-04 transport matrix identity changed")
    rows = matrix.get("rows")
    if not isinstance(rows, list):
        raise AcceptanceError("M1-04 transport rows are missing")
    row_ids = tuple(
        row.get("id") if isinstance(row, dict) else None for row in rows
    )
    if row_ids != RECOVERY_ROWS + IDENTITY_ROWS:
        raise AcceptanceError("M1-04 transport row inventory changed")
    tests: set[str] = set()
    for row in rows:
        if (
            not isinstance(row, dict)
            or set(row) != {"id", "tests"}
            or not isinstance(row["tests"], list)
            or not row["tests"]
            or len(row["tests"]) != len(set(row["tests"]))
        ):
            raise AcceptanceError("M1-04 transport row is malformed")
        tests.update(str(name) for name in row["tests"])
    return tests


def validate_tdd(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "base_sha",
        "test_only_commits",
        "hosted_ci_runs",
        "red_required_tests",
    }:
        raise AcceptanceError("M1-04 TDD_RED evidence changed")
    base_sha = value.get("base_sha")
    commits = value.get("test_only_commits")
    runs = value.get("hosted_ci_runs")
    red_required = value.get("red_required_tests")
    if (
        not isinstance(base_sha, str)
        or not isinstance(commits, list)
        or len(commits) != 2
        or any(
            not isinstance(commit, str)
            or not re.fullmatch(r"[0-9a-f]{40}", commit)
            for commit in [base_sha, *commits]
        )
        or len(set(commits)) != len(commits)
        or not isinstance(runs, list)
        or len(runs) != len(commits)
        or not isinstance(red_required, list)
        or set(red_required) != RED_REQUIRED_TESTS
        or len(red_required) != len(RED_REQUIRED_TESTS)
    ):
        raise AcceptanceError("M1-04 TDD_RED evidence changed")
    for commit, run in zip(commits, runs, strict=True):
        if (
            not isinstance(run, dict)
            or set(run) != {"commit_sha", "conclusion", "url"}
            or run.get("commit_sha") != commit
            or run.get("conclusion") != "failure"
            or not isinstance(run.get("url"), str)
        ):
            raise AcceptanceError("M1-04 TDD_RED run metadata changed")
        base.github_run_id(str(run["url"]))


def validate_static_gates(
    root: Path,
    document: dict[str, object],
) -> None:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("M1-04 gates are missing")
    ci = gates.get("CI")
    if not isinstance(ci, dict) or tuple(ci.get("commands", ())) != (
        EXPECTED_CI_COMMANDS
    ):
        raise AcceptanceError("M1-04 CI command contract changed")
    ci_script = (root / "scripts" / "ci_local.sh").read_text(encoding="utf-8")
    if "python3 scripts/validate_m1_04_acceptance.py" not in ci_script:
        raise AcceptanceError("M1-04 validator is absent from local CI")
    if gates.get("hardware_conditional") != {
        "required_disposition": "FIXTURE_ONLY_NO_HARDWARE",
        "physical_evidence_required": False,
        "supported_claim": False,
        "enabled_claim": False,
        "tcp_blocked_by_rtu_hardware": False,
    }:
        raise AcceptanceError("M1-04 hardware disposition changed")
    previous.validate_offline_surface(root, gates.get("offline_surface"))
    if gates.get("doc_gate") != {
        "applicable": False,
        "reason": (
            "public HELIANTHUS_MODBUS_FOUNDATION_PROFILE_V1 contract already "
            "merged; no documentation change"
        ),
    }:
        raise AcceptanceError("M1-04 doc-gate evidence changed")
    validate_tdd(gates.get("TDD_RED"))


def validate_test_evidence(
    root: Path,
    document: dict[str, object],
    required_tests: set[str],
) -> None:
    evidence = base.test_evidence(root)
    if evidence.get("test_mains"):
        raise AcceptanceError(f"TestMain is forbidden: {evidence['test_mains']}")
    actual_files = evidence.get("test_files")
    sources = evidence.get("test_sources")
    declared = document.get("test_file_sha256")
    if (
        not isinstance(actual_files, dict)
        or not isinstance(sources, dict)
        or not isinstance(declared, dict)
        or set(declared)
        != {
            "tcp_device_id_endpoint_test.go",
            "transport_conformance_test.go",
        }
    ):
        raise AcceptanceError("M1-04 test-file evidence is malformed")
    base.validate_declared_test_files(actual_files, declared)
    owned = {
        name
        for name, source in sources.items()
        if source
        in {
            "tcp_device_id_endpoint_test.go",
            "transport_conformance_test.go",
        }
    }
    if owned != OWNED_TESTS:
        raise AcceptanceError("M1-04 owned test inventory changed")
    available = set(evidence.get("tests", {}))
    missing = required_tests - available
    if missing:
        raise AcceptanceError(f"M1-04 mapped tests are missing: {sorted(missing)}")


def validate(
    root: Path,
    document: dict[str, object],
    *,
    execute_tests: bool = True,
) -> int:
    if (
        document.get("schema")
        != "helianthus.modbus.milestone-acceptance/v2"
        or document.get("milestone") != "FMV3-M1-04"
    ):
        raise AcceptanceError("M1-04 acceptance identity changed")
    validate_canonical_sources(document)
    required_tests = validate_requirements(document)
    required_tests.update(validate_transport_matrix(root, document))
    validate_static_gates(root, document)
    validate_test_evidence(root, document, required_tests)
    if execute_tests:
        base.run_mapped_tests(root, required_tests)
    return len(required_tests)


def main() -> int:
    try:
        document = base.load_json(ROOT / "policy" / "m1-04-acceptance.json")
        count = validate(ROOT, document)
    except (AcceptanceError, OSError, json.JSONDecodeError) as exc:
        print(f"M1-04 acceptance failed: {exc}", file=sys.stderr)
        return 1
    print(
        "M1-04 acceptance passed: "
        f"5 requirements, 21 transport rows, {count} tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
