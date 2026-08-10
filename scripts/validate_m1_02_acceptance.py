#!/usr/bin/env python3
"""Validate FMV3-M1-02 against its external plan and companion contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


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
PLAN_SOURCE = {
    "repository": "Project-Helianthus/helianthus-execution-plans",
    "path": (
        "fronius-modbus-multivendor-v3-w29-26.implementing/plan.yaml"
    ),
    "node": "FMV3-M1-02",
}
EXPECTED_REQUIREMENTS = (
    (
        "tcp_socket_owner_allocator_map",
        "companion_contract#ownership-and-correlation",
    ),
    (
        "tcp_correlation_match_and_generation",
        "execution_plan#tcp_correlation_contract.match_fields",
    ),
    (
        "request_offset_is_provenance_only",
        "execution_plan#tcp_correlation_contract.request_offset_role",
    ),
    (
        "socket_lifetime_tombstone_and_rollover",
        "companion_contract#response-wait-abandonment",
    ),
    (
        "bounded_isolated_profile_neutral_runtime",
        "execution_plan#tcp_correlation_contract.profile_semantics",
    ),
    (
        "wire_and_logical_identity_exact_replay",
        "execution_plan#coalescing_identity_contract",
    ),
    (
        "incompatible_reads_do_not_coalesce",
        "execution_plan#coalescing_identity_contract.incompatible_dimensions",
    ),
    ("abnormal_write_classification", "execution_plan#abnormal_write_results"),
    (
        "possibly_transmitted_recovery",
        "execution_plan#possibly_transmitted_action",
    ),
    ("scheduler_pool_fairness_and_limits", "execution_plan#what"),
    ("absolute_deadline_cancellation_and_backoff", "execution_plan#what"),
    ("operability_and_replay_trace", "execution_plan#gates.operability"),
    ("read_only_public_surface", "companion_contract#read-only"),
)
TCP_RECOVERY_ROWS = (
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
)
EXPECTED_CI_COMMANDS = (
    "./scripts/scope_gate.sh",
    "GOWORK=off go run ./scripts/read_only_surface .",
    "python3 scripts/validate_m1_02_acceptance.py",
    "python3 -m unittest discover -s tests -p 'test_*.py'",
    "GOWORK=off go vet ./...",
    "GOWORK=off go build ./...",
    "GOWORK=off go test -race -count=1 ./...",
)


class AcceptanceError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def github_run_id(run_url: str) -> str:
    match = re.fullmatch(
        r"https://github\.com/Project-Helianthus/helianthus-modbus/"
        r"actions/runs/(\d+)(?:/job/\d+)?",
        run_url,
    )
    if match is None:
        raise AcceptanceError("TDD_RED hosted CI URL is missing")
    return match.group(1)


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AcceptanceError(f"{path} must contain a JSON object")
    return value


def go_tool_context(root: Path) -> tuple[Path, Path, dict[str, str]]:
    tool_root = Path(__file__).resolve().parents[1]
    target_root = root.resolve()
    return tool_root, target_root, {
        **os.environ,
        "GOWORK": "off",
        "PWD": str(tool_root),
    }


def test_evidence(root: Path) -> dict[str, object]:
    tool_root, target_root, environment = go_tool_context(root)
    result = subprocess.run(
        ["go", "run", "./scripts/acceptance_evidence", str(target_root)],
        cwd=tool_root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError(result.stderr.strip())
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError(
            "test body evidence tool returned invalid JSON"
        ) from exc
    if not isinstance(value, dict):
        raise AcceptanceError("test body evidence tool returned non-object JSON")
    return value


def validate_canonical_sources(
    document: dict[str, object],
) -> None:
    sources = document.get("canonical_sources")
    if sources != {
        "companion_contract": COMPANION_SOURCE,
        "execution_plan": PLAN_SOURCE,
    }:
        raise AcceptanceError("canonical source identity changed")


def validate_requirement_contract(
    document: dict[str, object],
) -> set[str]:
    requirements = document.get("requirements")
    if not isinstance(requirements, list):
        raise AcceptanceError("requirements must be a list")
    actual_identity = tuple(
        (item.get("id"), item.get("source"))
        for item in requirements
        if isinstance(item, dict)
    )
    if actual_identity != EXPECTED_REQUIREMENTS:
        raise AcceptanceError("canonical requirement identity or order changed")
    mapped_tests: set[str] = set()
    for item in requirements:
        tests = item.get("tests")
        if (
            not isinstance(tests, list)
            or not tests
            or any(not isinstance(name, str) or not name for name in tests)
            or len(tests) != len(set(tests))
        ):
            raise AcceptanceError(
                f"invalid test evidence for requirement {item.get('id')}"
            )
        mapped_tests.update(tests)
    return mapped_tests


def validate_transport_matrix(
    root: Path,
    document: dict[str, object],
) -> set[str]:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("gate evidence is missing")
    gate = gates.get("transport_gate")
    if not isinstance(gate, dict):
        raise AcceptanceError("transport gate evidence is missing")
    relative = gate.get("matrix_path")
    if relative != "policy/m1-02-transport-matrix.json":
        raise AcceptanceError("transport matrix path changed")
    path = root / relative
    data = path.read_bytes()
    if sha256(data) != gate.get("matrix_sha256"):
        raise AcceptanceError("transport matrix hash changed")
    matrix = load_json(path)
    if (
        matrix.get("schema") != "helianthus.modbus.transport-gate/v1"
        or matrix.get("milestone") != "FMV3-M1-02"
        or matrix.get("canonical_source")
        != {
            "repository": COMPANION_SOURCE["repository"],
            "contract_id": COMPANION_SOURCE["contract_id"],
            "contract_version": COMPANION_SOURCE["contract_version"],
            "manifest_path": COMPANION_SOURCE["manifest_path"],
            "field": "transport_recovery_rows",
        }
    ):
        raise AcceptanceError("transport matrix canonical identity changed")
    rows = matrix.get("rows")
    if not isinstance(rows, list):
        raise AcceptanceError("transport matrix rows are missing")
    if tuple(row.get("id") for row in rows) != TCP_RECOVERY_ROWS:
        raise AcceptanceError("transport matrix row identity or order changed")
    tests: set[str] = set()
    for row in rows:
        row_tests = row.get("tests")
        if (
            not isinstance(row_tests, list)
            or not row_tests
            or len(row_tests) != len(set(row_tests))
        ):
            raise AcceptanceError(
                f"transport row {row.get('id')} lacks deterministic tests"
            )
        tests.update(row_tests)
    return tests


def validate_gate_contract(
    document: dict[str, object],
) -> None:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("gate evidence is missing")
    ci = gates.get("CI")
    if not isinstance(ci, dict) or tuple(ci.get("commands", ())) != (
        EXPECTED_CI_COMMANDS
    ):
        raise AcceptanceError("CI gate command contract changed")
    if gates.get("doc_gate") != {
        "applicable": False,
        "reason": (
            "public HELIANTHUS_MODBUS_FOUNDATION_PROFILE_V1 contract already "
            "merged; no documentation change"
        ),
    }:
        raise AcceptanceError("doc-gate evidence changed")
    operability = gates.get("operability")
    if not isinstance(operability, dict) or tuple(
        operability.get("required_requirement_ids", ())
    ) != (
        "absolute_deadline_cancellation_and_backoff",
        "operability_and_replay_trace",
    ):
        raise AcceptanceError("operability gate evidence changed")
    red = gates.get("TDD_RED")
    if not isinstance(red, dict) or not isinstance(red.get("commit_sha"), str):
        raise AcceptanceError("TDD_RED evidence is missing")
    validate_tdd_red(red)


def validate_tdd_red(
    value: object,
) -> None:
    if not isinstance(value, dict):
        raise AcceptanceError("TDD_RED evidence is missing")
    commit = value.get("commit_sha")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise AcceptanceError("TDD_RED commit must be a full immutable SHA")
    if (
        value.get("required_shape") != "tests_only_parented_by_fmv3_m1_01"
        or value.get("hosted_ci_conclusion") != "failure"
    ):
        raise AcceptanceError("TDD_RED evidence contract changed")
    run_url = value.get("hosted_ci_run_url")
    if not isinstance(run_url, str):
        raise AcceptanceError("TDD_RED hosted CI URL is missing")
    github_run_id(run_url)


def validate_declared_test_files(
    actual: object,
    declared: object,
) -> None:
    if (
        not isinstance(actual, dict)
        or not isinstance(declared, dict)
        or not declared
    ):
        raise AcceptanceError("test-file evidence is missing")
    invalid = {
        path: {
            "expected": digest,
            "actual": actual.get(path),
        }
        for path, digest in declared.items()
        if (
            not isinstance(path, str)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or actual.get(path) != digest
        )
    }
    if invalid:
        raise AcceptanceError(
            f"owned test-file inventory or content changed: {invalid}"
        )


def validate_body_evidence(
    root: Path,
    document: dict[str, object],
    required_tests: set[str],
) -> None:
    evidence = test_evidence(root)
    if evidence.get("test_mains"):
        raise AcceptanceError(f"TestMain is forbidden: {evidence['test_mains']}")
    declared_files = document.get("test_file_sha256")
    validate_declared_test_files(
        evidence.get("test_files"),
        declared_files,
    )
    available = set(evidence.get("tests", {}))
    missing = required_tests - available
    if missing:
        raise AcceptanceError(f"mapped tests are missing: {sorted(missing)}")


def run_mapped_tests(root: Path, required_tests: set[str]) -> None:
    pattern = "^(" + "|".join(re.escape(name) for name in sorted(required_tests))
    pattern += ")$"
    result = subprocess.run(
        [
            "go",
            "test",
            "-json",
            "-count=1",
            "-timeout=60s",
            "-run",
            pattern,
            ".",
        ],
        cwd=root,
        env={**os.environ, "GOWORK": "off"},
        check=False,
        capture_output=True,
        text=True,
    )
    evaluate_mapped_test_events(
        required_tests,
        result.stdout,
        result.stderr,
        result.returncode,
    )


def evaluate_mapped_test_events(
    required_tests: set[str],
    stdout: str,
    stderr: str,
    returncode: int,
) -> None:
    events: dict[str, set[str]] = {name: set() for name in required_tests}
    skipped_descendants: dict[str, set[str]] = {
        name: set() for name in required_tests
    }
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        name = event.get("Test")
        action = event.get("Action")
        if name in events and action in {"run", "pass", "fail", "skip"}:
            events[name].add(action)
        if action == "skip" and isinstance(name, str):
            for required in required_tests:
                if name.startswith(required + "/"):
                    skipped_descendants[required].add(name)
    invalid = {
        name: {
            "actions": sorted(actions),
            "skipped_descendants": sorted(skipped_descendants[name]),
        }
        for name, actions in events.items()
        if "run" not in actions
        or "pass" not in actions
        or "fail" in actions
        or "skip" in actions
        or skipped_descendants[name]
    }
    if returncode != 0 or invalid:
        detail = stderr.strip() or stdout[-2000:]
        raise AcceptanceError(
            f"mapped tests did not execute cleanly: {invalid}; {detail}"
        )


def validate(
    root: Path,
    document: dict[str, object],
    *,
    execute_tests: bool = True,
) -> int:
    if (
        document.get("schema")
        != "helianthus.modbus.milestone-acceptance/v2"
        or document.get("milestone") != "FMV3-M1-02"
    ):
        raise AcceptanceError("M1-02 acceptance identity changed")
    validate_canonical_sources(document)
    required_tests = validate_requirement_contract(document)
    required_tests.update(validate_transport_matrix(root, document))
    validate_gate_contract(document)
    validate_body_evidence(root, document, required_tests)
    if execute_tests:
        run_mapped_tests(root, required_tests)
    return len(required_tests)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        document = load_json(root / "policy" / "m1-02-acceptance.json")
        count = validate(root, document)
    except (AcceptanceError, OSError, json.JSONDecodeError) as exc:
        print(f"M1-02 acceptance failed: {exc}", file=sys.stderr)
        return 1
    print(
        "M1-02 acceptance passed: "
        f"{len(EXPECTED_REQUIREMENTS)} requirements, "
        f"{len(TCP_RECOVERY_ROWS)} transport rows, {count} tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
