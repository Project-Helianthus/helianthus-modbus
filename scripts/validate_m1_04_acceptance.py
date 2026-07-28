#!/usr/bin/env python3
"""Validate the offline FMV3-M1-04 transport-conformance milestone."""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
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
    "commit_sha": "0576544bd8851c4e32da3ca7c401270eee43ef5c",
    "path": "fronius-modbus-multivendor-v3-w29-26.locked/plan.yaml",
    "artifact_sha256": (
        "c36f66d8e9b2952b9464fa5a4d64e86a314dba331cbc59d833fdf8edfd1de7d8"
    ),
    "task_block_sha256": (
        "3617fef8b6f567a0c66200fc340cb9d41a2a5c6592bd4b619415218a65d691e2"
    ),
}
COMPANION_SOURCE = {
    "repository": "Project-Helianthus/helianthus-docs-ebus",
    "commit_sha": "711a556fee344c6fe7f1ecf3253fcdb3f5f22d06",
    "manifest_path": (
        "docs/platform/manifests/"
        "modbus-foundation-profile-contract-v1.json"
    ),
    "manifest_sha256": (
        "c411e3e8a464e4b9d3a59d3f5a0c82b57e176e24dec9550b9bc0c8b3e4b28c70"
    ),
}
AUTHORIZATION_SOURCE = {
    "repository": PLAN_SOURCE["repository"],
    "issue": 71,
    "comment": 5084046142,
    "body_sha256": (
        "3333171904c729e2ab317637b37c0fac570df2c465419b1bc5b5d8fedef83356"
    ),
    "author": "d3vi1",
    "author_associations": ("MEMBER", "CONTRIBUTOR"),
    "created_at": "2026-07-26T15:04:12Z",
    "updated_at": "2026-07-26T15:04:12Z",
    "authorized_issue": "FMV3-M1-04",
}
BASE_SHA = "f4b4b9b1c7eb2d2f7bab9e29255ca97260b40c5d"
RED_EVIDENCE = (
    {
        "sha": "1cdbfe75fc5a102d7f71ac612e305bec60b34912",
        "parent": BASE_SHA,
        "files": ("rtu_adu_test.go", "rtu_endpoint_test.go"),
        "run_id": 30380293017,
        "symbols": (
            "RTUDeviceIDPlan",
            "RTUDeviceIDResult",
            "BeginDeviceID",
            "EndDeviceIDFrame",
            "EncodeRTUDeviceIDAccessADU",
            "DecodeRTUDeviceIDResponseADU",
        ),
    },
    {
        "sha": "2912af6eef9b792106f5385ce79d20c323986cf3",
        "parent": "1cdbfe75fc5a102d7f71ac612e305bec60b34912",
        "files": ("tcp_device_id_endpoint_test.go",),
        "run_id": 30381957094,
        "symbols": (),
    },
)
PULL_REQUEST = 14
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
    "./scripts/validate_companion_lock.sh",
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


def extract_plan_task(plan: bytes) -> bytes:
    start_marker = b"  - id: FMV3-M1-04\n"
    end_marker = b"  - id: FMV3-M2-01\n"
    start = plan.find(start_marker)
    end = plan.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise AcceptanceError("canonical FMV3-M1-04 plan block is missing")
    return plan[start:end]


def parse_authorization(body: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in body.splitlines():
        if ": " in line and not line.startswith("<!--"):
            key, value = line.split(": ", 1)
            fields[key] = value
    return fields


def expected_authorization_payload() -> dict[str, object]:
    body = "\n".join(
        (
            "<!-- execution-authorization:v1 -->",
            f"plan_repo: {PLAN_SOURCE['repository']}",
            f"plan_path: {PLAN_SOURCE['path']}",
            (
                "authorization_pr: https://github.com/Project-Helianthus/"
                "helianthus-execution-plans/pull/72"
            ),
            f"plan_head_sha: {PLAN_SOURCE['commit_sha']}",
            (
                "authorized_issue_contract_sha256: "
                "e2700e6da559b851fef6b9d510033f1f9b9004964d19cb8c136885c78e7da8a5"
            ),
            "authorized_issue: FMV3-M1-04",
        )
    )
    return {
        "id": AUTHORIZATION_SOURCE["comment"],
        "body": body,
        "user": {"login": AUTHORIZATION_SOURCE["author"]},
        "author_association": "MEMBER",
        "created_at": AUTHORIZATION_SOURCE["created_at"],
        "updated_at": AUTHORIZATION_SOURCE["updated_at"],
        "issue_url": (
            "https://api.github.com/repos/Project-Helianthus/"
            "helianthus-execution-plans/issues/71"
        ),
        "html_url": (
            "https://github.com/Project-Helianthus/"
            "helianthus-execution-plans/issues/71#issuecomment-5084046142"
        ),
    }


def validate_authorization(payload: dict[str, object]) -> None:
    body = payload.get("body")
    user = payload.get("user")
    if not isinstance(body, str) or not isinstance(user, dict):
        raise AcceptanceError("M1-04 authorization payload is malformed")
    expected_metadata = {
        "id": AUTHORIZATION_SOURCE["comment"],
        "author": AUTHORIZATION_SOURCE["author"],
        "created_at": AUTHORIZATION_SOURCE["created_at"],
        "updated_at": AUTHORIZATION_SOURCE["updated_at"],
        "issue_url": (
            "https://api.github.com/repos/Project-Helianthus/"
            "helianthus-execution-plans/issues/71"
        ),
        "html_url": (
            "https://github.com/Project-Helianthus/"
            "helianthus-execution-plans/issues/71#issuecomment-5084046142"
        ),
    }
    actual_metadata = {
        "id": payload.get("id"),
        "author": user.get("login"),
        "created_at": payload.get("created_at"),
        "updated_at": payload.get("updated_at"),
        "issue_url": payload.get("issue_url"),
        "html_url": payload.get("html_url"),
    }
    if (
        actual_metadata != expected_metadata
        or payload.get("author_association")
        not in AUTHORIZATION_SOURCE["author_associations"]
        or base.sha256(body.encode("utf-8"))
        != AUTHORIZATION_SOURCE["body_sha256"]
    ):
        raise AcceptanceError("M1-04 authorization provenance changed")
    expected_fields = {
        "plan_repo": PLAN_SOURCE["repository"],
        "plan_path": PLAN_SOURCE["path"],
        "authorization_pr": (
            "https://github.com/Project-Helianthus/"
            "helianthus-execution-plans/pull/72"
        ),
        "plan_head_sha": PLAN_SOURCE["commit_sha"],
        "authorized_issue_contract_sha256": (
            "e2700e6da559b851fef6b9d510033f1f9b9004964d19cb8c136885c78e7da8a5"
        ),
        "authorized_issue": AUTHORIZATION_SOURCE["authorized_issue"],
    }
    if parse_authorization(body) != expected_fields:
        raise AcceptanceError("M1-04 authorization fields changed")


def hosted_authorization(root: Path) -> dict[str, object]:
    result = subprocess.run(
        [
            "gh",
            "api",
            (
                "repos/Project-Helianthus/helianthus-execution-plans/"
                f"issues/comments/{AUTHORIZATION_SOURCE['comment']}"
            ),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError("cannot verify M1-04 execution authorization")
    return json.loads(result.stdout)


def validate_canonical_sources(
    root: Path,
    document: dict[str, object],
    *,
    plan_bytes: bytes | None,
    companion_bytes: bytes | None,
    authorization_payload: dict[str, object] | None,
    verify_hosted: bool,
) -> tuple[bytes, bytes]:
    expected = {
        "plan": PLAN_SOURCE,
        "companion": COMPANION_SOURCE,
        "authorization": {
            "repository": AUTHORIZATION_SOURCE["repository"],
            "issue": AUTHORIZATION_SOURCE["issue"],
            "comment": AUTHORIZATION_SOURCE["comment"],
            "body_sha256": AUTHORIZATION_SOURCE["body_sha256"],
            "author": AUTHORIZATION_SOURCE["author"],
            "author_associations": list(
                AUTHORIZATION_SOURCE["author_associations"]
            ),
            "created_at": AUTHORIZATION_SOURCE["created_at"],
            "updated_at": AUTHORIZATION_SOURCE["updated_at"],
            "authorized_issue": AUTHORIZATION_SOURCE["authorized_issue"],
        },
    }
    if document.get("canonical_sources") != expected:
        raise AcceptanceError("M1-04 canonical-source identity changed")
    if plan_bytes is None:
        plan_bytes = base.read_git_blob(
            PLAN_SOURCE["repository"],
            PLAN_SOURCE["commit_sha"],
            PLAN_SOURCE["path"],
        )
    if companion_bytes is None:
        companion_bytes = base.read_git_blob(
            COMPANION_SOURCE["repository"],
            COMPANION_SOURCE["commit_sha"],
            COMPANION_SOURCE["manifest_path"],
        )
    if (
        base.sha256(plan_bytes) != PLAN_SOURCE["artifact_sha256"]
        or base.sha256(extract_plan_task(plan_bytes))
        != PLAN_SOURCE["task_block_sha256"]
    ):
        raise AcceptanceError("M1-04 locked plan content changed")
    if base.sha256(companion_bytes) != COMPANION_SOURCE["manifest_sha256"]:
        raise AcceptanceError("M1-04 companion manifest changed")
    if authorization_payload is None:
        authorization_payload = (
            hosted_authorization(root)
            if verify_hosted
            else expected_authorization_payload()
        )
    validate_authorization(authorization_payload)
    return plan_bytes, companion_bytes


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
    companion_bytes: bytes,
) -> set[str]:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("M1-04 gates are missing")
    gate = gates.get("transport_gate")
    if gate != {
        "matrix_path": "policy/m1-04-transport-matrix.json",
        "matrix_sha256": (
            "0813808be5cb07010e9e696a80569a0dfff065639cb66fd2f3eaab4588cb9974"
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
    ):
        raise AcceptanceError("M1-04 transport matrix identity changed")
    companion = json.loads(companion_bytes)
    if tuple(companion.get("transport_recovery_rows", ())) != RECOVERY_ROWS:
        raise AcceptanceError("companion recovery rows changed")
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


def validate_tdd(root: Path, value: object, *, verify_hosted: bool) -> None:
    expected = {
        "base_sha": BASE_SHA,
        "test_only_commits": [item["sha"] for item in RED_EVIDENCE],
        "hosted_ci_runs": [
            {
                "commit_sha": item["sha"],
                "conclusion": "failure",
                "url": (
                    "https://github.com/Project-Helianthus/"
                    "helianthus-modbus/actions/runs/"
                    f"{item['run_id']}"
                ),
            }
            for item in RED_EVIDENCE
        ],
    }
    if not isinstance(value, dict):
        raise AcceptanceError("M1-04 TDD_RED evidence changed")
    red_required = value.get("red_required_tests")
    comparable = dict(value)
    comparable.pop("red_required_tests", None)
    if (
        comparable != expected
        or not isinstance(red_required, list)
        or set(red_required) != RED_REQUIRED_TESTS
        or len(red_required) != len(RED_REQUIRED_TESTS)
    ):
        raise AcceptanceError("M1-04 TDD_RED evidence changed")
    red_sources = ""
    for item in RED_EVIDENCE:
        sha = str(item["sha"])
        parent = str(item["parent"])
        expected_files = list(item["files"])
        base.ensure_git_object(root, sha)
        topology = subprocess.run(
            ["git", "rev-list", "--parents", "-n", "1", sha],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.split()
        if topology != [sha, parent]:
            raise AcceptanceError("M1-04 RED topology changed")
        files = subprocess.run(
            [
                "git",
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                sha,
            ],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        if files != expected_files or any(
            not path.endswith("_test.go") for path in files
        ):
            raise AcceptanceError("M1-04 RED commit is not tests-only")
        red_sources += b"".join(
            base.read_git_blob(
                "Project-Helianthus/helianthus-modbus",
                sha,
                path,
            )
            for path in files
        ).decode("utf-8")
    missing = sorted(name for name in RED_REQUIRED_TESTS if name not in red_sources)
    if missing:
        raise AcceptanceError(f"M1-04 RED tests are missing: {missing}")
    if not verify_hosted:
        return
    for item in RED_EVIDENCE:
        run_id = str(item["run_id"])
        run = subprocess.run(
            [
                "gh",
                "run",
                "view",
                run_id,
                "--repo",
                "Project-Helianthus/helianthus-modbus",
                "--json",
                "conclusion,event,headSha,workflowName,jobs",
            ],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        logs = subprocess.run(
            [
                "gh",
                "run",
                "view",
                run_id,
                "--repo",
                "Project-Helianthus/helianthus-modbus",
                "--log-failed",
            ],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
        )
        if run.returncode != 0 or logs.returncode != 0:
            raise AcceptanceError("cannot verify hosted M1-04 RED")
        payload = json.loads(run.stdout)
        jobs = {
            job.get("name"): job.get("conclusion")
            for job in payload.get("jobs", ())
            if isinstance(job, dict)
        }
        if (
            payload.get("conclusion") != "failure"
            or payload.get("event") != "pull_request"
            or payload.get("headSha") != item["sha"]
            or payload.get("workflowName") != "CI"
            or jobs.get("checks") != "failure"
            or jobs.get("lint") != "failure"
        ):
            raise AcceptanceError("hosted M1-04 RED binding changed")
        if any(symbol not in logs.stdout for symbol in item["symbols"]):
            raise AcceptanceError(
                "hosted M1-04 RED lacks missing-runtime evidence"
            )


def validate_pull_request(
    root: Path,
    value: object,
    *,
    verify_hosted: bool,
) -> None:
    if value != {
        "repository": "Project-Helianthus/helianthus-modbus",
        "number": PULL_REQUEST,
        "base": "main",
        "base_sha": BASE_SHA,
    }:
        raise AcceptanceError("M1-04 pull-request identity changed")
    if not verify_hosted:
        return
    result = subprocess.run(
        [
            "gh",
            "pr",
            "view",
            str(PULL_REQUEST),
            "--repo",
            "Project-Helianthus/helianthus-modbus",
            "--json",
            "number,state,baseRefName,headRefOid,mergeCommit,mergedAt",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError("cannot verify M1-04 pull request")
    payload = json.loads(result.stdout)
    head_sha = payload.get("headRefOid")
    if (
        payload.get("number") != PULL_REQUEST
        or payload.get("baseRefName") != "main"
        or not isinstance(head_sha, str)
    ):
        raise AcceptanceError("M1-04 pull-request metadata changed")
    head_ref = base.fetch_reviewed_pr_head(root, PULL_REQUEST, head_sha)
    if any(
        not base.git_is_ancestor(root, str(item["sha"]), head_ref)
        for item in RED_EVIDENCE
    ):
        raise AcceptanceError("M1-04 RED is not ancestral to reviewed head")
    if payload.get("state") == "OPEN":
        current = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if current != head_sha or dirty:
            raise AcceptanceError("open M1-04 validation requires clean PR head")
        return
    merge = payload.get("mergeCommit")
    if (
        payload.get("state") != "MERGED"
        or not payload.get("mergedAt")
        or not isinstance(merge, dict)
        or not isinstance(merge.get("oid"), str)
    ):
        raise AcceptanceError("M1-04 PR is neither open nor validly merged")
    merge_sha = merge["oid"]
    base.ensure_git_object(root, merge_sha)
    topology = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", merge_sha],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split()
    if topology != [merge_sha, BASE_SHA]:
        raise AcceptanceError("M1-04 merge is not one squash commit over base")
    if base.git_tree(root, head_ref) != base.git_tree(root, merge_sha):
        raise AcceptanceError("M1-04 reviewed and merged trees differ")
    if not base.git_is_ancestor(root, merge_sha, "HEAD"):
        raise AcceptanceError("M1-04 merge is not ancestral to HEAD")


def validate_static_gates(
    root: Path,
    document: dict[str, object],
    *,
    verify_hosted: bool,
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
    doc_gate = gates.get("doc_gate")
    if doc_gate != {
        "repository": COMPANION_SOURCE["repository"],
        "pull_request": 376,
        "commit_sha": COMPANION_SOURCE["commit_sha"],
        "required_check_run_url": (
            "https://github.com/Project-Helianthus/helianthus-docs-ebus/"
            "actions/runs/30238777804/job/89891563104"
        ),
    }:
        raise AcceptanceError("M1-04 doc-gate evidence changed")
    if verify_hosted:
        base.validate_doc_hosted_evidence(
            root,
            str(doc_gate["required_check_run_url"]),
        )
    validate_tdd(root, gates.get("TDD_RED"), verify_hosted=verify_hosted)
    validate_pull_request(
        root,
        gates.get("pull_request"),
        verify_hosted=verify_hosted,
    )


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
    plan_bytes: bytes | None = None,
    companion_bytes: bytes | None = None,
    authorization_payload: dict[str, object] | None = None,
    verify_hosted: bool = True,
    execute_tests: bool = True,
) -> int:
    if (
        document.get("schema")
        != "helianthus.modbus.milestone-acceptance/v2"
        or document.get("milestone") != "FMV3-M1-04"
    ):
        raise AcceptanceError("M1-04 acceptance identity changed")
    _, companion = validate_canonical_sources(
        root,
        document,
        plan_bytes=plan_bytes,
        companion_bytes=companion_bytes,
        authorization_payload=authorization_payload,
        verify_hosted=verify_hosted,
    )
    required_tests = validate_requirements(document)
    required_tests.update(
        validate_transport_matrix(root, document, companion)
    )
    validate_static_gates(root, document, verify_hosted=verify_hosted)
    validate_test_evidence(root, document, required_tests)
    if execute_tests:
        base.run_mapped_tests(root, required_tests)
    return len(required_tests)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="run structural checks without hosted publication claims",
    )
    arguments = parser.parse_args()
    try:
        document = base.load_json(ROOT / "policy" / "m1-04-acceptance.json")
        count = validate(
            ROOT,
            document,
            verify_hosted=not arguments.candidate,
        )
    except (AcceptanceError, OSError, json.JSONDecodeError) as exc:
        print(f"M1-04 acceptance failed: {exc}", file=sys.stderr)
        return 1
    disposition = "candidate-only" if arguments.candidate else "published"
    print(
        f"M1-04 {disposition} acceptance passed: "
        f"5 requirements, 21 transport rows, {count} tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
