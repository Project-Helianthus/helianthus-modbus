#!/usr/bin/env python3
"""Validate the offline-only FMV3-M1-03 RTU fixture milestone."""

from __future__ import annotations

import importlib.util
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASE_SCRIPT = ROOT / "scripts" / "validate_m1_02_acceptance.py"
BASE_SPEC = importlib.util.spec_from_file_location(
    "validate_m1_02_acceptance",
    BASE_SCRIPT,
)
if BASE_SPEC is None or BASE_SPEC.loader is None:
    raise RuntimeError("cannot load M1-02 acceptance helpers")
base = importlib.util.module_from_spec(BASE_SPEC)
BASE_SPEC.loader.exec_module(base)

AcceptanceError = base.AcceptanceError

COMPANION_SOURCE = {
    "repository": "Project-Helianthus/helianthus-docs-ebus",
    "commit_sha": "711a556fee344c6fe7f1ecf3253fcdb3f5f22d06",
    "consumer_lock_path": "policy/modbus-companion-consumer-lock-v1.json",
    "manifest_path": (
        "docs/platform/manifests/"
        "modbus-foundation-profile-contract-v1.json"
    ),
    "manifest_sha256": (
        "c411e3e8a464e4b9d3a59d3f5a0c82b57e176e24dec9550b9bc0c8b3e4b28c70"
    ),
    "policy_path": "docs/platform/modbus-foundation-profile-contract-v1.md",
    "policy_sha256": (
        "1a53f203eed42766ac2d91580c41f72674b5eaea374a1cf4fff650396f06b196"
    ),
}
PLAN_SOURCE = {
    "repository": "Project-Helianthus/helianthus-execution-plans",
    "commit_sha": "0576544bd8851c4e32da3ca7c401270eee43ef5c",
    "path": "fronius-modbus-multivendor-v3-w29-26.locked/plan.yaml",
    "artifact_sha256": (
        "c36f66d8e9b2952b9464fa5a4d64e86a314dba331cbc59d833fdf8edfd1de7d8"
    ),
    "task_block_sha256": (
        "a67d2434802c33ab2b886ce401a334daa225530e50aa41801bcb3c7952e8aed6"
    ),
}
AUTHORIZATION_SOURCE = {
    "issue": 71,
    "comment": 5084046075,
    "authorized_issue": "FMV3-M1-03",
    "plan_head_sha": PLAN_SOURCE["commit_sha"],
    "authorized_issue_contract_sha256": (
        "e2700e6da559b851fef6b9d510033f1f9b9004964d19cb8c136885c78e7da8a5"
    ),
    "body_sha256": (
        "7fea6d204082dba92951dc2229463c602ddd20aca560381f87613c1e71fea881"
    ),
    "author": "d3vi1",
    "author_association": "MEMBER",
    "created_at": "2026-07-26T15:04:11Z",
    "updated_at": "2026-07-26T15:04:11Z",
}
EXPECTED_REQUIREMENTS = (
    ("rtu_typed_framing_crc_and_bounds", "execution_plan#acceptance.framing_crc"),
    ("rtu_silent_interval_contract", "execution_plan#acceptance.silent_intervals"),
    ("rtu_single_fixture_owner", "execution_plan#rtu_abandonment_contract.scope"),
    ("rtu_abnormal_transmit_quarantine", "execution_plan#abnormal_write_results"),
    (
        "rtu_owned_timeout_and_cancellation",
        "execution_plan#rtu_abandonment_contract.response_wait_abandonment",
    ),
    (
        "rtu_discard_resynchronize_and_recover",
        "execution_plan#rtu_abandonment_contract",
    ),
    (
        "rtu_fixture_only_capability",
        "execution_plan#rtu_physical_qualification_contract.fixture_only",
    ),
    ("rtu_replay_and_provenance", "companion_contract#observability-and-provenance"),
)
RTU_RECOVERY_ROWS = (
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
EXPECTED_CI_COMMANDS = (
    "./scripts/validate_companion_lock.sh",
    "./scripts/scope_gate.sh",
    "GOWORK=off go run ./scripts/read_only_surface .",
    "python3 scripts/validate_m1_02_acceptance.py",
    "python3 scripts/validate_m1_03_acceptance.py",
    "python3 -m unittest discover -s tests -p 'test_*.py'",
    "GOWORK=off go vet ./...",
    "GOWORK=off go build ./...",
    "GOWORK=off GOOS=linux GOARCH=386 go test -c -o /dev/null .",
    "GOWORK=off go test -race -count=1 ./...",
)
RTU_PRODUCT_FILES = (
    "rtu_adu.go",
    "rtu_capability.go",
    "rtu_endpoint.go",
    "rtu_timing.go",
)
RTU_TEST_FILES = {
    "rtu_adu_test.go",
    "rtu_capability_test.go",
    "rtu_endpoint_test.go",
    "rtu_timing_test.go",
}
EXPECTED_TEST_GO_FILES = {
    "device_id_test.go",
    "pdu_test.go",
    "rtu_adu_test.go",
    "rtu_capability_test.go",
    "rtu_endpoint_test.go",
    "rtu_timing_test.go",
    "tcp_adu_test.go",
    "tcp_coalescing_test.go",
    "tcp_endpoint_test.go",
    "tcp_owner_test.go",
    "tcp_pool_test.go",
    "tcp_scheduler_test.go",
    "tcp_transport_test.go",
}
FORBIDDEN_COMPILED_FIELDS = (
    "CgoFiles",
    "CFiles",
    "CXXFiles",
    "MFiles",
    "HFiles",
    "FFiles",
    "SFiles",
    "SwigFiles",
    "SwigCXXFiles",
    "SysoFiles",
    "EmbedFiles",
    "TestEmbedFiles",
    "XTestEmbedFiles",
)
FORBIDDEN_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".m",
    ".mm",
    ".h",
    ".hh",
    ".hpp",
    ".f",
    ".for",
    ".f90",
    ".s",
    ".S",
    ".syso",
    ".swig",
    ".swigcxx",
}
CI_WORKFLOW_SHA256 = (
    "af8ef40d498d5f29dd67afb573d6082e8290e1d03820634e8acc64b9b171fbf5"
)
CI_LOCAL_SHA256 = (
    "22a6c2e861d066e89ff3adb551ab73eeb3d3a652eccd731c25c6e5d42f5e4589"
)
TRANSPORT_OVERRIDE_SOURCE = {
    "baseline_matrix": "T01..T88",
    "disposition": "NOT_APPLICABLE_FIXTURE_ONLY",
    "replacement_matrix": "policy/m1-03-transport-matrix.json",
    "repository": "Project-Helianthus/helianthus-modbus",
    "issue": 9,
    "comment": 5106470845,
    "label": "transport-gate-override",
    "body_sha256": (
        "20d79a154fb5ab5c15c0cf123ef11c9d315fbdd3b0fff1689f39a40d62432fba"
    ),
    "author": "d3vi1",
    "author_association": "MEMBER",
    "created_at": "2026-07-28T15:54:47Z",
    "updated_at": "2026-07-28T15:54:47Z",
}
EXPECTED_REQUIREMENT_MAPPING_SHA256 = (
    "a5648d9f4c27d9c1a9b88d1ea01a3258ce782b787c7aa9474ff4816f0b76863b"
)
EXPECTED_TRANSPORT_MAPPING_SHA256 = (
    "d1016a1b8aec0f6c809e428c54f699b0ff24db167f174903f07a030b59bacb8b"
)
EXPECTED_TEST_SOURCE_MAPPING_SHA256 = (
    "760fb4bfd7d286b76513128087385575f283627c6cdfb6b6fb8fd093f9a11161"
)
RED_REQUIRED_TESTS = (
    "TestEncodeRTUReadADUKnownCRCVector",
    "TestDecodeRTUReadResponseKnownCRCVector",
    "TestRTUTimingAtOrBelow19200UsesCeilingCharacterMultiples",
    "TestRTUCapabilityIsFixtureOnlyExperimentalAndDefaultDisabled",
    "TestRTUEndpointClaimsOneFixtureIdentity",
    "TestRTUUnsafeTransmitResultsEnterQuarantine",
    "TestRTULateSameShapeFrameIsDiscarded",
)


def extract_plan_task(plan: bytes) -> bytes:
    start_marker = b"  - id: FMV3-M1-03\n"
    end_marker = b"  - id: FMV3-M1-04\n"
    start = plan.find(start_marker)
    end = plan.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise AcceptanceError("canonical FMV3-M1-03 plan block is missing")
    return plan[start:end]


def canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base.sha256(encoded)


def parse_authorization(body: str) -> dict[str, str]:
    if "<!-- execution-authorization:v1 -->" not in body:
        raise AcceptanceError("execution authorization marker is missing")
    fields: dict[str, str] = {}
    for line in body.splitlines():
        if ": " in line and not line.startswith("<!--"):
            key, value = line.split(": ", 1)
            fields[key] = value
    return fields


def validate_authorization(payload: dict[str, object]) -> None:
    body = payload.get("body")
    user = payload.get("user")
    if (
        not isinstance(body, str)
        or payload.get("id") != AUTHORIZATION_SOURCE["comment"]
        or not isinstance(user, dict)
        or user.get("login") != AUTHORIZATION_SOURCE["author"]
        or payload.get("author_association")
        != AUTHORIZATION_SOURCE["author_association"]
        or payload.get("created_at") != AUTHORIZATION_SOURCE["created_at"]
        or payload.get("updated_at") != AUTHORIZATION_SOURCE["updated_at"]
        or base.sha256(body.encode("utf-8"))
        != AUTHORIZATION_SOURCE["body_sha256"]
        or payload.get("issue_url")
        != (
            "https://api.github.com/repos/Project-Helianthus/"
            "helianthus-execution-plans/issues/71"
        )
        or payload.get("html_url")
        != (
            "https://github.com/Project-Helianthus/"
            "helianthus-execution-plans/issues/71#issuecomment-5084046075"
        )
    ):
        raise AcceptanceError("execution authorization provenance changed")
    fields = parse_authorization(body)
    expected = {
        "plan_repo": PLAN_SOURCE["repository"],
        "plan_path": PLAN_SOURCE["path"],
        "authorization_pr": (
            "https://github.com/Project-Helianthus/"
            "helianthus-execution-plans/pull/72"
        ),
        "plan_head_sha": AUTHORIZATION_SOURCE["plan_head_sha"],
        "authorized_issue_contract_sha256": (
            AUTHORIZATION_SOURCE["authorized_issue_contract_sha256"]
        ),
        "authorized_issue": AUTHORIZATION_SOURCE["authorized_issue"],
    }
    if fields != expected:
        raise AcceptanceError("execution authorization fields changed")


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
        raise AcceptanceError(
            f"cannot verify execution authorization: {result.stderr.strip()}"
        )
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("execution authorization is invalid JSON") from exc
    if not isinstance(payload, dict):
        raise AcceptanceError("execution authorization is not an object")
    return payload


def validate_authorization_pull(root: Path) -> None:
    result = subprocess.run(
        [
            "gh",
            "pr",
            "view",
            "72",
            "--repo",
            "Project-Helianthus/helianthus-execution-plans",
            "--json",
            "number,state,baseRefName,mergeCommit,mergedAt",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    ancestry = subprocess.run(
        [
            "gh",
            "api",
            (
                "repos/Project-Helianthus/helianthus-execution-plans/"
                f"compare/{PLAN_SOURCE['commit_sha']}...main"
            ),
            "--jq",
            ".status",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or ancestry.returncode != 0:
        raise AcceptanceError("cannot verify authorization PR ancestry")
    payload = json.loads(result.stdout)
    merge = payload.get("mergeCommit")
    if (
        payload.get("number") != 72
        or payload.get("state") != "MERGED"
        or payload.get("baseRefName") != "main"
        or not payload.get("mergedAt")
        or not isinstance(merge, dict)
        or merge.get("oid") != PLAN_SOURCE["commit_sha"]
        or ancestry.stdout.strip() not in {"ahead", "identical"}
    ):
        raise AcceptanceError("authorization PR or main ancestry changed")


def validate_canonical_sources(
    root: Path,
    document: dict[str, object],
    *,
    plan_bytes: bytes | None = None,
    authorization_payload: dict[str, object] | None = None,
    verify_hosted: bool,
) -> None:
    if document.get("canonical_sources") != {
        "companion_contract": COMPANION_SOURCE,
        "execution_plan": PLAN_SOURCE,
        "execution_authorization": AUTHORIZATION_SOURCE,
    }:
        raise AcceptanceError("canonical source identity changed")
    lock = base.load_json(root / COMPANION_SOURCE["consumer_lock_path"])
    for field, expected in {
        "repository": COMPANION_SOURCE["repository"],
        "merged_commit_sha": COMPANION_SOURCE["commit_sha"],
        "manifest_sha256": COMPANION_SOURCE["manifest_sha256"],
    }.items():
        if lock.get(field) != expected:
            raise AcceptanceError(f"companion lock changed field {field}")
    if plan_bytes is None:
        plan_bytes = base.read_git_blob(
            PLAN_SOURCE["repository"],
            PLAN_SOURCE["commit_sha"],
            PLAN_SOURCE["path"],
        )
    if base.sha256(plan_bytes) != PLAN_SOURCE["artifact_sha256"]:
        raise AcceptanceError("canonical execution-plan artifact changed")
    if base.sha256(extract_plan_task(plan_bytes)) != PLAN_SOURCE["task_block_sha256"]:
        raise AcceptanceError("canonical FMV3-M1-03 task block changed")
    if authorization_payload is None and verify_hosted:
        authorization_payload = hosted_authorization(root)
    if authorization_payload is not None:
        validate_authorization(authorization_payload)
    if verify_hosted:
        validate_authorization_pull(root)


def validate_requirement_contract(document: dict[str, object]) -> set[str]:
    requirements = document.get("requirements")
    if not isinstance(requirements, list):
        raise AcceptanceError("requirements must be a list")
    identity = tuple(
        (item.get("id"), item.get("source"))
        for item in requirements
        if isinstance(item, dict)
    )
    if identity != EXPECTED_REQUIREMENTS:
        raise AcceptanceError("canonical requirement identity or order changed")
    if canonical_hash(requirements) != EXPECTED_REQUIREMENT_MAPPING_SHA256:
        raise AcceptanceError("canonical requirement-to-test mapping changed")
    mapped: set[str] = set()
    for requirement in requirements:
        tests = requirement.get("tests")
        if (
            not isinstance(tests, list)
            or not tests
            or any(not isinstance(name, str) or not name for name in tests)
            or len(tests) != len(set(tests))
        ):
            raise AcceptanceError(
                f"invalid test evidence for {requirement.get('id')}"
            )
        mapped.update(tests)
    return mapped


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
    if relative != "policy/m1-03-transport-matrix.json":
        raise AcceptanceError("RTU transport matrix path changed")
    path = root / relative
    if base.sha256(path.read_bytes()) != gate.get("matrix_sha256"):
        raise AcceptanceError("RTU transport matrix hash changed")
    matrix = base.load_json(path)
    if (
        matrix.get("schema") != "helianthus.modbus.transport-gate/v1"
        or matrix.get("milestone") != "FMV3-M1-03"
        or matrix.get("disposition") != "FIXTURE_ONLY_NO_HARDWARE"
        or matrix.get("execution_surface") != "offline_fixture_only"
    ):
        raise AcceptanceError("RTU transport matrix identity changed")
    rows = matrix.get("rows")
    if not isinstance(rows, list) or tuple(
        row.get("id") for row in rows if isinstance(row, dict)
    ) != RTU_RECOVERY_ROWS:
        raise AcceptanceError("RTU transport row identity or order changed")
    if canonical_hash(rows) != EXPECTED_TRANSPORT_MAPPING_SHA256:
        raise AcceptanceError("RTU transport row-to-test mapping changed")
    tests: set[str] = set()
    for row in rows:
        row_tests = row.get("tests")
        if (
            not isinstance(row_tests, list)
            or not row_tests
            or len(row_tests) != len(set(row_tests))
        ):
            raise AcceptanceError(
                f"RTU transport row {row.get('id')} lacks tests"
            )
        tests.update(row_tests)
    return tests


def validate_transport_override_payload(payload: dict[str, object]) -> None:
    user = payload.get("user")
    body = payload.get("body")
    if (
        payload.get("id") != TRANSPORT_OVERRIDE_SOURCE["comment"]
        or not isinstance(body, str)
        or base.sha256(body.encode("utf-8"))
        != TRANSPORT_OVERRIDE_SOURCE["body_sha256"]
        or not isinstance(user, dict)
        or user.get("login") != TRANSPORT_OVERRIDE_SOURCE["author"]
        or payload.get("author_association")
        != TRANSPORT_OVERRIDE_SOURCE["author_association"]
        or payload.get("created_at") != TRANSPORT_OVERRIDE_SOURCE["created_at"]
        or payload.get("updated_at") != TRANSPORT_OVERRIDE_SOURCE["updated_at"]
        or payload.get("issue_url")
        != (
            "https://api.github.com/repos/Project-Helianthus/"
            "helianthus-modbus/issues/9"
        )
        or payload.get("html_url")
        != (
            "https://github.com/Project-Helianthus/helianthus-modbus/"
            "issues/9#issuecomment-5106470845"
        )
    ):
        raise AcceptanceError("transport-gate override provenance changed")


def validate_transport_override(
    root: Path,
    gate: dict[str, object],
    *,
    verify_hosted: bool,
) -> None:
    override = gate.get("owner_override")
    if override != TRANSPORT_OVERRIDE_SOURCE:
        raise AcceptanceError("transport-gate owner override changed")
    if not verify_hosted:
        return
    comment = subprocess.run(
        [
            "gh",
            "api",
            (
                "repos/Project-Helianthus/helianthus-modbus/"
                f"issues/comments/{TRANSPORT_OVERRIDE_SOURCE['comment']}"
            ),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    issue = subprocess.run(
        [
            "gh",
            "api",
            "repos/Project-Helianthus/helianthus-modbus/issues/9",
            "--jq",
            "{number,state,labels:[.labels[].name]}",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if comment.returncode != 0 or issue.returncode != 0:
        raise AcceptanceError("cannot verify transport-gate owner override")
    validate_transport_override_payload(json.loads(comment.stdout))
    issue_payload = json.loads(issue.stdout)
    if (
        issue_payload.get("number") != 9
        or issue_payload.get("state") not in {"open", "closed"}
        or TRANSPORT_OVERRIDE_SOURCE["label"]
        not in issue_payload.get("labels", ())
    ):
        raise AcceptanceError("transport-gate override label changed")


def changed_files(root: Path, commit: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"cannot inspect TDD commit {commit}")
    return [line for line in result.stdout.splitlines() if line]


def git_parent(root: Path, commit: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", f"{commit}^"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError(f"cannot inspect TDD parent {commit}")
    return result.stdout.strip()


def validate_tdd_hosted_payload(
    red_head: str,
    hosted: dict[str, object],
    failed_log: str,
) -> None:
    if (
        hosted.get("conclusion") != "failure"
        or hosted.get("event") != "pull_request"
        or hosted.get("headSha") != red_head
        or hosted.get("workflowName") != "CI"
    ):
        raise AcceptanceError("hosted RTU TDD_RED evidence changed")
    jobs = hosted.get("jobs")
    failed = {
        job.get("name")
        for job in jobs
        if isinstance(job, dict) and job.get("conclusion") == "failure"
    } if isinstance(jobs, list) else set()
    if not {"checks", "lint"}.issubset(failed):
        raise AcceptanceError("hosted RTU TDD_RED jobs did not both fail")
    markers = (
        "undefined: RTUEvent",
        "undefined: RTUFixtureEndpoint",
        "undefined: RTUReadPlan",
        "undefined: RTUTiming",
        "undefined: EncodeRTUReadADU",
        "undefined: DecodeRTUReadResponseADU",
    )
    missing = [marker for marker in markers if marker not in failed_log]
    if missing:
        raise AcceptanceError(
            f"hosted RTU TDD_RED lacks missing-runtime evidence: {missing}"
        )


def validate_tdd_hosted_binding(
    red_head: str,
    run: dict[str, object],
    pulls: object,
) -> str:
    if run != {
        "id": 30367710672,
        "event": "pull_request",
        "head_sha": red_head,
        "head_branch": "issue/9-fixture-only-modbus-rtu",
        "path": ".github/workflows/ci.yml",
        "run_attempt": 1,
        "conclusion": "failure",
    }:
        raise AcceptanceError("hosted RTU TDD_RED run binding changed")
    expected_pull = {
        "number": 10,
        "base_ref": "main",
        "base_sha": "79f9c6da6efd5be9f3e31ddf62720c1a3d0bf3e7",
    }
    if not isinstance(pulls, list) or len(pulls) != 1:
        raise AcceptanceError("hosted RTU TDD_RED PR/base binding changed")
    pull = pulls[0]
    if (
        not isinstance(pull, dict)
        or pull.get("state") not in {"open", "closed"}
        or {key: pull.get(key) for key in expected_pull} != expected_pull
        or set(pull) != {*expected_pull, "state", "head_sha"}
        or not isinstance(pull.get("head_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", str(pull["head_sha"])) is None
    ):
        raise AcceptanceError("hosted RTU TDD_RED PR/base binding changed")
    return str(pull["head_sha"])


def validate_tdd(
    root: Path,
    value: object,
    *,
    verify_hosted: bool,
) -> None:
    if not isinstance(value, dict):
        raise AcceptanceError("RTU TDD_RED evidence is missing")
    base_sha = value.get("base_sha")
    commits = value.get("test_only_commits")
    red_tests = value.get("red_required_tests")
    if (
        base_sha != "79f9c6da6efd5be9f3e31ddf62720c1a3d0bf3e7"
        or commits
        != [
            "89aba4e3df8a09b61713961556058c59e715eabe",
            "f5e55fccafc060c5556d5510ddb373dc8dbc2bf4",
        ]
        or value.get("hosted_ci_conclusion") != "failure"
        or tuple(red_tests) != RED_REQUIRED_TESTS
    ):
        raise AcceptanceError("RTU TDD_RED contract changed")
    base.ensure_full_history(root)
    for commit in [base_sha, *commits]:
        base.ensure_git_object(root, commit)
    if git_parent(root, commits[0]) != base_sha or git_parent(
        root,
        commits[1],
    ) != commits[0]:
        raise AcceptanceError("RTU TDD_RED commit chain changed")
    allowed_files = {
        "rtu_adu_test.go",
        "rtu_capability_test.go",
        "rtu_endpoint_test.go",
        "rtu_timing_test.go",
    }
    for commit in commits:
        files = changed_files(root, commit)
        if not files or any(path not in allowed_files for path in files):
            raise AcceptanceError(
                f"RTU TDD_RED commit is not tests-only: {commit} {files}"
            )
    sources = subprocess.run(
        ["git", "grep", "-h", "-E", r"^func Test[A-Za-z0-9_]+\(", commits[-1]],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if sources.returncode != 0:
        raise AcceptanceError("cannot inspect RTU TDD_RED tests")
    available = set(
        re.findall(r"^func (Test[A-Za-z0-9_]+)\(", sources.stdout, re.MULTILINE)
    )
    if not set(red_tests).issubset(available):
        raise AcceptanceError("RTU TDD_RED lacks required failing tests")
    run_url = value.get("hosted_ci_run_url")
    if (
        run_url
        != "https://github.com/Project-Helianthus/"
        "helianthus-modbus/actions/runs/30367710672"
    ):
        raise AcceptanceError("RTU TDD_RED hosted run changed")
    if not verify_hosted:
        return
    result = subprocess.run(
        [
            "gh",
            "run",
            "view",
            "30367710672",
            "--repo",
            "Project-Helianthus/helianthus-modbus",
            "--json",
            "conclusion,event,headSha,jobs,workflowName",
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
            "30367710672",
            "--repo",
            "Project-Helianthus/helianthus-modbus",
            "--log-failed",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    run = subprocess.run(
        [
            "gh",
            "api",
            (
                "repos/Project-Helianthus/helianthus-modbus/"
                "actions/runs/30367710672"
            ),
            "--jq",
            (
                "{id,event,head_sha,head_branch,path,run_attempt,conclusion}"
            ),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    pulls = subprocess.run(
        [
            "gh",
            "api",
            (
                "repos/Project-Helianthus/helianthus-modbus/commits/"
                f"{commits[-1]}/pulls"
            ),
            "--jq",
            (
                "map({number,state,base_ref:.base.ref,"
                "base_sha:.base.sha,head_sha:.head.sha})"
            ),
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if (
        result.returncode != 0
        or logs.returncode != 0
        or run.returncode != 0
        or pulls.returncode != 0
    ):
        raise AcceptanceError("cannot verify hosted RTU TDD_RED evidence")
    validate_tdd_hosted_payload(
        commits[-1],
        json.loads(result.stdout),
        logs.stdout,
    )
    associated_head = validate_tdd_hosted_binding(
        commits[-1],
        json.loads(run.stdout),
        json.loads(pulls.stdout),
    )
    base.ensure_git_object(root, associated_head)
    if not base.git_is_ancestor(root, commits[-1], associated_head):
        raise AcceptanceError("RTU TDD_RED is not ancestral to associated PR head")


def validate_pull_request(
    root: Path,
    value: object,
    red_head: str,
    *,
    verify_hosted: bool,
    require_published: bool,
) -> None:
    if value != {
        "repository": "Project-Helianthus/helianthus-modbus",
        "number": 10,
        "base": "main",
        "base_sha": "79f9c6da6efd5be9f3e31ddf62720c1a3d0bf3e7",
    }:
        raise AcceptanceError("M1-03 pull-request identity changed")
    if not verify_hosted or not require_published:
        if not base.git_is_ancestor(root, red_head, "HEAD"):
            raise AcceptanceError("RTU TDD_RED is not ancestral to HEAD")
        return
    result = subprocess.run(
        [
            "gh",
            "pr",
            "view",
            "10",
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
        raise AcceptanceError(
            f"cannot verify M1-03 pull request: {result.stderr.strip()}"
        )
    payload = json.loads(result.stdout)
    if payload.get("number") != 10 or payload.get("baseRefName") != "main":
        raise AcceptanceError("M1-03 pull-request metadata changed")
    head_sha = payload.get("headRefOid")
    if not isinstance(head_sha, str):
        raise AcceptanceError("M1-03 pull-request head is missing")
    head_ref = base.fetch_reviewed_pr_head(root, 10, head_sha)
    if not base.git_is_ancestor(root, red_head, head_ref):
        raise AcceptanceError("RTU TDD_RED is not ancestral to PR head")
    state = payload.get("state")
    if state == "OPEN":
        current = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if current != head_sha:
            raise AcceptanceError("open M1-03 PR head differs from checkout")
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if dirty:
            raise AcceptanceError(
                "open M1-03 PR validation requires a clean published checkout"
            )
        return
    merge = payload.get("mergeCommit")
    if (
        state != "MERGED"
        or not payload.get("mergedAt")
        or not isinstance(merge, dict)
        or not isinstance(merge.get("oid"), str)
    ):
        raise AcceptanceError("M1-03 PR is neither open nor validly merged")
    merge_sha = merge["oid"]
    base.ensure_git_object(root, merge_sha)
    topology = subprocess.run(
        ["git", "rev-list", "--parents", "-n", "1", merge_sha],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if topology.returncode != 0:
        raise AcceptanceError("cannot inspect M1-03 merge topology")
    validate_squash_topology(
        merge_sha,
        str(value["base_sha"]),
        topology.stdout,
    )
    if base.git_tree(root, head_ref) != base.git_tree(root, merge_sha):
        raise AcceptanceError("M1-03 reviewed and squash-merged trees differ")
    if not base.git_is_ancestor(root, merge_sha, "HEAD"):
        raise AcceptanceError("M1-03 squash merge is not ancestral to HEAD")


def validate_squash_topology(
    merge_sha: str,
    base_sha: str,
    revision_line: str,
) -> None:
    parts = revision_line.split()
    if len(parts) != 2 or parts[0] != merge_sha or parts[1] != base_sha:
        raise AcceptanceError("M1-03 merge is not one squash commit over its base")


def validate_compiled_inventory(
    package: dict[str, object],
    policy: dict[str, object],
) -> None:
    if (
        set(package.get("GoFiles", ()))
        != set(policy.get("allowed_product_go_files", ()))
        or set(package.get("TestGoFiles", ())) != EXPECTED_TEST_GO_FILES
        or package.get("XTestGoFiles")
        or any(package.get(field) for field in FORBIDDEN_COMPILED_FIELDS)
    ):
        raise AcceptanceError("compiled product, test, or non-Go inventory changed")


def validate_offline_source_filesystem(root: Path) -> None:
    forbidden_sources = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and ".git" not in path.parts
        and path.suffix in FORBIDDEN_SOURCE_SUFFIXES
    )
    if forbidden_sources:
        raise AcceptanceError(
            f"non-Go compilable source files are forbidden: {forbidden_sources}"
        )
    embedded = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*.go")
        if ".git" not in path.parts
        and "//go:embed" in path.read_text(encoding="utf-8")
    )
    if embedded:
        raise AcceptanceError(f"embedded product/test assets are forbidden: {embedded}")


def validate_offline_surface(root: Path, value: object) -> None:
    if value != {
        "physical_io_sites": 0,
        "gateway_dependencies": 0,
        "vendor_profile_dependencies": 0,
        "cgo_files": 0,
        "go_mod_sha256": (
            "c64fd63d81e8a9c6b013d06f8db676621b3945be57e203bd004910270383617f"
        ),
    }:
        raise AcceptanceError("offline RTU surface gate changed")
    if base.sha256((root / "go.mod").read_bytes()) != value["go_mod_sha256"]:
        raise AcceptanceError("go.mod changed")
    if (root / "go.sum").exists():
        raise AcceptanceError("unexpected external module dependency lock")
    validate_offline_source_filesystem(root)
    listed = subprocess.run(
        ["go", "list", "-json", "."],
        cwd=root,
        env={**__import__("os").environ, "GOWORK": "off"},
        check=False,
        capture_output=True,
        text=True,
    )
    if listed.returncode != 0:
        raise AcceptanceError(f"go list failed: {listed.stderr.strip()}")
    package = json.loads(listed.stdout)
    policy = base.load_json(root / "policy" / "phase1-readonly.json")
    validate_compiled_inventory(package, policy)
    forbidden_patterns = (
        r"/dev/",
        r"\btty[A-Za-z0-9]*\b",
        r"\bCOM[0-9]+\b",
        r"\bio\.(?:Reader|Writer|ReadWriter)\b",
        r"\bos\.Open(?:File)?\b",
        r"\bnet\.Conn\b",
        r"\.Write\s*\(",
    )
    for relative in RTU_PRODUCT_FILES:
        source = (root / relative).read_text(encoding="utf-8")
        for pattern in forbidden_patterns:
            if re.search(pattern, source):
                raise AcceptanceError(
                    f"{relative} exposes physical I/O pattern {pattern}"
                )
        if re.search(
            r'github\.com/Project-Helianthus/(?!helianthus-modbus(?:/|"))',
            source,
        ):
            raise AcceptanceError(f"{relative} imports another Helianthus repo")
    capability = (root / "rtu_capability.go").read_text(encoding="utf-8")
    if (
        capability.count('"FIXTURE_ONLY_NO_HARDWARE"') != 1
        or 'RTUMaturityExperimental RTUMaturity = "experimental"' not in capability
        or "func (RTUCapability) DefaultEnabled() bool {\n\treturn false\n}" not in capability
        or "func (RTUCapability) Supported() bool {\n\treturn false\n}" not in capability
        or "func (RTUCapability) HardwareQualified() bool {\n\treturn false\n}"
        not in capability
    ):
        raise AcceptanceError("fixture-only RTU capability claim changed")
    adu = (root / "rtu_adu.go").read_text(encoding="utf-8")
    if re.search(r"^func [A-Z]\w*CRC", adu, re.MULTILINE):
        raise AcceptanceError("public raw RTU CRC surface is forbidden")


def validate_ci_mode_controls(root: Path) -> str:
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    if (
        base.sha256(workflow.encode("utf-8")) != CI_WORKFLOW_SHA256
        or base.sha256((root / "scripts" / "ci_local.sh").read_bytes())
        != CI_LOCAL_SHA256
    ):
        raise AcceptanceError("CI publication-mode control changed")
    exact_head_checkout = (
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}"
    )
    if workflow.count(exact_head_checkout) != 2:
        raise AcceptanceError("CI does not test the exact PR head and push SHA")
    return workflow


def validate_gate_contract(
    root: Path,
    document: dict[str, object],
    *,
    verify_hosted: bool,
    require_published: bool,
) -> None:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("gate evidence is missing")
    ci = gates.get("CI")
    if not isinstance(ci, dict) or tuple(ci.get("commands", ())) != (
        EXPECTED_CI_COMMANDS
    ):
        raise AcceptanceError("M1-03 CI command contract changed")
    validate_ci_mode_controls(root)
    doc_gate = gates.get("doc_gate")
    if not isinstance(doc_gate, dict) or doc_gate != {
        "repository": COMPANION_SOURCE["repository"],
        "commit_sha": COMPANION_SOURCE["commit_sha"],
        "required_check_run_url": (
            "https://github.com/Project-Helianthus/helianthus-docs-ebus/"
            "actions/runs/30238777804/job/89891563104"
        ),
    }:
        raise AcceptanceError("M1-03 doc-gate evidence changed")
    if verify_hosted:
        base.validate_doc_hosted_evidence(
            root,
            doc_gate["required_check_run_url"],
        )
    hardware = gates.get("hardware_conditional")
    if hardware != {
        "required_disposition": "FIXTURE_ONLY_NO_HARDWARE",
        "physical_evidence_required": False,
        "supported_claim": False,
        "enabled_claim": False,
    }:
        raise AcceptanceError("M1-03 hardware-conditional gate changed")
    transport_gate = gates.get("transport_gate")
    if not isinstance(transport_gate, dict):
        raise AcceptanceError("RTU transport gate evidence is missing")
    validate_transport_override(
        root,
        transport_gate,
        verify_hosted=verify_hosted,
    )
    validate_offline_surface(root, gates.get("offline_surface"))
    red = gates.get("TDD_RED")
    validate_tdd(root, red, verify_hosted=verify_hosted)
    if not isinstance(red, dict):
        raise AcceptanceError("RTU TDD_RED evidence is missing")
    commits = red.get("test_only_commits")
    if not isinstance(commits, list) or len(commits) != 2:
        raise AcceptanceError("RTU TDD_RED commit chain is missing")
    validate_pull_request(
        root,
        gates.get("pull_request"),
        commits[-1],
        verify_hosted=verify_hosted,
        require_published=require_published,
    )


def validate_test_evidence(
    root: Path,
    document: dict[str, object],
    required_tests: set[str],
) -> None:
    evidence = base.test_evidence(root)
    if evidence.get("test_mains"):
        raise AcceptanceError(f"TestMain is forbidden: {evidence['test_mains']}")
    declared = document.get("test_file_sha256")
    if not isinstance(declared, dict) or set(declared) != RTU_TEST_FILES:
        raise AcceptanceError("M1-03 RTU test-file inventory changed")
    actual_files = evidence.get("test_files")
    if not isinstance(actual_files, dict):
        raise AcceptanceError("test-file evidence is missing")
    filesystem_test_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*_test.go")
        if ".git" not in path.parts
    }
    if filesystem_test_files != EXPECTED_TEST_GO_FILES:
        raise AcceptanceError("filesystem Go test-file inventory changed")
    if set(actual_files) != EXPECTED_TEST_GO_FILES:
        raise AcceptanceError("complete Go test-file inventory changed")
    base.validate_declared_test_files(actual_files, declared)
    sources = evidence.get("test_sources")
    if not isinstance(sources, dict):
        raise AcceptanceError("test-source evidence is missing")
    actual_rtu_tests = {
        name
        for name, source in sources.items()
        if source in RTU_TEST_FILES
    }
    if actual_rtu_tests != required_tests:
        raise AcceptanceError(
            "mapped tests do not equal the complete RTU test inventory"
        )
    source_mapping = {
        name: sources.get(name)
        for name in sorted(required_tests)
    }
    if canonical_hash(source_mapping) != EXPECTED_TEST_SOURCE_MAPPING_SHA256:
        raise AcceptanceError("RTU test-to-source mapping changed")


def validate(
    root: Path,
    document: dict[str, object],
    *,
    plan_bytes: bytes | None = None,
    authorization_payload: dict[str, object] | None = None,
    verify_hosted: bool = True,
    require_published: bool = True,
    execute_tests: bool = True,
) -> int:
    if (
        document.get("schema")
        != "helianthus.modbus.milestone-acceptance/v2"
        or document.get("milestone") != "FMV3-M1-03"
    ):
        raise AcceptanceError("M1-03 acceptance identity changed")
    validate_canonical_sources(
        root,
        document,
        plan_bytes=plan_bytes,
        authorization_payload=authorization_payload,
        verify_hosted=verify_hosted,
    )
    required_tests = validate_requirement_contract(document)
    required_tests.update(validate_transport_matrix(root, document))
    validate_gate_contract(
        root,
        document,
        verify_hosted=verify_hosted,
        require_published=require_published,
    )
    validate_test_evidence(root, document, required_tests)
    if execute_tests:
        base.run_mapped_tests(root, required_tests)
    return len(required_tests)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--candidate",
        action="store_true",
        help="run structural checks without claiming hosted publication",
    )
    arguments = parser.parse_args()
    try:
        document = base.load_json(ROOT / "policy" / "m1-03-acceptance.json")
        count = validate(
            ROOT,
            document,
            verify_hosted=not arguments.candidate,
            require_published=not arguments.candidate,
        )
    except (AcceptanceError, OSError, json.JSONDecodeError) as exc:
        print(f"M1-03 acceptance failed: {exc}", file=sys.stderr)
        return 1
    disposition = "candidate-only" if arguments.candidate else "published"
    print(
        f"M1-03 {disposition} acceptance passed: "
        f"{len(EXPECTED_REQUIREMENTS)} requirements, "
        f"{len(RTU_RECOVERY_ROWS)} transport rows, {count} tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
