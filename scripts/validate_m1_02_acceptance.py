#!/usr/bin/env python3
"""Validate FMV3-M1-02 against its external plan and companion contracts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


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
    "commit_sha": "e633fa22a6a6fe3e4f3b74a68eb44401fe26f38d",
    "path": (
        "fronius-modbus-multivendor-v3-w29-26.implementing/plan.yaml"
    ),
    "artifact_sha256": (
        "14f5a38e332f1a46abddee8fe551d357474bf6ad8200349ef0c1b9ca995ed85e"
    ),
    "task_block_sha256": (
        "0e69ce6935da0015a66f5243c2c0108e48cd75f10e81c0c834e197c20c1ac854"
    ),
}
M1_01_SHA = "c9b3281b5025fd3b1b714235493bd36d526f865f"
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
    "./scripts/validate_companion_lock.sh",
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


def docs_run_and_job_ids(check_url: str) -> tuple[str, str]:
    match = re.fullmatch(
        r"https://github\.com/Project-Helianthus/helianthus-docs-ebus/"
        r"actions/runs/(\d+)/job/(\d+)",
        check_url,
    )
    if match is None:
        raise AcceptanceError("doc-gate required-check evidence is missing")
    return match.group(1), match.group(2)


def load_json(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AcceptanceError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise AcceptanceError(f"{path} must contain a JSON object")
    return value


def validate_reviewed_revision_payload(
    evidence: object,
    pull_request: object,
    *,
    red_is_ancestor_of_reviewed_head: bool,
    reviewed_head_tree: str,
    squash_merge_tree: str,
    squash_merge_is_ancestor_of_head: bool,
) -> None:
    if not isinstance(evidence, dict) or not isinstance(pull_request, dict):
        raise AcceptanceError("reviewed revision evidence is missing")
    expected_keys = {
        "repository",
        "pull_request",
        "reviewed_head_sha",
        "reviewed_head_tree_sha",
        "squash_merge_sha",
        "squash_merge_tree_sha",
    }
    if set(evidence) != expected_keys:
        raise AcceptanceError("reviewed revision evidence shape changed")
    full_sha_fields = (
        "reviewed_head_sha",
        "reviewed_head_tree_sha",
        "squash_merge_sha",
        "squash_merge_tree_sha",
    )
    if any(
        not isinstance(evidence.get(field), str)
        or re.fullmatch(r"[0-9a-f]{40}", str(evidence[field])) is None
        for field in full_sha_fields
    ):
        raise AcceptanceError("reviewed revision requires full immutable SHAs")
    merge_commit = pull_request.get("mergeCommit")
    if (
        evidence.get("repository")
        != "Project-Helianthus/helianthus-modbus"
        or evidence.get("pull_request") != 6
        or pull_request.get("number") != evidence.get("pull_request")
        or pull_request.get("state") != "MERGED"
        or pull_request.get("baseRefName") != "main"
        or not pull_request.get("mergedAt")
        or pull_request.get("headRefOid") != evidence.get("reviewed_head_sha")
        or not isinstance(merge_commit, dict)
        or merge_commit.get("oid") != evidence.get("squash_merge_sha")
    ):
        raise AcceptanceError("hosted PR revision evidence mismatch")
    if not red_is_ancestor_of_reviewed_head:
        raise AcceptanceError("TDD_RED is not ancestral to the reviewed PR head")
    if reviewed_head_tree != evidence.get("reviewed_head_tree_sha"):
        raise AcceptanceError("reviewed PR head tree changed")
    if squash_merge_tree != evidence.get("squash_merge_tree_sha"):
        raise AcceptanceError("squash merge tree changed")
    if reviewed_head_tree != squash_merge_tree:
        raise AcceptanceError("reviewed and squash-merged trees differ")
    if not squash_merge_is_ancestor_of_head:
        raise AcceptanceError("squash merge is not an ancestor of HEAD")


def ensure_git_object(root: Path, commit: str) -> None:
    present = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if present.returncode == 0:
        return
    fetched = subprocess.run(
        ["git", "fetch", "--no-tags", "origin", commit],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if fetched.returncode != 0:
        raise AcceptanceError(
            f"cannot fetch immutable revision {commit}: {fetched.stderr.strip()}"
        )


def ensure_full_history(root: Path) -> None:
    shallow = subprocess.run(
        ["git", "rev-parse", "--is-shallow-repository"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if shallow.returncode != 0:
        raise AcceptanceError(
            f"cannot inspect repository depth: {shallow.stderr.strip()}"
        )
    if shallow.stdout.strip() == "false":
        return
    fetched = subprocess.run(
        ["git", "fetch", "--unshallow", "--no-tags", "origin"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if fetched.returncode != 0:
        raise AcceptanceError(
            f"cannot materialize checkout ancestry: {fetched.stderr.strip()}"
        )


def fetch_reviewed_pr_head(
    root: Path,
    pull_number: int,
    expected_sha: str,
) -> str:
    evidence_ref = f"refs/helianthus/evidence/pull-{pull_number}-head"
    fetched = subprocess.run(
        [
            "git",
            "fetch",
            "--no-tags",
            "origin",
            f"+refs/pull/{pull_number}/head:{evidence_ref}",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if fetched.returncode != 0:
        raise AcceptanceError(
            f"cannot fetch reviewed PR head: {fetched.stderr.strip()}"
        )
    resolved = subprocess.run(
        ["git", "rev-parse", evidence_ref],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if resolved.returncode != 0 or resolved.stdout.strip() != expected_sha:
        raise AcceptanceError("fetched PR head differs from hosted PR evidence")
    return evidence_ref


def git_is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "merge-base", "--is-ancestor", ancestor, descendant],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def git_tree(root: Path, commit: str) -> str:
    result = subprocess.run(
        ["git", "rev-parse", f"{commit}^{{tree}}"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError(
            f"cannot inspect immutable revision tree {commit}: "
            f"{result.stderr.strip()}"
        )
    return result.stdout.strip()


def validate_reviewed_revision(
    root: Path,
    evidence: object,
    red_commit: str,
) -> None:
    if not isinstance(evidence, dict):
        raise AcceptanceError("reviewed revision evidence is missing")
    repository = evidence.get("repository")
    pull_number = evidence.get("pull_request")
    if not isinstance(repository, str) or not isinstance(pull_number, int):
        raise AcceptanceError("reviewed revision repository or PR is invalid")
    result = subprocess.run(
        [
            "gh",
            "pr",
            "view",
            str(pull_number),
            "--repo",
            repository,
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
            f"cannot verify reviewed PR revision: {result.stderr.strip()}"
        )
    try:
        pull_request = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise AcceptanceError("reviewed PR evidence is invalid JSON") from exc
    reviewed_head = str(evidence.get("reviewed_head_sha", ""))
    squash_merge = str(evidence.get("squash_merge_sha", ""))
    ensure_full_history(root)
    reviewed_ref = fetch_reviewed_pr_head(
        root,
        pull_number,
        reviewed_head,
    )
    for commit in (red_commit, squash_merge):
        ensure_git_object(root, commit)
    validate_reviewed_revision_payload(
        evidence,
        pull_request,
        red_is_ancestor_of_reviewed_head=git_is_ancestor(
            root,
            red_commit,
            reviewed_ref,
        ),
        reviewed_head_tree=git_tree(root, reviewed_ref),
        squash_merge_tree=git_tree(root, squash_merge),
        squash_merge_is_ancestor_of_head=git_is_ancestor(
            root,
            squash_merge,
            "HEAD",
        ),
    )


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


def read_git_blob(
    repository: str,
    commit_sha: str,
    path: str,
) -> bytes:
    environment_key = (
        "HELIANTHUS_"
        + repository.rsplit("/", 1)[-1].replace("-", "_").upper()
        + "_REPO"
    )
    candidates = []
    configured = os.environ.get(environment_key)
    if configured:
        candidates.append(Path(configured))
    workspace = Path(__file__).resolve().parents[2]
    candidates.append(workspace / repository.rsplit("/", 1)[-1])
    for candidate in candidates:
        result = subprocess.run(
            ["git", "-C", str(candidate), "show", f"{commit_sha}:{path}"],
            check=False,
            capture_output=True,
        )
        if result.returncode == 0:
            return result.stdout
    with tempfile.TemporaryDirectory(prefix="helianthus-contract-") as temp:
        checkout = Path(temp) / "repository"
        remote = f"https://github.com/{repository}.git"
        clone = subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                remote,
                str(checkout),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if clone.returncode != 0:
            raise AcceptanceError(
                f"cannot clone canonical repository {repository}: "
                f"{clone.stderr.strip()}"
            )
        fetch = subprocess.run(
            [
                "git",
                "-C",
                str(checkout),
                "fetch",
                "--depth=1",
                "origin",
                commit_sha,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        if fetch.returncode != 0:
            raise AcceptanceError(
                f"cannot fetch canonical commit {commit_sha}: "
                f"{fetch.stderr.strip()}"
            )
        result = subprocess.run(
            ["git", "-C", str(checkout), "show", f"{commit_sha}:{path}"],
            check=False,
            capture_output=True,
        )
        if result.returncode != 0:
            raise AcceptanceError(
                f"canonical path missing: {repository}@{commit_sha}:{path}"
            )
        return result.stdout


def extract_plan_task(plan: bytes) -> bytes:
    start_marker = b"  - id: FMV3-M1-02\n"
    end_marker = b"  - id: FMV3-M1-03\n"
    start = plan.find(start_marker)
    end = plan.find(end_marker, start + len(start_marker))
    if start < 0 or end < 0:
        raise AcceptanceError("canonical FMV3-M1-02 plan block is missing")
    return plan[start:end]


def validate_canonical_sources(
    root: Path,
    document: dict[str, object],
    plan_bytes: bytes | None = None,
) -> None:
    sources = document.get("canonical_sources")
    if sources != {
        "companion_contract": COMPANION_SOURCE,
        "execution_plan": PLAN_SOURCE,
    }:
        raise AcceptanceError("canonical source identity changed")
    lock = load_json(root / str(COMPANION_SOURCE["consumer_lock_path"]))
    expected_lock = {
        "repository": COMPANION_SOURCE["repository"],
        "merged_commit_sha": COMPANION_SOURCE["commit_sha"],
        "manifest_sha256": COMPANION_SOURCE["manifest_sha256"],
    }
    for field, expected in expected_lock.items():
        if lock.get(field) != expected:
            raise AcceptanceError(f"companion lock changed field {field}")
    if plan_bytes is None:
        plan_bytes = read_git_blob(
            str(PLAN_SOURCE["repository"]),
            str(PLAN_SOURCE["commit_sha"]),
            str(PLAN_SOURCE["path"]),
        )
    if sha256(plan_bytes) != PLAN_SOURCE["artifact_sha256"]:
        raise AcceptanceError("canonical execution-plan artifact changed")
    if sha256(extract_plan_task(plan_bytes)) != PLAN_SOURCE["task_block_sha256"]:
        raise AcceptanceError("canonical FMV3-M1-02 task block changed")


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
            "commit_sha": COMPANION_SOURCE["commit_sha"],
            "manifest_path": COMPANION_SOURCE["manifest_path"],
            "manifest_sha256": COMPANION_SOURCE["manifest_sha256"],
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
    root: Path,
    document: dict[str, object],
    required_tests: set[str],
    verify_tdd_hosted: bool,
) -> None:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("gate evidence is missing")
    ci = gates.get("CI")
    if not isinstance(ci, dict) or tuple(ci.get("commands", ())) != (
        EXPECTED_CI_COMMANDS
    ):
        raise AcceptanceError("CI gate command contract changed")
    doc_gate = gates.get("doc_gate")
    if not isinstance(doc_gate, dict) or (
        doc_gate.get("repository"),
        doc_gate.get("commit_sha"),
    ) != (
        COMPANION_SOURCE["repository"],
        COMPANION_SOURCE["commit_sha"],
    ):
        raise AcceptanceError("doc-gate evidence changed")
    check_url = doc_gate.get("required_check_run_url")
    if not isinstance(check_url, str):
        raise AcceptanceError("doc-gate required-check evidence is missing")
    docs_run_and_job_ids(check_url)
    if verify_tdd_hosted:
        validate_doc_hosted_evidence(root, check_url)
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
    validate_reviewed_revision(
        root,
        gates.get("reviewed_revision"),
        str(red["commit_sha"]),
    )
    validate_tdd_red(
        root,
        red,
        required_tests,
        verify_tdd_hosted,
    )


def validate_tdd_red(
    root: Path,
    value: object,
    required_tests: set[str],
    verify_hosted: bool,
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
    parent = subprocess.run(
        ["git", "rev-parse", f"{commit}^"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if parent.returncode != 0 or parent.stdout.strip() != M1_01_SHA:
        raise AcceptanceError("TDD_RED commit is not based directly on FMV3-M1-01")
    changed = subprocess.run(
        ["git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    files = [line for line in changed.stdout.splitlines() if line]
    if changed.returncode != 0 or not files or any(
        not (
            path.endswith("_test.go")
            or path.startswith("tests/")
            or path.startswith("testdata/")
        )
        for path in files
    ):
        raise AcceptanceError(f"TDD_RED commit is not tests-only: {files}")
    required_red_files = {
        "tcp_adu_test.go",
        "tcp_coalescing_test.go",
        "tcp_endpoint_test.go",
        "tcp_owner_test.go",
        "tcp_pool_test.go",
        "tcp_scheduler_test.go",
        "tcp_transport_test.go",
    }
    if not required_red_files.issubset(files):
        raise AcceptanceError(
            "TDD_RED commit lacks runtime test surfaces: "
            f"{sorted(required_red_files - set(files))}"
        )
    red_sources = subprocess.run(
        ["git", "grep", "-h", "-E", r"^func Test[A-Za-z0-9_]+\(", commit, "--", "*_test.go"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if red_sources.returncode != 0:
        raise AcceptanceError("cannot inspect TDD_RED test inventory")
    red_tests = {
        match.group(1)
        for match in re.finditer(
            r"^func (Test[A-Za-z0-9_]+)\(",
            red_sources.stdout,
            re.MULTILINE,
        )
    }
    if not required_tests.issubset(red_tests):
        raise AcceptanceError(
            "TDD_RED tree lacks mapped tests: "
            f"{sorted(required_tests - red_tests)}"
        )
    run_url = value.get("hosted_ci_run_url")
    if not isinstance(run_url, str):
        raise AcceptanceError("TDD_RED hosted CI URL is missing")
    run_id = github_run_id(run_url)
    if not verify_hosted:
        return
    result = subprocess.run(
        [
            "gh",
            "run",
            "view",
            run_id,
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
    if result.returncode != 0:
        raise AcceptanceError(
            f"cannot verify TDD_RED hosted CI: {result.stderr.strip()}"
        )
    hosted = json.loads(result.stdout)
    jobs = hosted.get("jobs")
    lint_job = next(
        (
            job
            for job in jobs
            if isinstance(job, dict) and job.get("name") == "lint"
        ),
        None,
    ) if isinstance(jobs, list) else None
    if not isinstance(lint_job, dict):
        raise AcceptanceError("hosted TDD_RED lint job is missing")
    job_id = lint_job.get("databaseId")
    if not isinstance(job_id, int):
        raise AcceptanceError("hosted TDD_RED lint job identity is missing")
    log_result = subprocess.run(
        [
            "gh",
            "run",
            "view",
            run_id,
            "--repo",
            "Project-Helianthus/helianthus-modbus",
            "--job",
            str(job_id),
            "--log-failed",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if log_result.returncode != 0:
        raise AcceptanceError(
            f"cannot inspect TDD_RED failed log: {log_result.stderr.strip()}"
        )
    validate_tdd_hosted_payload(commit, hosted, log_result.stdout)


def validate_tdd_hosted_payload(
    commit: str,
    hosted: dict[str, object],
    failed_log: str,
) -> None:
    if (
        hosted.get("conclusion") != "failure"
        or hosted.get("event") != "pull_request"
        or hosted.get("headSha") != commit
        or hosted.get("workflowName") != "CI"
    ):
        raise AcceptanceError(f"hosted TDD_RED evidence mismatch: {hosted}")
    jobs = hosted.get("jobs")
    lint_jobs = [
        job
        for job in jobs
        if isinstance(job, dict) and job.get("name") == "lint"
    ] if isinstance(jobs, list) else []
    if len(lint_jobs) != 1 or lint_jobs[0].get("conclusion") != "failure":
        raise AcceptanceError("hosted TDD_RED lint job did not fail")
    required_markers = (
        "undefined: TCPEndpoint",
        "undefined: TCPTransportEvent",
        "undefined: ReadIntent",
        "undefined: EndpointScheduler",
    )
    missing = [marker for marker in required_markers if marker not in failed_log]
    if missing:
        raise AcceptanceError(
            f"hosted TDD_RED lacks missing-runtime evidence: {missing}"
        )


def validate_doc_hosted_evidence(root: Path, check_url: str) -> None:
    run_id, job_id = docs_run_and_job_ids(check_url)
    result = subprocess.run(
        [
            "gh",
            "run",
            "view",
            run_id,
            "--repo",
            "Project-Helianthus/helianthus-docs-ebus",
            "--json",
            "conclusion,event,jobs,workflowName",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise AcceptanceError(
            f"cannot verify doc-gate hosted CI: {result.stderr.strip()}"
        )
    log_result = subprocess.run(
        [
            "gh",
            "run",
            "view",
            run_id,
            "--repo",
            "Project-Helianthus/helianthus-docs-ebus",
            "--job",
            job_id,
            "--log",
        ],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if log_result.returncode != 0:
        raise AcceptanceError(
            f"cannot inspect doc-gate log: {log_result.stderr.strip()}"
        )
    validate_doc_hosted_payload(
        job_id,
        json.loads(result.stdout),
        log_result.stdout,
    )


def validate_doc_hosted_payload(
    job_id: str,
    hosted: dict[str, object],
    job_log: str,
) -> None:
    if (
        hosted.get("conclusion") != "success"
        or hosted.get("event") != "pull_request_target"
        or hosted.get("workflowName") != "Modbus Trusted Revision"
    ):
        raise AcceptanceError(f"doc-gate hosted evidence mismatch: {hosted}")
    jobs = hosted.get("jobs")
    selected = [
        job
        for job in jobs
        if isinstance(job, dict) and str(job.get("databaseId")) == job_id
    ] if isinstance(jobs, list) else []
    if (
        len(selected) != 1
        or selected[0].get("name") != "Modbus Trusted Revision"
        or selected[0].get("conclusion") != "success"
    ):
        raise AcceptanceError("doc-gate hosted job identity changed")
    required_markers = (
        COMPANION_SOURCE["commit_sha"],
        PLAN_SOURCE["commit_sha"],
        "modbus_docs_trust_ok",
    )
    missing = [marker for marker in required_markers if marker not in job_log]
    if missing:
        raise AcceptanceError(
            f"doc-gate log lacks immutable evidence: {missing}"
        )


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
    plan_bytes: bytes | None = None,
    verify_tdd_hosted: bool = True,
    execute_tests: bool = True,
) -> int:
    if (
        document.get("schema")
        != "helianthus.modbus.milestone-acceptance/v2"
        or document.get("milestone") != "FMV3-M1-02"
    ):
        raise AcceptanceError("M1-02 acceptance identity changed")
    validate_canonical_sources(root, document, plan_bytes)
    required_tests = validate_requirement_contract(document)
    required_tests.update(validate_transport_matrix(root, document))
    validate_gate_contract(
        root,
        document,
        required_tests,
        verify_tdd_hosted,
    )
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
