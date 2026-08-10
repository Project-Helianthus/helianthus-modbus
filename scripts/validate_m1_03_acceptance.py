#!/usr/bin/env python3
"""Validate the offline-only FMV3-M1-03 RTU fixture milestone."""

from __future__ import annotations

import importlib.util
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
    "path": "fronius-modbus-multivendor-v3-w29-26.locked/plan.yaml",
    "node": "FMV3-M1-03",
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
    "runtime_acquisition_test.go",
    "tcp_adu_test.go",
    "tcp_coalescing_test.go",
    "tcp_endpoint_test.go",
    "tcp_owner_test.go",
    "tcp_pool_test.go",
    "tcp_scheduler_test.go",
    "tcp_transport_test.go",
    "tcp_device_id_endpoint_test.go",
    "transport_conformance_test.go",
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
    "be8834d7dd350e7516e794360bb4e9e49a798b20c959a32b9c28730dc8c7c408"
)
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


def canonical_hash(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base.sha256(encoded)


def validate_canonical_sources(
    document: dict[str, object],
) -> None:
    if document.get("canonical_sources") != {
        "companion_contract": COMPANION_SOURCE,
        "execution_plan": PLAN_SOURCE,
    }:
        raise AcceptanceError("canonical source identity changed")


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
    if gate.get("disposition") != "NOT_APPLICABLE_FIXTURE_ONLY":
        raise AcceptanceError("RTU transport disposition changed")
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


def validate_tdd(value: object) -> None:
    if not isinstance(value, dict):
        raise AcceptanceError("RTU TDD_RED evidence is missing")
    base_sha = value.get("base_sha")
    commits = value.get("test_only_commits")
    red_tests = value.get("red_required_tests")
    if (
        not isinstance(base_sha, str)
        or re.fullmatch(r"[0-9a-f]{40}", base_sha) is None
        or not isinstance(commits, list)
        or len(commits) != 2
        or any(
            not isinstance(commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", commit) is None
            for commit in commits
        )
        or value.get("hosted_ci_conclusion") != "failure"
        or tuple(red_tests) != RED_REQUIRED_TESTS
    ):
        raise AcceptanceError("RTU TDD_RED contract changed")
    run_url = value.get("hosted_ci_run_url")
    if not isinstance(run_url, str):
        raise AcceptanceError("RTU TDD_RED hosted run changed")
    base.github_run_id(run_url)


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


def validate_ci_controls(root: Path) -> str:
    workflow = (root / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    if (
        base.sha256(workflow.encode("utf-8")) != CI_WORKFLOW_SHA256
        or base.sha256((root / "scripts" / "ci_local.sh").read_bytes())
        != CI_LOCAL_SHA256
    ):
        raise AcceptanceError("CI control changed")
    exact_head_checkout = (
        "ref: ${{ github.event.pull_request.head.sha || github.sha }}"
    )
    if workflow.count(exact_head_checkout) != 2:
        raise AcceptanceError("CI does not test the exact PR head and push SHA")
    return workflow


def validate_gate_contract(
    root: Path,
    document: dict[str, object],
) -> None:
    gates = document.get("gates")
    if not isinstance(gates, dict):
        raise AcceptanceError("gate evidence is missing")
    ci = gates.get("CI")
    if not isinstance(ci, dict) or tuple(ci.get("commands", ())) != (
        EXPECTED_CI_COMMANDS
    ):
        raise AcceptanceError("M1-03 CI command contract changed")
    validate_ci_controls(root)
    if gates.get("doc_gate") != {
        "applicable": False,
        "reason": (
            "public HELIANTHUS_MODBUS_FOUNDATION_PROFILE_V1 contract already "
            "merged; no documentation change"
        ),
    }:
        raise AcceptanceError("M1-03 doc-gate evidence changed")
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
    validate_offline_surface(root, gates.get("offline_surface"))
    red = gates.get("TDD_RED")
    validate_tdd(red)
    if not isinstance(red, dict):
        raise AcceptanceError("RTU TDD_RED evidence is missing")


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
    execute_tests: bool = True,
) -> int:
    if (
        document.get("schema")
        != "helianthus.modbus.milestone-acceptance/v2"
        or document.get("milestone") != "FMV3-M1-03"
    ):
        raise AcceptanceError("M1-03 acceptance identity changed")
    validate_canonical_sources(document)
    required_tests = validate_requirement_contract(document)
    required_tests.update(validate_transport_matrix(root, document))
    validate_gate_contract(root, document)
    validate_test_evidence(root, document, required_tests)
    if execute_tests:
        base.run_mapped_tests(root, required_tests)
    return len(required_tests)


def main() -> int:
    try:
        document = base.load_json(ROOT / "policy" / "m1-03-acceptance.json")
        count = validate(ROOT, document)
    except (AcceptanceError, OSError, json.JSONDecodeError) as exc:
        print(f"M1-03 acceptance failed: {exc}", file=sys.stderr)
        return 1
    print(
        "M1-03 acceptance passed: "
        f"{len(EXPECTED_REQUIREMENTS)} requirements, "
        f"{len(RTU_RECOVERY_ROWS)} transport rows, {count} tests."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
