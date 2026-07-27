#!/usr/bin/env python3
"""Validate the public runtime boundary without importing product code."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Iterable


EXPECTED_POLICY = {
    "schema": "helianthus-modbus-boundary/v1",
    "mode": "read_only",
    "implementation_lock": "m1_protocol",
    "allowed_product_go_files": ["device_id.go", "doc.go", "pdu.go"],
    "allowed_product_go_sha256": {
        "device_id.go": (
            "7931407186b0381d505a35ffadb8855a059a3acd68caf0589ccffc1aefb69db2"
        ),
        "doc.go": (
            "1c61f67ded68b6eba4d6af2fdfe3e840628529af9ebbe2457de3962f8b2f093d"
        ),
        "pdu.go": (
            "31729f695a879213cff35b47d993d8d6172a7ebe2c2cf1f282f2c1ffff34a80c"
        ),
    },
    "allowed_operations": [
        {"function_code": 3, "name": "read_holding_registers"},
        {"function_code": 4, "name": "read_input_registers"},
        {
            "function_code": 43,
            "mei_type": 14,
            "name": "read_device_identification",
        },
    ],
    "allowed_project_import_prefixes": [
        "github.com/Project-Helianthus/helianthus-modbus"
    ],
    "forbidden_source_tokens": [
        "fronius",
        "growatt",
        "huawei",
        "sunspec",
        "writesinglecoil",
        "writesingleregister",
        "writemultiplecoils",
        "writemultipleregisters",
        "maskwriteregister",
        "readwritemultipleregisters",
        "arbitraryfunction",
        "customfunction",
        "functioncodeoverride",
    ],
    "write_support": "separate_plan_required",
}


class PolicyError(RuntimeError):
    pass


def load_policy(root: Path) -> dict[str, object]:
    path = root / "policy" / "phase1-readonly.json"
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"cannot load {path}: {exc}") from exc
    if policy != EXPECTED_POLICY:
        raise PolicyError("phase-one policy differs from the authorized read-only contract")
    return policy


def validate_imports(imports: Iterable[str], policy: dict[str, object]) -> None:
    allowed = tuple(str(item) for item in policy["allowed_project_import_prefixes"])
    project_prefix = "github.com/Project-Helianthus/"
    for import_path in imports:
        if import_path.startswith(project_prefix) and not import_path.startswith(allowed):
            raise PolicyError(f"forbidden Helianthus dependency: {import_path}")


def validate_go_sources(root: Path, policy: dict[str, object]) -> None:
    forbidden = tuple(str(item) for item in policy["forbidden_source_tokens"])
    for path in sorted(root.rglob("*.go")):
        if ".git" in path.parts:
            continue
        compact = re.sub(r"[^a-z0-9]+", "", path.read_text(encoding="utf-8").lower())
        for token in forbidden:
            if token in compact:
                raise PolicyError(f"{path.relative_to(root)} contains forbidden token {token}")


def validate_product_lock(root: Path, policy: dict[str, object]) -> None:
    if policy["implementation_lock"] != "m1_protocol":
        raise PolicyError("implementation lock must remain m1_protocol")
    allowed = {str(item) for item in policy["allowed_product_go_files"]}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.go")
        if ".git" not in path.parts and not path.name.endswith("_test.go")
    }
    unexpected = actual - allowed
    missing = allowed - actual
    if unexpected or missing:
        raise PolicyError(
            f"product Go-file lock mismatch: unexpected={sorted(unexpected)} "
            f"missing={sorted(missing)}"
        )
    expected_hashes = {
        str(path): str(digest)
        for path, digest in policy["allowed_product_go_sha256"].items()
    }
    if set(expected_hashes) != allowed:
        raise PolicyError("product Go-file hash inventory differs from allowed files")
    for relative, expected in expected_hashes.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != expected:
            raise PolicyError(f"product Go-file content changed: {relative}")


def go_imports(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "go",
            "list",
            "-f",
            (
                '{{range .Imports}}{{.}}{{"\\n"}}{{end}}'
                '{{range .TestImports}}{{.}}{{"\\n"}}{{end}}'
                '{{range .XTestImports}}{{.}}{{"\\n"}}{{end}}'
            ),
            "./...",
        ],
        cwd=root,
        env={**__import__("os").environ, "GOWORK": "off"},
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PolicyError(f"go list failed: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line]


def validate(root: Path) -> None:
    policy = load_policy(root)
    validate_product_lock(root, policy)
    validate_imports(go_imports(root), policy)
    validate_go_sources(root, policy)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    try:
        validate(root)
    except PolicyError as exc:
        print(f"scope policy failed: {exc}", file=sys.stderr)
        return 1
    print("Scope policy passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
