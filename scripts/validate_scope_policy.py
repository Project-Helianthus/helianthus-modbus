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
    "allowed_product_go_files": [
        "device_id.go",
        "doc.go",
        "pdu.go",
        "tcp_adu.go",
        "tcp_coalescing.go",
        "tcp_endpoint.go",
        "tcp_owner.go",
        "tcp_pool.go",
        "tcp_scheduler.go",
        "tcp_transport.go",
    ],
    "allowed_product_go_sha256": {
        "device_id.go": (
            "5bcad6b6af8ba827ee16ea832c7d688e0d851b9dabb42376fefb2a4837bd0d9f"
        ),
        "doc.go": (
            "9f16ddba12a48cb50566ec16472d9fb170a6894059ffec2ad59b3855836133bc"
        ),
        "pdu.go": (
            "6e10a628f3f79d5c19c7c51307308179644364a5ba2c698e39e4ec49ef4e1d8b"
        ),
        "tcp_adu.go": (
            "29468e151d3b241ac49cda6e97be2c1e78561bb41703be347ff0dbf17650c42b"
        ),
        "tcp_coalescing.go": (
            "d57ec064b99bdfe49d12e608fafc5883e84eec8037aa6ee485602424e2c9be7d"
        ),
        "tcp_endpoint.go": (
            "f0d46215dd3e5639695551178da0ae9fdfee6a5f3467922796316a1148918b15"
        ),
        "tcp_owner.go": (
            "b062e796fb3c60c9dd3b6716af6271543fc394b4646af52990cfc1b3d8032b00"
        ),
        "tcp_pool.go": (
            "bdbc8f871915f1173d67a211dcff8572516e071cdb3d1793a463f5598c8e7114"
        ),
        "tcp_scheduler.go": (
            "d30b7154b9762380dc69bb334436abf62cde45273310a829c08ed2fac9b27252"
        ),
        "tcp_transport.go": (
            "0b95a1311ad5df7c55aff0d9db9543eb46a9ccde205b2461f5b4f618d21ef2ab"
        ),
    },
    "trusted_go_tool_sha256": {
        "scripts/acceptance_evidence/main.go": (
            "903cfc5df5569c316186032ab2da644dcb664a51548b064e3d3e67c945b96880"
        ),
        "scripts/read_only_surface/main.go": (
            "e8a3d211d7ad9f70edab01bb552087e12c7e1ea97bafbeab48700241737f86c8"
        ),
    },
    "trusted_python_tool_sha256": {
        "scripts/validate_m1_02_acceptance.py": (
            "78a422c705d18167fa8dc515097d12bc5a96d54fd17cedc911ec6dcb579683c5"
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


TRUSTED_GO_TOOL_FILES = {
    "scripts/acceptance_evidence/main.go",
    "scripts/read_only_surface/main.go",
}
TRUSTED_PYTHON_TOOL_FILES = {
    "scripts/validate_m1_02_acceptance.py",
}


def is_trusted_go_tool(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    return relative in TRUSTED_GO_TOOL_FILES


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
        permitted = any(
            import_path == prefix or import_path.startswith(prefix + "/")
            for prefix in allowed
        )
        if import_path.startswith(project_prefix) and not permitted:
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


def product_go_sources(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted(root.rglob("*.go"))
        if ".git" not in path.parts
        and not path.name.endswith("_test.go")
        and not is_trusted_go_tool(path, root)
    }


def validate_read_only_wire_surface(root: Path) -> None:
    sources = product_go_sources(root)
    output_call = re.compile(
        r"\.(?:Write|WriteString|WriteByte|WriteRune|WriteTo|ReadFrom|Encode|Flush)"
        r"\s*\(|\b(?:io\.(?:Copy|CopyBuffer|CopyN)|fmt\.Fprint(?:f|ln)?|"
        r"os\.WriteFile)\s*\("
    )
    write_sites = [
        (relative, line.strip())
        for relative, source in sources.items()
        for line in source.splitlines()
        if output_call.search(line)
    ]
    if write_sites != [
        ("tcp_transport.go", "written, writeErr := transport.conn.Write(adu)")
    ]:
        raise PolicyError(f"unexpected product write sites: {write_sites}")

    raw_encoder_sites = [
        (relative, line.strip())
        for relative, source in sources.items()
        for line in source.splitlines()
        if re.search(r"\bencodeTCPADU\s*\(", line)
    ]
    if raw_encoder_sites != [
        ("tcp_adu.go", "return encodeTCPADU(transactionID, unitID, pdu)"),
        ("tcp_adu.go", "return encodeTCPADU(transactionID, unitID, pdu)"),
        ("tcp_adu.go", "func encodeTCPADU("),
    ]:
        raise PolicyError(
            f"unexpected raw TCP encoder sites: {raw_encoder_sites}"
        )

    function_codes: dict[str, int] = {}
    declaration = re.compile(
        r"^\s*(\w+)\s+FunctionCode\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*$"
    )
    for source in sources.values():
        for line in source.splitlines():
            match = declaration.match(line)
            if match:
                function_codes[match.group(1)] = int(match.group(2), 0)
    expected_codes = {
        "FunctionReadHoldingRegisters": 3,
        "FunctionReadInputRegisters": 4,
        "FunctionEncapsulatedInterface": 43,
    }
    if function_codes != expected_codes:
        raise PolicyError(f"unexpected function-code declarations: {function_codes}")

    byte_api_pattern = re.compile(
        r"func\s+(?:\([^)]*\)\s+)?([A-Z]\w*)\s*"
        r"\([^)]*\)\s*(?:\(\s*)?\[\]byte",
        re.MULTILINE,
    )
    byte_apis = {
        relative: sorted(byte_api_pattern.findall(source))
        for relative, source in sources.items()
        if byte_api_pattern.search(source)
    }
    expected_byte_apis = {
        "device_id.go": ["EncodePDU"],
        "pdu.go": ["EncodePDU"],
        "tcp_adu.go": [
            "Bytes",
            "EncodeTCPDeviceIDAccessADU",
            "EncodeTCPReadADU",
            "PDU",
        ],
        "tcp_owner.go": ["Bytes"],
    }
    if byte_apis != expected_byte_apis:
        raise PolicyError(f"unexpected exported byte APIs: {byte_apis}")

    pdu_literals = {
        relative: source.count("return []byte{")
        for relative, source in sources.items()
        if "return []byte{" in source
    }
    if pdu_literals != {"device_id.go": 1, "pdu.go": 1}:
        raise PolicyError(f"unexpected direct PDU emitters: {pdu_literals}")
    if "return []byte{\n\t\tbyte(request.function)," not in sources["pdu.go"]:
        raise PolicyError("register PDU does not emit its validated function")
    if (
        "return []byte{\n\t\tbyte(FunctionEncapsulatedInterface),"
        not in sources["device_id.go"]
    ):
        raise PolicyError("Device Identification PDU function changed")


def validate_product_lock(root: Path, policy: dict[str, object]) -> None:
    if policy["implementation_lock"] != "m1_protocol":
        raise PolicyError("implementation lock must remain m1_protocol")
    allowed = {str(item) for item in policy["allowed_product_go_files"]}
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.go")
        if ".git" not in path.parts
        and not path.name.endswith("_test.go")
        and not is_trusted_go_tool(path, root)
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


def validate_tool_lock(root: Path, policy: dict[str, object]) -> None:
    expected = {
        str(path): str(digest)
        for path, digest in policy["trusted_go_tool_sha256"].items()
    }
    if set(expected) != TRUSTED_GO_TOOL_FILES:
        raise PolicyError("trusted Go-tool inventory changed")
    for relative, digest in expected.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != digest:
            raise PolicyError(f"trusted Go-tool content changed: {relative}")


def validate_python_tool_lock(root: Path, policy: dict[str, object]) -> None:
    expected = {
        str(path): str(digest)
        for path, digest in policy["trusted_python_tool_sha256"].items()
    }
    if set(expected) != TRUSTED_PYTHON_TOOL_FILES:
        raise PolicyError("trusted Python-tool inventory changed")
    for relative, digest in expected.items():
        actual = hashlib.sha256((root / relative).read_bytes()).hexdigest()
        if actual != digest:
            raise PolicyError(f"trusted Python-tool content changed: {relative}")


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


def validate_go_packages(root: Path) -> None:
    expected = {
        "github.com/Project-Helianthus/helianthus-modbus",
        (
            "github.com/Project-Helianthus/helianthus-modbus/"
            "scripts/acceptance_evidence"
        ),
        (
            "github.com/Project-Helianthus/helianthus-modbus/"
            "scripts/read_only_surface"
        ),
    }
    result = subprocess.run(
        ["go", "list", "-f", "{{.ImportPath}}", "./..."],
        cwd=root,
        env={**__import__("os").environ, "GOWORK": "off"},
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise PolicyError(f"go list failed: {result.stderr.strip()}")
    actual = {line for line in result.stdout.splitlines() if line}
    if actual != expected:
        raise PolicyError(f"Go package inventory changed: {sorted(actual)}")


def validate(root: Path) -> None:
    policy = load_policy(root)
    validate_product_lock(root, policy)
    validate_tool_lock(root, policy)
    validate_python_tool_lock(root, policy)
    validate_go_packages(root)
    validate_read_only_wire_surface(root)
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
