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
    "schema": "helianthus-modbus-boundary/v2",
    "mode": "vendor_neutral_transport",
    "implementation_lock": "m2_configured_serial_transport",
    "allowed_product_go_files": [
        "device_id.go",
        "doc.go",
        "private_function.go",
        "pdu.go",
        "rtu_adu.go",
        "rtu_capability.go",
        "rtu_endpoint.go",
        "rtu_production.go",
        "rtu_production_private.go",
        "rtu_serial.go",
        "rtu_serial_linux.go",
        "rtu_serial_stub.go",
        "rtu_session.go",
        "rtu_timing.go",
        "runtime_acquisition.go",
        "runtime_normalization.go",
        "tcp_adu.go",
        "tcp_coalescing.go",
        "tcp_endpoint.go",
        "tcp_endpoint_lifecycle.go",
        "tcp_endpoint_read.go",
        "tcp_endpoint_response.go",
        "tcp_endpoint_retry.go",
        "tcp_endpoint_write.go",
        "tcp_owner.go",
        "tcp_pool.go",
        "tcp_scheduler.go",
        "tcp_transport.go",
    ],
    "allowed_product_go_sha256": {
        "device_id.go": (
            "ba30fd0cc2c6957f439e4d0acea5563522ff544a960cbb2785e0779a83360774"
        ),
        "doc.go": (
            "eda8957599a7c09e63fc561c4f18df1b94745fe56e47f365d8c643f67c6dabc1"
        ),
        "private_function.go": (
            "d514d4065fbbe3a8fc5f0f83f7f623e59a045c07526a610a4e96249ae1892919"
        ),
        "pdu.go": (
            "b40f22702a31d72e99af0a113525813e71782db96bd7968c413fd63b7b10fc44"
        ),
        "rtu_adu.go": (
            "2aede649a154c135a1da2c3b78f9a6fad2c6c814db6fb56c31efdbdb61b79001"
        ),
        "rtu_capability.go": (
            "b27ca42ed0afbc37a1a6a4df4dfae88ac513a2065a39a222426e7127617c7a9b"
        ),
        "rtu_endpoint.go": (
            "01697f4ec36f6d556f30dc95a18189397c408cd7d5cbffb0e2876dc8445737b3"
        ),
        "rtu_production.go": "413f439807fc579a908adcb69d0bbe192aae21ba872c087fcb2759b12bb04bca",
        "rtu_production_private.go": "959b6cb6ebf2493dd3e85b6cb0dd4954adb973d4b06a74220797f72db99d3660",
        "rtu_serial.go": "eac149dac75658e6f3a9816fbdd17f2e426b54510e355d3c4e032e1176cd878b",
        "rtu_serial_linux.go": "f825932f6683a473f5c7177c687e5510746aae30778b595448edc8c617321f0a",
        "rtu_serial_stub.go": "98a471cd37831225e9c34bd8bf315fdad831637282265df3e75db69aab9b1649",
        "rtu_session.go": (
            "0a88a60fd804e7a3d74355323cd7d9899b162ce379991f619a89ce3a4cc38f17"
        ),
        "rtu_timing.go": (
            "0cfc690a288ca75d5e418e0eac76d2609921d13e4a266068c77cd857a1fb1a60"
        ),
        "runtime_acquisition.go": (
            "15051f8d13408854995b9fd96f4c629d5fbcf5fe8d5975514dd04ef376be3d3b"
        ),
        "runtime_normalization.go": (
            "8ac474df1245b79eeb88eefc5a2e23d09d752e3b77f51c3c9b698d1edb39da38"
        ),
        "tcp_adu.go": (
            "5fe703c370733eb8f0389b2e1261a9cd140eb5de9e061ec2a965cc72cca4fcea"
        ),
        "tcp_coalescing.go": (
            "af5054f6334b96dd8fa62d5f078318a665e3916d46cb4aea393f57fdc2d40a31"
        ),
        "tcp_endpoint.go": (
            "1edb614f14dcc7cfe76b7f57547ffa125a8616acf95be8350bd2618dbb9498e8"
        ),
        "tcp_endpoint_lifecycle.go": (
            "55bbc6e32f931f966c47b19b614fea1efd338c22b578d3834e182774528857c5"
        ),
        "tcp_endpoint_read.go": (
            "9601cc73e9b3d9831190ffc203f02e3b9af344faf1d7687d2ae6c2d97d723dc5"
        ),
        "tcp_endpoint_response.go": (
            "5c2acfd663e3bc479e80efd20427a952b04a80362a717acb4d79ea1d0b9c4cd5"
        ),
        "tcp_endpoint_retry.go": (
            "7b88977f3ddf7470b807199ecc7498b97487dacba12e14e28a6ddc30ba50b930"
        ),
        "tcp_endpoint_write.go": (
            "9c86a54747b369fb6e38da3b58e3b6ae8dd996991599d72dd8976706a29f61cd"
        ),
        "tcp_owner.go": (
            "5e9c353db9a853be82e8bd7ef376e031e33e53d10397041bebc6f136b8e51e24"
        ),
        "tcp_pool.go": (
            "0ff5b4048c2c0e9804acaacdd548669add425c129d325e6ddeb95e19f6603818"
        ),
        "tcp_scheduler.go": (
            "b76228b8630e2704820806239082318cce8a0056471e4f11769ac8492a83dc0a"
        ),
        "tcp_transport.go": (
            "f70990b894007534164f46abb508ccc0b2d34bbd7f6c548baa9af0a12a8fcdfb"
        ),
    },
    "trusted_go_tool_sha256": {
        "scripts/acceptance_evidence/doc.go": (
            "782265598efd135fec2ca6b2bbd3c3dccae77383e51992f15b9d134b4cf989d3"
        ),
        "scripts/acceptance_evidence/main.go": (
            "903cfc5df5569c316186032ab2da644dcb664a51548b064e3d3e67c945b96880"
        ),
        "scripts/read_only_surface/doc.go": (
            "347a388e7438cd5234423bab6d561960b87e50f870cd1651a06905b506a9a877"
        ),
        "scripts/read_only_surface/main.go": (
            "0e6d6412ddb399210b14ee45b9e6bcdce25f81b61ae2aba203c7e1527fac9b0f"
        ),
    },
    "trusted_python_tool_sha256": {
        "scripts/validate_m1_02_acceptance.py": (
            "f64e579546bb49c22cdc092cae63d297d846e7e0d31aa46a91bddacc20b69092"
        ),
        "scripts/validate_m1_03_acceptance.py": (
            "6aac2592b38a1d1fc8c44026d101dca32e3cb1ef47dad370679a0acd0e353465"
        ),
        "scripts/validate_m1_04_acceptance.py": (
            "67eefbf1db0b90cf172e627ad9c21a1a6641d8231500504d7f3b3e9f55d93add"
        ),
        "scripts/validate_m1_06_conformance.py": (
            "8b22bfcfccecc23e6aa0c9c4661a0ca6d98f45f7813afca9e78c1af9a4b544d6"
        ),
    },
    "allowed_operations": [
        {"function_code": 3, "name": "read_holding_registers"},
        {"function_code": 4, "name": "read_input_registers"},
        {
            "function_code_policy": "caller_supplied_non_exception_byte",
            "name": "generic_private_function_code",
        },
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
    "write_support": "configured_stream_only",
}


class PolicyError(RuntimeError):
    pass


TRUSTED_GO_TOOL_FILES = {
    "scripts/acceptance_evidence/doc.go",
    "scripts/acceptance_evidence/main.go",
    "scripts/read_only_surface/doc.go",
    "scripts/read_only_surface/main.go",
}
TRUSTED_PYTHON_TOOL_FILES = {
    "scripts/validate_m1_02_acceptance.py",
    "scripts/validate_m1_03_acceptance.py",
    "scripts/validate_m1_04_acceptance.py",
    "scripts/validate_m1_06_conformance.py",
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
    if (
        policy.get("schema") != "helianthus-modbus-boundary/v2"
        or policy.get("mode") != "vendor_neutral_transport"
        or policy.get("implementation_lock") != "m2_configured_serial_transport"
        or policy.get("write_support") != "configured_stream_only"
    ):
        raise PolicyError("transport policy identity differs from the configured-stream contract")
    if policy.get("allowed_operations") != EXPECTED_POLICY.get("allowed_operations") or (
        policy.get("forbidden_source_tokens") != EXPECTED_POLICY.get("forbidden_source_tokens")
    ):
        raise PolicyError("transport policy operation or semantic boundary changed")
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
        ("rtu_serial.go", "return backend.Write(ctx, frame)"),
        ("rtu_serial_linux.go", "written, err := backend.file.Write(frame)"),
        ("tcp_transport.go", "written, writeErr := transport.conn.Write(adu)"),
    ]:
        raise PolicyError(f"unexpected product write sites: {write_sites}")

    raw_encoder_sites = [
        (relative, line.strip())
        for relative, source in sources.items()
        for line in source.splitlines()
        if re.search(r"\bencodeTCPADU\s*\(", line)
    ]
    if raw_encoder_sites != [
        ("private_function.go", "return encodeTCPADU(transactionID, unitID, pdu)"),
        ("tcp_adu.go", "return encodeTCPADU(transactionID, unitID, pdu)"),
        ("tcp_adu.go", "return encodeTCPADU(transactionID, unitID, pdu)"),
        ("tcp_adu.go", "func encodeTCPADU("),
    ]:
        raise PolicyError(
            f"unexpected raw TCP encoder sites: {raw_encoder_sites}"
        )

    raw_rtu_encoder_sites = [
        (relative, line.strip())
        for relative, source in sources.items()
        for line in source.splitlines()
        if re.search(r"\bencodeRTUADU\s*\(", line)
    ]
    if raw_rtu_encoder_sites != [
        ("private_function.go", "return encodeRTUADU(unitID, pdu)"),
        ("rtu_adu.go", "return encodeRTUADU(unitID, pdu)"),
        ("rtu_adu.go", "return encodeRTUADU(unitID, pdu)"),
        ("rtu_adu.go", "func encodeRTUADU(unitID byte, pdu []byte) ([]byte, error) {"),
    ]:
        raise PolicyError(
            f"unexpected raw RTU encoder sites: {raw_rtu_encoder_sites}"
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
        "private_function.go": [
            "Begin",
            "Bytes",
            "Bytes",
            "EncodePDU",
            "EncodeRTUPrivateFunctionADU",
            "EncodeTCPPrivateFunctionADU",
            "Payload",
            "Payload",
            "Payload",
        ],
        "rtu_adu.go": [
            "Bytes",
            "Bytes",
            "Bytes",
            "EncodeRTUDeviceIDAccessADU",
            "EncodeRTUReadADU",
            "PDU",
        ],
        "runtime_acquisition.go": [
            "GobEncode",
            "GobEncode",
            "GobEncode",
            "MarshalBinary",
            "MarshalBinary",
            "MarshalBinary",
            "MarshalJSON",
            "MarshalJSON",
            "MarshalJSON",
            "MarshalJSON",
            "MarshalJSON",
            "MarshalText",
            "MarshalText",
        ],
        "runtime_normalization.go": ["AppendJSON", "Bytes", "MarshalJSON"],
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
    if policy["implementation_lock"] != "m2_configured_serial_transport":
        raise PolicyError("implementation lock must remain m2_configured_serial_transport")
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
