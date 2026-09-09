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
            "2897dee6ab1917b0267de94aefc2d018c9ba803ec3f42a11143fc914caa865e5"
        ),
        "doc.go": (
            "a8f1e9ea1e8f13e40af5ebeba95d07d11d593969afe814a3fe64d3f8dcb1f365"
        ),
        "private_function.go": (
            "d514d4065fbbe3a8fc5f0f83f7f623e59a045c07526a610a4e96249ae1892919"
        ),
        "pdu.go": (
            "6e10a628f3f79d5c19c7c51307308179644364a5ba2c698e39e4ec49ef4e1d8b"
        ),
        "rtu_adu.go": (
            "2aede649a154c135a1da2c3b78f9a6fad2c6c814db6fb56c31efdbdb61b79001"
        ),
        "rtu_capability.go": (
            "33f8427bccd92b337afe1c8947ed2809f0262db7e3a9697629ef593a6ab2b010"
        ),
        "rtu_endpoint.go": (
            "5ec493f52dc4d7058589542fb532232036d235182e5f19530732ecad2b51bb61"
        ),
        "rtu_production.go": "232a29c5b4751df22856adbdba60d245af4dd299d79bdcfce35370bab7e17e0b",
        "rtu_serial.go": "8bc0a0b696f4b5f3bbd5f20cfa66afffb16ba1e3ec8356de05470f43bb49ad61",
        "rtu_serial_linux.go": "2ebee9f012ae7e88714b78fe192938178a0a3cba4611ec167584b4bf385ae0b5",
        "rtu_serial_stub.go": "98a471cd37831225e9c34bd8bf315fdad831637282265df3e75db69aab9b1649",
        "rtu_session.go": (
            "1621aba290efc6f701d660a00173f22a258fd63f5679748f0547fea50e469f74"
        ),
        "rtu_timing.go": (
            "daea0680aa70f1a552fc6facdd35e54161728c673625088c599951d560155231"
        ),
        "runtime_acquisition.go": (
            "efa2aa5125d203dbf2bcd95330a279ee32e10ef6cb0f74d9fe030ec666112c0e"
        ),
        "runtime_normalization.go": (
            "0e45d3ae333556b8cd7633151e324752c994e9a427875a0c4e611510e7313b9d"
        ),
        "tcp_adu.go": (
            "1b2a670759be0865b59060efd7bc90a43f7a67607c3c7e3767e0227c4fcca88c"
        ),
        "tcp_coalescing.go": (
            "2cb7178b709156261ef4e704f127d7524ca3e9f3ec33f18856f0415a2f9a15b7"
        ),
        "tcp_endpoint.go": (
            "ef390c3571c2ed8e439782a3786eac43267e7a1bd64d965e3ef5765c22ef33c0"
        ),
        "tcp_endpoint_lifecycle.go": (
            "c4e87eec337419bad97494283cafde8df5f98c344bf77766b96b5d6bfe5c36e8"
        ),
        "tcp_endpoint_read.go": (
            "8bb475db4601194839d804e3ae4da9bc0941f7004b36a064c3eb861b2f415c24"
        ),
        "tcp_endpoint_response.go": (
            "40ac04f81e2e31244f3e62fadf487f31e103511b4343478a82cd1b8adbde34a4"
        ),
        "tcp_endpoint_retry.go": (
            "5b3ca071626f039bbd12439eccefeddb931f093ea28a6a5bf821586dddb2fe6c"
        ),
        "tcp_endpoint_write.go": (
            "cf7f1075f2ef2932883f50937441002cf428b4907beda503eb53d40af9289998"
        ),
        "tcp_owner.go": (
            "919029df866f3db1157742c84bdeb689ea4b898d639d2ea993ec5b896bdc608b"
        ),
        "tcp_pool.go": (
            "bdbc8f871915f1173d67a211dcff8572516e071cdb3d1793a463f5598c8e7114"
        ),
        "tcp_scheduler.go": (
            "5429a20ac9ab2410224c79f47cdfeac712e3f613844f476a13ce8a5ab21e27a9"
        ),
        "tcp_transport.go": (
            "935104fd4086a016241fa8358be885aa99c55f80d220a03255e42b31e1c4fca4"
        ),
    },
    "trusted_go_tool_sha256": {
        "scripts/acceptance_evidence/main.go": (
            "903cfc5df5569c316186032ab2da644dcb664a51548b064e3d3e67c945b96880"
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
            "c3b476c1101b09b38bd03c48ede98a288f07bc3d81b6a623a2fa301172f32589"
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
    "scripts/acceptance_evidence/main.go",
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
