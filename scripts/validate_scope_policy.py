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
    "implementation_lock": "m1_vendor_opaque_protocol",
    "allowed_product_go_files": [
        "device_id.go",
        "doc.go",
        "opaque_rtu.go",
        "pdu.go",
        "rtu_adu.go",
        "rtu_capability.go",
        "rtu_endpoint.go",
        "rtu_timing.go",
        "runtime_acquisition.go",
        "runtime_normalization.go",
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
            "2897dee6ab1917b0267de94aefc2d018c9ba803ec3f42a11143fc914caa865e5"
        ),
        "doc.go": (
            "ebf7602eea88e91db901ee5e250bcf3fbb35f4babf9c548a43876071a4b7ea77"
        ),
        "opaque_rtu.go": (
            "0228fae2eab804b54aa88b727e211939b894f16a2328adca9d6ec17990602c02"
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
            "085bb755a96c6a8990a7cf72cf5c9fdddc3c430f291e72357ee9b5b88dde7b5f"
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
            "d87d51b240cbf80605b7c939acde62f4c5d7bc92fac63bdf0ea67d527f7c3980"
        ),
    },
    "trusted_python_tool_sha256": {
        "scripts/validate_m1_02_acceptance.py": (
            "f64e579546bb49c22cdc092cae63d297d846e7e0d31aa46a91bddacc20b69092"
        ),
        "scripts/validate_m1_03_acceptance.py": (
            "0df1e3344f743d6a8f2a4bea490f37cf9af6ffa50f2e1bdc3e278b8acfc3dc48"
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
        {"function_code": 100, "name": "opaque_vendor_100"},
        {"function_code": 101, "name": "opaque_vendor_101"},
        {"function_code": 102, "name": "opaque_vendor_102"},
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

    raw_rtu_encoder_sites = [
        (relative, line.strip())
        for relative, source in sources.items()
        for line in source.splitlines()
        if re.search(r"\bencodeRTUADU\s*\(", line)
    ]
    if raw_rtu_encoder_sites != [
        ("opaque_rtu.go", "return encodeRTUADU(unitID, pdu)"),
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
        "FunctionVendor100": 100,
        "FunctionVendor101": 101,
        "FunctionVendor102": 102,
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
        "opaque_rtu.go": [
            "Begin",
            "Bytes",
            "EncodePDU",
            "EncodeRTUOpaqueADU",
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
    if policy["implementation_lock"] != "m1_vendor_opaque_protocol":
        raise PolicyError("implementation lock must remain m1_vendor_opaque_protocol")
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
