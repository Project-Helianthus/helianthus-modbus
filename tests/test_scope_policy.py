from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_scope_policy.py"
SPEC = importlib.util.spec_from_file_location("validate_scope_policy", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class ScopePolicyTests(unittest.TestCase):
    def write_policy(self, root: Path, policy: dict[str, object]) -> None:
        path = root / "policy" / "phase1-readonly.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(policy), encoding="utf-8")

    def test_exact_policy_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_policy(root, validator.EXPECTED_POLICY)
            self.assertEqual(validator.load_policy(root), validator.EXPECTED_POLICY)

    def test_extra_operation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = copy.deepcopy(validator.EXPECTED_POLICY)
            policy["allowed_operations"].append(
                {"function_code": 6, "name": "unexpected_operation"}
            )
            self.write_policy(root, policy)
            with self.assertRaises(validator.PolicyError):
                validator.load_policy(root)

    def test_foreign_helianthus_dependency_is_rejected(self) -> None:
        for import_path in (
            "github.com/Project-Helianthus/helianthus-ebusgateway/internal/x",
            "github.com/Project-Helianthus/helianthus-modbusreg",
        ):
            with self.subTest(import_path=import_path):
                with self.assertRaises(validator.PolicyError):
                    validator.validate_imports(
                        [import_path],
                        validator.EXPECTED_POLICY,
                    )

    def test_own_module_and_subpackage_imports_are_accepted(self) -> None:
        validator.validate_imports(
            [
                "github.com/Project-Helianthus/helianthus-modbus",
                "github.com/Project-Helianthus/helianthus-modbus/internal/x",
            ],
            validator.EXPECTED_POLICY,
        )

    def materialize_product_lock(
        self,
        root: Path,
    ) -> dict[str, object]:
        policy = copy.deepcopy(validator.EXPECTED_POLICY)
        for relative in policy["allowed_product_go_files"]:
            target = root / relative
            target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            policy["allowed_product_go_sha256"][relative] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
        return policy

    def test_unlisted_product_file_is_rejected_by_product_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = self.materialize_product_lock(root)
            (root / "extra.go").write_text(
                "package modbus\nfunc request(code byte) []byte { return []byte{code} }\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_product_lock(root, policy)

    def test_nested_product_file_is_rejected_by_product_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = self.materialize_product_lock(root)
            nested = root / "internal" / "escape"
            nested.mkdir(parents=True)
            (nested / "escape.go").write_text(
                "package escape\nfunc emit() {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_product_lock(root, policy)

    def test_nested_file_below_trusted_tool_is_not_exempt(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = self.materialize_product_lock(root)
            nested = root / "scripts" / "read_only_surface" / "escape"
            nested.mkdir(parents=True)
            (nested / "emit.go").write_text(
                (
                    "package escape\n"
                    "import \"net\"\n"
                    "func Emit(conn net.Conn, frame []byte) error {\n"
                    "    _, err := conn.Write(frame)\n"
                    "    return err\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_product_lock(root, policy)

    def test_acceptance_validator_is_content_locked(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relative = "scripts/validate_m1_02_acceptance.py"
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            policy = copy.deepcopy(validator.EXPECTED_POLICY)
            policy["trusted_python_tool_sha256"][relative] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
            validator.validate_python_tool_lock(root, policy)
            target.write_text("# weakened\n", encoding="utf-8")
            with self.assertRaises(validator.PolicyError):
                validator.validate_python_tool_lock(root, policy)

    def test_test_file_is_not_product_code_under_product_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = self.materialize_product_lock(root)
            (root / "pdu_test.go").write_text(
                "package modbus\nfunc missingImplementation() {}\n",
                encoding="utf-8",
            )
            validator.validate_product_lock(root, policy)

    def test_raw_pdu_in_allowed_doc_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = self.materialize_product_lock(root)
            (root / "doc.go").write_text(
                "package modbus\nfunc request(code byte) []byte { return []byte{code} }\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_product_lock(root, policy)

    def test_vendor_semantics_in_go_source_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "profile.go").write_text(
                "package modbus\nconst vendorFamily = \"fronius\"\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_go_sources(root, validator.EXPECTED_POLICY)

    def test_write_surface_token_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "operation.go").write_text(
                "package modbus\nfunc WriteSingleRegister() {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_go_sources(root, validator.EXPECTED_POLICY)

    def test_neutral_numeric_write_api_is_rejected_independently_of_hashes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            (root / "neutral.go").write_text(
                (
                    "package modbus\n"
                    "func EmitOperation() []byte {\n"
                    "    return []byte{6, 0, 1, 0, 2}\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_read_only_wire_surface(root)

    def test_extra_raw_encoder_call_is_rejected_independently_of_hashes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_adu.go"
            path.write_text(
                path.read_text(encoding="utf-8")
                + (
                    "\nfunc neutralOperation(transactionID uint16, unitID byte) "
                    "([]byte, error) {\n"
                    "    return encodeTCPADU(transactionID, unitID, "
                    "[]byte{6, 0, 1, 0, 2})\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_read_only_wire_surface(root)

    def test_io_write_string_escape_is_rejected_independently_of_hashes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "doc.go"
            path.write_text(
                (
                    "package modbus\n"
                    "import \"io\"\n"
                    "func Relay(dst io.Writer, frame string) error {\n"
                    "    _, err := io.WriteString(dst, frame)\n"
                    "    return err\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            with self.assertRaises(validator.PolicyError):
                validator.validate_read_only_wire_surface(root)

    def test_ast_gate_rejects_method_value_write_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            path.write_text(
                path.read_text(encoding="utf-8")
                + (
                    "\nfunc (transport *TCPTransport) Execute("
                    "code FunctionCode) error {\n"
                    "    frame := []byte{byte(code), 0, 1, 0, 2}\n"
                    "    emit := transport.conn.Write\n"
                    "    _, err := emit(frame)\n"
                    "    return err\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized exported TCPTransport method", result.stderr)

    def test_ast_gate_rejects_reflective_write_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            (root / "escape.go").write_text(
                (
                    "package modbus\n"
                    "import \"reflect\"\n"
                    "func escape(transport *TCPTransport, frame []byte) {\n"
                    "    reflect.ValueOf(transport.conn)."
                    "MethodByName(\"Write\").Call("
                    "[]reflect.Value{reflect.ValueOf(frame)})\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("forbidden capability import reflect", result.stderr)

    def test_ast_gate_recursively_rejects_nested_direct_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            nested = root / "internal" / "escape"
            nested.mkdir(parents=True)
            (nested / "escape.go").write_text(
                (
                    "package escape\n"
                    "import \"net\"\n"
                    "func emit(conn net.Conn, frame []byte) error {\n"
                    "    _, err := conn.Write(frame)\n"
                    "    return err\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized or aliased Write selector", result.stderr)

    def test_ast_gate_rejects_io_copy_write_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            path.write_text(
                path.read_text(encoding="utf-8")
                + (
                    "\nfunc emitCopy(transport *TCPTransport, source io.Reader) "
                    "error {\n"
                    "    _, err := io.Copy(transport.conn, source)\n"
                    "    return err\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unauthorized indirect write call io.Copy", result.stderr)

    def test_ast_gate_rejects_io_write_string_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            path.write_text(
                path.read_text(encoding="utf-8")
                + (
                    "\nfunc emitString(target io.Writer, frame string) error {\n"
                    "    _, err := io.WriteString(target, frame)\n"
                    "    return err\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "unauthorized indirect write call io.WriteString",
                result.stderr,
            )

    def test_ast_gate_rejects_aliased_write_package(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            source = path.read_text(encoding="utf-8").replace(
                '\t"fmt"\n',
                '\tprinter "fmt"\n',
                1,
            )
            source += (
                "\nfunc emitAliased(target io.Writer, frame []byte) error {\n"
                "    _, err := printer.Fprint(target, frame)\n"
                "    return err\n"
                "}\n"
            )
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("product import aliases are forbidden", result.stderr)

    def test_ast_gate_rejects_deadline_capability_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            path.write_text(
                path.read_text(encoding="utf-8")
                + (
                    "\nfunc escapeDeadline(transport *TCPTransport) any {\n"
                    "    return transport.conn.SetWriteDeadline\n"
                    "}\n"
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "unauthorized access to transport connection",
                result.stderr,
            )

    def test_ast_gate_rejects_mutated_authorized_adu(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            source = path.read_text(encoding="utf-8")
            source = source.replace(
                "\twritten, writeErr := transport.conn.Write(adu)\n",
                (
                    "\tadu[7] = byte(2 + 4)\n"
                    "\twritten, writeErr := transport.conn.Write(adu)\n"
                ),
                1,
            )
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("encoded ADU dataflow changed", result.stderr)

    def test_ast_gate_rejects_noncanonical_adu_trace_encoding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for relative in validator.EXPECTED_POLICY["allowed_product_go_files"]:
                target = root / relative
                target.write_bytes((SCRIPT.parents[1] / relative).read_bytes())
            path = root / "tcp_transport.go"
            source = path.read_text(encoding="utf-8")
            source = source.replace(
                "hex.EncodeToString(adu)",
                'fmt.Sprintf("%x", adu)',
                1,
            )
            path.write_text(source, encoding="utf-8")
            result = subprocess.run(
                [
                    "go",
                    "run",
                    str(SCRIPT.parents[1] / "scripts" / "read_only_surface"),
                    str(root),
                ],
                check=False,
                capture_output=True,
                text=True,
                env={**__import__("os").environ, "GOWORK": "off"},
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("encoded ADU trace dataflow changed", result.stderr)


if __name__ == "__main__":
    unittest.main()
