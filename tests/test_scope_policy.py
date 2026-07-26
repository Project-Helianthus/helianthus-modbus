from __future__ import annotations

import copy
import importlib.util
import json
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
        with self.assertRaises(validator.PolicyError):
            validator.validate_imports(
                ["github.com/Project-Helianthus/helianthus-ebusgateway/internal/x"],
                validator.EXPECTED_POLICY,
            )

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


if __name__ == "__main__":
    unittest.main()
