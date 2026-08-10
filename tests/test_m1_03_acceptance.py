from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_m1_03_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_m1_03_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class M103AcceptanceTests(unittest.TestCase):
    def test_exact_manifest_validates_without_hosted_queries(self) -> None:
        document = json.loads(
            (ROOT / "policy" / "m1-03-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        count = validator.validate(
            ROOT,
            document,
            execute_tests=False,
        )
        self.assertGreater(count, 0)

    def test_structural_plan_identity_drift_is_rejected(self) -> None:
        document = {
            "canonical_sources": {
                "companion_contract": validator.COMPANION_SOURCE,
                "execution_plan": {
                    **validator.PLAN_SOURCE,
                    "node": "FMV3-M1-99",
                },
            }
        }
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_canonical_sources(document)

    def test_transport_matrix_requires_every_offline_rtu_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relative = Path("policy/m1-03-transport-matrix.json")
            target = root / relative
            target.parent.mkdir(parents=True)
            shutil.copy2(ROOT / relative, target)
            document = {
                "gates": {
                    "transport_gate": {
                        "matrix_path": relative.as_posix(),
                        "matrix_sha256": validator.base.sha256(
                            target.read_bytes()
                        ),
                        "disposition": "NOT_APPLICABLE_FIXTURE_ONLY",
                    }
                }
            }
            self.assertTrue(
                validator.validate_transport_matrix(root, document)
            )
            matrix = json.loads(target.read_text(encoding="utf-8"))
            matrix["rows"].pop()
            target.write_text(json.dumps(matrix), encoding="utf-8")
            document["gates"]["transport_gate"]["matrix_sha256"] = (
                validator.base.sha256(target.read_bytes())
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_transport_matrix(root, document)

    def test_offline_surface_rejects_physical_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            policy = json.loads(
                (ROOT / "policy" / "phase1-readonly.json").read_text(
                    encoding="utf-8"
                )
            )
            for relative in policy["allowed_product_go_files"]:
                shutil.copy2(ROOT / relative, root / relative)
            shutil.copy2(ROOT / "go.mod", root / "go.mod")
            (root / "policy").mkdir()
            shutil.copy2(
                ROOT / "policy" / "phase1-readonly.json",
                root / "policy" / "phase1-readonly.json",
            )
            endpoint = root / "rtu_endpoint.go"
            endpoint.write_text(
                endpoint.read_text(encoding="utf-8")
                + "\nfunc physicalEscape(dst io.Writer) {}\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_offline_surface(
                    root,
                    {
                        "physical_io_sites": 0,
                        "gateway_dependencies": 0,
                        "vendor_profile_dependencies": 0,
                        "cgo_files": 0,
                        "go_mod_sha256": (
                            "c64fd63d81e8a9c6b013d06f8db676621b3945be57e203b"
                            "d004910270383617f"
                        ),
                    },
                )

    def test_compiled_inventory_rejects_extra_test_and_non_go_sources(
        self,
    ) -> None:
        policy = json.loads(
            (ROOT / "policy" / "phase1-readonly.json").read_text(
                encoding="utf-8"
            )
        )
        package = {
            "GoFiles": policy["allowed_product_go_files"],
            "TestGoFiles": sorted(validator.EXPECTED_TEST_GO_FILES),
        }
        validator.validate_compiled_inventory(package, policy)
        package["TestGoFiles"].append("m1_03_extra_test.go")
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_compiled_inventory(package, policy)
        package["TestGoFiles"].pop()
        package["SFiles"] = ["unlocked_amd64.s"]
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_compiled_inventory(package, policy)

    def test_offline_filesystem_rejects_arch_specific_and_embed_sources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "unlocked_amd64.s").write_text("TEXT", encoding="utf-8")
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_offline_source_filesystem(root)
            (root / "unlocked_amd64.s").unlink()
            (root / "ignored_arm64_test.go").write_text(
                "package modbus\n//go:embed hidden.bin\n",
                encoding="utf-8",
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_offline_source_filesystem(root)

    def test_current_ci_controls_are_hash_locked(self) -> None:
        validator.validate_ci_controls(ROOT)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            workflow = root / ".github/workflows/ci.yml"
            workflow.parent.mkdir(parents=True)
            shutil.copy2(ROOT / ".github/workflows/ci.yml", workflow)
            script = root / "scripts/ci_local.sh"
            script.parent.mkdir(parents=True)
            script.write_text(
                (ROOT / "scripts/ci_local.sh").read_text(encoding="utf-8")
                .replace(
                    "python3 scripts/validate_m1_03_acceptance.py",
                    "true # validator removed",
                ),
                encoding="utf-8",
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_ci_controls(root)

    def test_requirement_source_identity_is_immutable(self) -> None:
        document = json.loads(
            (ROOT / "policy" / "m1-03-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertTrue(validator.validate_requirement_contract(document))
        document["requirements"][0]["source"] = "self-authored#replacement"
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_requirement_contract(document)

    def test_requirement_mapping_cannot_collapse_to_one_test(self) -> None:
        document = json.loads(
            (ROOT / "policy" / "m1-03-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        for requirement in document["requirements"]:
            requirement["tests"] = ["TestContract"]
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_requirement_contract(document)

if __name__ == "__main__":
    unittest.main()
