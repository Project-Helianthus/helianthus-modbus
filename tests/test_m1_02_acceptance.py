from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_m1_02_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_m1_02_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


def event(action: str, test: str) -> str:
    return json.dumps({"Action": action, "Test": test})


class M102AcceptanceTests(unittest.TestCase):
    def test_m1_02_owns_declared_tests_without_blocking_later_tests(self) -> None:
        digest = "a" * 64
        validator.validate_declared_test_files(
            {
                "tcp_owned_test.go": digest,
                "rtu_later_milestone_test.go": "b" * 64,
            },
            {"tcp_owned_test.go": digest},
        )
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_declared_test_files(
                {"tcp_owned_test.go": "c" * 64},
                {"tcp_owned_test.go": digest},
            )

    def test_go_tool_context_normalizes_symlinked_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            link = Path(temp) / "checkout"
            link.symlink_to(ROOT, target_is_directory=True)
            tool_root, target_root, environment = validator.go_tool_context(link)
            self.assertEqual(tool_root, ROOT.resolve())
            self.assertEqual(target_root, ROOT.resolve())
            self.assertEqual(environment["PWD"], str(tool_root))
            self.assertEqual(environment["GOWORK"], "off")

    def test_skipped_required_subtest_is_rejected(self) -> None:
        output = "\n".join(
            (
                event("run", "TestContract"),
                event("run", "TestContract/behavior"),
                event("skip", "TestContract/behavior"),
                event("pass", "TestContract"),
            )
        )
        with self.assertRaises(validator.AcceptanceError):
            validator.evaluate_mapped_test_events(
                {"TestContract"},
                output,
                "",
                0,
            )

    def test_passing_required_subtest_is_accepted(self) -> None:
        output = "\n".join(
            (
                event("run", "TestContract"),
                event("run", "TestContract/behavior"),
                event("pass", "TestContract/behavior"),
                event("pass", "TestContract"),
            )
        )
        validator.evaluate_mapped_test_events(
            {"TestContract"},
            output,
            "",
            0,
        )

    def test_requirement_identity_is_anchored_to_canonical_sources(self) -> None:
        document = {
            "requirements": [
                {"id": requirement, "source": source, "tests": ["TestContract"]}
                for requirement, source in validator.EXPECTED_REQUIREMENTS
            ]
        }
        self.assertEqual(
            validator.validate_requirement_contract(document),
            {"TestContract"},
        )
        document["requirements"][0]["source"] = "self-authored#replacement"
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_requirement_contract(document)

    def test_canonical_plan_source_is_structural(self) -> None:
        document = {
            "canonical_sources": {
                "companion_contract": validator.COMPANION_SOURCE,
                "execution_plan": validator.PLAN_SOURCE,
            }
        }
        validator.validate_canonical_sources(document)
        document["canonical_sources"]["execution_plan"] = {
            **validator.PLAN_SOURCE,
            "node": "FMV3-M1-99",
        }
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_canonical_sources(document)

    def test_transport_matrix_requires_every_canonical_tcp_row(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            relative = Path("policy/m1-02-transport-matrix.json")
            target = root / relative
            target.parent.mkdir(parents=True)
            target.write_bytes((ROOT / relative).read_bytes())
            document = {
                "gates": {
                    "transport_gate": {
                        "matrix_path": relative.as_posix(),
                        "matrix_sha256": validator.sha256(target.read_bytes()),
                    }
                }
            }
            tests = validator.validate_transport_matrix(root, document)
            self.assertTrue(tests)
            matrix = json.loads(target.read_text(encoding="utf-8"))
            matrix["rows"].pop()
            target.write_text(json.dumps(matrix), encoding="utf-8")
            document["gates"]["transport_gate"]["matrix_sha256"] = (
                validator.sha256(target.read_bytes())
            )
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_transport_matrix(root, document)

    def test_pending_tdd_red_evidence_is_rejected(self) -> None:
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_tdd_red(
                {
                    "commit_sha": "037264cbfdea82fb73c64978fa538c34855cf48b",
                    "required_shape": "tests_only_parented_by_fmv3_m1_01",
                    "hosted_ci_conclusion": "failure",
                    "hosted_ci_run_url": None,
                },
            )

    def test_hosted_tdd_red_uses_numeric_run_id(self) -> None:
        run_id = validator.github_run_id(
            "https://github.com/Project-Helianthus/"
            "helianthus-modbus/actions/runs/30353538725"
        )
        self.assertEqual(run_id, "30353538725")
        with self.assertRaises(validator.AcceptanceError):
            validator.github_run_id(
                "https://github.com/Project-Helianthus/"
                "helianthus-modbus/actions/runs/not-a-run"
            )

    def test_doc_gate_rejects_authority_reintroduction(self) -> None:
        document = validator.load_json(
            ROOT / "policy" / "m1-02-acceptance.json"
        )
        document["gates"]["doc_gate"] = {
            "applicable": True,
            "reason": "documentation authority reintroduced",
        }
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_gate_contract(document)


if __name__ == "__main__":
    unittest.main()
