from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {relative}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


conformance = load_module(
    "validate_m1_06_conformance",
    "scripts/validate_m1_06_conformance.py",
)


class M106ConformanceMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact = json.loads(
            (ROOT / "policy" / "m1-06-conformance.json").read_text(
                encoding="utf-8"
            )
        )

    def assert_conformance_rejected(self, artifact: dict[str, object]) -> None:
        with self.assertRaises(conformance.ConformanceError):
            conformance.validate_artifact(artifact)

    def test_current_inventory_is_closed(self) -> None:
        tests = conformance.validate_artifact(self.artifact)
        self.assertEqual(
            tests,
            set().union(*conformance.REQUIREMENTS.values()),
        )

    def test_contract_identity_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.artifact)
        mutated["references"]["public_contract"]["contract_version"] = 2
        self.assert_conformance_rejected(mutated)

    def test_red_commit_mutation_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.artifact)
        mutated["gates"]["TDD_RED"]["test_only_commit_sha"] = "0" * 40
        self.assert_conformance_rejected(mutated)

    def test_test_omission_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.artifact)
        mutated["requirements"][0]["tests"] = []
        self.assert_conformance_rejected(mutated)

    def test_scope_broadening_is_rejected(self) -> None:
        mutated = copy.deepcopy(self.artifact)
        mutated["scope_stop"]["gateway"] = True
        self.assert_conformance_rejected(mutated)
if __name__ == "__main__":
    unittest.main()
