from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_m1_04_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_m1_04_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class M104AcceptanceTests(unittest.TestCase):
    @staticmethod
    def document() -> dict[str, object]:
        return json.loads(
            (ROOT / "policy" / "m1-04-acceptance.json").read_text(
                encoding="utf-8"
            )
        )

    def test_exact_manifest_validates_without_hosted_queries(self) -> None:
        count = validator.validate(
            ROOT,
            self.document(),
            verify_hosted=False,
            execute_tests=False,
        )
        self.assertGreater(count, 0)

    def test_authorization_identity_and_body_are_immutable(self) -> None:
        payload = validator.expected_authorization_payload()
        validator.validate_authorization(payload)
        payload["author_association"] = "CONTRIBUTOR"
        validator.validate_authorization(payload)
        payload["body"] = str(payload["body"]).replace(
            "authorized_issue: FMV3-M1-04",
            "authorized_issue: FMV3-M4-01",
        )
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_authorization(payload)

    def test_transport_gate_rejects_row_and_result_drift(self) -> None:
        document = self.document()
        gate = document["gates"]["transport_gate"]
        gate["expected_rows"] = 20
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_transport_matrix(ROOT, document)

        document = self.document()
        document["gates"]["transport_gate"]["skipped"] = 1
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_transport_matrix(ROOT, document)

    def test_structural_companion_identity_drift_is_rejected(self) -> None:
        document = self.document()
        document["canonical_sources"]["companion"]["contract_version"] = 2
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_canonical_sources(
                ROOT,
                document,
                plan_bytes=None,
                authorization_payload=validator.expected_authorization_payload(),
                verify_hosted=False,
            )

    def test_tdd_red_commit_is_tests_only_and_bound_to_base(self) -> None:
        value = copy.deepcopy(self.document()["gates"]["TDD_RED"])
        validator.validate_tdd(ROOT, value, verify_hosted=False)
        value["base_sha"] = "0" * 40
        with self.assertRaises(validator.AcceptanceError):
            validator.validate_tdd(ROOT, value, verify_hosted=False)


if __name__ == "__main__":
    unittest.main()
