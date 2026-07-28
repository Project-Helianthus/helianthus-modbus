from __future__ import annotations

import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "validate_m1_02_acceptance.py"
SPEC = importlib.util.spec_from_file_location("validate_m1_02_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validator)


class AcceptanceEvidenceTests(unittest.TestCase):
    def document_and_tests(self) -> tuple[dict[str, object], set[str]]:
        document = json.loads(
            (ROOT / "policy" / "m1-02-acceptance.json").read_text(
                encoding="utf-8"
            )
        )
        evidence = validator.test_evidence(ROOT)
        document["test_file_sha256"] = evidence["test_files"]
        tests = validator.validate_requirement_contract(document)
        tests.update(validator.validate_transport_matrix(ROOT, document))
        return document, tests

    def test_all_mapped_tests_emit_run_and_pass_events(self) -> None:
        _, tests = self.document_and_tests()
        validator.run_mapped_tests(ROOT, tests)

    def test_empty_mapped_test_body_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for source in ROOT.glob("*_test.go"):
                shutil.copy2(source, root / source.name)
            target = root / "tcp_adu_test.go"
            original = target.read_text(encoding="utf-8")
            mutated, replacements = re.subn(
                (
                    r"func TestTCPStreamDecoderHandlesFragmentationAndMultipleADUs"
                    r"\(t \*testing\.T\) \{.*?\n\}\n\nfunc "
                ),
                (
                    "func TestTCPStreamDecoderHandlesFragmentationAndMultipleADUs"
                    "(t *testing.T) {}\n\nfunc "
                ),
                original,
                count=1,
                flags=re.DOTALL,
            )
            self.assertEqual(replacements, 1)
            target.write_text(mutated, encoding="utf-8")
            document, tests = self.document_and_tests()
            with self.assertRaises(validator.AcceptanceError):
                validator.validate_body_evidence(root, document, tests)

    def test_test_main_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for source in ROOT.glob("*_test.go"):
                shutil.copy2(source, root / source.name)
            target = root / "tcp_adu_test.go"
            target.write_text(
                target.read_text(encoding="utf-8")
                + "\nfunc TestMain(m *testing.M) {}\n",
                encoding="utf-8",
            )
            document, tests = self.document_and_tests()
            with self.assertRaisesRegex(
                validator.AcceptanceError,
                "TestMain is forbidden",
            ):
                validator.validate_body_evidence(root, document, tests)


if __name__ == "__main__":
    unittest.main()
