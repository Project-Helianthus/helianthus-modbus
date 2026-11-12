"""Exercise the real pinned linter with synthetic repositories and debt."""

import importlib.util
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "python_lint", Path(__file__).resolve().parents[1] / "scripts/check_python_lint.py"
)
LINT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LINT)


def complex_function(count):
    return "def complex_function(value):\n" + "    if value:\n        pass\n" * count


def long_function(count):
    return "def long_function():\n" + "    value = 1\n" * count


class PythonLintTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "existing.py"
        self.source.write_text("def OldName():\n    pass\n")
        self.before = LINT.document(LINT.collect(self.root))

    def assert_rejected(self):
        with self.assertRaises(ValueError):
            LINT.compare(self.before, LINT.document(LINT.collect(self.root)))

    def test_unchanged_debt_passes(self):
        LINT.compare(self.before, LINT.document(LINT.collect(self.root)))

    def test_new_rules_in_already_baselined_file(self):
        for source, rule in [
            ("def NewName():\n    pass\n", "N802"),
            (complex_function(11), "C901"),
            (long_function(52), "PLR0915"),
        ]:
            with self.subTest(rule=rule):
                self.source.write_text("def OldName():\n    pass\n" + source)
                self.assertIn(rule, {row["rule"] for row in LINT.collect(self.root)})
                self.assert_rejected()

    def test_measured_growth(self):
        for factory, start in [(complex_function, 11), (long_function, 52)]:
            with self.subTest(factory=factory.__name__):
                self.source.write_text(factory(start))
                self.before = LINT.document(LINT.collect(self.root))
                self.source.write_text(factory(start + 1))
                self.assert_rejected()

    def test_removed_violation_and_deleted_file_are_stale(self):
        self.source.write_text("def valid_name():\n    pass\n")
        self.assert_rejected()
        self.source.unlink()
        self.assert_rejected()

    def test_identity_fields(self):
        # Path, rule, symbol, diagnostic, measured value and occurrence count
        # are all admission keys: dropping any one permits misattributed debt.
        for field, value in [("path", "other.py"), ("rule", "N803"),
                             ("symbol", "OtherName"), ("diagnostic", "other"),
                             ("measured", 99), ("count", 2)]:
            with self.subTest(field=field):
                actual = LINT.document([dict(self.before["violations"][0], **{field: value})])
                with self.assertRaises(ValueError):
                    LINT.compare(self.before, actual)

    def test_nested_inventory_and_noqa(self):
        nested = self.root / "tooling" / "tests"
        nested.mkdir(parents=True)
        (nested / "extra.py").write_text("def NewName():  # noqa: N802\n    pass\n")
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()
