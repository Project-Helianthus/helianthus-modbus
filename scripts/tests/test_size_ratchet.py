"""Synthetic parser, threshold, baseline and fail-closed regression tests."""

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "size_ratchet", Path(__file__).resolve().parents[1] / "check_size_ratchet.py")
ratchet = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ratchet)


def record(count, metric="function_lines", category="production", path="source.go", symbol="Read"):
    return dict(path=path, symbol=symbol, metric=metric, count=count, category=category)


def baseline(*items):
    return {ratchet.identity(item): item for item in items}


class ThresholdTests(unittest.TestCase):
    def test_every_threshold_pair(self):
        for kind, metrics in ratchet.LIMITS.items():
            for metric, (soft, hard) in metrics.items():
                for value in (soft, soft + 1, hard, hard + 1):
                    with self.subTest(category=kind, metric=metric, count=value):
                        errors, notices = ratchet.evaluate([record(value, metric, kind)], {})
                        self.assertEqual(bool(notices), value > soft)
                        self.assertEqual(bool(errors), value > hard)

    def test_each_baseline_identity_field(self):
        old = record(100)
        for field, value in [("path", "other.go"), ("symbol", "Write"),
                             ("metric", "file_lines")]:
            with self.subTest(field=field):
                changed = {**old, field: value}
                if field == "metric":
                    changed["count"] = 1100
                errors, _ = ratchet.evaluate([changed], baseline(old))
                self.assertTrue(errors)

    def test_growth_by_one(self):
        for kind, metrics in ratchet.LIMITS.items():
            for metric, (soft, _) in metrics.items():
                old = record(soft + 1, metric, kind)
                for delta in (-1, 0, 1):
                    with self.subTest(kind=kind, metric=metric, delta=delta):
                        errors, _ = ratchet.evaluate([{**old, "count": old["count"] + delta}], baseline(old))
                        self.assertEqual(bool(errors), delta > 0)

    def test_existing_hard_debt_can_shrink_but_not_grow(self):
        for kind, metrics in ratchet.LIMITS.items():
            for metric, (_, hard) in metrics.items():
                old = record(hard + 10, metric, kind)
                for delta in (-1, 0, 1):
                    with self.subTest(kind=kind, metric=metric, delta=delta):
                        errors, _ = ratchet.evaluate([{**old, "count": old["count"] + delta}], baseline(old))
                        self.assertEqual(bool(errors), delta > 0)

    def test_removal_is_allowed(self):
        self.assertEqual(ratchet.evaluate([], baseline(record(100)))[0], [])

    def test_soft_move_or_rename_is_rejected(self):
        for field, value in [("path", "moved.go"), ("symbol", "Renamed")]:
            with self.subTest(field=field):
                old = record(100)
                errors, _ = ratchet.evaluate([{**old, field: value}], baseline(old))
                self.assertTrue(any("moved/renamed" in error for error in errors))

    def test_new_soft_is_report_only(self):
        errors, notices = ratchet.evaluate([record(81)], {})
        self.assertEqual(errors, [])
        self.assertEqual(len(notices), 1)


class ParserTests(unittest.TestCase):
    def test_python_nested_methods_async_decorators_and_strings(self):
        text = ('class Reader:\n @decorator\n async def read(self):\n'
                '  text = """def fake():\n } {\n """\n'
                '  # def ignored():\n  def nested():\n   return 1\n  return nested()\n')
        self.assertEqual(ratchet.python_functions(text), [
            {"symbol": "Reader.read", "lines": 9},
            {"symbol": "Reader.read.nested", "lines": 2}])

    def test_python_repeated_names(self):
        text = 'def read():\n pass\ndef read():\n pass\n'
        self.assertEqual([f["symbol"] for f in ratchet.python_functions(text)], ["read", "read#2"])

    def test_conditional_python_repeated_names(self):
        text = 'if True:\n def read():\n  pass\nelse:\n def read():\n  pass\n'
        self.assertEqual([f["symbol"] for f in ratchet.python_functions(text)], ["read", "read#2"])

    def test_python_syntax_error(self):
        with self.assertRaises(SyntaxError):
            ratchet.python_functions("def broken(")

    def test_source_classification(self):
        for path, expected in [("reader_test.go", "test"), ("reader.go", "production"),
                               ("tests/reader.py", "test"), ("scripts/tests/check.py", "test"),
                               ("scripts/check.py", "production")]:
            with self.subTest(path=path):
                self.assertEqual(ratchet.category(Path(path)), expected)

    def test_go_methods_literals_comments_strings_and_line_directive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.go"
            path.write_text('package sample\n//line synthetic.go:9000\n'
                            'func (r *Reader) Read() {\n // func fake() { }\n'
                            ' _ = `} {\nfunc fake() {}`\n /* func hidden() {\n } */\n _ = func() {\n }\n}\n'
                            'type Reader struct{}\n')
            self.assertEqual(ratchet.go_functions([path])[str(path)], [
                {"symbol": "Reader.Read", "lines": 9}, {"symbol": "literal#1", "lines": 2}])

    def test_actual_physical_line_boundaries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for suffix, function, closer, test_name, kinds in [
                    (".py", "def read():\n", " pass", "tests/source.py", ("production", "test")),
                    (".go", "package sample\nfunc Read() {\n", "}", "source_test.go", ("production", "test"))]:
                for kind in kinds:
                    name = test_name if kind == "test" else "source" + suffix
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    for metric, (soft, hard) in ratchet.LIMITS[kind].items():
                        for count in (soft, soft + 1, hard, hard + 1):
                            with self.subTest(suffix=suffix, kind=kind, metric=metric, count=count):
                                if metric == "file_lines":
                                    text = ("package sample\n" if suffix == ".go" else "# source\n")
                                    text += "\n" * (count - 1)
                                elif metric == "function_lines":
                                    prefix = 1 if suffix == ".py" else 2
                                    text = function + "\n" * (count - 2) + closer + "\n"
                                    if prefix == 2:
                                        self.assertEqual(text.count("\n"), count + 1)
                                else:
                                    text = "package sample\n" if suffix == ".go" else ""
                                    for number in range(count):
                                        text += (f"func Read{number}() {{}}\n" if suffix == ".go"
                                                 else f"def read{number}():\n pass\n")
                                path.write_text(text)
                                measured = ratchet.measure(root)
                                actual = [r for r in measured if r["path"] == name and r["metric"] == metric]
                                self.assertEqual(len(actual), 1)
                                self.assertEqual(actual[0]["count"], count)
                    path.unlink()

    def test_unterminated_line_and_unicode_string(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.py"
            path.write_text('value = "a\u2028b"')
            self.assertEqual(ratchet.measure(path.parent)[0]["count"], 1)

    def test_ignored_scratch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".tmp").mkdir()
            (root / ".tmp/broken.py").write_text("def broken(")
            self.assertEqual(ratchet.measure(root), [])

    def test_go_parse_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.go"
            path.write_text("package broken\nfunc (")
            with self.assertRaises(subprocess.CalledProcessError):
                ratchet.go_functions([path])


class BaselineAndToolTests(unittest.TestCase):
    def write_baseline(self, root, entries):
        path = root / "baseline.json"
        path.write_text(json.dumps(dict(version=1, convention="physical lines", violations=entries)))
        return path

    def test_duplicate_baseline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self.write_baseline(Path(directory), [record(100), record(100)])
            with self.assertRaisesRegex(ValueError, "duplicate"):
                ratchet.load_baseline(path)

    def test_baseline_category_and_count_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            for changes in [{"category": "test"}, {"count": 80}, {"count": True},
                            {"path": "../source.go"}, {"metric": "unknown"}]:
                with self.subTest(changes=changes):
                    path = self.write_baseline(Path(directory), [{**record(100), **changes}])
                    with self.assertRaises((ValueError, KeyError)):
                        ratchet.load_baseline(path)

    def test_category_cannot_reclassify_existing_debt(self):
        with tempfile.TemporaryDirectory() as directory:
            original = record(180)
            path = self.write_baseline(Path(directory), [original])
            self.assertEqual(ratchet.load_baseline(path), baseline(original))
            path = self.write_baseline(Path(directory), [{**original, "category": "test"}])
            with self.assertRaisesRegex(ValueError, "category mismatch"):
                ratchet.load_baseline(path)

    def test_tool_failures_are_nonzero(self):
        for error in [FileNotFoundError("go"), subprocess.TimeoutExpired("go", 1),
                      subprocess.CalledProcessError(1, "go"), ValueError("bad parser JSON"), SyntaxError("bad Python")]:
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(ratchet, "load_baseline", return_value={}), \
                        mock.patch.object(ratchet, "measure", side_effect=error):
                    self.assertEqual(ratchet.main(["--check"]), 2)

    def test_invalid_baseline_fails_cli(self):
        with mock.patch.object(ratchet, "load_baseline", side_effect=ValueError("duplicate")):
            self.assertEqual(ratchet.main(["--check"]), 2)

    def test_missing_go_tool_propagates(self):
        with mock.patch.object(ratchet.subprocess, "run", side_effect=FileNotFoundError("go")):
            with self.assertRaises(FileNotFoundError):
                ratchet.go_functions([Path("source.go")])


if __name__ == "__main__":
    unittest.main()
