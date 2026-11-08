"""Synthetic tests for finite diagnostic identities and tool failures."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('guard', Path(__file__).resolve().parents[1] / 'check_go_lint_baseline.py')
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class BaselineTests(unittest.TestCase):
    def row(self, **changes):
        return dict(dict(path='sample.go', symbol='ReadValue', rule='revive/exported', count=2), **changes)

    def load(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'baseline.json'
            path.write_text(json.dumps(dict(version=1, golangci_lint=guard.VERSION, entries=rows)))
            return guard.load_baseline(path)

    def test_equal(self):
        expected = self.load([self.row()])
        self.assertEqual([], guard.compare(expected, expected))

    def test_reduction(self):
        expected = self.load([self.row()])
        self.assertEqual([], guard.compare(expected, {next(iter(expected)): 1}))

    def test_growth(self):
        expected = self.load([self.row()])
        self.assertTrue(guard.compare(expected, {next(iter(expected)): 3}))

    def test_path_move(self):
        expected = self.load([self.row()])
        self.assertTrue(guard.compare(expected, self.load([self.row(path='other.go')])))

    def test_symbol_change(self):
        expected = self.load([self.row()])
        self.assertTrue(guard.compare(expected, self.load([self.row(symbol='OtherValue')])))

    def test_rule_change(self):
        expected = self.load([self.row()])
        self.assertTrue(guard.compare(expected, self.load([self.row(rule='revive/package-comments')])))

    def test_duplicate_rows(self):
        with self.assertRaises(ValueError):
            self.load([self.row(), self.row()])

    def test_stale_debt(self):
        self.assertTrue(guard.compare(self.load([self.row()]), {}))

    def test_invalid_counts(self):
        for count in (0, -1, True, 1.5, '2'):
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.load([self.row(count=count)])

    def test_invalid_path(self):
        for path in ('../sample.go', '/sample.go', './sample.go'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.load([self.row(path=path)])

    def test_unknown_rule(self):
        with self.assertRaises(ValueError):
            self.load([self.row(rule='govet')])

    def test_nonzero_tool_exit(self):
        result = subprocess.CompletedProcess([], 7, '', 'synthetic failure')
        with patch.object(guard.subprocess, 'run', return_value=result), self.assertRaisesRegex(ValueError, 'tool exit 7'):
            guard.checked_run(['synthetic-linter'])

    def test_timeout(self):
        with patch.object(guard.subprocess, 'run', side_effect=subprocess.TimeoutExpired('synthetic', 150)), self.assertRaises(subprocess.TimeoutExpired):
            guard.checked_run(['synthetic-linter'])

    def test_duplicate_json_fields(self):
        with self.assertRaises(ValueError):
            json.loads('{"version":1,"version":1}', object_pairs_hook=guard.unique_object)

    def test_unbaselined_linter(self):
        with self.assertRaises(ValueError):
            guard.diagnostic_key(dict(Pos=dict(Filename='sample.go'), FromLinter='govet', Text='synthetic'))

    def test_exported_identity(self):
        issue = dict(Pos=dict(Filename='sample.go'), FromLinter='revive', Text='exported: exported method Reader.ReadValue should have comment or be unexported')
        self.assertEqual(('sample.go', 'Reader.ReadValue', 'revive/exported'), guard.diagnostic_key(issue))

    def test_main_fails_closed(self):
        with patch('sys.argv', ['guard', '--check']), patch.object(guard, 'collect', side_effect=ValueError('synthetic tool failure')):
            self.assertEqual(1, guard.main())

    def test_diagnostic_path_identity(self):
        def issue(path):
            return dict(Pos=dict(Filename=path), FromLinter='revive', Text='exported: exported type ReadValue should have comment or be unexported')
        self.assertNotEqual(guard.diagnostic_key(issue('sample.go')), guard.diagnostic_key(issue('other.go')))

    def test_diagnostic_symbol_identity(self):
        def issue(symbol):
            return dict(Pos=dict(Filename='sample.go'), FromLinter='revive', Text=f'exported: exported type {symbol} should have comment or be unexported')
        self.assertNotEqual(guard.diagnostic_key(issue('ReadValue')), guard.diagnostic_key(issue('OtherValue')))

    def test_diagnostic_rule_identity(self):
        first = dict(Pos=dict(Filename='sample.go'), FromLinter='revive', Text='exported: exported type ReadValue should have comment or be unexported')
        second = dict(Pos=dict(Filename='sample.go'), FromLinter='revive', Text='package-comments: should have a package comment')
        self.assertNotEqual(guard.diagnostic_key(first)[2], guard.diagnostic_key(second)[2])
