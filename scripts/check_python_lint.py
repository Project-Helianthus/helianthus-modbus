"""Offline, symbol-level ratchet for the complete repository Python inventory."""

import argparse
import ast
from collections import Counter
import json
from pathlib import Path
import re
import subprocess
import sys

VERSION = "0.15.10"
GENERATOR_VERSION = 1
THRESHOLDS = {"complexity": 10, "statements": 50}
ROOT = Path(__file__).resolve().parents[1]
BASELINE = "scripts/python-lint-baseline.json"


def inventory(root):
    return sorted(
        path for path in root.rglob("*.py")
        if not {".git", ".tmp", "__pycache__"}.intersection(path.relative_to(root).parts)
    )


def symbol_at(tree, line):
    names = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if child.lineno <= line <= child.end_lineno:
                    names.append(child.name)
                    visit(child)
            else:
                visit(child)

    visit(tree)
    return ".".join(names) or "<module>"


def collect(root):
    version = subprocess.run(
        [sys.executable, "-m", "ruff", "--version"], capture_output=True, text=True, timeout=30,
        check=True,
    ).stdout.strip()
    if version != f"ruff {VERSION}":
        raise ValueError(f"required ruff {VERSION}; found {version}")
    paths = inventory(root)
    records = Counter()
    for path in paths:
        # Explicit files and isolated settings prevent exclusions, inline suppressions,
        # or unrelated repository configuration from hiding new debt.
        result = subprocess.run(
            [sys.executable, "-m", "ruff", "check", "--isolated", "--no-cache",
             "--ignore-noqa", "--select", "N,C90,PLR0915", "--output-format", "json",
             "--config", "lint.mccabe.max-complexity=10",
             "--config", "lint.pylint.max-statements=50", str(path)],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode not in (0, 1):
            raise ValueError(result.stderr)
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for diagnostic in json.loads(result.stdout):
            message = diagnostic["message"]
            measured = re.search(r"\((\d+) > (\d+)\)", message)
            metric = int(measured[1]) if measured else None
            identity = re.sub(r"\(\d+ > \d+\)", "", message).strip()
            records[(path.relative_to(root).as_posix(), diagnostic["code"],
                     symbol_at(tree, diagnostic["location"]["row"]), identity, metric)] += 1
    return [dict(path=key[0], rule=key[1], symbol=key[2], diagnostic=key[3],
                 measured=key[4], count=count) for key, count in sorted(records.items())]


def document(records):
    return {"generator_version": GENERATOR_VERSION, "ruff_version": VERSION,
            "thresholds": THRESHOLDS,
            "regenerate": "python3 scripts/check_python_lint.py --generate",
            "violations": records}


def compare(expected, actual):
    if expected != actual:
        raise ValueError("Python lint baseline mismatch: new, growing, or stale debt; review regeneration")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    args = parser.parse_args()
    try:
        actual = document(collect(ROOT))
        baseline = ROOT / BASELINE
        if args.generate:
            baseline.write_text(json.dumps(actual, indent=2) + "\n", encoding="utf-8")
        else:
            compare(json.loads(baseline.read_text(encoding="utf-8")), actual)
        print(f"Python lint: {len(inventory(ROOT))} files; baseline matches")
        return 0
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Python lint failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
