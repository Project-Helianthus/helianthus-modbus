#!/usr/bin/env python3
"""Offline physical-line size ratchet for Go and Python sources.

A limit is exceeded only above its stated value. File spans count blank/comment
lines, including a final unterminated line. Function spans include signatures,
decorators and closing lines; nested declarations count independently (and remain
inside their parent's span). Go literals count with traversal-order identities;
Python identities use lexical class/function scopes, with ordinals for repeated
names. *_test.go and Python beneath any tests/ directory are tests.

The baseline records every soft violation, including hard debt. New soft debt is
reported; new hard debt and growth of any recorded debt fail. Retired identities
paired with new debt of the same metric are rejected as possible moves/renames:
review must reconcile the exact baseline entries rather than laundering debt.
Shrinkage and outright removal are allowed. Baselines are not release clearance:
existing release debt remains due before 0.7. There are no inline exemptions;
exact, justified exceptions require a separate review of the baseline change.
"""

import argparse
import ast
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

LIMITS = {
    "production": {"file_lines": (500, 1000), "function_lines": (80, 150),
                   "functions_per_file": (40, 60)},
    "test": {"file_lines": (800, 1500), "function_lines": (120, 200),
             "functions_per_file": (40, 60)},
}
SKIP = {".git", ".tmp", ".venv", "venv", "vendor", "node_modules", "__pycache__"}
ROOT = Path(__file__).resolve().parent.parent


def source_paths(root):
    return sorted(p for p in root.rglob("*") if p.is_file()
                  and p.suffix in {".go", ".py"}
                  and not SKIP.intersection(p.relative_to(root).parts))


def category(path):
    return "test" if (path.name.endswith("_test.go") or
                      (path.suffix == ".py" and "tests" in path.parts)) else "production"


def python_functions(text):
    result = []
    seen = {}

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                key = (*scope, child.name)
                seen[key] = seen.get(key, 0) + 1
                name = child.name + ("#" + str(seen[key]) if seen[key] > 1 else "")
                qualified = (*scope, name)
                if not isinstance(child, ast.ClassDef):
                    start = min([child.lineno] + [d.lineno for d in child.decorator_list])
                    result.append({"symbol": ".".join(qualified),
                                   "lines": child.end_lineno - start + 1})
                visit(child, qualified)
            else:
                visit(child, scope)

    visit(ast.parse(text), ())
    symbols = [item["symbol"] for item in result]
    if len(symbols) != len(set(symbols)):
        raise ValueError("ambiguous Python function identity")
    return result


def go_functions(paths):
    if not paths:
        return {}
    with tempfile.TemporaryDirectory(prefix="size-parser-") as directory:
        binary = str(Path(directory) / "parser")
        # The parser source is kept as text so it is not a product Go file;
        # it is materialized as a standalone main package only to be built.
        source = Path(directory) / "main.go"
        source.write_text((ROOT / "scripts/sizeratchet/parser.go.txt")
                          .read_text(encoding="utf-8"), encoding="utf-8")
        subprocess.run(["go", "build", "-o", binary, str(source)],
                       check=True, capture_output=True, text=True, timeout=120,
                       cwd=directory,
                       env={**os.environ, "GOWORK": "off"})
        result = subprocess.run([binary, *map(str, paths)], check=True,
                                capture_output=True, text=True, timeout=30)
        return json.loads(result.stdout)


def measure(root):
    paths = source_paths(root)
    parsed = go_functions([p for p in paths if p.suffix == ".go"])
    records = []
    for path in paths:
        text = path.read_text(encoding="utf-8")
        functions = (parsed[str(path)] if path.suffix == ".go"
                     else python_functions(text))
        relative = path.relative_to(root).as_posix()
        common = {"path": relative, "category": category(Path(relative))}
        records.extend([{**common, "symbol": "", "metric": "file_lines",
                         "count": text.count("\n") + int(bool(text) and not text.endswith("\n"))},
                        {**common, "symbol": "", "metric": "functions_per_file",
                         "count": len(functions)}])
        records.extend({**common, "symbol": f["symbol"], "metric": "function_lines",
                        "count": f["lines"]} for f in functions)
    return records


def identity(record):
    return record["path"], record["symbol"], record["metric"]


def load_baseline(path):
    data = json.loads(path.read_text())
    if set(data) != {"version", "convention", "violations"} or data["version"] != 1:
        raise ValueError("unsupported baseline schema")
    result = {}
    for item in data["violations"]:
        if set(item) != {"path", "symbol", "metric", "count", "category"}:
            raise ValueError("invalid baseline entry fields")
        if (not isinstance(item["path"], str) or not item["path"] or
                Path(item["path"]).is_absolute() or ".." in Path(item["path"]).parts or
                not isinstance(item["symbol"], str)):
            raise ValueError("invalid baseline identity")
        limits = LIMITS[item["category"]][item["metric"]]
        if type(item["count"]) is not int or item["count"] <= limits[0]:
            raise ValueError("baseline entry is not a violation")
        if item["category"] != category(Path(item["path"])):
            raise ValueError("baseline category mismatch")
        key = identity(item)
        if key in result:
            raise ValueError("duplicate baseline entry")
        result[key] = item
    return result


def evaluate(records, baseline):
    errors, notices = [], []
    current = {identity(r): r for r in records}
    retired = {key for key, old in baseline.items()
               if key not in current or current[key]["count"] <=
               LIMITS[old["category"]][old["metric"]][0]}
    for record in records:
        key = identity(record)
        soft, hard = LIMITS[record["category"]][record["metric"]]
        count = record["count"]
        label = ":".join(key) + "=" + str(count)
        if key in baseline and count > baseline[key]["count"]:
            errors.append("existing debt grew: " + label)
        if count <= soft:
            continue
        notices.append(("HARD " if count > hard else "SOFT ") + label)
        if key not in baseline:
            if count > hard:
                errors.append("new hard violation: " + label)
            if any(old[2] == record["metric"] for old in retired):
                errors.append("possible moved/renamed debt: " + label)
    return errors, notices


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", required=True)
    args = parser.parse_args(argv)
    del args
    try:
        baseline = load_baseline(ROOT / "scripts/size-baseline.json")
        records = measure(ROOT)
        errors, notices = evaluate(records, baseline)
        for notice in notices:
            print(notice)
        for error in errors:
            print(error, file=sys.stderr)
        print(f"Measured {len(records)} metrics; {len(notices)} violations; {len(errors)} errors")
        return bool(errors)
    except (OSError, ValueError, KeyError, TypeError, SyntaxError, subprocess.SubprocessError) as exc:
        print(f"size ratchet tool error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
