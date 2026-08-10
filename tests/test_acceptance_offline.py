from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATORS = (
    "scripts/validate_m1_02_acceptance.py",
    "scripts/validate_m1_03_acceptance.py",
    "scripts/validate_m1_04_acceptance.py",
)


class OfflineAcceptanceTests(unittest.TestCase):
    def test_historical_validators_pass_without_git_history_or_github(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            temp_root = Path(temp)
            checkout = temp_root / "checkout"
            shutil.copytree(
                ROOT,
                checkout,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    ".pytest_cache",
                ),
            )
            self.assertFalse((checkout / ".git").exists())

            fake_bin = temp_root / "bin"
            fake_bin.mkdir()
            for command in ("git", "gh"):
                executable = fake_bin / command
                executable.write_text(
                    "#!/bin/sh\n"
                    "echo 'historical external command invoked' >&2\n"
                    "exit 97\n",
                    encoding="utf-8",
                )
                executable.chmod(0o755)

            environment = {
                **os.environ,
                "CI": "true",
                "GITHUB_ACTIONS": "true",
                "GOWORK": "off",
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            }
            for validator in VALIDATORS:
                with self.subTest(validator=validator):
                    result = subprocess.run(
                        [sys.executable, validator],
                        cwd=checkout,
                        env=environment,
                        check=False,
                        capture_output=True,
                        text=True,
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        msg=f"{result.stdout}\n{result.stderr}",
                    )


if __name__ == "__main__":
    unittest.main()
