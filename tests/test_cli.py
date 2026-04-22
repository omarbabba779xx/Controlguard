from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from controlguard.cli import main


class CliTests(unittest.TestCase):
    def test_validate_command_returns_zero_for_builtin_profile(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["validate", "--profile", "windows-workstation"])
        self.assertEqual(exit_code, 0)
        self.assertIn("is valid", stdout.getvalue())

    def test_strict_exit_code_fails_on_warn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "warn.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "warn",
                        "manual_evidence": {"disk": "partial"},
                        "controls": [
                            {
                                "id": "manual",
                                "title": "manual",
                                "type": "manual_assertion",
                                "severity": "medium",
                                "evidence_key": "disk",
                                "expected": "encrypted",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["scan", "--config", str(config_path), "--strict", "--format", "json"])
            self.assertEqual(exit_code, 1)

    def test_configuration_error_returns_two(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = main(["validate", "--config", "missing.json"])
        self.assertEqual(exit_code, 2)
        self.assertIn("Configuration error", stderr.getvalue())

    def test_compare_command_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline = Path(temp_dir) / "baseline.json"
            current = Path(temp_dir) / "current.json"
            baseline.write_text(
                json.dumps(
                    {
                        "lab_name": "lab",
                        "generated_at": "2026-04-20T00:00:00+00:00",
                        "results": [{"control_id": "a", "status": "fail", "severity": "high", "title": "A"}],
                        "summary": {"score": 10.0, "blocking_controls": ["a"], "frameworks": {}},
                    }
                ),
                encoding="utf-8",
            )
            current.write_text(
                json.dumps(
                    {
                        "lab_name": "lab",
                        "generated_at": "2026-04-21T00:00:00+00:00",
                        "results": [{"control_id": "a", "status": "pass", "severity": "high", "title": "A"}],
                        "summary": {"score": 90.0, "blocking_controls": [], "frameworks": {}},
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["compare", "--baseline", str(baseline), "--current", str(current)])
            self.assertEqual(exit_code, 0)
            self.assertIn("Score delta", stdout.getvalue())
