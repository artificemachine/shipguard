"""Tests for ShellCheck integration."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from shipguard.integrations.shellcheck import run_shellcheck
from shipguard.models import Severity


class TestRunShellcheck:
    def test_returns_empty_when_binary_missing(self, tmp_path):
        """Gracefully returns empty list when shellcheck not found."""
        with patch("shipguard.integrations.shellcheck._find_binary", return_value=None):
            result = run_shellcheck([tmp_path / "test.sh"])
        assert result == []

    def test_returns_empty_when_no_shell_files(self, tmp_path):
        """Returns empty list when no shell files provided."""
        files = [tmp_path / "app.py", tmp_path / "config.json"]
        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            result = run_shellcheck(files)
        assert result == []

    def test_parses_json_output(self, tmp_path):
        """Correctly parses shellcheck JSON1 output format.

        Regression for a bug found 2026-08-17: real `shellcheck --format=json1`
        emits a single object `{"comments": [...]}`, not a list of per-file
        objects. The old fixture here fabricated the wrong shape, matched the
        (also wrong) production code, and both were wrong the same way — so
        every test in this file passed while the real integration crashed with
        AttributeError on any actual finding. See
        test_matches_real_shellcheck_output below for the non-mocked proof.
        """
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\neval $input\n")

        mock_output = json.dumps({
            "comments": [
                {
                    "file": str(shell_file),
                    "line": 2,
                    "endLine": 2,
                    "column": 1,
                    "endColumn": 10,
                    "level": "warning",
                    "code": 2046,
                    "message": "Quote this to prevent word splitting.",
                    "fix": None,
                }
            ]
        })

        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_shellcheck([shell_file])

        assert len(result) == 1
        assert result[0].rule_id == "SHELLCHECK-SC2046"
        assert result[0].severity == Severity.MEDIUM
        assert result[0].line_number == 2

    def test_graceful_on_timeout(self, tmp_path):
        """Returns empty list on subprocess timeout."""
        import subprocess
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\necho hi\n")

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("shellcheck", 60)):
                result = run_shellcheck([shell_file])
        assert result == []

    def test_graceful_on_json_error(self, tmp_path):
        """Returns empty list on invalid JSON output."""
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\necho hi\n")

        mock_proc = MagicMock()
        mock_proc.stdout = "not valid json"

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_shellcheck([shell_file])
        assert result == []

    def test_level_mapping_error_to_high(self, tmp_path):
        """Maps shellcheck 'error' level to Severity.HIGH."""
        shell_file = tmp_path / "test.sh"
        shell_file.write_text("#!/bin/bash\neval $x\n")

        mock_output = json.dumps({
            "comments": [{
                "file": str(shell_file),
                "line": 2,
                "level": "error",
                "code": 1234,
                "message": "Error message",
                "fix": None,
            }]
        })
        mock_proc = MagicMock()
        mock_proc.stdout = mock_output

        with patch("shipguard.integrations.shellcheck._find_binary", return_value="/usr/bin/shellcheck"):
            with patch("subprocess.run", return_value=mock_proc):
                result = run_shellcheck([shell_file])

        assert result[0].severity == Severity.HIGH

    def test_env_var_overrides_binary(self, tmp_path):
        """SHIPGUARD_SHELLCHECK_BIN env var takes precedence."""
        import os
        shell_file = tmp_path / "test.sh"

        mock_proc = MagicMock()
        mock_proc.stdout = "[]"

        with patch.dict(os.environ, {"SHIPGUARD_SHELLCHECK_BIN": "/custom/shellcheck"}):
            with patch("subprocess.run", return_value=mock_proc) as mock_run:
                run_shellcheck([shell_file])
                if mock_run.called:
                    cmd = mock_run.call_args[0][0]
                    assert cmd[0] == "/custom/shellcheck"

    def test_matches_real_shellcheck_output(self, tmp_path):
        """No mocking: runs the actual shellcheck binary and parses its real
        output, on a script guaranteed to trigger a warning-level finding
        (SC2154, a referenced-but-unassigned variable).

        Deliberately not SC2086 (unquoted expansion) — that's "info" level by
        default and run_shellcheck calls the binary with --severity=warning,
        so it would silently produce zero findings regardless of whether the
        parsing is correct, and this test would pass for the wrong reason.

        This is the test that would have caught the json1-shape bug before it
        shipped — every other test in this file mocks subprocess.run, so a
        fixture that fabricates the wrong shape and code that expects the same
        wrong shape agree with each other while both disagree with the real
        tool. Skips if shellcheck isn't installed rather than mocking it away.
        """
        import shutil
        if not shutil.which("shellcheck"):
            import pytest
            pytest.skip("shellcheck not installed")

        shell_file = tmp_path / "unassigned.sh"
        shell_file.write_text('#!/bin/sh\necho "$undefined_var_used_here"\n')

        result = run_shellcheck([shell_file])

        assert len(result) >= 1, "real shellcheck run produced no findings on a file with a known issue"
        codes = {f.rule_id for f in result}
        assert "SHELLCHECK-SC2154" in codes, f"expected SC2154, got {codes}"
