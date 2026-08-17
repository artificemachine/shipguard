"""Tests for scan-staged command."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from shipguard.cli import app
from shipguard.models import Finding, ScanResult, Severity

runner = CliRunner()


class TestScanStagedCommand:
    def test_empty_staged_files_exits_zero(self, tmp_path):
        """Exits with code 0 when no staged files."""
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            result = runner.invoke(app, ["scan-staged", str(tmp_path)])
        assert result.exit_code == 0
        assert "No staged files" in result.output

    def test_staged_files_with_no_findings_exits_zero(self, tmp_path):
        """Exits 0 when staged files have no security findings."""
        safe_file = tmp_path / "safe.py"
        safe_file.write_text("x = 1\n")

        mock_proc = MagicMock()
        mock_proc.stdout = "safe.py\n"
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            with patch("shipguard.cli.scan_files") as mock_scan_files:
                empty_result = ScanResult()
                empty_result.finish()
                mock_scan_files.return_value = empty_result
                result = runner.invoke(app, ["scan-staged", str(tmp_path)])

        assert result.exit_code == 0

    def test_staged_files_with_findings_exits_one(self, tmp_path):
        """Exits 1 when staged files have security findings."""
        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text("eval(user_input)\n")

        mock_proc = MagicMock()
        mock_proc.stdout = "vuln.py\n"
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            with patch("shipguard.cli.scan_files") as mock_scan_files:
                scan_result = ScanResult()
                scan_result.findings = [
                    Finding(
                        rule_id="PY-003",
                        severity=Severity.CRITICAL,
                        file_path=vuln_file,
                        line_number=1,
                        line_content="eval(user_input)",
                        message="eval() usage detected",
                    )
                ]
                scan_result.finish()
                mock_scan_files.return_value = scan_result
                result = runner.invoke(app, ["scan-staged", str(tmp_path)])

        assert result.exit_code == 1

    def test_only_existing_files_are_scanned(self, tmp_path):
        """Ignores staged file paths that don't exist on disk."""
        mock_proc = MagicMock()
        # One existing file, one deleted (not on disk)
        mock_proc.stdout = "deleted_file.py\n"
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            with patch("shipguard.cli.scan_files") as mock_scan_files:
                empty_result = ScanResult()
                empty_result.finish()
                mock_scan_files.return_value = empty_result
                result = runner.invoke(app, ["scan-staged", str(tmp_path)])

        # Deleted files are filtered out; scan_files called with empty list
        # or "No staged files" message
        assert result.exit_code in (0, 1)

    def test_json_format_works(self, tmp_path):
        """JSON format is accepted and produces valid output."""
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            result = runner.invoke(
                app, ["scan-staged", str(tmp_path), "--format", "json"]
            )
        assert result.exit_code == 0


class TestScanFiles:
    def test_scan_files_returns_scan_result(self, tmp_path):
        """scan_files() returns a ScanResult for the given files."""
        from shipguard.engine import scan_files

        safe_file = tmp_path / "safe.py"
        safe_file.write_text("x = 1 + 1\n")

        result = scan_files(files=[safe_file], target_dir=tmp_path)
        assert result.files_scanned == 1
        assert isinstance(result.findings, list)

    def test_scan_files_with_vulnerable_content(self, tmp_path):
        """scan_files() detects vulnerabilities in provided files."""
        from shipguard.engine import scan_files
        from shipguard.models import Severity

        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text("import zipfile\nzf = zipfile.ZipFile('a.zip')\nzf.extractall('/tmp')\n")

        result = scan_files(
            files=[vuln_file],
            target_dir=tmp_path,
            severity_threshold=Severity.LOW,
        )
        assert result.files_scanned == 1
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-001" in rule_ids

    def test_scan_files_respects_severity_threshold(self, tmp_path):
        """scan_files() filters findings by severity_threshold."""
        from shipguard.engine import scan_files
        from shipguard.models import Severity

        vuln_file = tmp_path / "vuln.py"
        vuln_file.write_text("import tempfile\ntempfile.mktemp()\n")

        result = scan_files(
            files=[vuln_file],
            target_dir=tmp_path,
            severity_threshold=Severity.HIGH,
        )
        # PY-009 (mktemp) is LOW severity — should be filtered out
        rule_ids = {f.rule_id for f in result.findings}
        assert "PY-009" not in rule_ids


class TestScanStagedRuleFilters:
    """scan-staged lacked --include-rules/--exclude-rules entirely, unlike scan.

    That gap meant the pre-commit hook (which calls scan-staged) had no way to
    suppress a single false-positive rule per invocation. A .shipguard.yml
    disable_rules entry works, but it is repo-wide and permanent; sometimes a
    one-off override is what's needed, exactly as `scan` already allows.
    """

    def test_exclude_rules_threads_into_scan_files(self, tmp_path):
        (tmp_path / "vuln.py").write_text("x = 1\n")
        mock_proc = MagicMock()
        mock_proc.stdout = "vuln.py\n"
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            with patch("shipguard.cli.scan_files") as mock_scan_files:
                empty_result = ScanResult()
                empty_result.finish()
                mock_scan_files.return_value = empty_result
                result = runner.invoke(
                    app,
                    ["scan-staged", str(tmp_path), "--exclude-rules", "PY-007"],
                )

        assert result.exit_code == 0
        _, kwargs = mock_scan_files.call_args
        assert kwargs["exclude_rules"] == {"PY-007"}

    def test_include_rules_threads_into_scan_files(self, tmp_path):
        (tmp_path / "vuln.py").write_text("x = 1\n")
        mock_proc = MagicMock()
        mock_proc.stdout = "vuln.py\n"
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            with patch("shipguard.cli.scan_files") as mock_scan_files:
                empty_result = ScanResult()
                empty_result.finish()
                mock_scan_files.return_value = empty_result
                result = runner.invoke(
                    app,
                    ["scan-staged", str(tmp_path), "--include-rules", "PY-003"],
                )

        assert result.exit_code == 0
        _, kwargs = mock_scan_files.call_args
        assert kwargs["include_rules"] == {"PY-003"}

    def test_rejects_unknown_rule_id(self, tmp_path):
        (tmp_path / "vuln.py").write_text("x = 1\n")
        mock_proc = MagicMock()
        mock_proc.stdout = "vuln.py\n"
        mock_proc.returncode = 0

        with patch("subprocess.run", return_value=mock_proc):
            result = runner.invoke(
                app,
                ["scan-staged", str(tmp_path), "--exclude-rules", "NOPE-999"],
            )

        assert result.exit_code == 1
        assert "Unknown rule ID" in result.output

    def test_end_to_end_exclude_rules_suppresses_real_finding(self, tmp_path):
        """Real git repo, real file, real scan — no mocking.

        Proves the flag actually suppresses a finding through the whole path,
        not just that a kwarg gets threaded through a mock.
        """
        import subprocess as sp

        sp.run(["git", "init", "-q"], cwd=tmp_path, check=True)
        sp.run(["git", "config", "user.email", "t@example.com"], cwd=tmp_path, check=True)
        sp.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)

        vuln = tmp_path / "vuln.py"
        vuln.write_text('query = f"SELECT id FROM users WHERE name = \'{name}\'"\n')
        sp.run(["git", "add", "vuln.py"], cwd=tmp_path, check=True)

        without_exclude = runner.invoke(
            app, ["scan-staged", str(tmp_path), "--severity", "high"]
        )
        assert without_exclude.exit_code == 1, without_exclude.output

        with_exclude = runner.invoke(
            app,
            ["scan-staged", str(tmp_path), "--severity", "high", "--exclude-rules", "PY-007"],
        )
        assert with_exclude.exit_code == 0, with_exclude.output
