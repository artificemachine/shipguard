"""Tests for the ShipGuard CLI."""

from pathlib import Path

from typer.testing import CliRunner

from shipguard.cli import app
from shipguard.rules import _registry

runner = CliRunner()
FIXTURES = Path(__file__).parent / "fixtures"


class TestScanCommand:
    def test_scan_finds_vulnerabilities(self):
        result = runner.invoke(app, ["scan", str(FIXTURES)])
        # Exit code 1 means findings were found
        assert result.exit_code == 1

    def test_scan_json_format(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "json"])
        assert result.exit_code == 1
        assert '"findings"' in result.output
        assert '"summary"' in result.output

    def test_scan_markdown_format(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "markdown"])
        assert result.exit_code == 1
        assert "# ShipGuard Security Report" in result.output

    def test_scan_severity_filter(self):
        result = runner.invoke(
            app, ["scan", str(FIXTURES), "--severity", "critical", "--format", "json"]
        )
        # May find critical issues
        import json
        data = json.loads(result.output)
        for finding in data["findings"]:
            assert finding["severity"] == "critical"

    def test_scan_empty_dir(self, tmp_path):
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_output_file(self, tmp_path):
        out = tmp_path / "report.json"
        result = runner.invoke(
            app, ["scan", str(FIXTURES), "--format", "json", "--output", str(out)]
        )
        assert out.exists()
        assert '"findings"' in out.read_text()

    def test_scan_output_file_terminal_format(self, tmp_path):
        out = tmp_path / "report.txt"
        result = runner.invoke(
            app, ["scan", str(FIXTURES), "--format", "terminal", "--output", str(out)]
        )
        assert result.exit_code == 1
        assert out.exists()
        assert "Security Findings" in out.read_text()

    def test_scan_invalid_severity(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--severity", "bogus"])
        assert result.exit_code == 1

    def test_scan_invalid_format(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--format", "bogus"])
        assert result.exit_code == 1
        assert "Unknown format" in result.output

    def test_scan_accepts_rust_secrets_flag(self):
        result = runner.invoke(app, ["scan", str(FIXTURES), "--rust-secrets", "--format", "json"])
        assert result.exit_code == 1

    def test_scan_include_rules_filters_findings(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES), "--include-rules", "PY-003", "--format", "json"],
        )
        assert result.exit_code == 1
        import json
        data = json.loads(result.output)
        assert data["summary"]["total"] >= 1
        assert {f["rule_id"] for f in data["findings"]} == {"PY-003"}

    def test_scan_exclude_rules_filters_findings(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES), "--exclude-rules", "PY-003", "--format", "json"],
        )
        assert result.exit_code == 1
        import json
        data = json.loads(result.output)
        assert "PY-003" not in {f["rule_id"] for f in data["findings"]}

    def test_scan_rejects_unknown_rule_filter(self):
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES), "--include-rules", "NOPE-999", "--format", "json"],
        )
        assert result.exit_code == 1
        assert "Unknown rule ID" in result.output

    def test_scan_include_custom_rule_via_config(self, tmp_path):
        custom_dir = tmp_path / "custom_rules"
        custom_dir.mkdir()
        (custom_dir / "custom_rule.py").write_text(
            """
from shipguard.models import Finding, Severity
from shipguard.rules import register

@register(
    id="CUST-001",
    name="custom-test-rule",
    severity=Severity.LOW,
    description="Custom rule for tests",
    extensions=[".txt"],
)
def custom_rule(file_path, content, config=None, **kwargs):
    findings = []

    for i, line in enumerate(content.splitlines(), 1):
        if "danger" in line:
            findings.append(
                Finding(
                    rule_id="CUST-001",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="custom danger marker found",
                )
            )
    return findings
""".strip()
        )
        cfg = tmp_path / ".shipguard.yml"
        cfg.write_text("custom_rules_dirs:\n  - custom_rules\n")
        (tmp_path / "sample.txt").write_text("ok\ndanger\n")

        try:
            result = runner.invoke(
                app,
                [
                    "scan",
                    str(tmp_path),
                    "--config",
                    str(cfg),
                    "--include-rules",
                    "CUST-001",
                    "--format",
                    "json",
                    "--severity",
                    "low",
                ],
            )
            assert result.exit_code == 1
            import json
            payload = json.loads(result.output)
            assert payload["summary"]["total"] >= 1
            assert {f["rule_id"] for f in payload["findings"]} == {"CUST-001"}
        finally:
            _registry.pop("CUST-001", None)


class TestListRulesCommand:
    def test_list_rules_terminal(self):
        result = runner.invoke(app, ["list-rules"])
        assert result.exit_code == 0
        assert "SHELL-001" in result.output
        assert "PY-001" in result.output

    def test_list_rules_json(self):
        result = runner.invoke(app, ["list-rules", "--format", "json"])
        assert result.exit_code == 0
        import json
        rules = json.loads(result.output)
        assert len(rules) == 61
        ids = {r["id"] for r in rules}
        assert "SHELL-001" in ids
        assert "CFG-003" in ids
        assert "SEC-001" in ids
        assert "SEC-004" in ids
        assert "SEC-010" in ids
        assert "SEC-011" in ids
        assert "SEC-015" in ids
        assert "PY-010" in ids
        assert "PY-012" in ids
        assert "SC-001" in ids
        assert "SC-004" in ids
        assert "PII-001" in ids
        # New rules from Phase 2
        assert "SC-005" in ids
        assert "SC-006" in ids
        assert "CFG-004" in ids
        assert "CFG-005" in ids
        # Verify compliance_tags field present
        rule_map = {r["id"]: r for r in rules}
        assert "compliance_tags" in rule_map["PY-001"]
        assert isinstance(rule_map["PY-001"]["compliance_tags"], list)
        assert "SOC2-CC6.1" in rule_map["SEC-001"]["compliance_tags"]

    def test_list_rules_invalid_format(self):
        result = runner.invoke(app, ["list-rules", "--format", "bogus"])
        assert result.exit_code == 1
        assert "Unknown format" in result.output


class TestInitCommand:
    def test_init_creates_config(self, tmp_path):
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / ".shipguard.yml").exists()

    def test_init_refuses_overwrite(self, tmp_path):
        (tmp_path / ".shipguard.yml").write_text("existing")
        result = runner.invoke(app, ["init", str(tmp_path)])
        assert result.exit_code == 1


class TestVersion:
    def test_version_flag(self):
        result = runner.invoke(app, ["--version"])
        assert result.exit_code == 0
        assert "shipguard" in result.output
