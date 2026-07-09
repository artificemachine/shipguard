"""Tests for the engine-level max_findings_per_file cap mechanism.

Covers:
- _cap_findings_per_file: per-file cap with synthesized suppression notice
- Config: max_findings_per_file field, default 0 (unlimited), YAML parsing
- DEFAULT_CONFIG_TEMPLATE: documents the key
- Integration: scan() and scan_files() apply the cap per-file via
  _run_parallel_scans
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shipguard.config import DEFAULT_CONFIG_TEMPLATE, Config
from shipguard.engine import _cap_findings_per_file, scan, scan_files
from shipguard.models import Finding, Severity
from shipguard.rules import get_registry, load_builtin_rules


def _mk_finding(rule_id: str, line: int, file_path: Path | None = None) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        file_path=file_path or Path("x.yml"),
        line_number=line,
        line_content=f"line {line}",
        message=f"finding at line {line}",
        cwe_id="CWE-359",
        fix_hint="fix it",
    )


class TestCapFindingsPerFile:
    def test_cap_disabled_when_zero(self):
        """config.max_findings_per_file=0 means unlimited; no cap, no notice."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 201)]
        out = _cap_findings_per_file(findings, 0, Path("x.yml"))
        assert out == findings
        assert len(out) == 200
        assert all("further" not in f.message for f in out)

    def test_cap_disabled_when_none(self):
        """config.max_findings_per_file=None means unlimited."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 201)]
        out = _cap_findings_per_file(findings, None, Path("x.yml"))
        assert out == findings
        assert len(out) == 200

    def test_cap_triggers_above_threshold(self):
        """200 findings with cap=100 -> 100 kept + 1 notice = 101 total."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 201)]
        out = _cap_findings_per_file(findings, 100, Path("x.yml"))
        assert len(out) == 101
        assert all("further" not in f.message for f in out[:100])
        assert "further" in out[-1].message

    def test_cap_emits_suppression_notice(self):
        """105 findings with cap=100 -> notice names the true total + opt-out paths.

        Notice uses Severity.MEDIUM (not LOW) so it survives the default
        severity_threshold filter in _scan_file. The plan specified LOW,
        but a LOW notice is invisible to users on the default MEDIUM
        threshold. MEDIUM keeps the notice visible by default without
        inflating the report.
        """
        findings = [_mk_finding("PII-004", i) for i in range(1, 106)]
        out = _cap_findings_per_file(findings, 100, Path("x.yml"))
        assert len(out) == 101
        notice = out[-1]
        assert notice.severity == Severity.MEDIUM
        assert "further" in notice.message
        assert "105" in notice.message  # true total
        assert "exclude_paths" in notice.message
        assert "disable_rules" in notice.message

    def test_cap_uses_last_kept_line_number(self):
        """Notice inherits the line number of the last kept finding."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 1001)]
        out = _cap_findings_per_file(findings, 100, Path("x.yml"))
        # 100th kept finding has line_number=100 (i starts at 1).
        assert out[-1].line_number == 100

    def test_cap_groups_by_rule_id(self):
        """Per-file cap aggregates across rules in input order.

        200 findings (150 PII-004 + 50 PII-001) with cap=100. The cap
        keeps the first 100 findings by *input order*, not per-rule —
        the rationale being that all rules' findings compete for the
        same budget on a single file. Since the first 100 findings
        are all PII-004 (lines 1-150), the kept set is 100 PII-004
        and 0 PII-001. The notice names PII-004 (the rule with
        overflow) and includes the per-rule count.
        """
        findings = (
            [_mk_finding("PII-004", i) for i in range(1, 151)]  # 150 findings
            + [_mk_finding("PII-001", i) for i in range(151, 201)]  # 50 findings
        )
        out = _cap_findings_per_file(findings, 100, Path("x.yml"))
        assert len(out) == 101
        pii001_count = sum(1 for f in out if f.rule_id == "PII-001")
        pii004_count = sum(1 for f in out if f.rule_id == "PII-004")
        # 100 kept PII-004 + 1 notice (whose rule_id is PII-004) = 101.
        assert pii004_count == 101
        assert pii001_count == 0
        # Notice names PII-004 (the rule with overflow).
        assert "PII-004" in out[-1].message
        # Notice names the per-rule overflow count: 150 - 100 = 50 from PII-004.
        assert "50 from PII-004" in out[-1].message

    def test_cap_preserves_kept_finding_identity(self):
        """First N kept findings are the same objects (identity, not just equality)."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 106)]
        out = _cap_findings_per_file(findings, 100, Path("x.yml"))
        for i in range(100):
            assert out[i] is findings[i]

    def test_cap_below_threshold_no_notice(self):
        """50 findings with cap=100 -> 50 unchanged, no notice."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 51)]
        out = _cap_findings_per_file(findings, 100, Path("x.yml"))
        assert len(out) == 50
        assert all("further" not in f.message for f in out)


class TestEngineConfig:
    def test_default_config_has_max_findings_per_file_field(self):
        """Config() constructs without error; the field exists with default 0."""
        cfg = Config()
        assert hasattr(cfg, "max_findings_per_file")
        assert cfg.max_findings_per_file == 0

    def test_config_parses_max_findings_per_file_from_yaml(self, tmp_path):
        """A .shipguard.yml with max_findings_per_file: 250 is loaded into Config."""
        from shipguard.config import load_config

        config_file = tmp_path / ".shipguard.yml"
        config_file.write_text("max_findings_per_file: 250\n")
        cfg = load_config(config_path=config_file)
        assert cfg.max_findings_per_file == 250

    def test_config_template_documents_max_findings_per_file(self):
        """DEFAULT_CONFIG_TEMPLATE contains a comment showing the cap key."""
        assert "max_findings_per_file" in DEFAULT_CONFIG_TEMPLATE


class TestEngineIntegration:
    def test_scan_applies_cap_to_per_rule_findings(self, tmp_path):
        """scan() applies the cap per-file via _run_parallel_scans."""
        # Build a 1000-line .sql file of distinct PII-004-detectable emails.
        seed = tmp_path / "seed.sql"
        lines = [
            f"INSERT INTO users (email) VALUES ('user{i}@realcompany.io');"
            for i in range(1000)
        ]
        seed.write_text("\n".join(lines))

        config_file = tmp_path / ".shipguard.yml"
        config_file.write_text("max_findings_per_file: 50\n")

        from shipguard.config import load_config

        cfg = load_config(config_path=config_file)
        result = scan(tmp_path, config=cfg)

        # 1 file, 1000 PII-004 findings, cap=50 -> 50 + 1 notice = 51.
        assert len(result.findings) == 51
        # The notice is the last finding; the rest are PII-004.
        assert result.findings[-1].rule_id == "PII-004"
        assert "further" in result.findings[-1].message
        # First 50 are real findings, not notices.
        assert all("further" not in f.message for f in result.findings[:50])

    def test_scan_files_applies_cap(self, tmp_path):
        """scan_files() applies the cap per-file via _run_parallel_scans."""
        seed = tmp_path / "seed.sql"
        lines = [
            f"INSERT INTO users (email) VALUES ('user{i}@realcompany.io');"
            for i in range(1000)
        ]
        seed.write_text("\n".join(lines))

        config_file = tmp_path / ".shipguard.yml"
        config_file.write_text("max_findings_per_file: 50\n")

        from shipguard.config import load_config

        cfg = load_config(config_path=config_file)
        result = scan_files([seed], tmp_path, config=cfg)

        assert len(result.findings) == 51
        assert "further" in result.findings[-1].message

    def test_scan_with_default_config_unaffected(self, tmp_path):
        """scan() with default config + low severity threshold = 101 findings.

        With default config (cap=0), the engine cap is a no-op. The
        PII-local cap (100, hardcoded) is still active. With severity
        threshold LOW (to bypass the default MEDIUM filter, which would
        drop the LOW-severity PII notice), the result is 100 real PII
        findings + 1 PII suppression notice = 101. The engine cap
        contributed nothing here.
        """
        from shipguard.models import Severity

        seed = tmp_path / "seed.sql"
        lines = [
            f"INSERT INTO users (email) VALUES ('user{i}@realcompany.io');"
            for i in range(1000)
        ]
        seed.write_text("\n".join(lines))

        result = scan(tmp_path, severity_threshold=Severity.LOW)
        assert len(result.findings) == 101
        # The PII-local cap's notice is the last finding.
        assert "further" in result.findings[-1].message
