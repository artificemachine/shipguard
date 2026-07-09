"""Tests for PII rules (PII-001+)."""

from __future__ import annotations

from pathlib import Path

import pytest

from shipguard.models import Severity
from shipguard.rules import get_rules_for_file, load_builtin_rules
from shipguard.rules.pii import pii_001_ssn

FIXTURES = Path(__file__).parent / "fixtures" / "pii"


class TestPii001Ssn:
    def test_pii_001_detects_ssn(self):
        """Test that PII-001 detects US SSN pattern (XXX-XX-XXXX)."""
        findings = pii_001_ssn(Path("x.yml"), "ssn: 123-45-6789")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PII-001"
        assert f.severity == Severity.HIGH
        assert f.cwe_id == "CWE-359"
        assert "123-45-6789" in f.line_content

    def test_pii_001_skips_invalid_area_number(self):
        """Structurally invalid SSN area numbers (000, 666, 9XX) are rejected."""
        for invalid in ("000-45-6789", "666-45-6789", "900-45-6789", "901-45-6789", "999-45-6789"):
            findings = pii_001_ssn(Path("x.yml"), f"ssn: {invalid}")
            assert findings == [], f"expected 0 findings for area-invalid {invalid!r}"

    def test_pii_001_skips_invalid_group_or_serial(self):
        """SSN group == 00 or serial == 0000 are rejected."""
        for invalid in ("123-00-6789", "123-45-0000"):
            findings = pii_001_ssn(Path("x.yml"), f"ssn: {invalid}")
            assert findings == [], f"expected 0 findings for {invalid!r}"

    def test_pii_001_skips_comments(self):
        """Commented-out SSN lines are skipped."""
        findings = pii_001_ssn(Path("x.yml"), "# ssn: 123-45-6789")
        assert findings == []

    def test_pii_001_skips_env_var_refs(self):
        """Environment-variable references are skipped."""
        findings = pii_001_ssn(Path("x.yml"), "ssn: ${SSN}")
        assert findings == []

    def test_pii_001_multiple_ssns(self):
        """Two valid SSNs on separate lines produce two findings."""
        content = "ssn: 123-45-6789\nssn_field: 456-78-9012\n"
        findings = pii_001_ssn(Path("x.yml"), content)
        assert len(findings) == 2
        assert {f.line_number for f in findings} == {1, 2}

    def test_pii_001_no_match_returns_empty(self):
        """Lines without any SSN pattern return no findings."""
        findings = pii_001_ssn(Path("x.yml"), "name: alice\nage: 30\nphone: 555-0100\n")
        assert findings == []

    def test_pii_001_metadata(self):
        """PII-001 is registered with the correct metadata."""
        load_builtin_rules()
        rules_for_py = get_rules_for_file(Path("x.py"))
        rules_for_yml = get_rules_for_file(Path("x.yml"))
        assert any(r.id == "PII-001" for r in rules_for_py)
        assert any(r.id == "PII-001" for r in rules_for_yml)

    def test_pii_001_compliance_tags(self):
        """PII-001 carries GDPR/SOC2/HIPAA compliance tags."""
        from shipguard.rules import get_registry

        load_builtin_rules()
        meta = get_registry()["PII-001"]
        assert "GDPR-Art32" in meta.compliance_tags
        assert "SOC2-CC6.1" in meta.compliance_tags
        assert "HIPAA-164.312.a" in meta.compliance_tags
