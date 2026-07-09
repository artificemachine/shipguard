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


class TestPii002CreditCard:
    def test_pii_002_non_allowlisted_luhn_valid_card_emits_finding(self):
        """A Luhn-valid, non-allowlisted card number emits a CRITICAL finding."""
        from shipguard.rules.pii import pii_002_credit_card

        findings = pii_002_credit_card(Path("x.yml"), "card: 4111111111111111")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PII-002"
        assert f.severity == Severity.CRITICAL
        assert f.cwe_id == "CWE-359"
        assert "4111111111111111" in f.line_content

    def test_pii_002_skips_luhn_invalid_number(self):
        """A number that fails Luhn is not reported."""
        from shipguard.rules.pii import pii_002_credit_card

        findings = pii_002_credit_card(Path("x.yml"), "card: 1234567890123456")
        assert findings == []

    def test_pii_002_skips_known_test_cards(self):
        """Public Stripe/Visa/Mastercard/Amex/Discover test numbers are allowlisted."""
        from shipguard.rules.pii import pii_002_credit_card

        for test_card in (
            "4242424242424242",  # Stripe Visa
            "4000000000000002",  # Stripe declined
            "5555555555554444",  # Stripe Mastercard
            "378282246310005",   # Stripe Amex
            "6011111111111117",  # Stripe Discover
        ):
            findings = pii_002_credit_card(Path("x.yml"), f"card: {test_card}")
            assert findings == [], f"expected 0 findings for allowlisted {test_card!r}"

    def test_pii_002_detects_with_spaces_or_dashes(self):
        """Cards written with spaces or dashes are normalised before validation."""
        from shipguard.rules.pii import pii_002_credit_card

        for formatted in ("4111-1111-1111-1111", "4111 1111 1111 1111"):
            findings = pii_002_credit_card(Path("x.yml"), f"card: {formatted}")
            assert len(findings) == 1, f"expected 1 finding for {formatted!r}"
            assert findings[0].severity == Severity.CRITICAL

    def test_luhn_valid_helper(self):
        """_luhn_valid directly validates known-good and known-bad numbers."""
        from shipguard.rules.pii import _luhn_valid

        assert _luhn_valid("4111111111111111") is True
        assert _luhn_valid("4111111111111112") is False
        assert _luhn_valid("4242424242424242") is True  # Luhn-valid (and allowlisted)
        assert _luhn_valid("1234567890123456") is False  # Luhn-invalid

    def test_pii_002_compliance_tags(self):
        """PII-002 carries PCI-3.4/GDPR/SOC2 compliance tags."""
        from shipguard.rules import get_registry

        load_builtin_rules()
        meta = get_registry()["PII-002"]
        assert "PCI-3.4" in meta.compliance_tags
        assert "GDPR-Art32" in meta.compliance_tags
        assert "SOC2-CC6.1" in meta.compliance_tags


class TestPii003Phone:
    def test_pii_003_detects_phone(self):
        """PII-003 detects a NANP-formatted phone number."""
        from shipguard.rules.pii import pii_003_phone

        findings = pii_003_phone(Path("x.yml"), "phone: 415-867-5309")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PII-003"
        assert f.severity == Severity.LOW
        assert f.cwe_id == "CWE-359"

    def test_pii_003_skips_fictional_555_range(self):
        """NANP reserved fictional 555-0100 to 555-0199 is skipped."""
        from shipguard.rules.pii import pii_003_phone

        for fictional in ("415-555-0142", "212-555-0199", "555-0100"):
            findings = pii_003_phone(Path("x.yml"), f"phone: {fictional}")
            assert findings == [], f"expected 0 findings for NANP fictional {fictional!r}"

    @pytest.mark.parametrize(
        "placeholder",
        [
            "000-000-0000",
            "123-456-7890",
            "111-111-1111",
            "555-555-5555",   # not in NANP fictional range — explicit placeholder
            "800-555-1212",   # not in NANP fictional range — explicit placeholder
        ],
    )
    def test_pii_003_skips_placeholder(self, placeholder):
        """Known placeholder phone numbers produce zero findings.

        `555-555-5555` and `800-555-1212` match the PII-003 regex and fall
        outside the 555-0100–555-0199 fictional range, so the range check alone
        does not skip them — the PLACEHOLDER_PHONES set does.
        """
        from shipguard.rules.pii import pii_003_phone

        findings = pii_003_phone(Path("x.yml"), f"phone: {placeholder}")
        assert findings == [], f"expected 0 findings for placeholder {placeholder!r}"

    @pytest.mark.parametrize(
        "formatted",
        [
            "555.555.5555",
            "(555) 555-5555",
        ],
    )
    def test_pii_003_separator_normalisation(self, formatted):
        """PLACEHOLDER_PHONES skips by normalised digits — separator-form does not slip through."""
        from shipguard.rules.pii import pii_003_phone

        findings = pii_003_phone(Path("x.yml"), f"phone: {formatted}")
        assert findings == [], f"expected 0 findings for normalised-placeholder {formatted!r}"


class TestPii004Email:
    def test_pii_004_detects_email(self):
        """PII-004 detects a real-looking email in source/data files."""
        from shipguard.rules.pii import pii_004_email

        findings = pii_004_email(Path("x.py"), "user_record: jane.doe@realcompany.io")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "PII-004"
        assert f.severity == Severity.MEDIUM
        assert f.cwe_id == "CWE-359"

    @pytest.mark.parametrize(
        "email",
        ["user@example.com", "user@example.org", "test@test.com"],
    )
    def test_pii_004_skips_example_domains(self, email):
        """RFC-2606 reserved example domains are skipped."""
        from shipguard.rules.pii import pii_004_email

        findings = pii_004_email(Path("x.py"), f"user: {email}")
        assert findings == [], f"expected 0 findings for example-domain {email!r}"

    @pytest.mark.parametrize(
        "line",
        [
            "author: jane@realcompany.io",
            '"author": "jane@realcompany.io"',
            "maintainer: bob@realcompany.io",
            "email: dev@realcompany.io",
        ],
    )
    def test_pii_004_skips_public_metadata_keys(self, line):
        """Package metadata keys whose value is intentionally public are skipped."""
        from shipguard.rules.pii import pii_004_email

        findings = pii_004_email(Path("x.py"), line)
        assert findings == [], f"expected 0 findings for public-metadata line {line!r}"

    def test_pii_004_skips_noreply_addresses(self):
        """GitHub noreply addresses are skipped."""
        from shipguard.rules.pii import pii_004_email

        findings = pii_004_email(Path("x.py"), "user: 12345+jane@users.noreply.github.com")
        assert findings == []


class TestPiiExtensions:
    def test_csv_excluded_from_pii_dispatch(self):
        """.csv is excluded from PII_EXTS — no PII-* rule applies."""
        from shipguard.rules import get_rules_for_file

        load_builtin_rules()
        rule_ids = {r.id for r in get_rules_for_file(Path("x.csv"))}
        pii_ids = {r for r in rule_ids if r.startswith("PII-")}
        assert pii_ids == set(), f"expected no PII-* on .csv, got {pii_ids}"

    def test_log_excluded_from_pii_dispatch(self):
        """.log is excluded from PII_EXTS — no PII-* rule applies."""
        from shipguard.rules import get_rules_for_file

        load_builtin_rules()
        rule_ids = {r.id for r in get_rules_for_file(Path("x.log"))}
        pii_ids = {r for r in rule_ids if r.startswith("PII-")}
        assert pii_ids == set(), f"expected no PII-* on .log, got {pii_ids}"
