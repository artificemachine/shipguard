"""PII security rules (PII-001+)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register
from shipguard.rules._common import _make_finding, _skip_false_positive

PII_EXTS = [
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rb", ".java", ".php",
    ".sql", ".json", ".yml", ".yaml", ".env", ".conf", ".cfg", ".ini", ".xml",
]

# US SSN: structural validity built into the pattern.
# - area: not 000, not 666, not 9XX (entire 9XX range per SSA rules)
# - group: not 00
# - serial: not 0000
_SSN_PATTERN = re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")

# Credit-card candidate: 4 groups of 4 digits, optional single space or dash
# between groups, total 13-19 digits. We strip separators before validating.
_CARD_PATTERN = re.compile(r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b")

# Public test card numbers from Stripe / major card networks — greppable, extendable.
# Members of this set are Luhn-valid; the rule fires on the intersection of
# Luhn-valid AND not-allowlisted.
TEST_CARD_ALLOWLIST = frozenset({
    "4242424242424242",  # Stripe Visa
    "4000000000000002",  # Stripe declined
    "5555555555554444",  # Stripe Mastercard
    "378282246310005",   # Stripe Amex
    "6011111111111117",  # Stripe Discover
})


def _luhn_valid(digits: str) -> bool:
    """Return True if `digits` (>=2 digit chars) passes the Luhn checksum."""
    if not digits or not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    # Process from rightmost digit; double every second digit from the right.
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


@register(
    id="PII-001",
    name="us-ssn",
    severity=Severity.HIGH,
    description="Detects US Social Security Numbers (XXX-XX-XXXX) in files",
    extensions=PII_EXTS,
    cwe_id="CWE-359",
    compliance_tags=["GDPR-Art32", "SOC2-CC6.1", "HIPAA-164.312.a"],
)
def pii_001_ssn(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for _ in _SSN_PATTERN.finditer(line):
            findings.append(_make_finding(
                "PII-001", Severity.HIGH, file_path, i, line.rstrip(),
                "US Social Security Number detected in file",
                "CWE-359",
                "Remove the SSN from source; if this is test data, use a clearly fake value (e.g. 000-00-0000) or move it to an ignored fixture path",
            ))
    return findings


@register(
    id="PII-002",
    name="credit-card-number",
    severity=Severity.CRITICAL,
    description="Detects credit card numbers (Luhn-validated) in files",
    extensions=PII_EXTS,
    cwe_id="CWE-359",
    compliance_tags=["PCI-3.4", "GDPR-Art32", "SOC2-CC6.1"],
)
def pii_002_credit_card(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for match in _CARD_PATTERN.finditer(line):
            raw = match.group(0)
            digits = raw.replace("-", "").replace(" ", "")
            if not (13 <= len(digits) <= 19):
                continue
            if digits in TEST_CARD_ALLOWLIST:
                continue
            if not _luhn_valid(digits):
                continue
            findings.append(_make_finding(
                "PII-002", Severity.CRITICAL, file_path, i, line.rstrip(),
                f"Credit card number detected in file (Luhn-valid, ending in {digits[-4:]})",
                "CWE-359",
                "Remove the card number and rotate it with the issuer; store payment data only in a PCI-DSS-compliant vault",
            ))
    return findings
