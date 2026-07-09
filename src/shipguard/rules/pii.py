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

# NANP phone candidate. We parse the matched group to digits before placeholder /
# fictional-range checks, so the matching pattern can stay loose.
_PHONE_PATTERN = re.compile(r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b")

# Placeholder phone numbers stored as normalised bare digits — checked against
# the matched group with separators stripped, so `555.555.5555` and
# `(555) 555-5555` hit the same entry as `555-555-5555`.
# `555-555-5555` and `800-555-1212` match the PII-003 regex and fall OUTSIDE the
# NANPA reserved 555-0100–555-0199 fictional range, so the range check alone does
# not skip them — they need an explicit entry here.
PLACEHOLDER_PHONES = frozenset({
    "0000000000",
    "1234567890",
    "1111111111",
    "5555555555",
    "8005551212",
})

# Email address — local-part @ domain . TLD. TLD is 2+ alpha chars.
_EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

# RFC 2606 reserved example domains (also includes common test/loopback).
SAFE_EMAIL_DOMAINS = frozenset({
    "example.com", "example.org", "example.net", "test.com", "localhost",
})

# Package-metadata keys whose value is intentionally public. Both unquoted (YAML,
# TOML) and double-quoted (JSON) forms. Matched against the line's stripped
# lowercase prefix, not the address, so a maintainer's own email under `email:`
# in package.json is skipped by design. Curated and non-exhaustive — repo-level
# opt-out remains `disable_rules: [PII-004]`.
PUBLIC_METADATA_KEYS = frozenset({
    "author", "maintainer", "contact", "homepage", "support",
    "email", "author_email", "maintainer_email", "contact_email",
    '"author"', '"maintainer"', '"contact"', '"homepage"', '"support"',
    '"email"', '"author_email"', '"maintainer_email"', '"contact_email"',
})

# Per-file cap on findings emitted by any single PII rule. Bounds the worst-case
# output for files like .sql dumps or .json fixtures that can hold dense PII.
# The cap emits an explicit suppression notice — never truncates silently.
MAX_FINDINGS_PER_FILE = 100


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


def _normalise_phone_digits(s: str) -> str:
    """Strip phone separators (`-`, `.`, space, parens, leading +)."""
    return re.sub(r"[+\-.\s()]", "", s)


def _line_starts_with_key(line: str, keys: frozenset[str]) -> bool:
    """True if `line` (stripped, lowercased) begins with one of `keys` followed by `:` or `=`."""
    s = line.lstrip().lower()
    for key in keys:
        if s.startswith(key):
            tail = s[len(key):].lstrip()
            if tail.startswith(":") or tail.startswith("="):
                return True
    return False


def _cap_findings(findings: list[Finding], rule_id: str, file_path: Path) -> list[Finding]:
    """Cap `findings` at MAX_FINDINGS_PER_FILE; append explicit suppression notice if truncated.

    Never silent — the +1 finding names the suppressed total and points at the
    repo-level opt-out mechanisms (exclude_paths, disable_rules).
    """
    total = len(findings)
    if total <= MAX_FINDINGS_PER_FILE:
        return findings
    kept = findings[:MAX_FINDINGS_PER_FILE]
    last_line = kept[-1].line_number if kept else 1
    kept.append(_make_finding(
        rule_id, Severity.LOW, file_path, last_line,
        f"(suppression notice for {rule_id})",
        f"{total - MAX_FINDINGS_PER_FILE} further {rule_id} matches suppressed in this file "
        f"({total} total). Add the path to exclude_paths, or {rule_id} to disable_rules, "
        f"in .shipguard.yml.",
        "CWE-359",
        "Cap is a safety net, not a fix — exclude the file or disable the rule if the data is intentional.",
    ))
    return kept


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
    return _cap_findings(findings, "PII-001", file_path)


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
    return _cap_findings(findings, "PII-002", file_path)


@register(
    id="PII-003",
    name="phone-number",
    severity=Severity.LOW,
    description="Detects NANP phone numbers in files",
    extensions=PII_EXTS,
    cwe_id="CWE-359",
    compliance_tags=["GDPR-Art32"],
)
def pii_003_phone(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        for match in _PHONE_PATTERN.finditer(line):
            raw = match.group(0)
            digits = _normalise_phone_digits(raw)
            if digits in PLACEHOLDER_PHONES:
                continue
            # NANP reserved fictional range 555-0100 through 555-0199.
            if len(digits) == 10 and digits[3:6] == "555":
                try:
                    last4 = int(digits[6:10])
                except ValueError:
                    last4 = -1
                if 100 <= last4 <= 199:
                    continue
            findings.append(_make_finding(
                "PII-003", Severity.LOW, file_path, i, line.rstrip(),
                f"Phone number detected in file ({digits})",
                "CWE-359",
                "If this is real customer PII, remove it; if it is test data, use a placeholder (e.g. 000-000-0000)",
            ))
    return _cap_findings(findings, "PII-003", file_path)


@register(
    id="PII-004",
    name="email-address",
    severity=Severity.MEDIUM,
    description="Detects email addresses in source/data files",
    extensions=PII_EXTS,
    cwe_id="CWE-359",
    compliance_tags=["GDPR-Art32"],
)
def pii_004_email(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    for i, line in enumerate(content.splitlines(), 1):
        if _skip_false_positive(line):
            continue
        if _line_starts_with_key(line, PUBLIC_METADATA_KEYS):
            continue
        for match in _EMAIL_PATTERN.finditer(line):
            address = match.group(0)
            domain = address.rsplit("@", 1)[-1].lower()
            if domain in SAFE_EMAIL_DOMAINS:
                continue
            if domain == "users.noreply.github.com" or domain.endswith(".noreply.github.com"):
                continue
            findings.append(_make_finding(
                "PII-004", Severity.MEDIUM, file_path, i, line.rstrip(),
                f"Email address detected in file ({address})",
                "CWE-359",
                "If this is real customer PII, remove it; if it is intentional, exclude the file in .shipguard.yml",
            ))
    return _cap_findings(findings, "PII-004", file_path)
