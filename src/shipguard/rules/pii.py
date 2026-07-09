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
