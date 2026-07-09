"""Shared helpers for rule modules."""

from __future__ import annotations

from pathlib import Path

from shipguard.models import Finding, Severity


def _skip_false_positive(line: str) -> bool:
    """Check if a line should be skipped as a false positive."""
    line_upper = line.upper()
    # Skip comments
    if line.lstrip().startswith("#"):
        return True
    # Skip obvious placeholders (with clear markers like _NOT_REAL, _PLACEHOLDER)
    if any(
        keyword in line_upper
        for keyword in ["_NOT_REAL", "_PLACEHOLDER", "YOUR_", "CHANGE_ME", "REPLACE_ME"]
    ):
        return True
    # Skip environment variable references
    if "$" in line or "${" in line or "${{" in line:
        return True
    # Skip template syntax
    if "<" in line or ">" in line:
        return True
    return False


def _make_finding(
    rule_id: str,
    severity: Severity,
    file_path: Path,
    line_number: int,
    line_content: str,
    message: str,
    cwe_id: str,
    fix_hint: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        file_path=file_path,
        line_number=line_number,
        line_content=line_content,
        message=message,
        cwe_id=cwe_id,
        fix_hint=fix_hint,
    )
