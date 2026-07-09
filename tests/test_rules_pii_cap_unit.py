"""Boundary test for the engine-level finding cap mechanism.

This is the surviving test from PR #20's `tests/test_rules_pii_cap_unit.py`,
which originally exercised the PII-local `_cap_findings` helper. As of
v0.5.1, the cap is engine-level (`shipguard.engine._cap_findings_per_file`),
and the PII-local helper was deleted.

The xfail decorator (added in PR #20) is the migration contract: the
test asserts the `0 = unlimited` semantics that the engine-level helper
now provides. When this file is re-pointed at the engine helper, the
test passes without the xfail — and serves as a regression guard
against a future change that re-introduces the PII-local cap or
breaks the engine-level "0 = unlimited" semantics.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shipguard.models import Finding, Severity


def _mk_finding(rule_id: str, line: int) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        file_path=Path("x.yml"),
        line_number=line,
        line_content=f"line {line}",
        message=f"finding at line {line}",
        cwe_id="CWE-359",
        fix_hint="fix it",
    )


def test_cap_of_zero_is_unlimited():
    """When cap=0, the engine-level cap helper treats it as unlimited.

    The plan's contract: `0` (or `None`) means "no cap." This is the
    boundary case that distinguishes "cap disabled" from "cap = 0
    findings allowed" (the latter would suppress every finding).
    """
    from shipguard.engine import _cap_findings_per_file

    findings = [_mk_finding("PII-004", i) for i in range(1, 6)]
    out = _cap_findings_per_file(findings, 0, Path("x.yml"))
    assert len(out) == 5, "cap=0 should mean unlimited; no findings should be suppressed"
    assert all("further" not in f.message for f in out)
