"""Direct unit tests for the _cap_findings helper in shipguard.rules.pii.

These pin the contract of the cap mechanism independently of any rule:
- input N findings where N <= cap -> output N findings, no notice
- input N findings where N > cap -> output (cap + 1) findings, last is the notice
- the notice names the true total
- the notice names both opt-out mechanisms (exclude_paths, disable_rules)
- the notice uses Severity.LOW (matches the helper's intent)
- the notice inherits the last kept finding's line number
- the notice inherits the cap-passed rule_id
- empty input -> empty output (no notice even if cap = 0)
- cap-of-1 boundary: input of 2 findings -> output 2 (1 kept + 1 notice)
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shipguard.models import Finding, Severity
from shipguard.rules.pii import MAX_FINDINGS_PER_FILE, _cap_findings


def _mk_finding(rule_id: str, line: int, file_path: Path | None = None) -> Finding:
    """Build a minimal Finding for cap tests."""
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


class TestCapFindingsNoTrigger:
    def test_empty_input_returns_empty(self):
        """Empty input returns empty output, no suppression notice."""
        out = _cap_findings([], "PII-004", Path("x.yml"))
        assert out == []

    def test_below_cap_returns_unchanged(self):
        """When findings <= cap, return the input list verbatim (same objects)."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 6)]  # 5 findings
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert out == findings  # same list, same order
        assert len(out) == 5
        assert all("further" not in f.message for f in out)

    def test_at_cap_returns_unchanged(self):
        """When findings == cap, return the input list verbatim (no notice)."""
        findings = [_mk_finding("PII-004", i) for i in range(1, MAX_FINDINGS_PER_FILE + 1)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert out == findings
        assert len(out) == MAX_FINDINGS_PER_FILE
        assert all("further" not in f.message for f in out)


class TestCapFindingsTriggers:
    def test_one_over_cap_emits_notice(self):
        """cap+1 findings -> cap kept + 1 notice = cap+1 total."""
        findings = [_mk_finding("PII-004", i) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert len(out) == MAX_FINDINGS_PER_FILE + 1

    def test_far_over_cap_emits_notice_with_true_total(self):
        """1010 findings -> 100 kept + 1 notice naming 910 suppressed (1010 total)."""
        findings = [_mk_finding("PII-004", i) for i in range(1, 1011)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert len(out) == MAX_FINDINGS_PER_FILE + 1
        notice = out[-1]
        assert "further" in notice.message
        assert "1010" in notice.message  # names the true total
        assert "910" in notice.message   # names the suppressed count

    def test_notice_uses_low_severity(self):
        """The suppression notice uses Severity.LOW — informational, not a new finding."""
        findings = [_mk_finding("PII-004", i) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert out[-1].severity == Severity.LOW

    def test_notice_inherits_rule_id(self):
        """The notice names the rule that was capped, not a generic placeholder."""
        findings = [_mk_finding("PII-001", i) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-001", Path("x.yml"))
        assert "PII-001" in out[-1].message

    def test_notice_names_opt_out_mechanisms(self):
        """The notice points at exclude_paths AND disable_rules."""
        findings = [_mk_finding("PII-004", i) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert "exclude_paths" in out[-1].message
        assert "disable_rules" in out[-1].message

    def test_notice_inherits_last_kept_line_number(self):
        """The notice uses the line number of the last KEPT finding (not 1, not the total)."""
        findings = [_mk_finding("PII-004", i) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        # The last kept finding is at line MAX_FINDINGS_PER_FILE (index = cap-1 in 0-indexed,
        # line_number = cap because _mk_finding starts at line=1).
        assert out[-1].line_number == MAX_FINDINGS_PER_FILE

    def test_notice_inherits_file_path(self):
        """The notice's file_path matches the file_path passed in."""
        findings = [_mk_finding("PII-004", i, file_path=Path("/tmp/seed.sql")) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-004", Path("/tmp/seed.sql"))
        assert out[-1].file_path == Path("/tmp/seed.sql")

    def test_kept_findings_are_unchanged_objects(self):
        """The cap preserves the original Finding objects for the first N — no copies."""
        findings = [_mk_finding("PII-004", i) for i in range(1, MAX_FINDINGS_PER_FILE + 2)]
        out = _cap_findings(findings, "PII-004", Path("x.yml"))
        assert out[:MAX_FINDINGS_PER_FILE] == findings[:MAX_FINDINGS_PER_FILE]
        # Same object identity, not just equality.
        for i in range(MAX_FINDINGS_PER_FILE):
            assert out[i] is findings[i]


class TestCapFindingsBoundary:
    @pytest.mark.xfail(
        reason="known failing gate: '0 = unlimited' is the engine-level contract "
               "(see issue #19); the PII-local helper does not yet honour it. "
               "When issue #19 lands, remove the xfail and the helper change should "
               "make this pass.",
        strict=True,
    )
    def test_cap_of_zero_is_unlimited(self):
        """When MAX_FINDINGS_PER_FILE is set to 0, treat as unlimited — no cap, no notice.

        This pins the contract that '0 or null = unlimited' from issue #19. The
        current implementation hardcodes 100 and only checks `total <= cap`,
        so this test will fail until the engine-level replacement lands and
        treats 0 as unlimited. Documented here as a known failing gate —
        the test exists to fail loudly when the engine-level fix ships.
        """
        import shipguard.rules.pii as pii

        original = pii.MAX_FINDINGS_PER_FILE
        pii.MAX_FINDINGS_PER_FILE = 0
        try:
            findings = [_mk_finding("PII-004", i) for i in range(1, 6)]
            out = _cap_findings(findings, "PII-004", Path("x.yml"))
            # When cap=0, behaviour is "unlimited": all 5 findings returned, no notice.
            # The current helper returns findings[:0] + notice (a 0+1=1 output, wrong).
            # This test asserts the *desired* behaviour; the helper is wrong here.
            assert len(out) == 5, "MAX_FINDINGS_PER_FILE=0 should mean unlimited"
            assert all("further" not in f.message for f in out)
        finally:
            pii.MAX_FINDINGS_PER_FILE = original

    def test_cap_of_one_triggers_at_two(self):
        """Boundary: cap=1, input=2 -> 1 kept + 1 notice = 2 output."""
        import shipguard.rules.pii as pii

        original = pii.MAX_FINDINGS_PER_FILE
        pii.MAX_FINDINGS_PER_FILE = 1
        try:
            findings = [_mk_finding("PII-004", 1), _mk_finding("PII-004", 2)]
            out = _cap_findings(findings, "PII-004", Path("x.yml"))
            assert len(out) == 2
            assert out[0] is findings[0]  # kept: the first
            assert "further" in out[1].message
            assert "1" in out[1].message  # 1 suppressed
            assert "2" in out[1].message  # 2 total
        finally:
            pii.MAX_FINDINGS_PER_FILE = original
