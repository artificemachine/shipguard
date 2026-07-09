"""Tests for shared rule helpers in shipguard.rules._common.

These guard two contracts:
1. The helpers exist in _common and are the *same objects* exported by
   shipguard.rules.secrets (behaviour-preserving re-export, not a copy).
2. _skip_false_positive behaves the same after the move (regression guard).
"""

from __future__ import annotations

import shipguard.rules._common as _common
import shipguard.rules.secrets as _secrets


class TestCommonHelpersBackCompat:
    def test_secrets_module_still_exports_helpers(self):
        """shipguard.rules.secrets must keep re-exporting the helpers verbatim."""
        # Names must be importable from secrets (the back-compat surface).
        from shipguard.rules.secrets import _make_finding, _skip_false_positive

        # They must be the *same object* as in _common, not a copy.
        assert _skip_false_positive is _common._skip_false_positive
        assert _make_finding is _common._make_finding

    def test_common_module_does_not_import_rules(self):
        """_common.py must not import shipguard.rules (would create a cycle)."""
        import shipguard.rules._common as common

        # Either no shipguard.rules attribute is bound, or it's the package itself
        # bound by side effect of importing the module — but no sub-import inside
        # the module body. The strongest static check is: 'shipguard.rules' should
        # not appear in the module's source.
        import inspect

        source = inspect.getsource(common)
        assert "import shipguard.rules" not in source
        assert "from shipguard.rules" not in source


class TestCommonHelpers:
    def test_skip_false_positive_behaviour(self):
        """_skip_false_positive should classify known patterns the same after the move."""
        from shipguard.rules._common import _skip_false_positive

        # True cases — should be skipped
        skip_lines = [
            "# ssn: 123-45-6789",         # comment
            "ssn: ${SSN}",                # env-var ref
            "ssn: $SSN",                  # bare $-ref
            "ssn: <TEMPLATE_VAR>",        # template syntax
            'token = "YOUR_API_KEY"',     # YOUR_ marker
            'token = "CHANGE_ME"',        # CHANGE_ME marker
            'token = "REPLACE_ME"',       # REPLACE_ME marker
            'token = "_NOT_REAL"',        # _NOT_REAL marker
            'token = "_PLACEHOLDER"',     # _PLACEHOLDER marker
        ]
        for line in skip_lines:
            assert _skip_false_positive(line) is True, f"expected skip: {line!r}"

        # False case — must NOT be skipped
        keep_lines = [
            "ssn: 123-45-6789",
            'card = "4111111111111111"',
        ]
        for line in keep_lines:
            assert _skip_false_positive(line) is False, f"expected keep: {line!r}"

    def test_make_finding_constructs_finding(self):
        """_make_finding should produce a Finding with the fields it was given."""
        from pathlib import Path

        from shipguard.models import Finding, Severity
        from shipguard.rules._common import _make_finding

        f = _make_finding(
            rule_id="TEST-001",
            severity=Severity.HIGH,
            file_path=Path("x.py"),
            line_number=7,
            line_content="ssn: 123-45-6789",
            message="test message",
            cwe_id="CWE-359",
            fix_hint="fix it",
        )
        assert isinstance(f, Finding)
        assert f.rule_id == "TEST-001"
        assert f.severity == Severity.HIGH
        assert f.file_path == Path("x.py")
        assert f.line_number == 7
        assert f.line_content == "ssn: 123-45-6789"
        assert f.message == "test message"
        assert f.cwe_id == "CWE-359"
        assert f.fix_hint == "fix it"
