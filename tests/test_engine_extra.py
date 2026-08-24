"""Additional engine tests for branch coverage."""

from __future__ import annotations

from pathlib import Path

from shipguard.config import Config
from shipguard.engine import _discover_files, _load_gitignore, _scan_file, scan
from shipguard.models import Finding, Severity
from shipguard.rules import RuleMeta


def test_load_gitignore_and_discover_files_honor_ignore(tmp_path):
    (tmp_path / ".gitignore").write_text("ignored.txt\n")
    (tmp_path / "ignored.txt").write_text("x")
    (tmp_path / "keep.py").write_text("print(1)\n")

    spec = _load_gitignore(tmp_path)
    assert spec is not None

    files = _discover_files(tmp_path, Config())
    names = {p.name for p in files}
    assert "keep.py" in names
    assert "ignored.txt" not in names


def test_scan_file_handles_read_error(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("print(1)\n")

    monkeypatch.setattr(Path, "read_text", lambda *a, **k: (_ for _ in ()).throw(OSError("denied")))
    findings = _scan_file(p, Config(), Severity.LOW, set(), set())
    assert findings == []


def test_scan_file_skips_rule_without_func(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("print(1)\n")
    nofunc = RuleMeta(
        id="NOFUNC-1",
        name="no-func",
        severity=Severity.LOW,
        description="x",
        extensions=[".py"],
        func=None,
    )
    monkeypatch.setattr("shipguard.engine.get_rules_for_file", lambda _: [nofunc])
    findings = _scan_file(p, Config(), Severity.LOW, set(), set())
    assert findings == []


def test_scan_files_sets_scan_root(tmp_path):
    """scan_files() must set scan_root so SARIF output uses relative paths."""
    from shipguard.engine import scan_files
    f = tmp_path / "safe.py"
    f.write_text("x = 1\n")
    result = scan_files(files=[f], target_dir=tmp_path)
    assert result.scan_root == tmp_path


def test_scan_populates_discovered_files(tmp_path):
    """scan() must populate discovered_files so --with-external avoids re-discovery."""
    from shipguard.engine import scan
    (tmp_path / "safe.py").write_text("x = 1\n")
    result = scan(target_dir=tmp_path)
    assert isinstance(result.discovered_files, list)
    assert any(p.name == "safe.py" for p in result.discovered_files)


def test_scan_file_respects_inline_suppression(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("# shipguard:ignore CUST-SUP-1\nprint('x')\n")

    def _func(file_path, content, config, **kwargs):
        return [
            Finding(
                rule_id="CUST-SUP-1",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                line_content="# shipguard:ignore CUST-SUP-1",
                message="x",
            )
        ]

    meta = RuleMeta(
        id="CUST-SUP-1",
        name="suppression-test",
        severity=Severity.HIGH,
        description="x",
        extensions=[".py"],
        func=_func,
    )
    monkeypatch.setattr("shipguard.engine.get_rules_for_file", lambda _: [meta])
    findings = _scan_file(p, Config(), Severity.LOW, set(), set())
    assert findings == []


def test_scan_rust_branch_filters_disabled_severity_and_suppressed(tmp_path, monkeypatch):
    p = tmp_path / "x.yml"
    p.write_text("# shipguard:ignore SEC-KEEP\nsecret: value\n")
    missing = tmp_path / "missing.yml"  # read_text raises OSError

    rust_findings = [
        Finding(
            rule_id="SEC-DISABLED",
            severity=Severity.CRITICAL,
            file_path=p,
            line_number=1,
            line_content="x",
            message="x",
        ),
        Finding(
            rule_id="SEC-LOW",
            severity=Severity.LOW,
            file_path=p,
            line_number=1,
            line_content="x",
            message="x",
        ),
        Finding(
            rule_id="SEC-KEEP",
            severity=Severity.CRITICAL,
            file_path=p,
            line_number=1,
            line_content="x",
            message="x",
        ),
        Finding(
            rule_id="SEC-OSE",
            severity=Severity.CRITICAL,
            file_path=missing,
            line_number=1,
            line_content="x",
            message="x",
        ),
    ]

    monkeypatch.setattr("shipguard.engine.run_rust_secrets_scan", lambda files, target_dir: rust_findings)
    res = scan(
        tmp_path,
        config=Config(use_rust_secrets=True, disable_rules=["SEC-DISABLED"]),
        severity_threshold=Severity.HIGH,
    )
    ids = [f.rule_id for f in res.findings]
    assert "SEC-DISABLED" not in ids
    assert "SEC-LOW" not in ids
    assert "SEC-KEEP" not in ids
    assert "SEC-OSE" in ids


def test_scan_counts_skipped_files_when_worker_raises(tmp_path, monkeypatch):
    p = tmp_path / "x.py"
    p.write_text("print(1)\n")
    monkeypatch.setattr("shipguard.engine._scan_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    res = scan(tmp_path, severity_threshold=Severity.LOW)
    assert res.files_skipped >= 1


def test_rule_config_skip_paths_documented_in_init_template_is_honored(tmp_path):
    """.shipguard.yml's rule_config.<RULE-ID>.skip_paths is documented in the
    `shipguard init` template (config.py) but was never wired into the scan
    path — every finding still fired regardless of skip_paths. Confirmed by
    an A/B against disable_rules (which does work) on 2026-08-24 during a
    real false-positive triage (SHELL-002 firing on a script that
    intentionally interpolates unquoted variables inside a heredoc, where
    quoting them would corrupt the generated output)."""
    target = tmp_path / "repo"
    scripts_dir = target / "commands"
    scripts_dir.mkdir(parents=True)
    flagged = scripts_dir / "regen-callgraph.sh"
    flagged.write_text("#!/usr/bin/env bash\nfile=$1\nrm $file\n")
    other = target / "other.sh"
    other.write_text("#!/usr/bin/env bash\nfile=$1\nrm $file\n")

    config = Config(rule_config={"SHELL-002": {"skip_paths": ["commands/regen-callgraph.sh"]}})
    result = scan(target, config=config, severity_threshold=Severity.LOW)

    flagged_hits = [f for f in result.findings if f.file_path == flagged and f.rule_id == "SHELL-002"]
    other_hits = [f for f in result.findings if f.file_path == other and f.rule_id == "SHELL-002"]
    assert flagged_hits == []
    assert other_hits != []


def test_scan_file_skip_paths_matches_relative_to_target_dir(tmp_path):
    """Unit-level: _scan_file resolves skip_paths against file_path relative
    to target_dir, not the absolute path (so patterns like
    "commands/x.sh" — anchored, no leading **/ — work as documented)."""
    target = tmp_path / "repo"
    (target / "commands").mkdir(parents=True)
    flagged = target / "commands" / "regen-callgraph.sh"
    flagged.write_text("#!/usr/bin/env bash\nfile=$1\nrm $file\n")

    config = Config(rule_config={"SHELL-002": {"skip_paths": ["commands/regen-callgraph.sh"]}})
    findings = _scan_file(flagged, config, Severity.LOW, target_dir=target)
    assert [f for f in findings if f.rule_id == "SHELL-002"] == []
