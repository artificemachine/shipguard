"""ShellCheck integration for ShipGuard."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path
from shipguard.models import Finding, Severity

SHELL_EXTS = {".sh", ".bash", ".zsh", ".ksh"}

_LEVEL_MAP = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.LOW,
}


def _find_binary() -> str | None:
    env = os.environ.get("SHIPGUARD_SHELLCHECK_BIN")
    if env:
        return env
    return shutil.which("shellcheck")


def run_shellcheck(files: list[Path]) -> list[Finding]:
    binary = _find_binary()
    if not binary:
        return []
    shell_files = [str(f) for f in files if f.suffix in SHELL_EXTS]
    if not shell_files:
        return []
    try:
        proc = subprocess.run(
            [binary, "--format=json1", "--severity=warning"] + shell_files,
            capture_output=True, text=True, timeout=60
        )
        data = json.loads(proc.stdout or '{"comments": []}')
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return []

    # ShellCheck's json1 format is a single object {"comments": [...]}, not a
    # list of per-file objects — each comment already carries its own "file"
    # key, since one invocation can cover multiple files.
    comments = data.get("comments", []) if isinstance(data, dict) else []

    findings: list[Finding] = []
    for comment in comments:
        level = comment.get("level", "warning")
        severity = _LEVEL_MAP.get(level, Severity.LOW)
        file_path = Path(comment.get("file", "unknown"))
        line = comment.get("line", 1)
        message = comment.get("message", "")
        code = comment.get("code", 0)
        cwe = None  # ShellCheck JSON1 doesn't provide CWE mappings
        replacements = (comment.get("fix") or {}).get("replacements") or []
        fix_replacement = replacements[0].get("replacement", "") if replacements else ""
        findings.append(Finding(
            rule_id=f"SHELLCHECK-SC{code}",
            severity=severity,
            file_path=file_path,
            line_number=line,
            line_content="",  # original line not available from JSON1 format
            message=f"ShellCheck SC{code}: {message}",
            cwe_id=cwe,
            fix_hint=f"See https://www.shellcheck.net/wiki/SC{code}" + (f" — suggested fix: {fix_replacement}" if fix_replacement else ""),
        ))
    return findings
