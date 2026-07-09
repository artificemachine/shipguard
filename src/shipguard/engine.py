"""Scanner engine with parallel file scanning and suppression support."""

from __future__ import annotations

import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import pathspec

from shipguard.config import Config
from shipguard.models import Finding, ScanResult, Severity
from shipguard.rust_secrets import run_rust_secrets_scan
from shipguard.rules import get_registry, get_rules_for_file, load_builtin_rules, load_custom_rules
from shipguard.semantic import SemanticEngine
from shipguard.ai import AITriage
from shipguard.db import Database

DB_PATH = Path(".shipguard") / "state.db"


def _cap_findings_per_file(
    findings: list[Finding], cap: int | None, file_path: Path
) -> list[Finding]:
    """Bound `findings` at `cap` per file. Emits suppression notice on overflow.

    `cap=0` or `cap=None` means unlimited (no cap, no notice).
    `cap=N>0` with `len(findings) > N` returns the first N findings plus
    one synthesized suppression notice naming the true suppressed total
    and the rule with the largest overflow.

    Per the no-silent-truncation rule: the cap is a safety net, not a fix.
    The notice points at both `exclude_paths` (file-level) and `disable_rules`
    (rule-level) so the operator has the opt-out paths in front of them.
    """
    if not cap or cap <= 0:
        return findings
    if len(findings) <= cap:
        return findings
    total = len(findings)
    kept = findings[:cap]
    # Identify the rule with the largest overflow so the notice names the
    # most likely culprit. Ties broken by first occurrence in input order.
    overflow: dict[str, int] = {}
    for f in findings:
        overflow[f.rule_id] = overflow.get(f.rule_id, 0) + 1
    overflow_by_rule = {rid: cnt - cap for rid, cnt in overflow.items() if cnt > cap}
    if overflow_by_rule:
        worst_rule = max(overflow_by_rule.items(), key=lambda kv: (kv[1], findings.index(next(f for f in findings if f.rule_id == kv[0]))))[0]
        per_rule_overflow = overflow_by_rule[worst_rule]
    else:
        # Should not happen if total > cap, but fall back gracefully.
        worst_rule = findings[cap].rule_id
        per_rule_overflow = total - cap
    last_line = kept[-1].line_number if kept else 1
    notice = Finding(
        rule_id=worst_rule,
        # Severity.MEDIUM (not LOW) so the notice survives the default
        # severity_threshold filter in _scan_file. The plan specified
        # LOW, but a LOW notice is invisible to users on the default
        # MEDIUM threshold — a usability regression. MEDIUM keeps the
        # notice visible by default without inflating the report.
        severity=Severity.MEDIUM,
        file_path=file_path,
        line_number=last_line,
        line_content="(suppression notice)",
        message=(
            f"{total - cap} further findings suppressed in this file "
            f"({per_rule_overflow} from {worst_rule}, {total} total). "
            f"Add the path to exclude_paths, or {worst_rule} to disable_rules, "
            f"in .shipguard.yml."
        ),
        cwe_id="CWE-359",
        fix_hint="Cap is a safety net, not a fix — exclude the file or disable the rule if the data is intentional.",
    )
    return [*kept, notice]


def _build_rule_sets(
    config: Config,
    include_rules: set[str] | None,
    exclude_rules: set[str] | None,
) -> tuple[set[str], set[str], int]:
    """Resolve include/exclude sets and count rules that will be applied.

    Returns (include_rule_ids, excluded_rule_ids, rules_applied).
    """
    include_rule_ids = include_rules or set()
    excluded_rule_ids = set(config.disable_rules or []) | set(exclude_rules or set())
    registry_ids = set(get_registry().keys())
    if include_rule_ids:
        registry_ids &= include_rule_ids
    registry_ids -= excluded_rule_ids
    return include_rule_ids, excluded_rule_ids, len(registry_ids)

SUPPRESSION_RE = re.compile(r"(?:#|//)\s*shipguard:ignore\s+([\w\-,\s]+)")
DEFAULT_EXCLUDES = [
    "node_modules/**",
    ".git/**",
    "__pycache__/**",
    "*.pyc",
    ".venv/**",
    "venv/**",
    "dist/**",
    "build/**",
    ".tox/**",
    ".mypy_cache/**",
]


def _load_gitignore(target_dir: Path) -> pathspec.PathSpec | None:
    """Load .gitignore patterns if present."""
    gitignore = target_dir / ".gitignore"
    if gitignore.is_file():
        return pathspec.PathSpec.from_lines("gitignore", gitignore.read_text().splitlines())
    return None


def _discover_files(target_dir: Path, config: Config) -> list[Path]:
    """Discover scannable files, respecting exclusions."""
    exclude_patterns = DEFAULT_EXCLUDES + (config.exclude_paths or [])
    
    # Rust-based discovery (temporarily disabled for stabilization)
    # try:
    #     import shipguard_core
    #     files_str = shipguard_core.discover_files(str(target_dir), exclude_patterns)
    #     return [Path(f) for f in files_str]
    # except ImportError:
    #     pass

    # Fallback to Python discovery
    exclude_spec = pathspec.PathSpec.from_lines("gitignore", exclude_patterns)
    gitignore_spec = _load_gitignore(target_dir)

    files: list[Path] = []
    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(target_dir)
        rel_str = str(rel)
        if exclude_spec.match_file(rel_str):
            continue
        if gitignore_spec and gitignore_spec.match_file(rel_str):
            continue
        files.append(path)
    return files


def _get_suppressed_rules(lines: list[str], line_number: int) -> set[str]:
    """Get suppressed rule IDs for a given line (checking current and previous line)."""
    suppressed: set[str] = set()
    for offset in (line_number - 1, line_number - 2):  # current line, line above
        if 0 <= offset < len(lines):
            m = SUPPRESSION_RE.search(lines[offset])
            if m:
                ids = [r.strip() for r in m.group(1).split(",")]
                suppressed.update(ids)
    return suppressed


def _scan_file(
    file_path: Path,
    config: Config,
    severity_threshold: Severity,
    include_rules: set[str] | None = None,
    excluded_rules: set[str] | None = None,
) -> list[Finding]:
    """Scan a single file with all applicable rules."""
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []

    rules = get_rules_for_file(file_path)
    include = include_rules or set()
    excluded = excluded_rules or set()
    findings: list[Finding] = []
    lines = content.splitlines()

    # Pre-parse AST if language is supported
    tree = None
    try:
        tree = SemanticEngine.parse_file(file_path, content)
        if tree:
            # Populate Global Index (Phase 2: The Flow)
            index = SemanticEngine.get_index()
            # Simple indexing of function definitions
            query_defs = "(function_definition name: (identifier) @name)"
            matches = SemanticEngine.query(tree, query_defs)
            for _, match in matches:
                for node in match.get("name", []):
                    index.add_symbol(content[node.start_byte:node.end_byte], file_path, node.start_point[0] + 1)
    except Exception:
        # Fallback to no AST if parsing fails or language not supported
        pass

    seen_line_rules: dict[int, set[str]] = {}
    for rule in rules:
        if include and rule.id not in include:
            continue
        if rule.id in excluded:
            continue
        if config.use_rust_secrets and rule.id.startswith("SEC-"):
            continue
        if rule.func is None:
            continue

        rule_findings = rule.func(file_path, content, config=config, tree=tree)
        for finding in rule_findings:
            # Skip if a higher-priority rule already flagged this line for all rule IDs
            # that this rule supersedes (declared via the supersedes field on RuleMeta).
            line_rules_here = seen_line_rules.get(finding.line_number, set())
            if any(sup in line_rules_here for sup in rule.supersedes):
                continue
            # Check severity threshold
            if finding.severity < severity_threshold:
                continue
            # Check inline suppression — reuse pre-split lines to avoid O(n*m)
            suppressed = _get_suppressed_rules(lines, finding.line_number)
            if finding.rule_id in suppressed:
                continue
            findings.append(finding)
            seen_line_rules.setdefault(finding.line_number, set()).add(finding.rule_id)

    return findings


def _run_parallel_scans(
    files: list[Path],
    config: Config,
    threshold: Severity,
    include_rule_ids: set[str],
    excluded_rule_ids: set[str],
    max_workers: int,
) -> tuple[list[Finding], int]:
    """Run _scan_file in parallel; returns (findings, files_skipped)."""
    all_findings: list[Finding] = []
    files_skipped = 0
    cap = getattr(config, "max_findings_per_file", 0) or 0
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _scan_file, f, config, threshold, include_rule_ids, excluded_rule_ids
            ): f
            for f in files
        }
        for future in as_completed(futures):
            try:
                file_findings = future.result()
                # Apply the per-file cap here, so each file's findings are bounded
                # *before* the merge. Without this, capping the aggregated list
                # would over-suppress (e.g. 2 files × 600 findings + cap=100 = 100
                # total, not 50+1 per file). Per the plan §3 Iteration 1 GREEN.
                file_findings = _cap_findings_per_file(
                    file_findings, cap, futures[future]
                )
                all_findings.extend(file_findings)
            except Exception as exc:
                print(
                    f"[shipguard] warning: error scanning {futures[future]}: {exc}",
                    file=sys.stderr,
                )
                files_skipped += 1
    return all_findings, files_skipped


def scan_files(
    files: list[Path],
    target_dir: Path,
    config: Config | None = None,
    severity_threshold: Severity | None = None,
    max_workers: int = 4,
    include_rules: set[str] | None = None,
    exclude_rules: set[str] | None = None,
) -> ScanResult:
    """Scan an explicit list of files (for incremental/staged scanning).

    Args:
        files: List of files to scan.
        target_dir: Root directory (for context).
        config: Configuration object. Uses defaults if None.
        severity_threshold: Minimum severity to report.
        max_workers: Number of parallel workers.
        include_rules: Rule IDs to include (empty = all).
        exclude_rules: Rule IDs to exclude.

    Returns:
        ScanResult with all findings.
    """
    if config is None:
        config = Config()

    load_builtin_rules()

    threshold = severity_threshold or Severity(config.severity_threshold)
    result = ScanResult()
    include_rule_ids, excluded_rule_ids, rules_applied = _build_rule_sets(
        config, include_rules, exclude_rules
    )

    result.files_scanned = len(files)
    result.rules_applied = rules_applied

    all_findings, skipped = _run_parallel_scans(
        files, config, threshold, include_rule_ids, excluded_rule_ids, max_workers
    )
    result.files_skipped = skipped
    all_findings.sort(
        key=lambda f: (-f.severity.rank, str(f.file_path), f.line_number)
    )
    
    if getattr(config, "ai_triage", False):
        triage = AITriage()
        filtered_findings = []
        for f in all_findings:
            triage.evaluate(f)
            if not getattr(f, "is_false_positive", False):
                filtered_findings.append(f)
        all_findings = filtered_findings

    result.findings = all_findings
    result.scan_root = target_dir
    result.finish()

    # Sync with persistence layer
    try:
        db = Database(target_dir / DB_PATH)
        db.sync_findings(all_findings)
    except Exception as e:
        print(f"[shipguard] warning: failed to sync with database: {e}", file=sys.stderr)

    return result


def scan(
    target_dir: Path,
    config: Config | None = None,
    severity_threshold: Severity | None = None,
    max_workers: int = 4,
    include_rules: set[str] | None = None,
    exclude_rules: set[str] | None = None,
) -> ScanResult:
    """Scan a directory for security vulnerabilities.

    Args:
        target_dir: Directory to scan.
        config: Configuration object. Uses defaults if None.
        severity_threshold: Minimum severity to report. Overrides config.
        max_workers: Number of parallel workers.

    Returns:
        ScanResult with all findings.
    """
    if config is None:
        config = Config()

    load_builtin_rules()
    custom_dirs: list[Path] = []
    for rule_dir in config.custom_rules_dirs:
        p = Path(rule_dir)
        custom_dirs.append(p if p.is_absolute() else (target_dir / p))
    load_custom_rules(custom_dirs)

    threshold = severity_threshold or Severity(config.severity_threshold)
    result = ScanResult()
    include_rule_ids, excluded_rule_ids, rules_applied = _build_rule_sets(
        config, include_rules, exclude_rules
    )

    files = _discover_files(target_dir, config)
    result.files_scanned = len(files)
    result.discovered_files = files
    result.rules_applied = rules_applied

    all_findings: list[Finding] = []
    if config.use_rust_secrets:
        rust_findings = run_rust_secrets_scan(files, target_dir)
        for finding in rust_findings:
            if include_rule_ids and finding.rule_id not in include_rule_ids:
                continue
            if finding.rule_id in excluded_rule_ids:
                continue
            if finding.severity < threshold:
                continue
            try:
                content = finding.file_path.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                content = ""
            if content and finding.rule_id in _get_suppressed_rules(content.splitlines(), finding.line_number):
                continue
            all_findings.append(finding)

    parallel_findings, skipped = _run_parallel_scans(
        files, config, threshold, include_rule_ids, excluded_rule_ids, max_workers
    )
    result.files_skipped += skipped
    all_findings.extend(parallel_findings)

    # Sort by severity (descending), then file path, then line number
    all_findings.sort(
        key=lambda f: (-f.severity.rank, str(f.file_path), f.line_number)
    )
    
    if getattr(config, "ai_triage", False):
        triage = AITriage()
        filtered_findings = []
        for f in all_findings:
            triage.evaluate(f)
            if not getattr(f, "is_false_positive", False):
                filtered_findings.append(f)
        all_findings = filtered_findings

    result.findings = all_findings
    result.scan_root = target_dir
    result.finish()

    # Sync with persistence layer
    try:
        db = Database(target_dir / DB_PATH)
        db.sync_findings(all_findings)
    except Exception as e:
        print(f"[shipguard] warning: failed to sync with database: {e}", file=sys.stderr)

    return result
