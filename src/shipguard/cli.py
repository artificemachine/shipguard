"""Typer CLI for ShipGuard security scanner."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.table import Table

from shipguard import __version__
from shipguard.config import DEFAULT_CONFIG_TEMPLATE, load_config
from shipguard.engine import _discover_files, _get_suppressed_rules, scan, scan_files
from shipguard.formatters import get_formatter
from shipguard.models import ScanResult, Severity
from shipguard.rules import get_registry, load_builtin_rules, load_custom_rules

app = typer.Typer(
    name="shipguard",
    help="ShipGuard — Security audit tool for any repository.",
    no_args_is_help=True,
)
console = Console()


def _emit_output(result: ScanResult, formatter, fmt: str, output: Optional[Path]) -> None:
    """Write formatted scan output to file or stdout."""
    if fmt == "terminal":
        if output:
            output.write_text(formatter(result))
            console.print(f"Report written to {output}")
        else:
            formatter(result, console=console)
    else:
        text = formatter(result)
        if output:
            output.write_text(text)
            console.print(f"Report written to {output}")
        else:
            typer.echo(text)


def _parse_rule_csv(raw: Optional[str]) -> set[str]:
    """Parse comma-separated rule IDs."""
    if not raw:
        return set()
    return {item.strip().upper() for item in raw.split(",") if item.strip()}


def _resolve_custom_rule_dirs(target_dir: Path, configured_dirs: list[str]) -> list[Path]:
    """Resolve custom rule directories against scan target dir."""
    resolved: list[Path] = []
    for rule_dir in configured_dirs:
        p = Path(rule_dir)
        resolved.append(p if p.is_absolute() else (target_dir / p))
    return resolved


def version_callback(value: bool) -> None:
    if value:
        console.print(f"shipguard {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", callback=version_callback, is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """ShipGuard — Security audit tool for any repository."""


@app.command("scan")
def scan_cmd(
    path: Path = typer.Argument(
        ".", help="Directory to scan.", exists=True, file_okay=False, resolve_path=True,
    ),
    fmt: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, markdown, sarif.",
    ),
    severity: str = typer.Option(
        None, "--severity", "-s",
        help="Minimum severity: critical, high, medium, low. Overrides config.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file instead of stdout.",
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to config file.",
    ),
    rust_secrets: Optional[bool] = typer.Option(
        None,
        "--rust-secrets/--no-rust-secrets",
        help="Use optional Rust-accelerated secrets scanning for SEC-* rules.",
    ),
    include_rules: Optional[str] = typer.Option(
        None,
        "--include-rules",
        help="Comma-separated rule IDs to include (e.g., PY-003,SEC-001).",
    ),
    exclude_rules: Optional[str] = typer.Option(
        None,
        "--exclude-rules",
        help="Comma-separated rule IDs to exclude.",
    ),
    ai_triage: bool = typer.Option(
        False,
        "--ai-triage",
        help="Enable AI-driven false positive reduction.",
    ),
    with_external: bool = typer.Option(
        False,
        "--with-external/--no-external",
        help="Run external tools (ShellCheck, Semgrep, TruffleHog, Trivy) and merge findings.",
    ),
) -> None:
    """Scan a directory for security vulnerabilities."""
    fmt = fmt.lower()
    config = load_config(config_path=config_file, target_dir=path)
    if rust_secrets is not None:
        config.use_rust_secrets = rust_secrets
    if ai_triage:
        config.ai_triage = True

    threshold = None
    if severity:
        try:
            threshold = Severity(severity.lower())
        except ValueError:
            console.print(f"[red]Invalid severity: {severity}[/red]")
            raise typer.Exit(code=1)

    include_rule_ids = _parse_rule_csv(include_rules)
    exclude_rule_ids = _parse_rule_csv(exclude_rules)

    # Validate rule IDs against loaded registry (builtin + configured custom rules).
    load_builtin_rules()
    load_custom_rules(_resolve_custom_rule_dirs(path, config.custom_rules_dirs))
    known_ids = set(get_registry().keys())
    unknown_ids = sorted((include_rule_ids | exclude_rule_ids) - known_ids)
    if unknown_ids:
        console.print(
            f"[red]Unknown rule ID(s): {', '.join(unknown_ids)}[/red]"
        )
        raise typer.Exit(code=1)

    result = scan(
        target_dir=path,
        config=config,
        severity_threshold=threshold,
        include_rules=include_rule_ids,
        exclude_rules=exclude_rule_ids,
    )

    if with_external:
        from shipguard.integrations import run_shellcheck, run_semgrep, run_trufflehog, run_trivy
        all_files = result.discovered_files or _discover_files(path, config)
        sev_threshold = threshold or Severity(config.severity_threshold)
        external_findings = []
        external_findings.extend(run_shellcheck(all_files))
        external_findings.extend(run_semgrep(path, config.semgrep_config))
        external_findings.extend(run_trufflehog(path, config.trufflehog_verify))
        external_findings.extend(run_trivy(path))
        for f in external_findings:
            if f.severity < sev_threshold:
                continue
            try:
                lines = f.file_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except (OSError, PermissionError):
                lines = []
            if f.rule_id not in _get_suppressed_rules(lines, f.line_number):
                result.findings.append(f)
        result.findings.sort(
            key=lambda f: (-f.severity.rank, str(f.file_path), f.line_number)
        )

    try:
        formatter = get_formatter(fmt)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)
    _emit_output(result, formatter, fmt, output)

    if result.findings:
        raise typer.Exit(code=1)


@app.command("fix")
def fix_cmd(
    path: Path = typer.Argument(
        ".", help="Directory to scan and fix.", exists=True, file_okay=False, resolve_path=True,
    ),
    id: str = typer.Option(
        ..., "--id", help="The Rule ID to target for fixes (e.g., PY-003)."
    ),
    apply: bool = typer.Option(
        False, "--apply", help="Actually write the fixes to the files instead of a dry run."
    ),
    config_file: Optional[Path] = typer.Option(
        None, "--config", "-c", help="Path to config file."
    ),
) -> None:
    """Automatically generate and apply AI fixes for vulnerabilities."""
    from shipguard.fixer import AutoFixer
    
    config = load_config(config_path=config_file, target_dir=path)
    
    # We only care about the target ID
    load_builtin_rules()
    load_custom_rules(_resolve_custom_rule_dirs(path, config.custom_rules_dirs))
    
    console.print(f"Scanning for {id} to apply fixes...")
    result = scan(
        target_dir=path,
        config=config,
        include_rules={id.upper()},
    )
    
    if not result.findings:
        console.print(f"[green]No findings for {id} found.[/green]")
        raise typer.Exit(0)
        
    fixer = AutoFixer()
    fixed_count = 0
    for finding in result.findings:
        if fixer.fix(finding, apply=apply):
            fixed_count += 1
            
    if apply:
        console.print(f"[green]Fixed {fixed_count} finding(s).[/green]")
    else:
        console.print(f"[yellow]Dry run completed. {fixed_count} finding(s) can be fixed. Run with --apply to apply.[/yellow]")


@app.command("list-rules")
def list_rules(
    fmt: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json.",
    ),
) -> None:
    """List all available security rules."""
    fmt = fmt.lower()
    if fmt not in {"terminal", "json"}:
        console.print(f"[red]Unknown format: {fmt!r}. Choose from: terminal, json[/red]")
        raise typer.Exit(code=1)

    load_builtin_rules()
    registry = get_registry()

    if fmt == "json":
        rules = [
            {
                "id": r.id,
                "name": r.name,
                "severity": r.severity.value,
                "description": r.description,
                "extensions": r.extensions,
                "cwe_id": r.cwe_id,
                "compliance_tags": r.compliance_tags,
            }
            for r in sorted(registry.values(), key=lambda r: r.id)
        ]
        typer.echo(json.dumps(rules, indent=2))
        return

    table = Table(title=f"ShipGuard Rules ({len(registry)} total)")
    table.add_column("ID", style="bold", width=12)
    table.add_column("Name", width=30)
    table.add_column("Severity", width=10)
    table.add_column("Description", min_width=40)
    table.add_column("CWE", width=10)

    severity_colors = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
    }

    for rule in sorted(registry.values(), key=lambda r: r.id):
        color = severity_colors[rule.severity]
        table.add_row(
            rule.id,
            rule.name,
            f"[{color}]{rule.severity.value.upper()}[/{color}]",
            rule.description,
            rule.cwe_id or "",
        )

    console.print(table)


@app.command()
def init(
    path: Path = typer.Argument(
        ".", help="Directory to create .shipguard.yml in.", exists=True,
    ),
) -> None:
    """Generate a .shipguard.yml configuration template."""
    config_path = Path(path) / ".shipguard.yml"
    if config_path.exists():
        console.print(f"[yellow]{config_path} already exists.[/yellow]")
        raise typer.Exit(code=1)
    config_path.write_text(DEFAULT_CONFIG_TEMPLATE)
    console.print(f"[green]Created {config_path}[/green]")


@app.command("scan-staged")
def scan_staged_cmd(
    path: Annotated[Path, typer.Argument(help="Repository root directory.")] = Path("."),
    fmt: str = typer.Option(
        "terminal", "--format", "-f", help="Output format: terminal, json, markdown, sarif.",
    ),
    severity: str = typer.Option(
        "low", "--severity", "-s", help="Minimum severity: critical, high, medium, low.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Write output to file instead of stdout.",
    ),
) -> None:
    """Scan only git-staged files (optimized for pre-commit hooks)."""
    resolved_path = path.resolve()
    git_result = subprocess.run(
        ["git", "diff", "--name-only", "--cached", "--diff-filter=ACMR"],
        capture_output=True, text=True, cwd=str(resolved_path)
    )
    if git_result.returncode != 0:
        console.print(f"[red]git diff failed: {git_result.stderr.strip()}[/red]")
        raise typer.Exit(code=1)
    staged = [
        resolved_path / f.strip()
        for f in git_result.stdout.splitlines()
        if f.strip()
    ]
    staged = [f for f in staged if f.is_file()]

    if not staged:
        typer.echo("No staged files to scan.")
        raise typer.Exit(0)

    config = load_config(target_dir=resolved_path)

    # Apply exclude_paths from config to staged files (mirrors _discover_files logic)
    if config.exclude_paths:
        import pathspec as _pathspec
        _exclude_spec = _pathspec.PathSpec.from_lines("gitignore", config.exclude_paths)
        staged = [f for f in staged if not _exclude_spec.match_file(str(f.relative_to(resolved_path)))]

    if not staged:
        typer.echo("No staged files to scan (all excluded by config).")
        raise typer.Exit(0)

    try:
        threshold = Severity(severity.lower())
    except ValueError:
        console.print(f"[red]Invalid severity: {severity}[/red]")
        raise typer.Exit(code=1)

    result = scan_files(
        files=staged,
        target_dir=resolved_path,
        config=config,
        severity_threshold=threshold,
    )

    fmt = fmt.lower()
    try:
        formatter = get_formatter(fmt)
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1)
    _emit_output(result, formatter, fmt, output)

    if result.findings:
        raise typer.Exit(code=1)
