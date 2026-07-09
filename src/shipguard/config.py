"""Configuration system for ShipGuard using Pydantic."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, ValidationError

CONFIG_FILENAMES = [".shipguard.yml", ".shipguard.yaml", "shipguard.yml"]

DEFAULT_CONFIG_TEMPLATE = """\
# ShipGuard configuration
# See: https://github.com/DevOpsCelstn/shipguard

# Minimum severity to report: critical, high, medium, low
severity_threshold: medium

# Glob patterns for paths to exclude from scanning
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/fixtures/**"
  - "**/__snapshots__/**"

# Rule IDs to disable
disable_rules: []
  # - SHELL-008
  # - JS-007

# Additional directories containing custom rule modules
custom_rules_dirs: []

# Optional: use Rust-accelerated secrets scanning (SEC-001/002/003)
# Requires a built `shipguard-secrets` binary in PATH or SHIPGUARD_RUST_SECRETS_BIN.
use_rust_secrets: false

# Cap on findings per file (0 = unlimited). When the cap is hit, a synthesized
# suppression notice is emitted naming the true suppressed total and pointing at
# exclude_paths and disable_rules in this file. Never silent truncation.
# max_findings_per_file: 100

# Per-rule configuration overrides
# rule_config:
#   PY-011:
#     skip_paths: ["tests/**", "scripts/seed_*.py"]
"""


class Config(BaseModel):
    """ShipGuard scan configuration."""

    severity_threshold: Literal["critical", "high", "medium", "low"] = Field(default="medium")
    exclude_paths: list[str] = Field(default_factory=list)
    disable_rules: list[str] = Field(default_factory=list)
    custom_rules_dirs: list[str] = Field(default_factory=list)
    use_rust_secrets: bool = Field(default=False)
    ai_triage: bool = Field(default=False)
    rule_config: dict[str, dict] = Field(default_factory=dict)
    external_tools: list[str] = Field(default_factory=list)
    trufflehog_verify: bool = Field(default=False)
    semgrep_config: str = Field(default="auto")
    max_findings_per_file: int = Field(default=0, ge=0)


def find_config(target_dir: Path) -> Path | None:
    """Find config file in target directory."""
    for name in CONFIG_FILENAMES:
        path = target_dir / name
        if path.is_file():
            return path
    return None


def load_config(config_path: Path | None = None, target_dir: Path | None = None) -> Config:
    """Load configuration from file or return defaults.

    Args:
        config_path: Explicit path to config file.
        target_dir: Directory to search for config file.

    Returns:
        Config object with settings.
    """
    if config_path is None and target_dir is not None:
        config_path = find_config(target_dir)

    if config_path is not None and config_path.is_file():
        raw = yaml.safe_load(config_path.read_text()) or {}
        try:
            return Config.model_validate(raw)
        except ValidationError as exc:
            raise ValueError(
                f"Invalid ShipGuard config in {config_path}:\n{exc}"
            ) from exc

    return Config()
