"""Rule registry with @register decorator."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from shipguard.models import Finding, Severity

# Type for a rule function: (file_path, content, **kwargs) -> list[Finding]
RuleFunc = Callable[..., list[Finding]]


@dataclass
class RuleMeta:
    """Metadata for a registered rule."""

    id: str
    name: str
    severity: Severity
    description: str
    extensions: list[str]
    cwe_id: str | None = None
    func: RuleFunc | None = field(default=None, repr=False)
    compliance_tags: list[str] = field(default_factory=list)
    supersedes: list[str] = field(default_factory=list)


# Global rule registry
_registry: dict[str, RuleMeta] = {}


def register(
    *,
    id: str,
    name: str,
    severity: Severity,
    description: str,
    extensions: list[str],
    cwe_id: str | None = None,
    compliance_tags: list[str] | None = None,
    supersedes: list[str] | None = None,
) -> Callable[[RuleFunc], RuleFunc]:
    """Decorator to register a rule function."""

    def decorator(func: RuleFunc) -> RuleFunc:
        meta = RuleMeta(
            id=id,
            name=name,
            severity=severity,
            description=description,
            extensions=extensions,
            cwe_id=cwe_id,
            func=func,
            compliance_tags=compliance_tags or [],
            supersedes=supersedes or [],
        )
        _registry[id] = meta
        # Attach metadata to function for introspection
        func._rule_meta = meta  # type: ignore[attr-defined]
        return func

    return decorator


def get_registry() -> dict[str, RuleMeta]:
    """Return a copy of the rule registry."""
    return dict(_registry)


def get_rules_for_file(file_path: Path) -> list[RuleMeta]:
    """Return rules applicable to a given file extension."""
    ext = file_path.suffix.lower()
    name = file_path.name.lower()
    applicable = []
    for rule in _registry.values():
        for pattern in rule.extensions:
            if pattern.startswith("."):
                # Extension patterns match normal suffixes (e.g., ".py"), and also
                # dotfiles like ".env" / ".env.local" that do not expose ".env" as suffix.
                if ext == pattern or name == pattern or name.startswith(f"{pattern}."):
                    applicable.append(rule)
                    break
            elif name == pattern:
                applicable.append(rule)
                break
    return applicable


def load_builtin_rules() -> None:
    """Import all builtin rule modules to trigger registration."""
    from shipguard.rules import config as _cfg  # noqa: F401
    from shipguard.rules import github_actions as _gha  # noqa: F401
    from shipguard.rules import javascript as _js  # noqa: F401
    from shipguard.rules import pii as _pii  # noqa: F401
    from shipguard.rules import python as _py  # noqa: F401
    from shipguard.rules import secrets as _sec  # noqa: F401
    from shipguard.rules import shell as _sh  # noqa: F401
    from shipguard.rules import supply_chain as _sc  # noqa: F401


def load_custom_rules(rule_dirs: list[Path]) -> int:
    """Load custom rule modules from configured directories.

    Python files under each directory are imported; @register calls inside those
    modules add rules to the global registry.
    """
    loaded = 0
    for rule_dir in rule_dirs:
        if not rule_dir.is_dir():
            continue
        for py_file in sorted(rule_dir.rglob("*.py")):
            digest = hashlib.md5(str(py_file.resolve()).encode()).hexdigest()[:12]
            module_name = f"shipguard_custom_{digest}"
            if module_name in sys.modules:
                continue
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(module)
            except Exception as exc:
                print(f"[shipguard] warning: failed to load custom rule {py_file}: {exc}", file=sys.stderr)
                sys.modules.pop(module_name, None)
                continue
            sys.modules[module_name] = module
            loaded += 1
    return loaded
