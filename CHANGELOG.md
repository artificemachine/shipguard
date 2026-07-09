> Maintainer instruction: This changelog is append-only. Always append new entries; do not edit or reorder previous entries.

# Changelog

All notable changes to this project will be documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.2.0] — 2026-03-08

### Added
- Go-live staging scaffolding: `Dockerfile`, `docker-compose.staging.yml`, `scripts/go_live_staging.sh`
- `.env.staging.example` for local staging bootstrap
- `uv.lock` for reproducible contributor installs
- GitHub Actions `security.yml` hardened: Layer-3 now gates on `critical + high` (was `critical` only)

### Fixed
- Removed `continue-on-error: true` from all security-critical CI jobs (fail-open posture)
- Removed `|| true` from blocking scan/audit steps
- Pinned `owasp/zap2docker-stable:latest` → `2.15.0` (SC-003 self-violation)
- Layer-2 secrets scan correctly labeled as report-only; enforcement remains in Layer-3

### Changed
- `APP_USER` config added to `.env.example`
- Broadened `.coverage` ignore pattern to catch `.coverage*` variants
- Added Release Runbook section in `README.md` for PyPI trusted publishing (OIDC), tag flow, rerun guidance, and smoke-test verification.
- Renamed tool to `shipguard`: package, CLI entrypoint, config files (`.shipguard.yml`), env vars (`SHIPGUARD_*`), GitHub Action usage example updated to `celstnblacc/shipguard@main`.

---

## [0.1.0] — 2026-02-01

### Added
- Initial release
- 40 security rules across 7 layers: Shell (9), Python (9), JavaScript (8), GitHub Actions (5), Config (3), Secrets (3), Supply Chain (3)
- CLI commands: `scan`, `list-rules`, `init`
- Output formats: terminal (Rich), JSON, Markdown
- GitHub Action integration (`action.yml`)
- Pre-commit hook support
- Test suite: 217 functions across 27 files
- Golden snapshot regression tests
- Concurrent scanning support

---

## [0.3.0] — 2026-03-10

### Added
- `scan` CLI flags for rule-level filtering:
  - `--include-rules` (comma-separated rule IDs)
  - `--exclude-rules` (comma-separated rule IDs)
- Validation for unknown rule IDs in `--include-rules` / `--exclude-rules`.

### Fixed
- Version alignment across package metadata:
  - `pyproject.toml` remains `0.3.0`
  - `src/shipguard/__init__.py` updated to `0.3.0`
- Makefile security targets now use supported CLI options and output formats:
  - replaced unsupported `--rules` with `--include-rules`
  - replaced unsupported `--format text` with `--format terminal`
- `.pre-commit-config.yaml.template` updated from legacy project-name references to `shipguard`, including config filename and command examples.

### Changed
- Documentation alignment for current rule inventory:
  - README updated from 40 → 48 total rules
  - Layer and category counts updated (`SEC-001..010`, `SC-001..004`)
  - Added README examples for `--include-rules` / `--exclude-rules`.
- `IMPLEMENTATION_SUMMARY.md` verification guidance updated to expect 48 rules from `shipguard list-rules`.

## [0.3.3] — 2026-03-26

### Fixed
- `supply_chain.py` SC-004: replaced f-string containing backslash expression
  (invalid in Python <3.12) with string concatenation — fixes SyntaxError on
  Python 3.10 and 3.11

### Docs
- `CLAUDE.md`: refreshed for v0.3.2 — added Rust secrets crate, integrations
  module, SARIF formatter, full 35-file test suite, new CI workflows

---

## [0.4.0] — 2026-04-30

### Added
- **Semantic Engine:** Integration of Tree-sitter for AST-aware scanning in Python and JavaScript, reducing false positives.
- **AI Triage (Layer 4):** Autonomous finding classification and reachability analysis using LiteLLM (Claude 3.5 Sonnet).
- **AutoFixer:** Intelligent remediation engine with automated patch verification and rollback safety.
- **MCP Server:** Native Model Context Protocol support for integration with AI agents like Claude Desktop and Cursor.
- **Persistence:** SQLite-backed state tracking at `.shipguard/state.db` to remember triage decisions across scans.
- **Rust Core:** High-performance multi-threaded engine for file discovery and rule dispatch.
- **Agent Formats:** Token-optimized output format for AI agent consumption.

### Changed
- Refactored core engine to support semantic plugins and AI reasoning layers.
- Expanded rule registry to 60 built-in security patterns.

## [Unreleased]
### Security
- Bump `litellm` to `>=1.83.7` to cover CVE-2026-42208 (pre-auth SQLi) and CVE-2026-42203 (SSTI). ShipGuard uses the SDK only; not exploitable, hygiene bump.
- 2026-05-18: chore(release): bump to v0.4.1 (litellm >=1.83.7 for CVE-2026-42208/42203 hygiene)
- 2026-05-18: fix: resolve __version__ from installed package metadata (was hardcoded, drifted from pyproject.toml). Bump to v0.4.2.
- 2026-05-18: docs(claude): bump CLAUDE.md version refs to 0.4.2 and add strict installation decoupling note.
- 2026-06-08: fix(scan-staged): load .shipguard.yml project config in scan-staged command; apply exclude_paths filtering to staged files and pass config to scan_files so disable_rules and other settings are respected
- 2026-06-08: docs(claude): document new modules (MCP server, AI triage, auto-remediation, semantic engine, db layer)
- 2026-06-08: chore(release): bump to v0.4.3
- 2026-06-25: chore: remove personal workspace path from tracked files
- 2026-07-09: Extract shared rule helpers to rules/_common.py (no behaviour change)
- 2026-07-09: Add PII-001 SSN detection rule
- 2026-07-09: Add PII-002 credit card number detection with Luhn validation
- 2026-07-09: Add PII-003 phone number and PII-004 email address detection
- 2026-07-09: chore(release): bump to v0.5.0 (PII rule category)
- 2026-07-09: test(pii): add direct unit tests for _cap_findings helper (13 tests; 12 pass + 1 xfailed boundary for issue #19)
- 2026-07-09: chore(repo): commit post-merge session artifacts (SOUL.md, docs/ADR-pii-detection.md, HANDOFF.md)
- 2026-07-09: docs: add PLAN-engine-cap (engine-level max_findings_per_file; implements issue #19)
- 2026-07-09: feat(engine): add configurable max_findings_per_file cap (engine-level)
- 2026-07-09: refactor(rules): remove PII-local _cap_findings (subsumed by engine-level cap)
- 2026-07-09: chore(release): bump to v0.5.1 (engine-level max_findings_per_file cap)
- 2026-07-09: fix(ci): bump CodeQL action to v3.28.0 (broken SHA was failing 4 jobs); convert .gitleaks.toml paths to RE2 regex (gitleaks 8.25+ no longer accepts globs)
- 2026-07-09: docs: update HANDOFF for v0.5.1 (engine-level cap shipped)
- 2026-07-09: chore(cleanup): remove redundant test_rules_pii_cap_unit.py (the boundary test is now covered by test_engine_cap.py::test_cap_disabled_when_zero)
