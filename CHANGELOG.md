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

## Retroactive notes

These are corrections or clarifications added after the original release. Listed in chronological order of the release they apply to (oldest first), with a link to the version that introduced the fix.

### v0.5.0 — PII suppression notice used `Severity.LOW` (fixed in v0.5.1)

The PII-local cap (`MAX_FINDINGS_PER_FILE = 100` in `pii.py`, deleted in v0.5.1) emitted its suppression notice at `Severity.LOW`. Users on the default `MEDIUM` severity threshold never saw the notice, so a scan that capped at 100 PII findings showed only 100 with no indication of the 900 suppressed.

**Reproduction (against the v0.5.0 wheel):**

```python
from shipguard.rules.pii import pii_004_email
from pathlib import Path

content = '\n'.join(f"user{i}@realcompany.io" for i in range(1000))
findings = pii_004_email(Path("seed.sql"), content)
# Returns 100 findings + 1 notice = 101 in the rule function's output.
# But `scan()` applies severity_threshold=medium (default), and
# Severity.LOW < medium, so the notice is dropped from `result.findings`.
# The user sees 100 PII findings with no suppression notice.
```

**Why this matters:** users on v0.5.0 who relied on the implicit "PII cap of 100 always on" got the cap, but never knew it was hitting. A user looking at a v0.5.0 scan output of "100 PII findings" would have no way to know whether the file actually had 100 PII or 1,000,000.

**Fix in v0.5.1:** `engine._cap_findings_per_file` uses `Severity.MEDIUM` for the notice (visible by default). The v0.5.1 cap mechanism was also moved to the engine layer (issue #19) and made opt-in via `Config.max_findings_per_file: 0` (unlimited) by default — restoring pre-v0.5.0 behaviour for users who don't want any cap.

**Action for v0.5.0 users:** upgrade to v0.5.1, or run scans with `--severity low` to see the notice.

**References:**
- Issue #27 (this retroactive note)
- PR #24 (v0.5.1 fix)
- [Release notes for v0.5.1](https://github.com/celstnblacc/shipguard/releases/tag/v0.5.1)
- `docs/ADR-pii-detection.md` §6 (the surviving decision record)
- `docs/PLAN-engine-cap.md` §3 Iteration 1 (the cap design that was promoted to MEDIUM mid-implementation)

---

## [Unreleased]
- 2026-07-21: docs: align CODE_OF_CONDUCT.md with concise 5-line CoC (replaces Contributor Covenant boilerplate with internal style)
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
- 2026-07-09: docs: retroactive note for v0.5.0 PII notice invisibility (issue #27); ADR-pii-detection.md cap section now references the severity choice
- 2026-07-11: fix: repo URLs pointed to celstnblacc/shipguard (stale org); corrected to artificemachine/shipguard in pyproject.toml, README.md, CONTRIBUTING.md, CLAUDE.md, SECURITY.md, sarif.py
- 2026-07-11: chore(ci): fixed PyPI trusted-publisher config for shipguard (was still registered to celstnblacc org, causing invalid-publisher OIDC failures); re-registered under artificemachine/shipguard, removed stale entry; v0.5.2 published manually as stopgap, future tag pushes publish via CI cleanly
- 2026-08-17: fix(PY-007): require SQL statement structure instead of a bare verb. The rule matched SELECT/INSERT/UPDATE/DELETE/DROP/CREATE/ALTER/GRANT anywhere inside an f-string or .format() string, with no requirement that the string resemble a query. Half of those are ordinary English, so the rule fired CWE-89 HIGH on help text, log messages and CLI instructions in repositories with no database access at all. Found in ai-forge, a project scaffolder with no SQL anywhere, where the trigger was a post-gen hook printing "3. Create remote and push"; because tree-sitter treats a triple-quoted f-string as one AST node, the finding was also misattributed to the opening print(f""" line rather than the matching word. Verbs now have to appear with the clause that makes them a statement (INSERT INTO, DELETE FROM, UPDATE ... SET, CREATE/DROP/ALTER TABLE, and so on), and SELECT ... FROM additionally requires FROM to be followed by something table-shaped rather than an article, since "select an option from the menu" is English. Both the semantic and regex-fallback paths now share one definition. Verified in both directions: the vulnerable fixture still reports PY-007, and a full scan of ai-forge drops from 1 finding to 0 with no suppression config.
- 2026-08-17: chore(release) — bump to v0.5.3 (PY-007 precision fix).
- 2026-08-17: feat(cli) — `scan-staged` gains `--include-rules` and `--exclude-rules`, matching `scan`. The pre-commit hook calls `scan-staged`, so until now there was no way to suppress a single false-positive rule for one invocation without editing `.shipguard.yml` (repo-wide, permanent) or bypassing the hook entirely with `--no-verify` (disables secret scanning and tests too). Unknown rule IDs are rejected with the same message `scan` uses.
- 2026-08-17: chore(release) — bump to v0.6.0 (scan-staged rule filters).
- 2026-08-17: fix(shellcheck): parse the real `--format=json1` shape — a single `{"comments": [...]}` object, not a list of per-file objects. The old code iterated the wrong level and crashed with `AttributeError: 'str' object has no attribute 'get'` on any real finding, silently returning zero ShellCheck findings from `scan --with-external` for every user who ever hit a real result (an empty-result run never reached the buggy line). Found via this session's own CI run: shipguard scanning itself under `--with-external` crashed. Every existing test in test_integrations_shellcheck.py mocked subprocess.run with the same wrong shape the buggy code expected, so they all passed while the real integration was broken — fixed those fixtures and added a non-mocked test that runs the actual shellcheck binary against a script with a known SC2154 finding.
- 2026-08-17: chore(release) — bump to v0.6.1 (shellcheck json1 parsing fix). Corrected from the branch's original 0.5.4: by the time this merged, main had already advanced to 0.6.0 via the two other independently-branched PRs above, so this lands as the next patch above that instead.
- 2026-08-24: fix(config): wire `rule_config.<RULE-ID>.skip_paths` into the scan path. This option is documented in `shipguard init`'s generated template (`config.py`) and parsed into `Config.rule_config`, but nothing ever consulted it — every finding fired regardless of `skip_paths`, only `disable_rules` (which is repo-wide, not per-path) actually worked. Found during a real false-positive triage in another project: SHELL-002/SHELL-005 fire on a script that intentionally interpolates unquoted variables inside a heredoc (`<<EOF`), where quoting them would print literal quote characters into the generated output instead of expanding them. `_scan_file` now accepts `target_dir` (threaded through `_run_parallel_scans`, `scan()`, and `scan_files()` — the latter is what `scan-staged` calls, so the pre-commit hook path is covered too), resolves each file's path relative to it, and skips a rule for a file when `rule_config.<rule.id>.skip_paths` matches. `target_dir` defaults to `None` (falls back to matching the file's raw path) so no existing caller breaks.
- 2026-08-24: chore(release) — bump to v0.6.2 (rule_config.skip_paths fix).
- 2026-08-24: fix(deps): cap litellm to `<1.90.0`. Discovered via PR #35's CI: the unpinned `litellm>=1.83.7` resolved to 1.98.0, which pulls in an experimental Anthropic context-management module (`llms/anthropic/experimental_pass_through/context_management/editors/compact.py`) that does `from typing import NotRequired` — added to stdlib `typing` in Python 3.11, absent in 3.10. `test (3.10)` failed on collection for every test file; `test (3.11/3.12/3.13)` were unaffected on import but got killed mid-run by GitHub's matrix fail-fast cascade after 3.10 failed. `main`'s last CI run (2026-08-17) was green, confirming this is dependency drift since then, not a regression in this PR. Capped conservatively below the point this session verified working (1.89.7, resolvable under the new range) rather than bisecting the exact break point.
- 2026-08-24: fix(JS-001,JS-004): stop misreading `.eval()` method calls and spread syntax as vulnerabilities. Found scanning `~/.claude` for a real triage: JS-001's `\beval\s*\(` matched `model.eval()` (a PyTorch call inside a Python heredoc embedded in a `.mjs` file), not the global `eval()` — added a negative lookbehind excluding a preceding `.`. JS-004's third alternative `\.\.\.\w+\s*,\s*\.\.\.\w+` matched any double object/array spread (`{...a, ...b}` / `[...a, ...b]`) as if it were the same vulnerability class as a hand-rolled recursive deep-merge function; spread copies own enumerable properties via `CopyDataProperties -> [[DefineOwnProperty]]`, which does not invoke `Object.prototype`'s inherited `__proto__` setter the way `Object.assign`'s `[[Set]]` semantics can — removed that alternative, kept `deepMerge`/`mergeDeep`/`extend` function detection and `Object.assign({}, ...)` (a real risk, unchanged). 4 new tests; 432 total passing.
- 2026-08-24: chore(release) — bump to v0.6.3 (JS-001/JS-004 precision fix).
