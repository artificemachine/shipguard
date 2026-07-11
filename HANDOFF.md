# Session Handoff — 2026-07-11 (org migration fix: celstnblacc → artificemachine, v0.5.2)
Agent: Claude Code (Sonnet 5) | Branch: main | Tests: 417 pass, 4 skip, 0 xfailed | COMMITTED (215e024) | v0.5.2 tagged, released, PyPI live

## What happened this session
- Found `origin` remote is `github.com/artificemachine/shipguard`, but repo URLs still referenced the old `celstnblacc` org: `pyproject.toml` (Homepage/Repository/Changelog/Bug Tracker/Security Policy), `README.md`, `CONTRIBUTING.md`, `CLAUDE.md`, `SECURITY.md`, `src/shipguard/formatters/sarif.py`'s `informationUri`. Fixed all six via PR #30 (`06702d2` → squash-merged `215e024`). Left `CHANGELOG.md` untouched (append-only) and `HANDOFF.md` untouched at the time (historical session log). Left README's `celstnblacc/spec-kit` and `celstnblacc/superpowers` refs alone — different repos, actually still under that org.
- Version bump `0.5.1` → `0.5.2` (patch, docs-only fix). Tagged `v0.5.2`, GitHub release published: https://github.com/artificemachine/shipguard/releases/tag/v0.5.2
- PyPI publish via CI failed: `invalid-publisher` OIDC error. Root cause — same org migration, one layer deeper: PyPI's trusted-publisher config for the `shipguard` project still pointed at `celstnblacc/shipguard`, so the `artificemachine/shipguard` workflow's OIDC claims didn't match. Published `v0.5.2` manually via `twine upload --repository shipguard` as a stopgap (required fixing `~/.pypirc` first — `[shipguard]` section was missing a `repository =` key and `[distutils]` was missing `index-servers`; both now fixed).
- Fixed the PyPI trusted-publisher config itself (via browser, pypi.org project settings → Publishing): added `artificemachine/shipguard` (workflow `publish.yml`, env `pypi`) as a trusted publisher, removed the stale `celstnblacc/shipguard` entry. Re-ran the failed publish workflow run (29152036152) to confirm — OIDC exchange now succeeds; it only fails afterward with `400 Bad Request` because `v0.5.2` already exists on PyPI (expected, from the manual upload). **Next real tag push will publish cleanly via CI with no manual steps.**
- Also found `shipguard --version` printing `0.5.0` locally — false alarm, not a code bug. `src/shipguard/__init__.py` correctly reads version from installed package metadata (`importlib.metadata.version("shipguard")`). The stale `0.5.0` was a separate `pipx`-installed venv (`~/.local/pipx/venvs/shipguard`) that predated this session and hadn't been upgraded. Ran `pipx upgrade shipguard` → now correctly reports `0.5.2`. (There's also a pyenv 3.11.6 site-packages install, upgraded separately via `pip install shipguard==0.5.2` for the reinstall verification — two independent shipguard installs exist on this machine, keep both in mind if `--version` looks stale again.)
- Doc sweep: updated 3 stale `v0.4.0`-pinned examples in `README.md` (pip install, pre-commit `rev:`, GitHub Action `uses:`) to `v0.5.2`. Updated `CLAUDE.md`'s two `**Version:**` stamps (0.4.2 → 0.5.2, both stale — hadn't been bumped since well before v0.5.0/PII rules shipped) and `**Last Updated:**` date.

## Next session — first moves
1. **`CLAUDE.md` rule-count drift not yet fixed.** It still says "60 built-in security rules" / "60 security vulnerability patterns" (lines 5, 11) — actual count is 64 (`shipguard list-rules --format json` confirms), missing the 4 PII-* rules added in v0.5.0. Flagged but not fixed this session — deeper content rewrite of a protected instruction file, wanted explicit go-ahead beyond the version-stamp bump that was approved. Needs an operator decision on scope (just the count, or a fuller Key Features rewrite adding the PII-* rule category).
2. **Two independent local `shipguard` installs exist**: pyenv 3.11.6 site-packages (`pip install`) and a `pipx` venv. Both now at 0.5.2 as of this session, but they drift independently — future `--version` staleness is almost certainly one of these two lagging, not a code bug.
3. No engine-cap or PII-arc follow-up remains open (carried over from the prior handoff below — still true).

### Operational notes
- **PyPI trusted publisher for `shipguard`**: now `artificemachine/shipguard`, workflow `publish.yml`, env `pypi`. Configured at https://pypi.org/manage/project/shipguard/settings/publishing/ (requires PyPI login, not automatable via CLI/API — did this via browser this session).
- **`~/.pypirc` `[shipguard]` section**: now has `repository = https://upload.pypi.org/legacy/` (was missing, causing `KeyError: 'repository'` on `twine upload --repository shipguard`). `[distutils]` now has `index-servers = pypi testpypi shipguard superharness` (was also missing).
- **GitHub auth**: unchanged from prior handoff — `gh auth` active is `newblacc`; `celstnblacc` in keyring. Note the celstnblacc GitHub org itself still exists (spec-kit, superpowers repos live there) — only `shipguard` moved to `artificemachine`.

---


## What happened this session
- Folded the redundant `tests/test_rules_pii_cap_unit.py` into `tests/test_engine_cap.py`. The 50-line file held 1 test (`test_cap_of_zero_is_unlimited`, the PR #20 migration contract) that was already covered by `test_engine_cap.py::TestCapFindingsPerFile::test_cap_disabled_when_zero`. Deletion as PR #28 (`29d75a8`). Test count: 418 → 417.
- Filed issue #27 (`docs: document v0.5.0 PII notice invisibility in CHANGELOG (fixed in v0.5.1)`) for the v0.5.0 PII notice `Severity.LOW` bug. The bug was that the v0.5.0 PII-local cap emitted a `Severity.LOW` notice, invisible to users on the default `MEDIUM` threshold — a scan capping at 100 PII showed only 100 with no indication of the 900 suppressed. v0.5.1 fixed this engine-side by promoting the notice to `Severity.MEDIUM`, but the v0.5.0 wheel on PyPI still has the bug.
- Resolved issue #27: new "Retroactive notes" section at the top of `CHANGELOG.md` with the v0.5.0 entry (full reproduction snippet, fix history, cross-references). `docs/ADR-pii-detection.md` cap section now references the severity choice and the v0.5.0 → v0.5.1 fix. PR #29 (`ad32b96`).
- Closed issue #27. All three engine-cap-arc issues (#19, #22, #27) are now closed.

## Next session — first moves
1. **No engine-cap follow-up work remains.** All open items are: ad-hoc operator decisions, project-level tooling that lives outside this repo (the `~/.claude/scripts/plan-check.py` patch is in operator-local config, not tracked), and the broken `.venv` (deferred with operator-approval gate). A fresh session can pick up whatever the operator brings; nothing from the engine-cap arc is dangling.
2. **If the operator has a new feature / refactor / bug-fix**, the pattern is: `/plan-iter <topic>` → review the plan against `~/.claude/scripts/plan-check.py` (now patched, accepts H2 DoD and file:line citations) → `/plan-implement <path>` for execution. The PII and engine-cap plans are templates; the PII review log is the cautionary reference for what plan-design mistakes look like in practice.
3. **Consider a v0.5.1 → v0.5.2 micro-release** if any further engine-cap issue surfaces. The retroactive CHANGELOG note (issue #27) is the only thing that changed since v0.5.1 shipped; the engine-cap code is identical. A patch release with the doc fix is a low-cost way to make the v0.5.0 → v0.5.1 → v0.5.2 upgrade path obvious for users who read changelogs carefully.

### Operational notes
- **PyPI token for `shipguard`**: `~/.pypirc` `[shipguard]` section holds the project-scoped token; works. `~/.pypirc` requires `[distutils] index-servers = pypi testpypi shipguard superharness` for twine to recognise non-default section names.
- **GitHub auth**: `gh auth` active is `newblacc`; `celstnblacc` in keyring. Switch with `gh auth switch --user <user>`.
- **Test command**: `PYTHONPATH=src /Users/airm2max/.pyenv/versions/3.11.6/bin/python -m pytest tests/` (system pytest on Python 3.11.6). **417 pass / 4 skip / 0 xfailed.** (The previous handoff said 418 — that was before PR #28 deleted the redundant test.)
- **`.venv` is broken** (missing pytest on Python 3.13). Do not try to fix without operator approval — outside the engine-cap arc's scope.
- **`plan-check.py` is patched** at `~/.claude/scripts/plan-check.py`. Four fixes: `strip_annotation` handles backticked/paren/PR-cited source references; `pass_3_source_refs` strips `:\d+`/`:Identifier`/`::test_name` suffixes before file existence checks; `pass_6_dod_tests` accepts H2 or H3 DoD headings; `TEST_FILE_RE` anchored on word boundaries. Regression fixture at `~/.claude/scripts/test_plans/PLAN-test-fixture.md` (exits 0).
- **Engine-cap arc, fully closed**: v0.5.0 (PII rules, PyPI), v0.5.1 (engine-level cap, PII shim deletion, CI fix, PyPI, tag force-moved for the CI fix), `docs/PLAN-engine-cap.md` saved, `docs/ADR-pii-detection.md` updated with the severity-choice note, all three engine-cap-arc issues (#19, #22, #27) closed. PyPI has `shipguard 0.5.1`. The retroactive CHANGELOG note documents the v0.5.0 → v0.5.1 bug for users reading the changelog in order.
- **`v0.5.1` tag was force-moved** from `d54f893` (post-PR-#24 squash) to `1b5e8c8` (post-PR-#25 squash) to include the CI fixes. The PyPI artifact is unchanged — the engine-cap code is identical between the two commits. The tag annotation explains the move.
- **`.shipguard.yml`** still has no `max_findings_per_file` set. Default = unlimited. v0.5.0 users who relied on the implicit PII cap of 100 should now set `max_findings_per_file: 100` in their config.

---

## What happened this session
- Implemented `docs/PLAN-engine-cap.md` end-to-end across 2 atomic commits on `feat/engine-cap` (5585d1c + dcf06fe), then squash-merged into main as PR #24 with a 3rd commit `0a7b828` bumping `pyproject.toml` to v0.5.1.
- New: `Config.max_findings_per_file` field (default `0` = unlimited, opt-in via `.shipguard.yml`); `engine._cap_findings_per_file()` helper applied per-file inside `_run_parallel_scans`; synthesized suppression notice (Severity.MEDIUM, never silent truncation) naming the true suppressed total + the rule with the largest overflow + both opt-out paths (`exclude_paths`, `disable_rules`).
- Removed: PII-local `_cap_findings` and `MAX_FINDINGS_PER_FILE` from `pii.py`; the 12 obsolete direct unit tests in `tests/test_rules_pii_cap_unit.py` (only the boundary test `test_cap_of_zero_is_unlimited` survived, re-pointed at the engine-level helper).
- Flipped: `test_cap_of_zero_is_unlimited` from xfail to pass — the migration contract from PR #20 held.
- Latent CI failures surfaced and fixed in PR #25: `github/codeql-action` SHA was force-removed upstream (3 jobs broke); `.gitleaks.toml` paths used glob syntax that gitleaks 8.25+ rejects with a panic. Both fixes are workflow-level, not engine-cap-related.
- Closed: issue #19 (the engine-cap design discussion this implements), issue #22 (the plan-check.py false-positive fix that unblocked the plan).
- Tagged `v0.5.1`, force-moved to the post-CI-fix commit `1b5e8c8`, PyPI wheel and sdist already published (the engine-cap code is identical between the two commits; re-tagging was cosmetic).
- Verified: `pip install --upgrade shipguard` → 0.5.1; 64 rules; 0 PII findings on self-scan; 5 PII-004 + 1 suppression notice on a 200-email .sql with `max_findings_per_file: 5`.

## Plan deviations (from the PLAN-engine-cap)
1. **Notice severity: MEDIUM, not LOW.** The plan said LOW; a LOW notice is invisible to users on the default MEDIUM threshold. Promoted to MEDIUM. Pre-existing v0.5.0 PII cap had the same invisibility bug; this fixes it engine-side.
2. **`test_cap_groups_by_rule_id` uses first-N-by-input-order, not per-rule balancing.** The plan's GREEN block said `findings[:cap]` (first N); the plan's test asserted "50 PII-001 + 50 PII-004" (per-rule balancing). Resolved in favour of the GREEN block. Test updated.

## Next session — first moves
1. **Watch PR #25's CI run for green.** The CodeQL action SHA bump should resolve the 3 jobs that were broken on the prior run; the gitleaks config fix should resolve the 4th. If anything is still red, the run is the canary.
2. **Triage the remaining xfail → flipped-test** — `test_cap_of_zero_is_unlimited` is now passing. The fixture plan (`~/.claude/scripts/test_plans/PLAN-test-fixture.md`) is the regression target for `plan-check.py`; if anyone modifies the script, that fixture should still exit 0.
3. **Consider filing a follow-up issue for the v0.5.0 PII notice invisibility bug** that v0.5.1 fixes engine-side. The bug existed from v0.5.0 to v0.5.1; users who skipped v0.5.1 will still see it on their PII cap. Document for the next major release.

### Operational notes
- **PyPI token for `shipguard`**: `~/.pypirc` `[shipguard]` section holds the project-scoped token; works. `~/.pypirc` requires `[distutils] index-servers = pypi testpypi shipguard superharness` for twine to recognise non-default section names.
- **GitHub auth**: `gh auth` active is `newblacc`; `celstnblacc` in keyring. Switch with `gh auth switch --user <user>`.
- **Test command**: `PYTHONPATH=src /Users/airm2max/.pyenv/versions/3.11.6/bin/python -m pytest tests/` (system pytest on Python 3.11.6). 418 pass / 4 skip / 0 xfailed.
- **`.venv` is broken** (missing pytest on Python 3.13). Do not try to fix without operator approval — outside this session's scope.
- **`plan-check.py` is patched** at `~/.claude/scripts/plan-check.py`. Three fixes: `strip_annotation` handles backticked/paren/PR-cited source references, `pass_3_source_refs` strips `:\d+`/`:Identifier`/`::test_name` suffixes, `pass_6_dod_tests` accepts H2 or H3 DoD headings, `TEST_FILE_RE` anchored on word boundaries. Regression fixture at `~/.claude/scripts/test_plans/PLAN-test-fixture.md` (exits 0).
- **`v0.5.1` tag was force-moved** from `d54f893` (post-PR-#24 squash) to `1b5e8c8` (post-PR-#25 squash) to include the CI fixes. The PyPI artifact is unchanged — the engine-cap code is identical between the two commits. The tag annotation explains the move.
- **`.shipguard.yml`** still has no `max_findings_per_file` set. Default = unlimited. v0.5.0 users who relied on the implicit PII cap of 100 should now set `max_findings_per_file: 100` in their config.

---

# Session Handoff — 2026-07-09 (PII rule category shipped v0.5.0)

## Follow-up this session
- PR #20 merged: 13 direct unit tests for `_cap_findings` (12 pass + 1 xfailed boundary for issue #19). No production code change. Main now at a654423.

## What happened this session
- Implemented `docs/PLAN-pii-detection.md` end-to-end across 4 atomic commits on `feat/pii-detection` (4da3e68 / 3c317cb / f12f2f4 / 76245ff), then squash-merged into main as PR #18 with a 5th commit `894b0a2` bumping `pyproject.toml` to v0.5.0.
- New rule category: `PII-001` (SSN, HIGH), `PII-002` (credit card, CRITICAL, Luhn + 5-card allowlist), `PII-003` (NANP phone, LOW, 555-01XX + 5-placeholder skip), `PII-004` (email, MEDIUM, example-domains + GitHub noreply + 9-key metadata skip). Rule count 60 → 64.
- New safety mechanism: `MAX_FINDINGS_PER_FILE = 100` cap applied to all 4 PII rules. Synthesized suppression notice names the true suppressed total + opt-out paths. Never silent truncation.
- Refactor: extracted `_skip_false_positive` + `_make_finding` from `src/shipguard/rules/secrets.py` into new `src/shipguard/rules/_common.py`; `secrets.py` re-exports both for back-compat. Pre-existing `tests/test_rules_secrets.py` (53 tests) passes with zero edits.
- Excluded by design: `.csv` and `.log` removed from `PII_EXTS`. Deferred to engine-level finding cap (named in plan §6 Out of scope as the proper fix).
- Tagged `v0.5.0`, published GitHub release, and pushed `shipguard-0.5.0` wheel + sdist to PyPI. Verified end-to-end: `pip install --upgrade shipguard` resolves to 0.5.0; 64 rules, all 4 PII severities correct; demo script returns 5 findings.
- Synced 12 drifted skills from `~/.claude/commands/` into `~/.config/opencode/skills/`, including the `plan-implement` skill now using the canonical `~/.claude/scripts/plan-check.py` instead of an inline 6-pass implementation.
- Retroactive plan consistency check (`plan-check.py --caller plan-implement`) on the executed plan: 24 findings, all `stale-vs-repo` or checker-convention mismatches. None are real `authored-invalid` bugs. Report saved to `docs/PLAN-pii-detection.check-report.txt`.

## Next session — first moves
1. **Watch the Iteration 0 refactor in CI for one cycle.** The back-compat re-export of `_skip_false_positive`/`_make_finding` from `secrets.py` is the load-bearing claim that the existing test suite kept passing. Verify the next CI run on main confirms it; then the claim is settled.
2. **File a follow-up issue for the engine-level finding cap.** Plan §6 names it as the proper fix for the flood risk; it should be in `engine.py`, configurable via `.shipguard.yml`, apply to all rule families. When it lands, delete `_cap_findings` from `pii.py`.
3. **Consider direct unit tests for `_cap_findings`.** Currently exercised transitively through `test_pii_004_large_file_capped`. A direct unit test (input = 101 findings → output = 100 + 1 notice) is cheaper to run and pins the contract for the future engine-level replacement.

### Operational notes
- **PyPI token for `shipguard`**: `~/.pypirc` `[shipguard]` section holds a project-scoped token; works. **Important:** twine requires a `[distutils] index-servers = pypi testpypi shipguard superharness` block to recognise non-default section names — without it, twine silently drops custom sections and returns "Missing 'shipguard' section." File mode is 600.
- **PyPI token for `superharness`**: `~/.pypirc` `[superharness]` section holds the original token. Unchanged.
- **GitHub auth**: `gh auth` active account is `newblacc`; `celstnblacc` remains in keyring. Switch with `gh auth switch --user <user>` when you need to push to `celstnblacc/shipguard`.
- **PyPI release URL**: https://pypi.org/project/shipguard/0.5.0/
- **GitHub release URL**: https://github.com/celstnblacc/shipguard/releases/tag/v0.5.0
- **PR URL**: https://github.com/celstnblacc/shipguard/pull/18
- **Test command**: `PYTHONPATH=src /Users/airm2max/.pyenv/versions/3.11.6/bin/python -m pytest tests/` (system pytest on Python 3.11.6; the project's `.venv` is broken — missing pytest on Python 3.13). 405 pass / 4 skip.
- **`.venv` is broken**: missing pytest on Python 3.13. Use system `pytest` via `/Users/airm2max/.pyenv/versions/3.11.6/bin/python -m pytest`. Do not try to fix the venv without operator approval — outside the scope of this session.
- **`.shipguard.yml`** already excludes `tests/**`, `docs/**`, and `src/shipguard/rules/**` so the new `pii.py` literal constants (test cards, placeholder phones) cannot self-flag during dogfood scans.
- **`docs/PLAN-pii-detection.md`** is the source-of-truth plan; retroactive check report at `docs/PLAN-pii-detection.check-report.txt`. Do not delete either — the next contributor running `plan-implement` against this repo will use both.

---

# ShipGuard Handoff: The Sentinel Transformation

## 🎯 Executive Summary
ShipGuard has been transformed from a regex-based scanner into a production-grade **AI-Native Security Sentinel**. It now features semantic intelligence, autonomous remediation, and persistent vulnerability tracking. The v0.4.0 release marks the completion of the core Sentinel architecture.
## 🛠️ Key Technical Achievements

### 1. The Semantic Cortex (AST-Aware Engine)
- **Technology:** Integrated **Tree-sitter** with compiled grammars for Python and JavaScript.
- **Hardening:** Rules like `PY-007` (SQL Injection) now use AST context to distinguish between dangerous interpolations and safe strings (like docstrings or literals), significantly reducing false positives.
- **Impact:** Scans understand code intent. It correctly identifies reachable vulnerabilities while ignoring safe patterns that regex would previously flag.

### 2. The Reasoning Layer (L4 AI Triage)
- **Technology:** `litellm` + `diskcache` + Claude 3.5 Sonnet / GPT-4o.
- **Impact:** Added the `--ai-triage` flag. ShipGuard now reasons about the "reachability" of findings. If code is provably dead or unreachable in the call graph, the Sentinel auto-dismisses the finding.

### 3. The Self-Healing Limb (AutoFixer)
- **Feature:** `shipguard fix --id [RULE]` command.
- **Flexibility:** Added multi-provider fallback (Anthropic -> OpenAI) for fix generation.
- **Impact:** Uses AI to generate secure refactors. Includes a verification loop that can run `pytest` and automatically rollback the patch if the build breaks.

### 4. Persistence Layer (The Memory)
- **Technology:** SQLite database at `.shipguard/state.db`.
- **Impact:** Tracks findings across their lifecycle (Open -> Triaged -> Fixed). This eliminates "finding fatigue" by remembering previous decisions and tracking "First Seen" metadata.

### 5. High-Performance Core (Rust)
- **Technology:** New `rust/shipguard-core` crate using **PyO3** and the `ignore` crate.
- **Impact:** Multi-threaded file discovery and rule dispatching, significantly faster than the previous pure-Python implementation.

### 6. Agent Integration (MCP Native)
- **Feature:** FastMCP server entrypoint (`shipguard-mcp`).
- **Impact:** Your AI agents (Claude, Cursor, Gemini CLI) can now use ShipGuard as a native tool to audit files during development.

## 📈 Release Status: v0.4.0
| Phase | Status | Feature |
| :--- | :--- | :--- |
| **Phase 1** | ✅ Complete | Persistence (SQLite State Tracking) |
| **Phase 2** | ✅ Complete | Semantic Engine (Tree-sitter AST) |
| **Phase 3** | ✅ Complete | Auto-Remediation (Verified Fixes) |
| **Phase 4** | ✅ Complete | Ecosystem (MCP & Agent Formats) |

**Self-Audit Result:** As of v0.4.0, ShipGuard returns **0 findings** on its own codebase when scanned with `--ai-triage`.

## 🚀 How to use the Sentinel
- **Scan with AI:** `shipguard scan --ai-triage`
- **Fix a Rule:** `shipguard fix --id PY-007 --apply`
- **Agent Output:** `shipguard scan --format agent` (Token-optimized)
- **Start MCP:** `shipguard-mcp`

## 🔮 Next Steps for Developers
1.  **Rules Expansion:** Convert the remaining Shell and GitHub Action rules from Regex to Tree-sitter queries.
2.  **Call Graph Deepening:** Enhance the `GlobalIndex` to trace data flow through multiple function calls across files.
3.  **Cross-Language Taint Analysis:** Extend the semantic engine to track untrusted input from a JS frontend through to a Python backend.
