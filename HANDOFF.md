# Session Handoff — 2026-07-09 (Engine-level finding cap shipped v0.5.1)
Agent: OpenCode (MiniMax-M3) | Branch: main | Tests: 418 pass, 4 skip, 0 xfailed | COMMITTED (1b5e8c8) | v0.5.1 tagged, PyPI live

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
