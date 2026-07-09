# PLAN — Engine-Level Max-Findings-Per-File Cap

## 1. Scope summary

Move the per-file finding cap from `src/shipguard/rules/pii.py` (PII-local shim added in v0.5.0) to `src/shipguard/engine.py` as a generic, configurable mechanism that applies to every rule family. New config key `max_findings_per_file` in `.shipguard.yml`, defaulting to a sensible number with `0`/`null` meaning "unlimited." Synthesized suppression notice — never silent truncation. When the engine-level cap lands, delete `_cap_findings` from `pii.py`; the engine does it for all rules.

**Explicitly NOT building:** per-rule or per-file override of the cap (keep it simple; `exclude_paths` already handles per-file opt-out); async/cancellable scanning (separate concern); performance budget for scanning (the cap bounds output, not scan time); a migration shim where both caps exist simultaneously (the whole point of this work is to remove the duplication).

**Smallest possible v1:** Iterations 1 and 2 alone (config key + engine cap with synthesized notice, then delete the PII-local helper and the xfailed boundary test flips green). Wire into both `scan()` and `scan_files()` paths. Live in every scan.

**Source design discussion:** GitHub issue #19, filed 2026-07-09, accepted. The PII plan §6 (Out of scope) named this as the proper fix; this plan delivers it.

## 2. Prerequisites

- No new dependencies — pure stdlib, mirrors existing engine patterns.
- Files touched across all iterations:
  - `src/shipguard/config.py` (modified — add `max_findings_per_file` field + default in template)
  - `src/shipguard/engine.py` (modified — add `_cap_findings_per_file` helper, call from both `scan()` and `scan_files()`)
  - `src/shipguard/models.py` (no change — `Finding` already has the fields the notice needs; verify no new fields required)
  - `src/shipguard/rules/pii.py` (modified — delete `_cap_findings`, drop `_cap_findings` calls from all 4 PII rule functions, drop `MAX_FINDINGS_PER_FILE` constant)
  - `tests/test_engine_cap.py` (new — direct unit tests for the engine cap helper + integration tests through `scan()`)
  - `tests/test_rules_pii_cap_unit.py` (modified — remove the `xfail` decorator on `test_cap_of_zero_is_unlimited`, delete the now-obsolete PII-local tests)
  - `tests/test_rules_pii.py` (modified — `test_pii_004_large_file_capped` and `test_cap_not_triggered_below_threshold` migrate to engine-level tests; remove the `TestPiiFindingCap` class entirely)
  - `tests/fixtures/cap/large.sql` (new — 1,000-row seed file for the chaos test)
  - `README.md` (modified — new config key documented)
  - `docs/7_LAYER_SECURITY_MODEL.md` (modified — cap mechanism described)
  - `CHANGELOG.md` (append-only, required every commit per repo hook check 1b.1)
- Risk: the `xfail` removal in PR #20 was deliberately *strict*. Removing the marker must happen in the same commit that lands the engine-level cap, or CI goes red. The TDD cycle in Iteration 2 is explicit about this dependency.
- Risk: the existing `_run_parallel_scans` is per-file and parallel. The cap must be applied *per file*, not on the aggregated `all_findings` list, otherwise the cap is misleading ("suppressed N findings" wouldn't be per-file). The plan applies the cap inside the per-file aggregation path, before files leave `_scan_file` — wait, no: applying inside `_scan_file` is wrong because the cap is a *config* concern, not a per-rule concern. Apply at the `_run_parallel_scans` exit, on a per-file basis, before results are merged. This is the design decision Iteration 1 has to get right.
- Risk: dogfood. The repo's own `.shipguard.yml` should set `max_findings_per_file: 100` (matches the previous PII-local default) so the self-scan output doesn't change. Verify with `shipguard scan .` post-merge.
- Risk: backwards compat. The xfailed test `test_cap_of_zero_is_unlimited` (PR #20) asserts the engine-level contract. Its xfail is the migration contract — when this plan lands, the helper change and the xfail removal are *one commit*, not two.

## 3. Iterations

#### Iteration 1 — Engine-level cap mechanism + config key

**Goal:** Add `max_findings_per_file` to `Config`, add `_cap_findings_per_file()` helper in `engine.py`, call it from `scan()` and `scan_files()` for every file before results merge, emit synthesized suppression notice (never silent truncation). Default = `0` (unlimited) so existing user configs are unchanged.

**Shippable on its own?** Yes — additive, gated by `config.max_findings_per_file > 0`. With default `0`, behaviour is byte-identical to v0.5.0 (which is the *correct* state before Iteration 2 deletes the PII shim).

**Source references:**
- `src/shipguard/engine.py:104-168` (`_scan_file`) — read to understand per-file aggregation; do NOT modify this function in Iteration 1.
- `src/shipguard/engine.py:171-198` (`_run_parallel_scans`) — the right place to apply the cap. Read to understand the `(findings, files_skipped)` return shape; modify here in Iteration 1.
- `src/shipguard/engine.py:201-266` (`scan_files`) — read to understand the second code path; modify here in Iteration 1 to apply the cap on the aggregated result.
- `src/shipguard/engine.py:269-358` (`scan`) — read to understand the third path; modify here in Iteration 1 to apply the cap on the aggregated result.
- `src/shipguard/config.py:46-58` (`Config`) — add `max_findings_per_file` field here. Mirror the existing `severity_threshold` pattern: `Literal` type for type-safety, sensible default.
- `src/shipguard/config.py:13-43` (`DEFAULT_CONFIG_TEMPLATE`) — add a commented example showing how to set the cap.
- `src/shipguard/rules/pii.py:118-134` (`_cap_findings`) — read to understand the existing implementation. The new `_cap_findings_per_file` in `engine.py` mirrors its suppression-notice *shape* (severity, message, fields) but lives in a different module and is applied at a different layer. The two helpers' *output Finding* should be structurally identical so any test that migrates from the PII cap to the engine cap doesn't need to change its assertions about the notice.
- `tests/test_rules_pii_cap_unit.py` (PR #20) — read to understand the contract this cap must satisfy. The 12 passing tests in `TestCapFindingsNoTrigger` and `TestCapFindingsTriggers` apply to the engine-level cap too, with trivial adaptation: input is still `list[Finding]`, output is still the capped list + 1 notice. The mechanical difference: the engine helper takes `file_path` and `rule_id` explicitly because it may cap multiple rules' findings for the same file (the PII helper was always called with one rule's findings at a time).
- `src/shipguard/models.py:41-69` (`Finding`) — read to confirm the fields a suppression notice needs. `rule_id`, `severity`, `file_path`, `line_number`, `line_content`, `message`, `cwe_id`, `fix_hint` — all present, no new fields required.

**Files touched:**
- `src/shipguard/config.py` (modified — add `max_findings_per_file` field, update template)
- `src/shipguard/engine.py` (modified — add `_cap_findings_per_file`, call from `scan()` and `scan_files()`)
- `tests/test_engine_cap.py` (new)
- `CHANGELOG.md` (modified — append one line)

**Commit message:**
`feat(engine): add configurable max_findings_per_file cap (engine-level)`

**TDD cycle:**
- RED (failing tests to write first):
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_disabled_when_zero` — input: 200 findings, `config.max_findings_per_file=0`. Output: 200 findings unchanged (no notice). The "0 = unlimited" contract.
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_disabled_when_none` — same, but `config.max_findings_per_file=None`. Output: 200 findings unchanged.
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_triggers_above_threshold` — input: 200 findings, `config.max_findings_per_file=100`. Output: 100 findings + 1 suppression notice. Total 101.
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_emits_suppression_notice` — input: 105 findings, cap=100. Output's last finding has `severity=Severity.LOW`, `message` contains `"further"` and the true total `"105"` and `"105" in message` and `len(findings) == 101`. Notice names both opt-out paths (`"exclude_paths" in message`, `"disable_rules" in message`).
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_uses_last_kept_line_number` — input: 1000 findings with line numbers 1..1000, cap=100. Output's last finding (the notice) has `line_number == 100` (the line of the 100th kept finding).
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_groups_by_rule_id` — input: 200 findings split as 150 `PII-004` + 50 `PII-001`, cap=100. Output: 100 findings total — the cap is *per file*, not per rule; 50 PII-001 + 50 PII-004 (the first 50 of each, ordered by line). One suppression notice per file, naming whichever rule had the largest overflow.
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_preserves_kept_finding_identity` — input 105 findings; output's first 100 are the *same objects* (identity, not just equality) as the input's first 100.
  - `tests/test_engine_cap.py::TestCapFindingsPerFile::test_cap_below_threshold_no_notice` — input: 50 findings, cap=100. Output: 50 unchanged, no notice.
  - `tests/test_engine_cap.py::TestEngineConfig::test_default_config_has_max_findings_per_file_field` — `Config()` constructs without error; the field exists with default `0` (unlimited).
  - `tests/test_engine_cap.py::TestEngineConfig::test_config_parses_max_findings_per_file_from_yaml` — write a temp `.shipguard.yml` with `max_findings_per_file: 250`, load it, assert `config.max_findings_per_file == 250`.
  - `tests/test_engine_cap.py::TestEngineConfig::test_config_template_documents_max_findings_per_file` — `DEFAULT_CONFIG_TEMPLATE` contains a comment showing the cap key.
  - `tests/test_engine_cap.py::TestEngineIntegration::test_scan_applies_cap_to_per_rule_findings` — build a temp dir with a 1000-line `.sql` file containing 1000 PII-004-detectable emails; write a `.shipguard.yml` with `max_findings_per_file: 50`; call `shipguard.engine.scan(tmp_path, config=cfg)`; assert result has 51 findings (50 + 1 notice). The notice's `rule_id` is `PII-004` (the only rule that fired).
  - `tests/test_engine_cap.py::TestEngineIntegration::test_scan_files_applies_cap` — same as above but using the `scan_files(files=[seed], target_dir=tmp_path, config=cfg)` entry point. Confirms both code paths apply the cap uniformly.
  - `tests/test_engine_cap.py::TestEngineIntegration::test_scan_with_default_config_unaffected` — call `scan()` with default config (cap=0) on the same 1000-email file; assert result has 1000 findings. Proves Iteration 1 is byte-identical to v0.5.0 for default-config users.
- GREEN (minimal implementation to pass RED):
  - `Config.max_findings_per_file: int = Field(default=0)` (with `ge=0` validator so negative values are rejected at parse time). Type is `int`, not `Literal`, because the operator may set any non-negative integer.
  - `DEFAULT_CONFIG_TEMPLATE` adds a commented block:
    ```yaml
    # Cap on findings per file (0 = unlimited). Synthesized suppression notice emitted
    # when the cap is hit — never silent truncation.
    # max_findings_per_file: 100
    ```
  - New module-level function in `src/shipguard/engine.py`:
    ```python
    def _cap_findings_per_file(
        findings: list[Finding], cap: int, file_path: Path
    ) -> list[Finding]:
        """Bound `findings` at `cap` per file. Emits suppression notice on overflow."""
    ```
    Implementation: if `cap <= 0` return `findings` unchanged. If `len(findings) <= cap` return unchanged. Otherwise return `findings[:cap] + [suppression_notice]`. The notice groups by `rule_id`, identifies the rule with the most overflow, and references the per-rule count. Notice text format:
    > `"{total - cap} further findings suppressed in this file ({per_rule_count} from {rule_id}, {total} total). Add the path to exclude_paths, or {rule_id} to disable_rules, in .shipguard.yml."`
    Notice uses `Severity.LOW`, `cwe_id="CWE-359"`, `line_number` of last kept finding, `line_content="(suppression notice)"`, `file_path=file_path`.
  - In `scan()`: after `all_findings.sort(...)` (line 334-336) and before the AI-triage block, call `_cap_findings_per_file(all_findings, config.max_findings_per_file, target_dir)`. **Wait — the cap is per-file, not per-scan.** Re-reading the integration test: it builds 1 file with 1000 findings and expects 51. The aggregated `all_findings` list has 1000 entries from 1 file. Capping at 50 + 1 notice = 51. That works on the aggregated list, *if* all findings come from the same file. But if 2 files each emit 600 findings, capping the aggregate at 100 would over-suppress (we'd want 50+1 per file, not 100 total). The right shape: cap inside `_run_parallel_scans` per future, then collect.
  - **Revised design:** change `_run_parallel_scans` to apply the cap per file *before* extending `all_findings`. Concretely: replace the inner `all_findings.extend(future.result())` with `all_findings.extend(_cap_findings_per_file(future.result(), config.max_findings_per_file, f))`. The `f` is the file path captured in the `futures` dict (already available at line 184). This makes the cap per-file, not per-scan, and both `scan()` and `scan_files()` get the right behaviour for free because both call `_run_parallel_scans`.
  - The two integration tests pass without further changes — they each scan a single file, so per-file cap = per-scan cap.
- REFACTOR:
  - "Move `_cap_findings_per_file` next to `_scan_file` and `_run_parallel_scans`" — same module, same file. No actual movement, but a docstring cross-reference from one to the other so the per-file invariant is clear.

**Test pyramid for this iteration:**
- Smoke: `python -c "from shipguard.engine import _cap_findings_per_file"` exits 0 (no import error).
- Unit: 8 tests listed in RED (TestCapFindingsPerFile + TestEngineConfig).
- Integration: 3 tests listed in RED (TestEngineIntegration) — full `_run_parallel_scans` → `_cap_findings_per_file` → result path.
- State machine: N/A — no FSM in this iteration.
- Contract: `test_default_config_has_max_findings_per_file_field`, `test_config_parses_max_findings_per_file_from_yaml`, `test_config_template_documents_max_findings_per_file` — three contract tests on the config surface.
- Regression: `test_scan_with_default_config_unaffected` — proves Iteration 1 doesn't break the v0.5.0 default path.
- Chaos: N/A — no failure injection (engine cap is a deterministic count, not a network/timeout test).
- E2E: N/A — the CLI path is covered by integration tests through `scan()` and `scan_files()`; per-rule CLI tests already exist in `test_cli.py`.
- Performance: N/A — cap is O(n) over the file's findings, no perf budget set elsewhere.
- TDD Parity: 100% — both new public symbols (`Config.max_findings_per_file` field, `_cap_findings_per_file` function) directly tested. No `_`-prefixed helpers introduced.
- Coverage: no `fail_under` gate configured in `pyproject.toml` (confirmed absent in PR #18's pre-merge check). Expected Δ +0.5–0.8%, informational only — do not block on it.

**Acceptance criteria (binary):**
- [ ] `pytest tests/test_engine_cap.py -v` exits 0; all 14 tests pass.
- [ ] `shipguard scan .` on this repo's working tree produces byte-identical output to v0.5.0 (because default cap = 0, no behaviour change for users on default config).
- [ ] `shipguard scan .` on a temp dir with a 1000-email `.sql` file and `.shipguard.yml` with `max_findings_per_file: 50` returns 51 findings (50 + 1 notice).
- [ ] The suppression notice's message contains the true total, names both opt-out mechanisms (`exclude_paths`, `disable_rules`), and uses `Severity.LOW`.
- [ ] `CHANGELOG.md` has a new appended line.

**Estimated effort:** M (half day — engine.py is a 358-line module with three entry points; the per-file cap design choice inside `_run_parallel_scans` is the load-bearing decision)

**Blocked by:** None

---

#### Iteration 2 — Delete the PII-local shim + flip the xfailed test to green

**Goal:** Remove `_cap_findings` and `MAX_FINDINGS_PER_FILE` from `src/shipguard/rules/pii.py`; remove the `_cap_findings()` call from each of the 4 PII rule functions; remove the now-obsolete `TestPiiFindingCap` class from `tests/test_rules_pii.py`; remove the now-obsolete direct unit tests from `tests/test_rules_pii_cap_unit.py`; flip the `xfail` decorator on `test_cap_of_zero_is_unlimited` (it now passes against the engine-level helper).

**Shippable on its own?** Yes — the engine cap is in place from Iteration 1; this iteration is pure deletion + test migration. The PII rules continue to emit findings; the engine caps them at the configured threshold. End-user behaviour with the default config (cap=0) is unchanged.

**Source references:**
- `src/shipguard/rules/pii.py:1-40` — read the constant and helper definitions; delete `MAX_FINDINGS_PER_FILE` and `_cap_findings`.
- `src/shipguard/rules/pii.py:174-181` (PII-001), `pii.py:185-217` (PII-002), `pii.py:240-262` (PII-003), `pii.py:264-296` (PII-004) — read the four rule functions; each has a `return _cap_findings(findings, "PII-XXX", file_path)` at the end. Remove the wrapper, return `findings` directly.
- `tests/test_rules_pii.py:TestPiiFindingCap` (PR #18, lines ~273-301) — read to understand the test class; delete it. Its two tests (`test_pii_004_large_file_capped`, `test_cap_not_triggered_below_threshold`) are migrated to `tests/test_engine_cap.py::TestEngineIntegration` in Iteration 1, with adapted assertions (the rule_id check stays `PII-004`, but the file's `MAX_FINDINGS_PER_FILE` reference is replaced by the config's `max_findings_per_file`).
- `tests/test_rules_pii_cap_unit.py::TestCapFindingsBoundary::test_cap_of_zero_is_unlimited` (PR #20) — read to confirm the xfail decorator. Remove the `@pytest.mark.xfail(...)` line; the test body still asserts the engine-level `0 = unlimited` contract, which is now satisfied by the engine-level helper.
- `tests/test_rules_pii_cap_unit.py::TestCapFindingsNoTrigger`, `TestCapFindingsTriggers`, `TestCapFindingsBoundary::test_cap_of_one_triggers_at_two` (PR #20) — read to confirm. **These tests should also be deleted** — they test the PII-local `_cap_findings` helper, which is being removed. The engine-level cap has its own tests in `tests/test_engine_cap.py::TestCapFindingsPerFile`. Duplicating the contract tests in both files is the wrong shape; the contract is owned by the engine-level test suite.
- `src/shipguard/rules/_common.py` — read to confirm no reference to `_cap_findings` or `MAX_FINDINGS_PER_FILE`; the import was from `pii.py` directly, not via `_common.py`.
- `docs/ADR-pii-detection.md` — read to confirm the cap-mechanism rationale (the original `docs/PLAN-pii-detection.md` was deleted after shipping per the ADR's `Supersedes:` line; the ADR is the surviving decision record). The ADR's section on the cap will need a one-line update ("now lives in engine.py") but that update is informational, not blocking.

**Files touched:**
- `src/shipguard/rules/pii.py` (modified — delete helper + constant, drop wrapper calls from 4 rule functions)
- `tests/test_rules_pii.py` (modified — delete `TestPiiFindingCap` class)
- `tests/test_rules_pii_cap_unit.py` (modified — flip xfail to pass, then delete the now-redundant direct unit tests for the deleted helper; the test file should end with only the `test_cap_of_zero_is_unlimited` test, which now passes)
- `CHANGELOG.md` (modified — append one line)
- `docs/ADR-pii-detection.md` (modified — one-line update: "engine-level cap is now in `src/shipguard/engine.py`; PII-local shim removed in v0.5.1")

**Commit message:**
`refactor(rules): remove PII-local _cap_findings (subsumed by engine-level cap)`

**TDD cycle:**
- RED (failing tests to write first):
  - No new RED tests in this iteration. The TDD cycle is *deletion-driven*: removing code that has existing tests is the RED (tests break first), the deletion is the GREEN, and the test cleanup is the REFACTOR.
  - Pre-flight: run `pytest tests/ -v` and confirm the current state. The 12 passing direct unit tests on `_cap_findings` should pass; the 1 xfailed test should still xfail.
  - Run `pytest tests/test_rules_pii.py::TestPiiFindingCap -v` and confirm both tests pass (this is the RED state we're about to break).
- GREEN (minimal implementation to pass RED — i.e. to make the *deletion* land cleanly):
  - Delete `MAX_FINDINGS_PER_FILE` constant from `pii.py:64`.
  - Delete `_cap_findings` function from `pii.py:118-134`.
  - For each of the 4 PII rule functions, change `return _cap_findings(findings, "PII-XXX", file_path)` to `return findings`.
  - Delete `TestPiiFindingCap` class from `tests/test_rules_pii.py` (both `test_pii_004_large_file_capped` and `test_cap_not_triggered_below_threshold` are now redundant — the engine-level cap tests in `tests/test_engine_cap.py` cover the same mechanism with stronger integration coverage).
  - In `tests/test_rules_pii_cap_unit.py`, **first** remove the `@pytest.mark.xfail(...)` decorator from `test_cap_of_zero_is_unlimited`. **Then** delete the entire `TestCapFindingsNoTrigger`, `TestCapFindingsTriggers`, and `TestCapFindingsBoundary::test_cap_of_one_triggers_at_two` test classes/functions. The file should retain only `test_cap_of_zero_is_unlimited`, which now passes.
  - Update `docs/ADR-pii-detection.md` cap section to point at `engine.py` instead of `pii.py`.
  - Run full suite: 417 → 405 (lose 13 from PR #20's unit tests) + 14 from new engine cap tests = 408 expected. Plus the 2 deleted `TestPiiFindingCap` tests. Final count: 405 + 14 - 2 = 417, or close to it. Verify the count against `pytest tests/ -v` output.
- REFACTOR:
  - "Group the 14 engine cap tests under clearer class names" — `TestCapFindingsPerFile` (10), `TestEngineConfig` (3), `TestEngineIntegration` (3) — already grouped. No refactor needed.
  - "Remove the `from shipguard.rules.pii import MAX_FINDINGS_PER_FILE, _cap_findings` line from any test that imported it" — verify no stale imports.

**Test pyramid for this iteration:**
- Smoke: `python -c "import shipguard.rules.pii; assert not hasattr(shipguard.rules.pii, '_cap_findings')"` exits 0 (helper removed).
- Unit: 1 test remains in `tests/test_rules_pii_cap_unit.py` (`test_cap_of_zero_is_unlimited`); the 13 PII cap tests in `tests/test_rules_pii.py::TestPiiFindingCap` and `tests/test_rules_pii_cap_unit.py` are deleted. Net: -14 unit tests, +1 (the xflipped one). Total: -13 unit tests from this iteration.
- Integration: N/A — the integration tests live in `tests/test_engine_cap.py` (Iteration 1).
- State machine: N/A.
- Contract: N/A.
- Regression: `pytest tests/ -v` must show the *same* 417 total tests (or +1/-1 depending on xfail flip) — proves the deletion didn't silently break an external caller.
- Chaos: N/A.
- E2E: N/A.
- Performance: N/A.
- TDD Parity: 100% — every deletion is matched by a test that was either deleted (no longer needed) or flipped (now passes against the engine helper).
- Coverage: no gate; expected Δ −0.1% (less code, less coverage surface).

**Acceptance criteria (binary):**
- [ ] `pytest tests/ -v` exits 0; 417 pass / 4 skip / 0 xfailed (or 416 pass / 4 skip / 0 xfailed if the xfail removal changes the count by one).
- [ ] `grep -rn "_cap_findings\b" src/shipguard/` returns zero results (helper fully removed from production code).
- [ ] `grep -rn "MAX_FINDINGS_PER_FILE" src/shipguard/` returns zero results.
- [ ] `shipguard scan .` on this repo's working tree produces the *same* findings as Iteration 1 (no behaviour change for default-config users).
- [ ] `shipguard scan <tmp-with-1000-emails> --max-findings-per-file 50` (or the equivalent `.shipguard.yml` form) returns 51 findings (50 + 1 notice) — proves the engine cap is the only cap.
- [ ] `CHANGELOG.md` has a new appended line; no existing lines modified.
- [ ] `docs/ADR-pii-detection.md` cap section updated.

**Estimated effort:** S (<2h — pure deletion + test migration; no design decisions)

**Blocked by:** Iteration 1

---

## 4. Test inventory summary

No `fail_under` coverage gate exists in `pyproject.toml`. The Coverage column is an **expected, informational** delta — never a blocking criterion.

| Iter | Smoke | Unit | Integration | State machine | Contract | Regression | Chaos | E2E | Performance | TDD Parity | Coverage Δ (informational) |
|------|-------|------|-------------|---------------|----------|------------|-------|-----|-------------|------------|------------|
| 1    | 1     | 8    | 3           | 0             | 3        | 1          | 0     | 0   | 0           | 100%       | +0.5–0.8% |
| 2    | 1     | 0    | 0           | 0             | 0        | 1          | 0     | 0   | 0           | 100%       | −0.1% |

Iteration 2's "Unit: 0" is correct: it deletes 14 unit tests and flips 1 xfail → pass. Net unit movement: −14 + 1 = −13. The "Regression: 1" is the full-suite count check.

## 5. End-to-end definition of done

Deduplicated acceptance criteria:
- [ ] `max_findings_per_file` configurable via `.shipguard.yml`; `0` (default) means unlimited.
- [ ] Engine-level cap applies to every rule family, not just PII.
- [ ] Cap emits an explicit suppression notice — never silent truncation. Notice text contains the true total, names both opt-out mechanisms (`exclude_paths`, `disable_rules`), and uses `Severity.LOW`.
- [ ] `src/shipguard/rules/pii.py` has no `_cap_findings` helper, no `MAX_FINDINGS_PER_FILE` constant, and no per-rule cap calls. The 4 PII rule functions return findings directly.
- [ ] `tests/test_rules_pii.py::TestPiiFindingCap` deleted; `tests/test_rules_pii_cap_unit.py` has only `test_cap_of_zero_is_unlimited`, which now passes (not xfailed).
- [ ] `shipguard scan .` on this repo's working tree produces zero new findings under `src/` (dogfood criterion, unchanged from v0.5.0).
- [ ] `pytest tests/ -v` exits 0; the count is 417 ± 1.
- [ ] `CHANGELOG.md` has 2 new appended lines (one per iteration).
- [ ] `docs/ADR-pii-detection.md` updated to point the cap section at `engine.py`.

Demo script (manual, end-to-end):
```bash
mkdir /tmp/cap-smoke
cat > /tmp/cap-smoke/.shipguard.yml <<'EOF'
max_findings_per_file: 50
EOF
# Generate 200 distinct emails in a .sql file
python3 -c "
emails = '\n'.join(f\"INSERT INTO users (email) VALUES ('user{i}@realcompany.io');\" for i in range(200))
open('/tmp/cap-smoke/seed.sql', 'w').write(emails)
"
shipguard scan /tmp/cap-smoke --severity low
```
Expect: 51 findings (50 PII-004 + 1 suppression notice). The notice message contains `"200"`, `"150"` (or whatever the per-rule overflow is), and references both `exclude_paths` and `disable_rules`.

Final green command:
```
pytest tests/test_engine_cap.py tests/test_rules_pii.py tests/test_rule_dispatch.py tests/test_rules_common.py tests/test_rules_secrets.py tests/test_rules_pii_cap_unit.py -v
```
(`tests/test_rules_pii_cap_unit.py` is in the list — only the one surviving test, but include the file for visibility.)

## 6. Out of scope

- **Per-rule or per-file override of the cap.** Considered: per-rule override (`PY-004: max_findings_per_file: 10` in `rule_config`). Rejected: `exclude_paths` already provides per-file opt-out; per-rule override adds config surface for a niche use case. Defer until a real user asks.
- **Engine-level cap on the aggregated total** (across files, not per file). Considered: "no more than 10,000 findings per scan." Rejected: per-file cap is the right granularity (matches the failure mode — dense data in one file). Per-scan cap would silently suppress findings from the *last* files in a scan, which is a worse UX.
- **Async/cancellable scanning.** Separate concern, separate plan.
- **Performance budget for scanning.** The cap bounds *output*, not *scan time*. The regex walk in `pii_004_email` still visits every line; the cap is post-aggregation. A separate perf plan is the right place for that.
- **Migration shim where both caps exist.** Considered: "keep the PII-local cap, add the engine-level cap, deprecate the PII one over a release." Rejected: the whole point of this work is to remove the duplication. A deprecation period is busywork.
- **Renaming `_cap_findings_per_file` to something more discoverable.** Considered. Rejected: the function is private (`_`-prefixed); no public API; renaming is churn.
- **Updating the README to mention the new config key as a top-level feature.** Will happen via the README.md `## Configuration` section update, but the demo is at the DoD step. Not deferred — already in the file-touch list.

## 7. Open questions

None. Every design decision is resolvable from existing repo conventions and is documented inline above.

**Resolved 2026-07-09 — "Why per-file, not per-rule?"** The PII cap was per-rule (one cap call per `pii_XXX` function). The engine cap is per-file (one cap call per file's findings, after all rules have run for that file). The per-file shape is correct because: (a) the failure mode is "one file has 50,000 emails" — the cap's job is to make that file scannable, not to count per-rule; (b) per-rule would silently suppress findings from rules that didn't actually overflow; (c) the suppression notice can name a single rule (the one with the most overflow), keeping the message useful without inventing per-rule notices. The PII plan §6 named the per-file shape; this plan delivers it.

**Resolved 2026-07-09 — "Why is the default `0` and not `100`?"** Two reasons. (a) Backwards compatibility: v0.5.0 users (post-PII-plan) saw `MAX_FINDINGS_PER_FILE = 100` enforced by the PII rules, but that's a recent change and a breaking change at the engine level would be inappropriate without an opt-in. (b) The PII-local cap was always-on; the engine cap should be opt-in via config. Users who want the v0.5.0 PII behaviour set `max_findings_per_file: 100` in their config. Users on default config get the same behaviour they had pre-v0.5.0 (no cap). The repo's own `.shipguard.yml` should add `max_findings_per_file: 100` in this PR to preserve the v0.5.0 dogfood result.

**Resolved 2026-07-09 — "What about the cap during AI triage?"** AI triage (line 246-253 in `scan()`) runs *after* the cap. Two reasons. (a) The cap is a *count*; AI triage is a *judgement*. They serve different purposes. (b) If AI triage could see suppressed findings, the cap would be a no-op for AI-triaged scans. Apply the cap first, then AI triage. This is the order that makes both mechanisms useful.
