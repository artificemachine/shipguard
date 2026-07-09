# ADR — PII detection rule category (`PII-001`..`PII-004`)

**Status:** Implemented. Shipped in `v0.5.0` (PR #18, commit `b9acc36`, 2026-07-09).
**Supersedes:** `docs/PLAN-pii-detection.md` (deleted; its iteration mechanics are spent).
**Why this document exists:** the code shows *what* was decided. Four of these decisions look like oversights in the source and will be re-litigated by anyone who reads `pii.py` without context. This records *why*, and what was considered and rejected.

---

## 1. What was built

A rule category in ShipGuard's plugin rule engine (`src/shipguard/rules/pii.py`) detecting personal data in source and data files, distinct from `secrets.py` (credentials/tokens) and the global git-hook path/username check.

| Rule | Detects | Severity |
|---|---|---|
| `PII-001` | US Social Security Numbers | HIGH |
| `PII-002` | Credit card numbers (Luhn-validated, test-card allowlist) | CRITICAL |
| `PII-003` | NANP phone numbers | LOW |
| `PII-004` | Email addresses | MEDIUM |

Shared helpers `_skip_false_positive` and `_make_finding` live in `src/shipguard/rules/_common.py`, imported by both `secrets.py` and `pii.py`.

---

## 2. Decision: `PII-002` (card) is CRITICAL, `PII-001` (SSN) is HIGH

**This looks inverted on harm, and it is.** A credit card number is revocable: the holder calls the bank, the number dies within a day, and regulation caps their liability. A Social Security Number is irrevocable — it cannot be rotated, it is the root identity credential, and a leak enables tax, credit, and benefits fraud for years. A harm-first model would set SSN=CRITICAL and card=HIGH.

**The pairing stands anyway.** A SAST tool's severity scale serves two audiences, and neither is the data subject: compliance auditors expect PCI-DSS 3.4 findings to read CRITICAL, and developers treat CRITICAL as drop-everything while HIGH may be batched. PCI violations carry immediate contractual and regulatory consequences that SSN exposure (absent HIPAA scope) may not.

This was argued explicitly and settled against the plan author, who had proposed SSN=CRITICAL. Do not reopen without new evidence about **who consumes these findings**.

---

## 3. Decision: `.csv` and `.log` are deliberately absent from `PII_EXTS`

**This is not an oversight.** Both are bulk-data formats where PII is the *expected* content, not an accident. A scanner that flags every row of a 50,000-row customer export is simultaneously correct and useless: the findings are all true positives, the pre-commit hook floods the terminal, and the operator's rational response is to disable `PII-004` wholesale rather than exclude one path. The documented opt-outs (`disable_rules`, `exclude_paths`) do not help on first contact — the operator sees the flood *before* learning the opt-out exists.

`.log` files are also usually gitignored, so the detector rarely sees them regardless.

**Re-adding them reopens a settled question.** Excluding them is what demotes `MAX_FINDINGS_PER_FILE` from a load-bearing tuning parameter to a safety net (see §4). If `.csv`/`.log` come back, the cap value must be *measured*, not guessed, and the engine-level cap in §5 should land first.

---

## 4. Decision: `MAX_FINDINGS_PER_FILE = 100` is a safety net, not a tuned value

`.sql` dumps and `.json` seed/fixture data remain in `PII_EXTS` and can legitimately hold hundreds of addresses. `_cap_findings` bounds worst-case *output* for those: past 100 findings it emits the first 100 plus one synthesized notice naming the true total and both opt-out mechanisms.

**Never truncate silently.** The suppression notice is mandatory. A cap that hides what it dropped reads as "clean scan" when it isn't.

The number 100 was never profiled against a real file. With `.csv`/`.log` excluded (§3) it no longer needs to be: on a realistic `.sql` fixture any value from roughly 50 to 500 produces identical operator experience. The tests assert the cap *mechanism*, not the number.

---

## 5. Decision: no AI-triage on PII findings — and the naive version is a trap

`ai.py::AITriage.evaluate` is **not** called from any PII rule. Two separate claims, both load-bearing:

1. **The existing triage asks the wrong question.** It reasons about code *reachability*. That is meaningless for a data-content finding: a hardcoded SSN is exploitable regardless of whether the containing function is ever called. Calling `AITriage.evaluate()` on a PII finding today fires the reachability prompt and will **silently mark real PII as a false positive whenever it lands in dead code.**

2. **The right question has an inverted error asymmetry.** The useful triage for PII is "is this synthetic test data or a real person's?" That is a legitimate LLM judgement and the highest-value thing AI could contribute here. But it needs a different prompt schema and a different `diskcache` key structure — it is not the current interface. And its failure mode is worse: a false negative (real PII classified synthetic, silently dropped) is far more dangerous than a false positive from the detector (synthetic data reported, human dismisses it in seconds).

Deferred until observed `PII-003`/`PII-004` false-positive rates justify the risk. Until then: report everything, let the deterministic allowlists suppress.

---

## 6. Decision: `_common.py` is a standalone module, not inlined into `secrets.py`

**This is the decision most at risk of being silently undone.** A future contributor seeing a ~50-line `_common.py` with two consumers may reasonably decide to inline it back. Don't.

`_make_finding` and `_skip_false_positive` existed only in `secrets.py`. `pii.py` needs both. The extraction shipped as its own commit (`refactor(rules): extract shared rule helpers to _common.py`) rather than bundled into the `PII-001` feature commit, so that a bad SSN regex could be reverted without dragging unrelated structural work with it.

The extraction is behaviour-preserving: helpers moved verbatim, `secrets.py` re-exports both names (`# noqa: F401`) because `tests/test_rules_secrets.py` imports `_skip_false_positive` directly. The entire pre-existing `test_rules_secrets.py` suite is the behaviour-preservation gate and passes **unedited**.

`_common.py` imports only `shipguard.models`. It must never import `shipguard.rules.__init__` — that creates a cycle.

---

## 7. Out of scope (considered, rejected, with reasons)

- **Physical/mailing address detection** — regex-based address matching has an unacceptable false-positive rate (matches version strings, changelogs, comments). Needs NER/ML; out of scope for a pattern-matching engine.
- **Passport / driver's-license numbers** — formats vary too widely by country and state to pattern-match reliably. Revisit only for a specific named jurisdiction.
- **PII detection in `.md`/`.txt`/prose docs** — author bios, contact pages, and READMEs legitimately contain names and emails. Would need an explicitly opt-in extension list.
- **`.csv` / `.log`** — see §3.
- **Generic engine-level `max-findings-per-file`** — landed in v0.5.1 as the proper fix for the flood risk. Now lives in `shipguard.engine._cap_findings_per_file` + `Config.max_findings_per_file`, applying to every rule category. The PII-local `_cap_findings` and `MAX_FINDINGS_PER_FILE` were deleted in v0.5.1; their regression tests (`TestPiiFindingCap`, the 12 direct unit tests in `tests/test_rules_pii_cap_unit.py`) were also removed. The xfailed boundary test `test_cap_of_zero_is_unlimited` (PR #20) was the migration contract — it now passes against the engine-level helper. Issue #19 closed.

  **Suppression-notice severity choice:** the v0.5.0 PII-local cap emitted its suppression notice at `Severity.LOW`, which is below the default `MEDIUM` severity threshold — making the notice invisible to users on default config. A scan that capped at 100 PII findings showed only 100 with no indication of the 900 suppressed. The v0.5.1 engine-level cap uses `Severity.MEDIUM` for the notice, so it survives the default threshold filter. The severity choice was a mid-implementation decision (the original `PLAN-engine-cap.md` specified `LOW`; the integration test surfaced the invisibility bug, and the cap was promoted to `MEDIUM`). See `CHANGELOG.md` §"Retroactive notes" for the full reproduction and history.
- **AI-triage** — see §5.
- **Rust-core parity** — `secrets.py` has an optional Rust-accelerated path for its 3 hottest rules. PII rules stay pure-Python given lower expected match volume per scan.
- **A new ignore-file mechanism** — `disable_rules` / `exclude_paths` in `.shipguard.yml` already cover repo-level opt-out.

---

## 8. Provenance and confidence

Reviewed twice before implementation.

**First pass (single reviewer)** established the `_common.py` extraction, corrected `PLACEHOLDER_PHONES` (verified empirically: `555-555-5555` and `800-555-1212` both match the `PII-003` regex and both fall *outside* the reserved 555-0100–555-0199 fictional range, so neither was skipped without an explicit entry), and added a dogfood self-scan criterion. It rejected one claim: that the SSN regex lets `901-45-6789` through. It does not — the branch is `9\d{2}`, covering the entire 9XX area range. Verified against the compiled pattern: `000`, `666`, `900`, `901`, `999` area numbers and `00` group / `0000` serial all correctly rejected.

**Second pass** was a three-round, two-agent discussion (`claude-code` = claude-sonnet-4-6; `opencode` = deepseek-v4-flash). **No consensus.** Both agents ended `partial`.

Two results matter:

- **The flood risk (§3, §4) was surfaced independently by both agents in round 1, blind**, on a plan that had already survived one review pass which missed it. This is the single most load-bearing result in the record.
- **On `_common.py` (§6) the agents deadlocked, then swapped sides in round 3.** `claude-code` reversed to "keep it bundled" on the grounds that a standalone `_common.py` has "zero consumers at commit time." In the same round, `opencode` explicitly *withdrew* that exact claim as factually wrong: `secrets.py` imports from `_common.py` from commit zero. So one agent capitulated to an argument the other had just retracted. The operator overrode the round-3 majority and kept the split, because a majority resting on a withdrawn premise is not evidence.

**Confidence caveat.** Two LLMs agreeing is weak evidence, and one shared a model family with the plan's author. Round 3 demonstrates the failure mode directly: mutual capitulation rather than convergence on the artifact. Sample size: one discussion, four points, two agents, three rounds. Full transcripts preserved in the `superharness` repo under `docs/discussions/pii-detection-review/`, alongside the audit of the tooling defects found while running it.
