# shipguard

## Identity
You are working for the project owner. Ship > plan.

## What This Is
**ShipGuard** is a SAST (static application security testing) tool with a 7-layer unified security framework. Scans source code for 60 built-in vulnerability patterns across Shell, Python, JavaScript/TypeScript, GitHub Actions, and config files.

Key features:
- **Tree-sitter semantic engine** — AST-based analysis for Python/JS, reducing false positives
- **AI Triage (Layer 4)** — LiteLLM-powered false-positive evaluation (Claude 3.5, GPT-4o)
- **Auto-Remediation** — LLM-powered fix generation via `AutoFixer`
- **MCP-native** — `shipguard-mcp` exposes scan/fix tools for AI agents
- **Rust accelerators** — optional `shipguard-secrets` binary, `shipguard-core` PyO3 native module
- **External integrations** — ShellCheck, Semgrep, TruffleHog, Trivy
- **SARIF output** for GitHub Security tab
- **Compliance tagging** — CWE IDs with SOC2/PCI/HIPAA tags

**Version:** 0.4.2 | **License:** Apache 2.0

## Tech Stack

| Layer | Tech |
|-------|------|
| **Language** | Python 3.10+ (primary), Rust (optional accelerators) |
| **CLI** | Typer |
| **Terminal** | Rich |
| **Parsing** | Tree-sitter (Python, JS grammars) |
| **AI** | LiteLLM (Anthropic, OpenAI) |
| **Config** | PyYAML, Pydantic v2 |
| **MCP** | FastMCP |
| **Persistence** | SQLite3, diskcache (AI cache) |
| **Build** | Hatchling |
| **Testing** | pytest, pytest-cov, hypothesis (property-based) |

## Architecture

```
src/shipguard/
├── cli.py           # Typer CLI: scan, fix, list-rules, init, scan-staged
├── engine.py        # Core engine: file discovery, parallel scan, AI triage, DB sync
├── models.py        # Finding, Severity enum (CRITICAL/HIGH/MEDIUM/LOW), ScanResult
├── ai.py            # AITriage: LLM false-positive eval (LiteLLM + diskcache)
├── semantic.py      # SemanticEngine: Tree-sitter AST, GlobalIndex for symbol tracking
├── fixer.py         # AutoFixer: LLM vulnerability remediation
├── mcp_server.py    # FastMCP: shipguard_scan, shipguard_fix tools
├── db.py            # SQLite persistence: finding status tracking
├── rules/           # 60 built-in rules (Python, Shell, JS, GHA, Config, Secrets, Supply Chain)
├── formatters/      # Terminal (Rich), JSON, Markdown, SARIF, Agent-optimized
└── integrations/    # ShellCheck, Semgrep, TruffleHog, Trivy wrappers

rust/
├── shipguard-secrets/  # Rust binary: regex-based SEC-001/002/003 scanning
└── shipguard-core/     # Rust native lib (PyO3): parallel .gitignore-aware file discovery

tests/fixtures/      # INTENTIONALLY VULNERABLE CODE — NEVER FIX
```

## CLI Commands

```bash
shipguard scan .                                    # Scan current dir
shipguard scan . --ai-triage                        # With AI false-positive reduction
shipguard scan . --format json                      # JSON output
shipguard scan . --severity critical                # Filter by severity
shipguard scan . --include-rules PY-003,SEC-001     # Specific rules
shipguard scan . --rust-secrets                     # Use Rust accelerator
shipguard scan . --with-external                    # Also run ShellCheck/Semgrep/Trivy
shipguard scan-staged .                             # Git-staged files only
shipguard fix --id PY-007 --apply                   # Auto-fix a finding
shipguard list-rules                                # List 60 rules
shipguard init                                      # Create config template
shipguard-mcp                                       # Start MCP server
```

## How to Run / Test

```bash
pip install -e ".[dev]"
shipguard scan .
shipguard-mcp                                       # For AI agent use

# Tests
pytest tests/ -v
pytest tests/ --cov=src/shipguard --cov-report=html
pytest tests/ -k "secrets" -v
pytest tests/test_property_based.py -v -m property  # Gated
pytest tests/test_performance_regression.py -v -m performance  # Gated

# Rust (optional)
cd rust/shipguard-secrets && cargo build --release
cd rust/shipguard-core && cargo build --release
```

## Strict Constraints

1. **Test fixtures contain intentional vulnerabilities.** `tests/fixtures/` has real-looking unsafe code (`eval()`, hardcoded tokens). **Never fix or remove.** The project excludes `tests/**` in `.shipguard.yml`.

2. **Rule IDs are immutable.** Never change existing rule IDs, `Severity` enum values, or `Finding`/`ScanResult` field names.

3. **Rule count is exactly 60.** Adding/removing rules requires updating `test_list_rules_json` in `test_cli.py`.

4. **Exit code semantics.** Exit 0 = no findings; exit 1 = findings detected (CI gating).

5. **AI features need API keys.** Triage + fixer require `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`. `MOCK_AI_FIXER` env for testing without API.

6. **Rust components partially disabled.** `shipguard-core` PyO3 library is commented out in engine.py ("temporarily disabled for stabilization"). `shipguard-secrets` binary needs build and `SHIPGUARD_RUST_SECRETS_BIN` env.

7. **Tree-sitter limited to Python + JS.** Shell, GHA, and config rules rely on regex/line-based scanning only.

8. **Inline suppression:** `# shipguard:ignore RULE-ID` and `// shipguard:ignore RULE-ID,RULE-ID` supported.

9. **Integration tests need external tools.** ShellCheck, Semgrep, Trivy, TruffleHog must be installed separately.

10. **Config file naming.** `.shipguard.yml`, `.shipguard.yaml`, or `shipguard.yml` in scan target.

## CHANGELOG Policy

`CHANGELOG.md` is append-only. Never edit, reorder, or delete existing lines. Add new entries at EOF only.
