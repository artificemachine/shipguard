# ShipGuard Project Guidelines for Claude Code

## Project Description

**ShipGuard** is a Python-based SAST (Static Application Security Testing) tool that implements a unified 7-layer security framework. It scans repositories for 60 security vulnerability patterns across Shell scripts, Python, JavaScript/TypeScript, GitHub Actions workflows, and configuration files.

**Version:** 0.4.2
**License:** Apache 2.0

**Key Features:**
- 60 built-in security rules across 7 layers
- Layer 3 (SAST): 34 core rules (Python ×12, Shell ×9, JS ×8, Config ×5, GHA ×5 — includes CWE + SOC2/PCI/HIPAA compliance tags)
- Layer 2 (Secrets): 15 credential/token detection rules (AWS, GCP, GitHub, Stripe, OpenAI, Anthropic, Slack, npm, HuggingFace, Azure, Twilio, SendGrid, Datadog, JWT)
- Layer 6 (Supply Chain): 6 integrity checks (Docker pinning, dep pinning, lockfile, .gitignore, cosign, SBOM)
- **Rust secrets scanner** (`rust/shipguard-secrets/`) — high-performance secrets scanning with Python parity tests
- **External tool integrations** — ShellCheck, Semgrep, TruffleHog, Trivy (via `src/shipguard/integrations/`)
- **MCP server** (`shipguard-mcp`) — exposes scan tools to AI agents via the Model Context Protocol
- **AI false-positive reduction** (`ai.py`) — LLM-backed triage via litellm with diskcache caching
- **Auto-remediation engine** (`fixer.py`) — generates and applies code patches via LLMs
- **Semantic analysis engine** (`semantic.py`) — tree-sitter AST analysis for deeper rule matching
- **Database layer** (`db.py`) — persistent state for scan history and findings
- CLI tool for scanning repositories (`shipguard scan`, `shipguard scan-staged`)
- SARIF output for GitHub Security tab integration
- Pre-commit hook integration (full scan + staged-only)
- GitHub Action integration
- Multiple output formats: terminal, JSON, markdown, SARIF
- Per-rule configuration via `.shipguard.yml`
- Entry point plugin system (`shipguard.rules` entry points for third-party rules)

**Technology Stack:**
- Python 3.10+, Rust (secrets scanner crate)
- Typer (CLI framework), Rich (terminal formatting)
- PyYAML, Pydantic (config/data handling)
- tree-sitter, tree-sitter-python, tree-sitter-javascript (semantic AST analysis)
- litellm, diskcache (AI false-positive reduction and auto-remediation)
- mcp (MCP server integration via FastMCP)
- pytest + hypothesis (testing)
- Hatchling (build system)

---

## Build Commands

```bash
# Install in editable/development mode (recommended)
pip install -e ".[dev]"

# Build the package (wheel)
hatch build
# or
python -m build

# Run as module
python -m shipguard scan .

# Run MCP server (for AI agent integration)
shipguard-mcp

# Build Rust secrets crate
cd rust/shipguard-secrets && cargo build --release

# Clean build artifacts
rm -rf build/ dist/ *.egg-info __pycache__
```

---

## Test Commands

**Run all tests:**
```bash
pytest tests/ -v
```

**Run specific test file:**
```bash
pytest tests/test_cli.py -v
pytest tests/test_rules_secrets.py -v
pytest tests/test_rules_supply_chain.py -v
pytest tests/test_formatters_sarif.py -v
pytest tests/test_rust_secrets.py -v
```

**Run with coverage:**
```bash
pytest tests/ --cov=src/shipguard --cov-report=html
```

**Run integration tests (require external tools installed):**
```bash
pytest tests/test_integrations_shellcheck.py -v
pytest tests/test_integrations_semgrep.py -v
pytest tests/test_integrations_trivy.py -v
pytest tests/test_integrations_trufflehog.py -v
```

**Run property-based and mutation tests (gated by env var):**
```bash
pytest tests/test_property_based.py -v -m property
pytest tests/test_mutation_harness.py -v -m mutation
```

**Run performance regression tests:**
```bash
pytest tests/test_performance_regression.py -v -m performance
```

**Run a specific test:**
```bash
pytest tests/test_cli.py::TestScanCommand::test_scan_finds_vulnerabilities -v
```

**Run tests matching a pattern:**
```bash
pytest tests/ -k "secrets" -v
```

---

## Project Structure

```
shipguard/
├── src/shipguard/                    # Main package
│   ├── __init__.py
│   ├── __main__.py                 # python -m shipguard entrypoint
│   ├── cli.py                      # CLI entry point (Typer app)
│   ├── engine.py                   # Scan engine logic
│   ├── models.py                   # Data models (Finding, Severity, ScanResult)
│   ├── config.py                   # Configuration handling
│   ├── rust_secrets.py             # Python bridge to Rust secrets scanner
│   ├── ai.py                       # AI false-positive reduction (litellm + diskcache)
│   ├── db.py                       # Persistent scan history / findings store
│   ├── fixer.py                    # Auto-remediation: LLM-generated code patches
│   ├── mcp_server.py               # MCP server (FastMCP) — agent-facing scan tools
│   ├── semantic.py                 # Semantic AST analysis via tree-sitter
│   ├── rules/                      # Security rules
│   │   ├── __init__.py             # Rule registry and loader
│   │   ├── config.py               # CFG rules (×5)
│   │   ├── github_actions.py       # GHA rules (×5)
│   │   ├── javascript.py           # JS rules (×8)
│   │   ├── python.py               # PY rules (×12)
│   │   ├── shell.py                # SHELL rules (×9)
│   │   ├── secrets.py              # SEC rules (×15)
│   │   └── supply_chain.py         # SC rules (×6)
│   ├── formatters/                 # Output formatters
│   │   ├── __init__.py
│   │   ├── terminal.py
│   │   ├── json_fmt.py
│   │   ├── markdown.py
│   │   └── sarif.py                # SARIF output (GitHub Security tab)
│   └── integrations/               # External tool wrappers
│       ├── __init__.py
│       ├── shellcheck.py
│       ├── semgrep.py
│       ├── trivy.py
│       └── trufflehog.py
├── rust/                           # Rust components
│   └── shipguard-secrets/          # High-performance secrets scanning crate
│       ├── Cargo.toml
│       ├── Cargo.lock
│       └── src/
├── tests/                          # Test suite (36 files)
│   ├── conftest.py
│   ├── test_cli.py
│   ├── test_cli_contract.py
│   ├── test_engine.py
│   ├── test_engine_extra.py
│   ├── test_action_security.py
│   ├── test_concurrency.py
│   ├── test_config_compatibility.py
│   ├── test_config_extra.py
│   ├── test_fixer.py
│   ├── test_formatters_extra.py
│   ├── test_formatters_sarif.py
│   ├── test_golden_snapshots.py
│   ├── test_integration_minirepo.py
│   ├── test_integrations_semgrep.py
│   ├── test_integrations_shellcheck.py
│   ├── test_integrations_trivy.py
│   ├── test_integrations_trufflehog.py
│   ├── test_models_extra.py
│   ├── test_mutation_harness.py
│   ├── test_parser_robustness.py
│   ├── test_performance_regression.py
│   ├── test_property_based.py
│   ├── test_rule_dispatch.py
│   ├── test_rules_config.py
│   ├── test_rules_github_actions.py
│   ├── test_rules_javascript.py
│   ├── test_rules_python.py
│   ├── test_rules_registry_extra.py
│   ├── test_rules_secrets.py
│   ├── test_rules_shell.py
│   ├── test_rules_supply_chain.py
│   ├── test_rust_python_parity.py
│   ├── test_rust_secrets.py
│   ├── test_scan_staged.py
│   └── fixtures/                   # Test data (intentionally vulnerable)
│       ├── shell/, python/, javascript/
│       ├── github_actions/, config/
│       ├── secrets/, supply_chain/
│       └── snapshots/
├── .github/workflows/
│   ├── test.yml                    # CI — pytest
│   ├── security.yml                # Security scan gate
│   ├── layer4_ai.yml               # AI security layer
│   ├── publish.yml                 # PyPI publish
│   └── release.yml                 # Release automation
├── docs/
│   ├── 7_LAYER_SECURITY_MODEL.md
│   ├── 7_LAYER_SECURITY_MODEL.html
│   └── PIPELINE.md
├── .pre-commit-hooks.yaml
├── .pre-commit-config.yaml.template
├── action.yml                      # GitHub Action definition
├── Dockerfile                      # Container image for shipguard
├── docker-compose.staging.yml      # Staging environment compose config
├── scripts/
│   └── go_live_staging.sh          # Staging deployment script
├── pyproject.toml
├── Makefile
├── CONTRIBUTING.md
├── SECURITY.md
└── CLAUDE.md                       # (THIS FILE)
```

---

## Development Conventions

### Code Style
- Follow PEP 8 for Python code
- Use type hints where applicable
- Use dataclasses for data structures
- Use descriptive variable and function names

### Rule Development
All security rules follow this pattern:

```python
from shipguard.models import Finding, Severity
from shipguard.rules import register

@register(
    id="CATEGORY-###",
    name="rule-short-name",
    severity=Severity.HIGH,
    description="What this rule detects",
    extensions=[".py"],
    cwe_id="CWE-XXX"
)
def rule_function(file_path: Path, content: str, config=None) -> list[Finding]:
    findings = []
    # Detection logic here
    return findings
```

**Rules must:**
- Return a list of `Finding` objects
- Handle edge cases (comments, false positives)
- Include fix hints in findings
- Map to relevant CWE IDs
- Support multiple file extensions where applicable

### Testing Conventions
- One test file per rule module (e.g., `test_rules_secrets.py`)
- Organize tests in classes by rule ID
- Include fixtures for vulnerable and safe examples
- Test normal cases, edge cases, and false positives
- Use descriptive test names: `test_{rule_id}_{what_it_tests}`
- Property-based tests go in `test_property_based.py` (hypothesis)
- Rust/Python parity tests go in `test_rust_python_parity.py`

---

## Common Development Tasks

### Add a New Security Rule

1. **Choose a category** (shell.py, python.py, javascript.py, github_actions.py, config.py, secrets.py, or supply_chain.py)
2. **Implement the rule** using the @register decorator
3. **Create test fixtures** in `tests/fixtures/{category}/vulnerable.{ext}` and `tests/fixtures/{category}/safe.{ext}`
4. **Write tests** in `tests/test_rules_{category}.py`
5. **Update the rule count** in `tests/test_cli.py` (test_list_rules_json)
6. **Update README.md** with the new rule in the rules table
7. **Run tests** to ensure everything passes:
   ```bash
   pytest tests/test_rules_{category}.py -v
   pytest tests/test_cli.py::TestListRulesCommand -v
   ```

### Run the Full Security Pipeline Locally

```bash
make security         # Runs L1, L2, L3, L6
make security-strict  # Blocking ShipGuard gate (fails on high+ findings)
make security-l3      # Full SAST scan
make help             # See all available targets
```

### Test a Specific Vulnerability

```bash
# Scan just the fixtures
shipguard scan tests/fixtures/

# Scan with SARIF output (for GitHub Security tab)
shipguard scan . --format sarif --output results.sarif

# Scan with JSON output
shipguard scan tests/fixtures/ --format json

# Filter by severity
shipguard scan tests/fixtures/ --severity critical

# Scan only staged files (pre-commit mode)
shipguard scan-staged
```

### Check Rule Count

```bash
shipguard list-rules --format json | python -c "import json,sys; print(len(json.load(sys.stdin)))"
# Expected: 60
```

---

## Important Rules

### Before Committing

1. **Run tests**: `pytest tests/ -v` — All tests must pass
2. **Check syntax**: `python -m compileall src/shipguard`
3. **Review rule counts**: rule count must match test expectations (currently 60)
4. **Verify no hardcoded secrets**: `grep -r "password\|api_key\|secret" src/ | grep -v "test\|example"`
5. **Update documentation** if adding/changing rules

### Security Exceptions for Test Fixtures

⚠️ **Important:** This is a security scanner tool. Test fixtures intentionally contain vulnerable code to verify ShipGuard detects security issues correctly.

**Test fixtures contain:**
- Unsafe `eval()` statements (PY-003)
- Insecure YAML loading (PY-002)
- Path traversal vulnerabilities (PY-001, PY-004)
- Unsafe shell `eval` (SHELL-001)
- Unsafe eval in JavaScript (JS-001)
- Untrusted data in GitHub Actions (GHA-001)
- Placeholder secrets/keys for secret detection testing (SEC rules)

**These are EXPECTED and necessary:**
- Located in `tests/fixtures/` — clearly marked as test data
- Used to verify ShipGuard detection works correctly
- Should NOT be fixed or removed
- The `tests/fixtures/secrets/safe.yml` placeholder key is a false-positive already resolved on GitHub

**During /ship pipeline:**
- ShipGuard will report vulnerabilities in `tests/fixtures/`
- This is expected behavior — proceed with commit
- Production code in `src/shipguard/` must remain clean

### No Destructive Operations

- Never delete rules (only deprecate if necessary)
- Never change existing rule IDs
- Never modify `Severity` enum values
- Never change `Finding` or `ScanResult` field names
- Never use absolute paths (use relative or environment variables)
- Never hardcode usernames or personal paths

---

## Troubleshooting

### "Module not found" errors
```bash
source .venv/bin/activate
pip install -e ".[dev]"
```

### Tests fail with import errors
```bash
pip install -e . --force-reinstall
```

### Rule changes not reflecting
```bash
find . -type d -name __pycache__ -exec rm -rf {} +
pip install -e .
```

### Rust crate build fails
```bash
cd rust/shipguard-secrets
cargo clean && cargo build --release
```

### Integration tests skipped (external tool missing)
```bash
# Install required tools
brew install shellcheck semgrep
# Trivy and TruffleHog via their install scripts (see docs/)
```

---

## References

- **Main Project**: [ShipGuard on GitHub](https://github.com/artificemachine/shipguard)
- **7-Layer Framework**: See `docs/7_LAYER_SECURITY_MODEL.md`
- **Pipeline Guide**: See `docs/PIPELINE.md`
- **User Guide**: See `README.md`
- **Contributing**: See `CONTRIBUTING.md`
- **Security Policy**: See `SECURITY.md`
- **Typer Docs**: https://typer.tiangolo.com/
- **CWE List**: https://cwe.mitre.org/

---

**Last Updated:** 2026-06-03
**Version:** 0.4.2
**Maintained By:** DevOpsCelstn

## Strict Installation Decoupling

Once installed (e.g., to ~/.local/bin), the project binary must NEVER depend on the local repository path for execution, configuration, or data. All paths must be relative to the installation root or use standard system config paths (~/.config).
