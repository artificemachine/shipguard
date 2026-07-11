# ShipGuard: The AI-Native Security Sentinel

ShipGuard is an intelligent security sentinel designed to protect your repository from vulnerabilities through semantic analysis and AI reasoning. It moves beyond simple pattern matching by using **Tree-sitter** to understand the "intent" of your code, virtually eliminating false positives. With its built-in **Layer 4 AI Triage**, it automatically determines if a vulnerability is reachable or just dead code. The integrated **Auto-Remediation** engine can autonomously generate and apply secure code patches to fix findings on the fly. As an **MCP-native** tool, it serves as a security sense-organ for AI agents like Claude and Cursor, providing a high-performance **Rust core** for instantaneous workspace audits.

## 🚀 The Sentinel Experience

### 📺 Demo
Run `shipguard scan --ai-triage` to see the Sentinel reason about your code in real-time. Watch as it dismisses safely handled patterns and focuses only on exploitable risks.

### 🧙 Wizard (Getting Started)
To initialize the Sentinel in your project, simply run:
```bash
shipguard init
```
This wizard will guide you through setting up your `.shipguard.yml` and configuring AI triage for your specific tech stack.

## Install

### From PyPI

```bash
python -m pip install shipguard
```

### Recommended: Using pipx (CLI tool)

```bash
pipx install shipguard
```

This installs ShipGuard in an isolated environment with global command access.

### From source (development)

```bash
git clone https://github.com/artificemachine/shipguard.git
cd shipguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### In a project (virtual environment)

```bash
python3 -m venv .venv && source .venv/bin/activate && pip install shipguard
```

### Install from GitHub (correct URL syntax)

```bash
pip install "git+https://github.com/artificemachine/shipguard.git"
```

You can pin to a branch/tag/commit:

```bash
pip install "git+https://github.com/artificemachine/shipguard.git@v0.5.2"
```

After install:

```bash
shipguard --version
shipguard scan .
```

Verify you are using the expected binary:

```bash
which shipguard
shipguard scan --help
```

If you open a new shell later:

```bash
source .venv/bin/activate && shipguard --version
```

## Quick Start

```bash
# Scan current directory with AI Triage
shipguard scan . --ai-triage

# Automatically fix a finding
shipguard fix --id PY-007 --apply

# Start MCP server for AI agents
shipguard-mcp

# Scan another repository by absolute path
shipguard scan /path/to/target-repo

# Scan with JSON output (for CI pipelines)
shipguard scan . --format json

# Scan another repository and save JSON report
shipguard scan /path/to/target-repo --format json --output /tmp/target-repo-shipguard.json

# Optional: enable Rust-accelerated secrets scanning
shipguard scan . --rust-secrets

# Only show critical and high findings
shipguard scan . --severity high

# Generate markdown report (for PR comments)
shipguard scan . --format markdown --output report.md

# List all 60 rules with descriptions
shipguard list-rules

# Include only selected rules
shipguard scan . --include-rules PY-003,SEC-001

# Create a config file
shipguard init
```

### Sample Terminal Output

```
ShipGuard Scan Results
──────────────────────────────────────────────────────
  Files scanned : 42      Rules applied : 60
  Findings      : 3       Files skipped : 0
  Duration      : 0.21s
──────────────────────────────────────────────────────

 CRITICAL  src/deploy.sh:14
           Rule  : SHELL-001  eval-injection
           CWE   : CWE-94
           Code  : eval $(get_user_input)
           Fix   : Avoid eval; use arrays or direct execution instead

 HIGH      scripts/build.py:37
           Rule  : SHELL-009  shell-true-subprocess
           CWE   : CWE-78
           Code  :     result = subprocess.run(cmd, shell=True)
           Fix   : Use shell=False with a list of arguments instead

 MEDIUM    .gitignore:1
           Rule  : SC-004  missing-gitignore-secret-entries
           CWE   : CWE-312
           Fix   : Add the following to .gitignore: *.key, *.pem, *.p12
──────────────────────────────────────────────────────
Exit code 1 (findings detected)
```

## Development Staging Bootstrap (Maintainers Only)

> **Note:** This section is for ShipGuard maintainers running the full go-live pipeline. Regular users do not need Docker or staging to use ShipGuard.

Use the helper script to create a local staging target for `/golive`/`/infra-probe` verification:

```bash
# Start local staging and wait for health
./scripts/go_live_staging.sh up

# Show status
./scripts/go_live_staging.sh status

# Tear down cleanly
./scripts/go_live_staging.sh down
```

This workflow uses `docker-compose.staging.yml` and `.env.staging` (auto-copied from `.env.staging.example` if missing).

### Release Rollback Runbook

Rollback trigger criteria:

- New `critical` or `high` finding in post-release scan
- PyPI installation failure for latest tag
- CLI regression in critical path (`shipguard scan`, `shipguard list-rules`)

Rollback steps:

1. Stop promotion and notify the on-call release owner.
2. Repoint users to the previous stable release tag in release notes.
3. Cut a patch release from `main` with the fix and rerun:
   - `pytest tests -q`
   - `shipguard scan . --format terminal`
4. Publish patched tag using `.github/workflows/release.yml`.

Ownership:

- Primary: repository maintainers listed in `SECURITY.md`
- Escalation: GitHub issue with `release-blocker` label and incident summary


## 7-Layer Security Pipeline

ShipGuard implements a **unified security model** across all 7 layers of the software development lifecycle:

| Layer | Focus | ShipGuard Capability | External Tools |
|-------|-------|---------------|---|
| **L1: Dependencies** | Vulnerable packages | — | pip-audit, npm audit, osv-scanner |
| **L2: Secrets** | Credential exposure | SEC-001–010 (10) | gitleaks, detect-secrets |
| **L3: SAST** | Code vulnerabilities | **Semantic Engine (Tree-sitter)** | ShellCheck, Bandit, ESLint |
| **L4: AI Reasoning** | Autonomous Triage | **Layer 4 AI Triage (--ai-triage)** | LiteLLM, Claude 3.5, GPT-4o |
| **L5: DAST** | Runtime vulnerabilities | — | OWASP ZAP, Burp Suite |
| **L6: Supply Chain** | Build integrity | SC-001–004 (4) | Sigstore, Cosign |
| **L7: Observability** | Production monitoring | **SQLite Persistence Layer** | SIEM, Datadog, PagerDuty |

**See [docs/PIPELINE.md](./docs/PIPELINE.md) for complete framework details.**

---

## Rules (64 total)

| Category | Layer | Count | IDs | Examples |
|----------|-------|-------|-----|----------|
| Shell | L3 | 9 | SHELL-001–009 | eval injection, unquoted vars, bash -c interpolation |
| Python | L3 | 12 | PY-001–012 | zip slip, yaml.load, eval/exec, SQL injection, temp files |
| JavaScript | L3 | 12 | JS-001–012 | eval, path traversal, prototype pollution, XSS, dangerous methods |
| GitHub Actions | L3 | 5 | GHA-001–005 | workflow injection, unpinned actions, secrets in logs |
| Config | L3 | 3 | CFG-001–003 | auto-approve, committed .env, permissive CORS |
| **Secrets** | **L2** | **15** | **SEC-001–015** | **Cloud/API tokens and other hardcoded secret patterns** |
| **PII** | **L2** | **4** | **PII-001–004** | **Personal data (SSN, credit card, phone, email) hardcoded in source/data files** |
| **Supply Chain** | **L6** | **4** | **SC-001–004** | **Docker :latest, unpinned deps, npm lockfiles, missing .gitignore entries** |

Run `shipguard list-rules` or `shipguard list-rules --format json` for full details.

---

## Quick Start: Complete Security Pipeline

Run the full 7-layer pipeline locally:

```bash
# Install optional dependencies
pip install pip-audit bandit shellcheck-py

# Run all layers (1, 2, 3, 6 local; others require additional setup)
make security

# Run strict blocking gate (fails on high+ findings)
make security-strict

# Or run individual layers
make security-l1   # Dependencies
make security-l2   # Secrets
make security-l3   # SAST
make security-l6   # Supply Chain

# For CI/CD, use GitHub Actions workflow
# See .github/workflows/security.yml
```

---

## Configuration

Create `.shipguard.yml` in your project root (or run `shipguard init`):

```yaml
# Minimum severity to report: critical, high, medium, low
severity_threshold: medium

# Enable AI-driven false positive reduction by default
ai_triage: true

# Glob patterns for paths to exclude
exclude_paths:
  - "vendor/**"
  - "node_modules/**"
  - "**/fixtures/**"

# Rule IDs to disable
disable_rules:
  - SHELL-008

# Additional directories containing custom rule modules
custom_rules_dirs: []
```

CLI flags override config file values.

### Optional Rust Acceleration (Secrets)

ShipGuard can offload `SEC-001`, `SEC-002`, and `SEC-003` scanning to a Rust binary while keeping the rest of the scanner in Python.

Build the optional binary:

```bash
cd rust/shipguard-secrets
cargo build --release
```

Then either:

```bash
export SHIPGUARD_RUST_SECRETS_BIN="$PWD/target/release/shipguard-secrets"
shipguard scan . --rust-secrets
```

Or place `shipguard-secrets` in your `PATH`.

## Inline Suppression

Suppress a finding on a specific line:

```python
eval(expr)  # shipguard:ignore PY-003
```

Or on the line above:

```python
# shipguard:ignore PY-003
eval(expr)
```

Multiple rules can be suppressed:

```bash
eval $cmd  # shipguard:ignore SHELL-001, SHELL-002
```

## Output Formats

- **terminal** (default) — Rich color-coded table with severity highlighting and fix hints
- **json** — Machine-readable `{"findings": [...], "summary": {...}}` for CI integration
- **markdown** — Report grouped by severity level, suitable for PR comments
- **agent** — Token-optimized output for AI agent consumption (Claude/Gemini)

## CI Integration

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/artificemachine/shipguard
    rev: v0.5.2
    hooks:
      - id: shipguard
```

### GitHub Action

```yaml
- uses: artificemachine/shipguard@v0.5.2
  with:
    severity: medium
    format: terminal
```

### Generic CI

```bash
pip install shipguard
shipguard scan . --severity high --format json
# Exit code 1 if findings exist, 0 if clean
```

## Release Runbook (PyPI Trusted Publishing)

Use this checklist for each release:

1. Prepare version + changelog
- Update package version and append the release notes in `CHANGELOG.md`.

2. Confirm GitHub workflow + environment
- Workflow file: `.github/workflows/publish.yml`
- Required workflow name: `publish.yml`
- Required job environment: `pypi`
- Workflow publishes on tag pushes matching `v*`.

3. Configure PyPI trusted publisher (one-time or when repo changes)
- URL: `https://pypi.org/manage/project/shipguard/settings/publishing/`
- Owner: `newblacc`
- Repository: `shipguard`
- Workflow: `publish.yml`
- Environment: `pypi`

4. Create and push release tag
```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

5. If publish failed before OIDC setup
- Open GitHub Actions and re-run the failed `publish.yml` run for the same tag after trusted publisher configuration is saved.

6. Post-publish smoke test
```bash
python -m pip install -U shipguard
shipguard --version
shipguard scan . --severity high
```

7. Verify release
- Confirm the new version is visible on PyPI and installable in a clean environment.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings at or above the severity threshold |
| 1 | One or more findings detected |

## Suppression Comments

Both `#` and `//` comment styles are supported:

```python
# Python / Shell
eval(expr)  # shipguard:ignore PY-003
```

```javascript
// JavaScript
eval(code);  // shipguard:ignore JS-001
```

```bash
# Shell
eval $cmd  # shipguard:ignore SHELL-001
```

Suppress multiple rules:
```bash
eval $cmd  # shipguard:ignore SHELL-001, SHELL-002
```

## About This Project

ShipGuard implements a **7-layer unified security framework** integrated into a single SAST tool. It was developed to package 60 security vulnerability patterns discovered during real-world audits of the [spec-kit](https://github.com/celstnblacc/spec-kit) and [superpowers](https://github.com/celstnblacc/superpowers) projects.

ShipGuard provides:
- **Layer 3 (SAST)**: 48 rules across command injection, path traversal, code injection, and configuration issues
- **Layer 2 (Secrets)**: 15 rules detecting cloud/API credentials and token patterns
- **Layer 6 (Supply Chain)**: 4 rules checking Docker image pinning, dependency pinning, and `.gitignore` secret baselines
- **Layer 4 (AI Reasoning)**: Autonomous triage and reachability analysis using LiteLLM
- **Integration**: GitHub Actions workflow, pre-commit hooks, MCP server for AI agents

**See [docs/7_LAYER_SECURITY_MODEL.md](./docs/7_LAYER_SECURITY_MODEL.md) for the complete security framework.**

The rules focus on:
- **Command injection**: eval, exec, bash -c, sed, printf with unquoted variables
- **Path traversal**: Unvalidated path.join(), symlink following
- **Code/data injection**: YAML unsafe load, pickle, SQL string formatting
- **Secrets**: AWS/GCP keys, GitHub tokens, hardcoded credentials
- **Supply chain**: Docker :latest tags, unpinned dependencies, npm lockfile verification
- **Configuration**: Committed .env files, overly permissive CORS, auto-approve settings

## Troubleshooting

### "Module not found" errors

If you get import errors, ensure you're in the correct environment:

```bash
# For pipx installations
pipx list  # Should show shipguard

# For venv installations
source .venv/bin/activate
which shipguard  # Should show venv path
```

### Pre-commit hook not running

Ensure `.pre-commit-hooks.yaml` is in the correct location and hooks are configured:

```bash
pre-commit install
pre-commit run --all-files  # Test manually
```

## Development

To contribute or modify rules:

```bash
git clone https://github.com/artificemachine/shipguard.git
cd shipguard
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Test the CLI
shipguard scan tests/fixtures/
```

New rules should be added to `src/shipguard/rules/` with the `@register` decorator:

```python
from shipguard.models import Finding, Severity
from shipguard.rules import register

@register(
    id="RULE-001",
    name="rule-description",
    severity=Severity.HIGH,
    description="What this rule detects",
    extensions=[".py"],
    cwe_id="CWE-123"
)
def rule_001_check(file_path, content, config=None, **kwargs):
    findings = []
    # Detection logic here
    # Use kwargs.get("tree") for Tree-sitter AST if available
    return findings
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
