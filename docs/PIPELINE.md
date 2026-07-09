# 7-Layer Unified Security Pipeline

A comprehensive security strategy requires defense at all layers. This document explains the 7-layer security model and how ShipGuard fits into it.

## The 7 Layers

### **Layer 1: Dependencies** (Supply Chain Integrity)
**Purpose:** Detect vulnerable or compromised dependencies before they reach production.

**Tools & Techniques:**
- `pip-audit` — scans Python dependencies for known vulnerabilities
- `npm audit` / `pnpm audit` — scans JavaScript/Node.js dependencies
- `osv-scanner` — checks Open Source Vulnerabilities (OSV) database
- Dependency locking — lock files (requirements.txt, package-lock.json, pnpm-lock.yaml)

**ShipGuard Coverage:** None (use external tools)

---

### **Layer 2: Secrets Management** (Credential Exposure Prevention)
**Purpose:** Prevent hardcoded credentials, API keys, and tokens from being committed to version control.

**Tools & Techniques:**
- `gitleaks` — detects secrets in Git history
- `shipguard` (SEC rules) — detects hardcoded cloud/API credentials and token patterns
- `.env` file auditing — ensures sensitive files are gitignored
- Pre-commit hooks — block commits with credential patterns

**ShipGuard Coverage:** SEC-001 to SEC-010 (cloud/API credentials and token patterns), PII-001 to PII-004 (SSN, credit card, phone, email — personal data patterns)

---

### **Layer 3: SAST (Static Application Security Testing)**
**Purpose:** Find vulnerabilities in code before runtime without executing it.

**Tools & Techniques:**
- Language-specific linters (bandit for Python, ESLint for JavaScript)
- Vulnerability pattern matching (path traversal, command injection, etc.)
- Type checking and static analysis
- Custom rules for organization-specific patterns

**ShipGuard Coverage:** 34 rules across Shell, Python, JavaScript, GitHub Actions, and Config files
- SHELL-001 to SHELL-009
- PY-001 to PY-009
- JS-001 to JS-008
- GHA-001 to GHA-005
- CFG-001 to CFG-003

---

### **Layer 4: AI Reasoning** (Semantic Analysis & Context)
**Purpose:** Use AI/LLM to understand code semantics, intent, and higher-level security issues that pattern matching misses.

**Tools & Techniques:**
- Claude or other LLMs for code review
- Context-aware vulnerability detection
- Business logic analysis
- Architecture and design pattern assessment

**ShipGuard Coverage:** None (manual, for human review process)

---

### **Layer 5: DAST (Dynamic Application Security Testing)**
**Purpose:** Find vulnerabilities by testing the running application.

**Tools & Techniques:**
- OWASP ZAP — automated web security scanner
- Burp Suite — interactive testing and scanning
- API fuzzing and endpoint testing
- Authentication and session management testing

**ShipGuard Coverage:** None (requires running application)

---

### **Layer 6: Supply Chain Integrity** (Build & Deployment)
**Purpose:** Ensure that build artifacts, container images, and deployments haven't been tampered with or use pinned/trusted versions.

**Tools & Techniques:**
- Unpinned dependency detection (bare package names, :latest tags)
- Lockfile integrity verification
- Artifact signing and verification
- Container image scanning
- SBOM (Software Bill of Materials) generation

**ShipGuard Coverage:** SC-001 to SC-004 (Docker pinning, dependency pinning, lockfile safety, .gitignore secret baseline)

---

### **Layer 7: Observability & Incident Response** (Runtime & Monitoring)
**Purpose:** Detect and respond to security incidents in production.

**Tools & Techniques:**
- Security logging and audit trails
- Real-time alerting and monitoring
- SIEM (Security Information and Event Management)
- Incident response playbooks
- Post-incident analysis

**ShipGuard Coverage:** None (runtime/deployment phase)

---

## ShipGuard's Position

ShipGuard is a **Layer 3 SAST tool** with **complementary coverage** of Layers 2 and 6:

| Layer | Coverage | Rules |
|-------|----------|-------|
| L1 (Dependencies) | External tools only | — |
| L2 (Secrets) | Partial (10 secret/token patterns) | SEC-001..SEC-010 |
| L3 (SAST) | **PRIMARY** (34 patterns) | SHELL, PY, JS, GHA, CFG |
| L4 (AI Reasoning) | External (manual review) | — |
| L5 (DAST) | External tools only | — |
| L6 (Supply Chain) | Partial (4 checks) | SC-001..SC-004 |
| L7 (Observability) | External (deployment) | — |

---

## Quick Start: Running All 7 Layers Locally

### 1. Layer 1: Check Dependency Vulnerabilities
```bash
pip-audit  # Python dependencies
npm audit  # Node.js dependencies
```

### 2. Layer 2: Detect Secrets
```bash
gitleaks detect --source=local --verbose
shipguard scan --severity critical  # Focus on secrets rules
```

### 3. Layer 3: Run Full SAST
```bash
shipguard scan  # All rules, all files
```

### 4. Layer 4: Manual AI Review
Use Claude or other LLM for architectural and business logic review.

### 5. Layer 5: DAST
Only applicable if application is running:
```bash
# Example: OWASP ZAP baseline scan
docker run -t owasp/zap2docker-stable zap-baseline.py -t http://localhost:8000
```

### 6. Layer 6: Supply Chain Checks
```bash
shipguard scan --include-rules SC-001,SC-002,SC-003,SC-004
# Also verify lockfiles are present and up-to-date
```

### 7. Layer 7: Observability Setup
Configure logging, monitoring, and alerting for your deployment (application-specific).

---

## CI/CD Integration

Use `.github/workflows/security.yml` to automate all 7 layers in GitHub Actions.

Each layer runs as a separate job:
- **L1:** `pip-audit` job
- **L2:** `gitleaks` job + `shipguard` (secrets rules)
- **L3:** `shipguard` job (full SAST)
- **L4:** Comment reminding of manual review
- **L5:** Conditional ZAP scan (if `PREVIEW_URL` is set)
- **L6:** Lockfile verification + `shipguard` (supply chain rules)
- **L7:** Comment with observability setup reminder

---

## Extending ShipGuard

To add custom rules beyond the 48 built-in patterns:

1. Create a new Python file in your rule directory:
   ```python
   from shipguard.models import Finding, Severity
   from shipguard.rules import register

   @register(
       id="CUSTOM-001",
       name="my-security-check",
       severity=Severity.HIGH,
       description="...",
       extensions=[".py"],
       cwe_id="CWE-XXXX",
   )
   def my_check(file_path, content, config=None):
       # Return list[Finding]
       ...
   ```

2. Register the directory in `.shipguard.yml`:
   ```yaml
   custom_rules_dirs:
     - ./custom_rules/
   ```

3. Run: `shipguard scan --include-rules CUSTOM-001`

---

## Further Reading

- See `docs/7_LAYER_SECURITY_MODEL.md` for detailed framework explanation
- See `docs/7_LAYER_SECURITY_MODEL.html` for interactive dashboard
- See `README.md` for ShipGuard rule reference
- Review `.github/workflows/security.yml` for complete CI/CD pipeline
- Review `Makefile` for local execution targets
