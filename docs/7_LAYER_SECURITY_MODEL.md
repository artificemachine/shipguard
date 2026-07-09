# 7-Layer Unified Security Model

A comprehensive approach to application security requires defense at every stage of the software development lifecycle (SDLC). This document outlines the 7-layer unified security framework that ensures complete coverage across dependencies, code, build, and runtime.

---

## Overview: The 7 Layers

The 7-layer security model segments security activities across the SDLC:

| Layer | Focus | Stage | Primary Tools |
|-------|-------|-------|---|
| **1. Dependencies** | Vulnerable libraries | Package selection | pip-audit, npm audit, osv-scanner |
| **2. Secrets** | Credential exposure | Code commit | gitleaks, shipguard, pre-commit hooks |
| **3. SAST** | Code vulnerabilities | Development | Linters, pattern matching (shipguard) |
| **4. AI Reasoning** | Semantic/business logic | Code review | LLMs, human architects |
| **5. DAST** | Runtime vulnerabilities | Testing/Pre-prod | OWASP ZAP, Burp Suite, fuzzing |
| **6. Supply Chain** | Build integrity | CI/CD | Pinned images, lockfile checks |
| **7. Observability** | Production incidents | Runtime | Logging, monitoring, alerting, SIEM |

---

## Layer 1: Dependencies

**Goal:** Prevent the use of vulnerable or malicious third-party libraries.

### Vulnerabilities Addressed:
- Known CVEs in dependencies
- Compromised packages or typosquatting
- Outdated libraries with unpatched security flaws

### Implementation:
```bash
# Python: Check for known CVEs
pip-audit --desc

# JavaScript/Node.js: Check npm packages
npm audit
pnpm audit

# Universal: Check against OSV database
osv-scanner --lockfile=package-lock.json
```

### Best Practices:
- Pin dependency versions (don't use `*` or `latest`)
- Regularly update and audit dependencies
- Use Software Bill of Materials (SBOM) to track all dependencies
- Establish a process for responding to CVE disclosures
- Use dependency lock files (package-lock.json, pnpm-lock.yaml, etc.)

---

## Layer 2: Secrets Management

**Goal:** Prevent hardcoded credentials, API keys, and tokens from entering version control.

### Vulnerabilities Addressed:
- Exposed AWS/GCP/Azure credentials
- GitHub tokens and personal access tokens
- Database passwords and connection strings
- API keys and secrets
- Hardcoded personal data (SSN, credit card, phone, email — see PII-001+)

### Implementation:

**A. Pre-commit Detection:**
```bash
gitleaks detect --source=local --verbose
```

**B. Pattern Scanning:**
Use tools like `shipguard` to scan for common secret patterns:
- AWS Access Key IDs (AKIA*)
- GCP API Keys (AIza*)
- GitHub Personal Access Tokens (ghp_*, gho_*, etc.)

**C. Configuration Auditing:**
Scan `.env`, `.yml`, JSON configs for secret-like values.

### Best Practices:
- **Never commit secrets** — always use environment variables or secret managers
- Use `.env.example` templates (with placeholder values)
- Enable secret scanning on GitHub (or equivalent)
- Rotate compromised secrets immediately
- Audit `.gitignore` to ensure secrets files are excluded
- Use pre-commit hooks to block secrets before commit

---

## Layer 3: SAST (Static Application Security Testing)

**Goal:** Find code vulnerabilities without executing the application.

### Vulnerability Categories:

**Command Injection:**
- Unsafe `eval()`, `exec()`, `os.system()`
- Unquoted variable expansion in bash
- String interpolation in command contexts

**Path Traversal:**
- Insufficient path validation
- Directory traversal with `..` sequences
- Symlink following without checks

**Injection Attacks:**
- SQL injection via string formatting
- Shell command injection
- XXE (XML External Entity)
- YAML unsafe deserialization

**Cryptography & Secrets:**
- Hardcoded API keys or secrets
- Weak cryptographic functions
- Improper random number generation

**Other Patterns:**
- Unsafe pickle deserialization
- Missing temporary file cleanup
- Prototype pollution (JavaScript)
- Regex denial of service (ReDoS)

### Implementation:

**ShipGuard provides 48 built-in rules:**
- 9 Shell script checks (SHELL-001 to SHELL-009)
- 9 Python checks (PY-001 to PY-009)
- 8 JavaScript checks (JS-001 to JS-008)
- 5 GitHub Actions checks (GHA-001 to GHA-005)
- 3 Configuration checks (CFG-001 to CFG-003)
- 10 Secrets checks (SEC-001 to SEC-010)
- 4 Supply chain checks (SC-001 to SC-004)

```bash
shipguard scan .  # Run all rules
shipguard scan . --severity critical  # Run critical rules only
```

### Best Practices:
- Run SAST in pre-commit hooks
- Integrate into CI/CD pipeline
- Review findings thoroughly (avoid dismissing as false positives)
- Use multiple SAST tools to catch edge cases
- Keep patterns/rules updated as new vulnerabilities emerge

---

## Layer 4: AI Reasoning

**Goal:** Apply semantic understanding and architectural knowledge to find vulnerabilities that pattern matching misses.

### Capabilities:
- **Architectural Review:** Identify design flaws that enable vulnerabilities
- **Business Logic Analysis:** Understand intent and catch authorization bypasses
- **Context-Aware Detection:** Consider surrounding code to reduce false positives
- **Complex Flows:** Trace data flow across multiple files
- **Compliance & Best Practices:** Ensure adherence to standards (OWASP, CWE, etc.)

### Implementation:

**Manual Process:**
1. Have a security-minded architect or engineer review code
2. Use an LLM (e.g., Claude) to analyze code for vulnerabilities
3. Focus on high-risk areas: authentication, authorization, payment processing, data handling

**Example Prompt for LLM:**
```
Review this code for security vulnerabilities:
- Authentication/authorization bypasses
- SQL injection opportunities
- Cross-site scripting (XSS) vulnerabilities
- Race conditions
- Data leaks or privacy issues

[CODE SNIPPET]
```

### Best Practices:
- Conduct code reviews on all changes
- Security review is mandatory for high-risk code
- Involve security experts in design decisions
- Use threat modeling before implementation
- Document security decisions and assumptions

---

## Layer 5: DAST (Dynamic Application Security Testing)

**Goal:** Find runtime vulnerabilities by testing the running application.

### Vulnerability Categories:
- Authentication/Session Management flaws
- Broken Access Control
- Injection (SQL, command, LDAP, etc.)
- Insecure Deserialization
- Broken Cryptography
- API security issues
- Security Misconfiguration

### Implementation:

**Automated Scanning (OWASP ZAP):**
```bash
docker run -t owasp/zap2docker-stable \
  zap-baseline.py -t http://localhost:3000
```

**Manual Testing:**
- Test authentication mechanisms
- Attempt unauthorized access
- Fuzz inputs to API endpoints
- Test file upload functionality
- Check for sensitive data exposure

### Best Practices:
- Run DAST in staging/pre-prod, not production
- Use a non-destructive baseline scan first
- Combine automated and manual testing
- Test both happy paths and error conditions
- Cover API endpoints, web interfaces, and file handling

---

## Layer 6: Supply Chain Integrity

**Goal:** Ensure build artifacts, containers, and dependencies are trustworthy and properly pinned.

### Vulnerabilities Addressed:
- Unpinned base images (`:latest` tag)
- Unpinned dependencies (bare package names)
- Unsafe installation practices (`npm install` without `--frozen-lockfile`)
- Compromised or tampered artifacts

### Implementation:

**A. Docker Image Pinning:**
```dockerfile
# ❌ BAD: Uses unpredictable base image
FROM python:latest

# ✅ GOOD: Pinned to specific version
FROM python:3.12-slim-bookworm
```

**B. Dependency Pinning:**
```
# ❌ BAD: No version pin
requests
flask

# ✅ GOOD: Explicit versions
requests==2.31.0
flask==3.0.0
```

**C. Lockfile Integrity:**
```bash
# ❌ BAD: May install newer versions
npm install

# ✅ GOOD: Uses exact versions from lockfile
npm install --frozen-lockfile
npm ci  # Clean install in CI/CD
```

### ShipGuard Rules:
- **SC-001:** Docker images with `:latest` tag
- **SC-002:** Python dependencies without version pins
- **SC-003:** npm/pnpm install without `--frozen-lockfile` or `--ci`
- **SC-004:** Missing baseline secret file patterns in `.gitignore`

```bash
shipguard scan . --include-rules SC-001,SC-002,SC-003,SC-004
```

### Best Practices:
- Always pin dependency versions
- Use immutable artifact tags
- Verify artifact checksums/signatures
- Maintain accurate SBOMs
- Regularly audit and update pinned versions
- Use artifact scanning tools to detect vulnerabilities in images

---

## Layer 7: Observability & Incident Response

**Goal:** Detect and respond to security incidents in production.

### Components:

**Logging:**
- Capture security-relevant events (login attempts, API calls, permission changes)
- Include timestamps, user info, and request details
- Ensure logs are tamper-proof and regularly backed up

**Monitoring & Alerting:**
- Real-time alerts for suspicious activity
- Threshold-based alerts (e.g., multiple failed logins)
- Anomaly detection

**SIEM (Security Information and Event Management):**
- Centralized log aggregation and analysis
- Correlation of events across systems
- Automated response to known attack patterns

**Incident Response:**
- Document security incidents
- Post-incident review and remediation
- Communication plan for security breaches

### Implementation:

**Example Alert Rules:**
- Multiple failed authentication attempts
- Unusual API access patterns
- Large data exports
- Permission elevations
- Infrastructure changes

### Best Practices:
- Establish a Security Operations Center (SOC)
- Create runbooks for common incident types
- Regularly test incident response procedures
- Track metrics: MTTR (Mean Time To Respond), MTTR (Mean Time To Remediate)
- Post-incident: Learn and update preventative controls

---

## Integration: The Complete Pipeline

```
┌─────────────┐
│ Code Commit │
└────┬────────┘
     │ Pre-commit hooks (Layer 2, 3)
     ├─ gitleaks (L2: secrets)
     ├─ shipguard scan (L2 & L3: secrets & SAST)
     ↓
┌─────────────┐
│ Code Review │
└────┬────────┘
     │ Layer 4: AI Reasoning + human review
     ↓
┌─────────────┐
│ CI/CD Build │
└────┬────────┘
     │ Layer 1: pip-audit, npm audit (dependencies)
     │ Layer 3: Full SAST scan
     │ Layer 6: Supply chain checks
     ├─ Dockerfile :latest detection
     ├─ Unpinned dependencies
     ├─ Lockfile verification
     ↓
┌──────────────┐
│ Testing/Staging
└────┬─────────┘
     │ Layer 5: DAST, fuzzing, penetration testing
     ↓
┌──────────────┐
│ Production Deploy
└────┬─────────┘
     │ Layer 6: Verify artifacts, checksums
     ├─ Container image scanning
     ├─ Artifact verification
     ↓
┌─────────────────────┐
│ Production Monitoring
└──────────────────────┘
     Layer 7: Logging, alerting, incident response
```

---

## Maturity Levels

### Level 0: No Security
- No tooling, no process, reactive responses only

### Level 1: Basic (Layer 1)
- Dependency auditing with tools like `npm audit` or `pip-audit`
- Manual vulnerability tracking

### Level 2: Code Security (Layers 1, 2, 3)
- SAST scanning integrated into CI
- Pre-commit hooks for secrets
- Dependency auditing automated

### Level 3: Comprehensive (Layers 1-6)
- All L1-L6 tools integrated and automated
- Code review with security focus
- Supply chain controls in place

### Level 4: Advanced (Layers 1-7)
- DAST and penetration testing
- Mature incident response program
- 24/7 security monitoring
- Threat modeling for new features

---

## Tools & Resources

### Layer 1 (Dependencies):
- pip-audit, npm audit, osv-scanner, Snyk

### Layer 2 (Secrets):
- gitleaks, TruffleHog, detect-secrets, shipguard

### Layer 3 (SAST):
- ShipGuard, Bandit (Python), ESLint (JavaScript), ShellCheck (Shell)

### Layer 4 (AI Reasoning):
- Claude, GPT-4, Codeium, GitHub Copilot

### Layer 5 (DAST):
- OWASP ZAP, Burp Suite, Acunetix, Rapid7 InsightVM

### Layer 6 (Supply Chain):
- Sigstore (artifact signing), Cosign (container verification)
- Dependabot, Renovate (dependency updates)

### Layer 7 (Observability):
- ELK Stack, Splunk, Datadog, New Relic, Grafana
- PagerDuty, Opsgenie (alerting)

---

## Conclusion

The 7-layer model ensures **defense in depth** across the entire SDLC. No single tool or layer is sufficient; all 7 must work together to create a truly secure development pipeline. Start with Layers 1-3 and 6 (which ShipGuard directly supports), and progressively add Layers 4-5 and 7 as your security maturity grows.
