"""JavaScript security rules (JS-001 through JS-008)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register

JS_EXTS = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]


@register(
    id="JS-001",
    name="eval-usage",
    severity=Severity.CRITICAL,
    description="Detects eval() usage in JavaScript/TypeScript production code",
    extensions=JS_EXTS,
    cwe_id="CWE-95",
    compliance_tags=["SOC2-CC6.1"],
)
def js_001_eval(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    # Negative lookbehind excludes a dotted method call (model.eval(),
    # range.eval(), etc.) — not the global eval() function and cannot
    # execute arbitrary code the way eval() can.
    pattern = re.compile(r"(?<!\.)\beval\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="JS-001",
                    severity=Severity.CRITICAL,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="eval() executes arbitrary code and should not be used",
                    cwe_id="CWE-95",
                    fix_hint="Use JSON.parse() for data or Function() constructor if unavoidable",
                )
            )
    return findings


@register(
    id="JS-002",
    name="path-traversal-no-check",
    severity=Severity.HIGH,
    description="Detects path.join() without path containment verification",
    extensions=JS_EXTS,
    cwe_id="CWE-22",
    compliance_tags=["SOC2-CC6.1"],
)
def js_002_path_traversal(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    join_pattern = re.compile(r"\bpath\.join\s*\(")
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if join_pattern.search(line):
            # Check surrounding 5 lines for a startsWith or includes check
            start = max(0, i - 3)
            end = min(len(lines), i + 5)
            context = "\n".join(lines[start:end])
            if not re.search(r"\.startsWith\s*\(|\.includes\s*\(|\.normalize\s*\(|realpath", context):
                findings.append(
                    Finding(
                        rule_id="JS-002",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="path.join() without containment check allows path traversal",
                        cwe_id="CWE-22",
                        fix_hint="Verify result.startsWith(baseDir) after path.resolve()",
                    )
                )
    return findings


@register(
    id="JS-003",
    name="symlink-following",
    severity=Severity.HIGH,
    description="Detects fs.readdirSync/readdir without symlink checking",
    extensions=JS_EXTS,
    cwe_id="CWE-59",
    compliance_tags=["SOC2-CC6.1"],
)
def js_003_symlink_following(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    readdir_pattern = re.compile(r"\bfs\.(?:readdirSync|readdir)\s*\(")
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if readdir_pattern.search(line):
            # Check if isSymbolicLink is checked within 15 lines after
            start = i - 1
            end = min(len(lines), i + 15)
            context = "\n".join(lines[start:end])
            if "isSymbolicLink" not in context and "lstat" not in context:
                findings.append(
                    Finding(
                        rule_id="JS-003",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Directory traversal without symlink check may follow malicious symlinks",
                        cwe_id="CWE-59",
                        fix_hint="Check entry.isSymbolicLink() and skip or resolve symlinks",
                    )
                )
    return findings


@register(
    id="JS-004",
    name="prototype-pollution",
    severity=Severity.HIGH,
    description="Detects deep merge operations without __proto__ protection",
    extensions=JS_EXTS,
    cwe_id="CWE-1321",
    compliance_tags=["SOC2-CC6.1"],
)
def js_004_prototype_pollution(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    # Detect custom deep merge functions or Object.assign with an empty
    # target. Object/array spread ({...a, ...b}) is intentionally NOT
    # matched here: spread copies own enumerable properties via
    # CopyDataProperties -> [[DefineOwnProperty]], which does not invoke
    # Object.prototype's inherited __proto__ setter the way Object.assign's
    # [[Set]] semantics can — it is not the same vulnerability class as a
    # hand-rolled recursive deep-merge function.
    merge_pattern = re.compile(
        r"""(?:function\s+(?:deep[Mm]erge|merge[Dd]eep|extend)|"""
        r"""Object\.assign\s*\(\s*\{\s*\})"""
    )
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if merge_pattern.search(line):
            # Check for __proto__ guard
            start = max(0, i - 3)
            end = min(len(lines), i + 10)
            context = "\n".join(lines[start:end])
            if "__proto__" not in context and "hasOwnProperty" not in context:
                findings.append(
                    Finding(
                        rule_id="JS-004",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Deep merge without __proto__/__constructor__ guard enables prototype pollution",
                        cwe_id="CWE-1321",
                        fix_hint="Filter out __proto__, constructor, and prototype keys during merge",
                    )
                )
    return findings


@register(
    id="JS-005",
    name="regex-dos",
    severity=Severity.MEDIUM,
    description="Detects regex patterns susceptible to catastrophic backtracking (ReDoS)",
    extensions=JS_EXTS,
    cwe_id="CWE-1333",
    compliance_tags=["SOC2-CC6.1"],
)
def js_005_regex_dos(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    # Patterns with nested quantifiers: (a+)+ , (a*)*,  (a|b+)+ etc.
    regex_def = re.compile(r"""(?:new\s+RegExp\s*\(\s*['"]|/)(.*?)(?:['"]\s*\)|/[gimsuy]*)""")
    nested_quantifier = re.compile(r"""[\+\*]\s*\)[\+\*\{]|[\+\*]\s*\}[\+\*\{]""")

    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for m in regex_def.finditer(line):
            regex_body = m.group(1)
            if nested_quantifier.search(regex_body):
                findings.append(
                    Finding(
                        rule_id="JS-005",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Regex with nested quantifiers is vulnerable to ReDoS",
                        cwe_id="CWE-1333",
                        fix_hint="Rewrite regex to avoid nested quantifiers or use a ReDoS-safe library",
                    )
                )
    return findings


@register(
    id="JS-006",
    name="xss-innerhtml",
    severity=Severity.MEDIUM,
    description="Detects innerHTML or dangerouslySetInnerHTML with dynamic content",
    extensions=JS_EXTS,
    cwe_id="CWE-79",
    compliance_tags=["SOC2-CC6.1"],
)
def js_006_xss_innerhtml(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        re.compile(r"\.innerHTML\s*=\s*(?!['\"]\s*['\"]\s*;)"),
        re.compile(r"dangerouslySetInnerHTML\s*=\s*\{"),
    ]
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        for pat in patterns:
            if pat.search(line):
                findings.append(
                    Finding(
                        rule_id="JS-006",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Setting innerHTML with dynamic content enables XSS attacks",
                        cwe_id="CWE-79",
                        fix_hint="Use textContent or a sanitization library (e.g., DOMPurify)",
                    )
                )
                break
    return findings


@register(
    id="JS-007",
    name="no-csp-header",
    severity=Severity.LOW,
    description="Detects missing Content-Security-Policy in Express/Fastify apps",
    extensions=JS_EXTS,
    cwe_id="CWE-1021",
    compliance_tags=["SOC2-CC6.1"],
)
def js_007_no_csp(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    # Check if this is an Express/Fastify app
    has_server = bool(
        re.search(r"""require\s*\(\s*['"](?:express|fastify)['"]|from\s+['"](?:express|fastify)['"]""", content)
    )
    if not has_server:
        return findings

    has_csp = bool(re.search(r"content-security-policy|helmet|csp", content, re.IGNORECASE))
    if not has_csp:
        # Report on the line with express/fastify import
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(r"""['"](?:express|fastify)['"]""", line):
                findings.append(
                    Finding(
                        rule_id="JS-007",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="Express/Fastify app without Content-Security-Policy header",
                        cwe_id="CWE-1021",
                        fix_hint="Use helmet middleware: app.use(helmet()) to set security headers",
                    )
                )
                break
    return findings


@register(
    id="JS-008",
    name="console-log-secrets",
    severity=Severity.LOW,
    description="Detects console.log with variables named secret/token/key/password",
    extensions=JS_EXTS,
    cwe_id="CWE-532",
    compliance_tags=["SOC2-CC6.1"],
)
def js_008_console_secrets(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(
        r"\bconsole\.(?:log|info|debug|warn|error)\s*\([^)]*\b(?:secret|token|key|password|apiKey|api_key|credential)\b",
        re.IGNORECASE,
    )
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="JS-008",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="Logging sensitive variable may expose secrets in logs",
                    cwe_id="CWE-532",
                    fix_hint="Remove console.log of sensitive data or use structured logging with redaction",
                )
            )
    return findings
