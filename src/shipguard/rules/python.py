"""Python security rules (PY-001 through PY-012)."""

from __future__ import annotations

import re
from pathlib import Path

from shipguard.models import Finding, Severity
from shipguard.rules import register

PY_EXTS = [".py"]


@register(
    id="PY-001",
    name="zip-path-traversal",
    severity=Severity.CRITICAL,
    description="Detects zipfile.extractall() without member path validation (zip slip)",
    extensions=PY_EXTS,
    cwe_id="CWE-22",
    compliance_tags=["SOC2-CC6.1", "PCI-6.5.1"],
)
def py_001_zip_traversal(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\.extractall\s*\(")
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line) and "zipfile" in content.lower():
            # Check if there's member validation nearby (within 10 lines before)
            start = max(0, i - 11)
            context = "\n".join(lines[start : i - 1])
            if not re.search(r"\.namelist\(\)|\.infolist\(\)|os\.path\..*\.\.", context):
                findings.append(
                    Finding(
                        rule_id="PY-001",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="zipfile.extractall() without path validation enables zip slip attacks",
                        cwe_id="CWE-22",
                        fix_hint="Validate each member name doesn't contain '..' before extraction",
                    )
                )
    return findings


@register(
    id="PY-002",
    name="yaml-unsafe-load",
    severity=Severity.CRITICAL,
    description="Detects yaml.load() without SafeLoader, enabling code execution",
    extensions=PY_EXTS,
    cwe_id="CWE-502",
    compliance_tags=["SOC2-CC6.1"],
)
def py_002_yaml_unsafe(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    tree = kwargs.get("tree")

    if tree:
        # Semantic Analysis
        query_scm = """
        (call
          function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
          arguments: (argument_list) @args
          (#eq? @obj "yaml")
          (#eq? @method "load"))
        """
        from shipguard.semantic import SemanticEngine
        matches = SemanticEngine.query(tree, query_scm)
        
        for _, match_captures in matches:
            # Check if Loader=SafeLoader is present in arguments
            args_node = match_captures.get("args", [None])[0]
            if args_node:
                args_text = content[args_node.start_byte : args_node.end_byte]
                if "SafeLoader" not in args_text and "safe_load" not in args_text:
                    node = match_captures.get("method")[0]
                    line_number = node.start_point[0] + 1
                    line_content = content.splitlines()[line_number - 1]
                    findings.append(
                        Finding(
                            rule_id="PY-002",
                            severity=Severity.CRITICAL,
                            file_path=file_path,
                            line_number=line_number,
                            line_content=line_content.rstrip(),
                            message="yaml.load() without SafeLoader allows arbitrary code execution",
                            cwe_id="CWE-502",
                            fix_hint="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                        )
                    )
    else:
        # Fallback to Regex
        pattern = re.compile(r"\byaml\.load\s*\(")
        safe_pattern = re.compile(r"Loader\s*=\s*(SafeLoader|yaml\.SafeLoader|CSafeLoader|yaml\.CSafeLoader)")
        for i, line in enumerate(content.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if pattern.search(line) and not safe_pattern.search(line):
                findings.append(
                    Finding(
                        rule_id="PY-002",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="yaml.load() without SafeLoader allows arbitrary code execution",
                        cwe_id="CWE-502",
                        fix_hint="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
                    )
                )
    return findings


@register(
    id="PY-003",
    name="eval-exec-usage",
    severity=Severity.CRITICAL,
    description="Detects eval() or exec() calls that may execute untrusted code",
    extensions=PY_EXTS,
    cwe_id="CWE-95",
    compliance_tags=["SOC2-CC6.1"],
)
def py_003_eval_exec(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    tree = kwargs.get("tree")

    if tree:
        # Semantic Analysis using Tree-sitter
        query_scm = """
        (call
          function: (identifier) @func
          (#match? @func "^(eval|exec)$"))
        """
        from shipguard.semantic import SemanticEngine
        matches = SemanticEngine.query(tree, query_scm)
        
        for pattern_index, match_captures in matches:
            nodes = match_captures.get("func", [])
            for node in nodes:
                func_name = content[node.start_byte : node.end_byte]
                line_number = node.start_point[0] + 1
                line_content = content.splitlines()[line_number - 1]
                findings.append(
                    Finding(
                        rule_id="PY-003",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=line_number,
                        line_content=line_content.rstrip(),
                        message=f"{func_name}() can execute arbitrary code if input is untrusted",
                        cwe_id="CWE-95",
                        fix_hint=f"Replace {func_name}() with ast.literal_eval() or a safe parser",
                    )
                )
    else:
        # Fallback to Regex Analysis
        pattern = re.compile(r"\b(eval|exec)\s*\(")
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = pattern.search(line)
            if m:
                func = m.group(1)
                findings.append(
                    Finding(
                        rule_id="PY-003",
                        severity=Severity.CRITICAL,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message=f"{func}() can execute arbitrary code if input is untrusted",
                        cwe_id="CWE-95",
                        fix_hint=f"Replace {func}() with ast.literal_eval() or a safe parser",
                    )
                )
    return findings


@register(
    id="PY-004",
    name="startswith-path-check",
    severity=Severity.HIGH,
    description="Detects str.startswith() for path containment checks (CVE-2025-53110)",
    extensions=PY_EXTS,
    cwe_id="CWE-22",
    compliance_tags=["SOC2-CC6.1", "PCI-6.5.1"],
)
def py_004_startswith_path(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    # Match path.startswith(, base_path.startswith(, my_dir.startswith(,
    # str(p).startswith(, p.resolve().startswith(.
    # Requires keyword to be bare (path, dir, file, folder) or preceded by
    # a word-and-underscore prefix (base_path, upload_dir, log_file).
    # Does NOT match profile/directory/direction because those have no
    # underscore separator before the keyword.
    pattern = re.compile(
        r"""(?:str\s*\(\s*\w+\s*\)|(?:\w+\.)?resolve\s*\(\s*\)|\b(?:\w+_)?(?:path|dir|file|folder)s?)\.startswith\s*\(""",
        re.IGNORECASE,
    )
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-004",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="str.startswith() for path containment is bypassable with crafted paths",
                    cwe_id="CWE-22",
                    fix_hint="Use pathlib: child.resolve().is_relative_to(parent.resolve())",
                )
            )
    return findings


@register(
    id="PY-005",
    name="subprocess-shell-true",
    severity=Severity.HIGH,
    description="Detects subprocess calls with shell=True",
    extensions=PY_EXTS,
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1", "PCI-6.5.1"],
)
def py_005_subprocess_shell(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    tree = kwargs.get("tree")

    if tree:
        # Semantic Analysis
        query_scm = """
        (call
          function: (attribute
            object: (identifier) @obj
            attribute: (identifier) @method)
          arguments: (argument_list
            (keyword_argument
              name: (identifier) @arg_name
              value: (true) @arg_val))
          (#eq? @obj "subprocess")
          (#eq? @arg_name "shell"))
        """
        from shipguard.semantic import SemanticEngine
        matches = SemanticEngine.query(tree, query_scm)
        
        for _, match_captures in matches:
            node = match_captures.get("arg_val")[0]
            line_number = node.start_point[0] + 1
            line_content = content.splitlines()[line_number - 1]
            findings.append(
                Finding(
                    rule_id="PY-005",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_number,
                    line_content=line_content.rstrip(),
                    message="subprocess with shell=True is vulnerable to shell injection",
                    cwe_id="CWE-78",
                    fix_hint="Use shell=False and pass arguments as a list",
                )
            )
    else:
        # Fallback to Regex
        pattern = re.compile(r"\bsubprocess\.\w+\(")
        shell_pattern = re.compile(r"shell\s*=\s*True")
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if line.strip().startswith("#"):
                continue
            if pattern.search(line):
                # Check this line and next few lines for shell=True
                window = "\n".join(lines[i - 1 : min(i + 4, len(lines))])
                if shell_pattern.search(window):
                    shell_line = i
                    for j in range(i - 1, min(i + 4, len(lines))):
                        if shell_pattern.search(lines[j]):
                            shell_line = j + 1
                            break
                    findings.append(
                        Finding(
                            rule_id="PY-005",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=shell_line,
                            line_content=lines[shell_line - 1].rstrip(),
                            message="subprocess with shell=True is vulnerable to shell injection",
                            cwe_id="CWE-78",
                            fix_hint="Use shell=False and pass arguments as a list",
                        )
                    )
    return findings


@register(
    id="PY-006",
    name="hardcoded-secrets",
    severity=Severity.HIGH,
    description="Detects hardcoded API keys, tokens, and passwords in Python source",
    extensions=PY_EXTS,
    cwe_id="CWE-798",
    compliance_tags=["SOC2-CC6.1"],
)
def py_006_hardcoded_secrets(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        (re.compile(r"""(?:api_key|apikey|api_secret|secret_key|auth_token|access_token|password)\s*=\s*["'][^"']{8,}["']""", re.IGNORECASE), "hardcoded secret"),
        (re.compile(r"""["'](?:sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9\-]{20,}|AKIA[A-Z0-9]{16})["']"""), "API key/token literal"),
    ]
    for i, line in enumerate(content.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        for pat, desc in patterns:
            if pat.search(line):
                # Skip obvious test/placeholder values
                lower = line.lower()
                if any(placeholder in lower for placeholder in [
                    "example", "placeholder", "change_me", "your-",
                    "test-fake", "xxx", "replace", "<",
                ]):
                    continue
                findings.append(
                    Finding(
                        rule_id="PY-006",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message=f"Possible {desc} found in source code",
                        cwe_id="CWE-798",
                        fix_hint="Use environment variables or a secrets manager instead",
                    )
                )
                break  # One finding per line
    return findings


# A SQL verb on its own is not evidence of SQL. SELECT, UPDATE, CREATE, DROP,
# GRANT and ALTER are all ordinary English words, and matching them bare made
# PY-007 fire on help text, log messages and CLI instructions in repositories
# with no database access at all. Require the verb to appear with the clause
# that makes it a statement, so "Create a private repo" is prose while
# "CREATE TABLE {t}" is a query.
#
# The gap between verb and clause is bounded rather than greedy: a triple-quoted
# string is a single AST node in the semantic path, so an unbounded matcher would
# happily pair a "SELECT" in one paragraph with a "FROM" fifty lines later.
_SQL_STATEMENT_RE = re.compile(
    r"""
    # "select ... from" is also plain English ("select an option from the
    # menu"), so require FROM to be followed by something table-shaped rather
    # than an article or pronoun.
      \bSELECT\b [\s\S]{0,400}? \bFROM\s+
        (?! (?:the|a|an|this|that|these|those|your|my|our|their|it|them|here|there)\b )
    | \bINSERT\s+INTO\b
    | \bUPDATE\b [\s\S]{0,400}? \bSET\b
    | \bDELETE\s+FROM\b
    | \bTRUNCATE\s+TABLE\b
    | \b(?:DROP|ALTER|CREATE)\s+(?:TABLE|DATABASE|SCHEMA|INDEX|VIEW|SEQUENCE)\b
    | \bCREATE\s+OR\s+REPLACE\b
    | \bGRANT\b [\s\S]{0,400}? \bON\b
    """,
    re.IGNORECASE | re.VERBOSE,
)


@register(
    id="PY-007",
    name="sql-string-format",
    severity=Severity.HIGH,
    description="Detects f-strings or .format() used in SQL queries",
    extensions=PY_EXTS,
    cwe_id="CWE-89",
    compliance_tags=["SOC2-CC6.1", "PCI-6.5.1", "HIPAA-164.312"],
)
def py_007_sql_injection(
    file_path: Path, content: str, config: object = None, **kwargs
) -> list[Finding]:
    findings: list[Finding] = []
    tree = kwargs.get("tree")
    sql_keywords_re = _SQL_STATEMENT_RE

    if tree:
        # Semantic Analysis
        # 1. Check f-strings and regular strings for SQL
        query_fstring = "(string) @fstring"
        from shipguard.semantic import SemanticEngine
        matches = SemanticEngine.query(tree, query_fstring)
        for _, match_captures in matches:
            for node in match_captures.get("fstring", []):
                text = content[node.start_byte : node.end_byte]
                
                # Only flag if it's an f-string or contains suspicious formatting
                is_fstring = text.lower().startswith("f")
                has_interpolation = "{" in text and "}" in text
                
                if (is_fstring or has_interpolation) and sql_keywords_re.search(text):
                    line_number = node.start_point[0] + 1
                    line_content = content.splitlines()[line_number - 1]
                    findings.append(
                        Finding(
                            rule_id="PY-007",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_number,
                            line_content=line_content.rstrip(),
                            message="SQL query built with f-string is vulnerable to SQL injection",
                            cwe_id="CWE-89",
                            fix_hint="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
                        )
                    )

        # 2. Check .format() calls
        query_format = """
        (call
          function: (attribute
            object: (string) @str
            attribute: (identifier) @method)
          (#eq? @method "format"))
        """
        matches = SemanticEngine.query(tree, query_format)
        for _, match_captures in matches:
            for node in match_captures.get("str", []):
                text = content[node.start_byte : node.end_byte]
                if sql_keywords_re.search(text):
                    line_number = node.start_point[0] + 1
                    line_content = content.splitlines()[line_number - 1]
                    findings.append(
                        Finding(
                            rule_id="PY-007",
                            severity=Severity.HIGH,
                            file_path=file_path,
                            line_number=line_number,
                            line_content=line_content.rstrip(),
                            message="SQL query built with .format() is vulnerable to SQL injection",
                            cwe_id="CWE-89",
                            fix_hint="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
                        )
                    )
    else:
        # Fallback to Regex. Uses the same structural definition as the semantic
        # path above so both agree on what counts as SQL.
        sql_keywords = _SQL_STATEMENT_RE.pattern
        fstring_pattern = re.compile(rf'f["\'].*(?:{sql_keywords})', re.IGNORECASE | re.VERBOSE)
        format_pattern = re.compile(
            rf'["\'].*(?:{sql_keywords}).*["\']\.format\s*\(', re.IGNORECASE | re.VERBOSE
        )
        percent_pattern = re.compile(
            rf'["\'].*(?:{sql_keywords}).*%s.*["\']\s*%', re.IGNORECASE | re.VERBOSE
        )

        for i, line in enumerate(content.splitlines(), 1):
            if line.strip().startswith("#"):
                continue
            if fstring_pattern.search(line) or format_pattern.search(line) or percent_pattern.search(line):
                findings.append(
                    Finding(
                        rule_id="PY-007",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        line_content=line.rstrip(),
                        message="SQL query built with string formatting is vulnerable to SQL injection",
                        cwe_id="CWE-89",
                        fix_hint="Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id=?', (id,))",
                    )
                )
    return findings


@register(
    id="PY-008",
    name="pickle-load",
    severity=Severity.MEDIUM,
    description="Detects pickle.load/loads() which can execute arbitrary code",
    extensions=PY_EXTS,
    cwe_id="CWE-502",
    compliance_tags=["SOC2-CC6.1"],
)
def py_008_pickle_load(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\bpickle\.(?:load|loads)\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-008",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="pickle.load() can execute arbitrary code from untrusted data",
                    cwe_id="CWE-502",
                    fix_hint="Use JSON or a safe serialization format for untrusted data",
                )
            )
    return findings


@register(
    id="PY-009",
    name="tempfile-no-cleanup",
    severity=Severity.LOW,
    description="Detects tempfile.mktemp() usage which has a race condition",
    extensions=PY_EXTS,
    cwe_id="CWE-377",
    compliance_tags=["SOC2-CC6.1"],
)
def py_009_tempfile_mktemp(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\btempfile\.mktemp\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-009",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="tempfile.mktemp() has a race condition between name creation and file creation",
                    cwe_id="CWE-377",
                    fix_hint="Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead",
                )
            )
    return findings


@register(
    id="PY-010",
    name="os-system-call",
    severity=Severity.HIGH,
    description="Detects os.system() calls which are vulnerable to shell injection",
    extensions=PY_EXTS,
    cwe_id="CWE-78",
    compliance_tags=["SOC2-CC6.1", "PCI-6.5.1"],
)
def py_010_os_system(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"\bos\.system\s*\(")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-010",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="os.system() is vulnerable to shell injection and lacks error handling",
                    cwe_id="CWE-78",
                    fix_hint="Use subprocess.run(args, shell=False) with a list of arguments instead",
                )
            )
    return findings


@register(
    id="PY-011",
    name="insecure-random-crypto",
    severity=Severity.MEDIUM,
    description="Detects use of the random module for cryptographic or security-sensitive purposes",
    extensions=PY_EXTS,
    cwe_id="CWE-338",
    compliance_tags=["SOC2-CC6.1"],
)
def py_011_insecure_random(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    # Only flag if the file imports `random` (not `secrets`)
    if "import random" not in content:
        return findings
    pattern = re.compile(
        r"\brandom\.(random|randint|choice|shuffle|seed|sample|randbytes)\s*\("
    )
    crypto_context = re.compile(
        r"(?:token|secret|password|key|salt|nonce|iv|csrf|session|auth)",
        re.IGNORECASE,
    )
    lines = content.splitlines()
    for i, line in enumerate(lines, 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line) and crypto_context.search(line):
            findings.append(
                Finding(
                    rule_id="PY-011",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="random module is not cryptographically secure; do not use for secrets or tokens",
                    cwe_id="CWE-338",
                    fix_hint="Use the secrets module or os.urandom() for cryptographic randomness",
                )
            )
    return findings


@register(
    id="PY-012",
    name="tempfile-delete-false",
    severity=Severity.MEDIUM,
    description="Detects NamedTemporaryFile(delete=False) which leaves sensitive files on disk",
    extensions=PY_EXTS,
    cwe_id="CWE-377",
    compliance_tags=["SOC2-CC6.1"],
)
def py_012_tempfile_delete_false(file_path: Path, content: str, config: object = None, **kwargs) -> list[Finding]:
    findings: list[Finding] = []
    pattern = re.compile(r"NamedTemporaryFile\s*\([^)]*delete\s*=\s*False")
    for i, line in enumerate(content.splitlines(), 1):
        if line.strip().startswith("#"):
            continue
        if pattern.search(line):
            findings.append(
                Finding(
                    rule_id="PY-012",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    line_content=line.rstrip(),
                    message="NamedTemporaryFile(delete=False) leaves the file on disk after the handle is closed",
                    cwe_id="CWE-377",
                    fix_hint="Ensure manual cleanup in a finally block, or use delete=True (default)",
                )
            )
    return findings
