"""Tests for Python security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.python import (
    py_001_zip_traversal,
    py_002_yaml_unsafe,
    py_003_eval_exec,
    py_004_startswith_path,
    py_005_subprocess_shell,
    py_006_hardcoded_secrets,
    py_007_sql_injection,
    py_008_pickle_load,
    py_009_tempfile_mktemp,
    py_010_os_system,
    py_011_insecure_random,
    py_012_tempfile_delete_false,
)

FIXTURES = Path(__file__).parent / "fixtures" / "python"


class TestPY001ZipTraversal:
    def test_detects_extractall(self):
        content = "import zipfile\nwith zipfile.ZipFile(f) as zf:\n    zf.extractall('/tmp')"
        findings = py_001_zip_traversal(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_safe_code(self):
        content = "import json\ndata = json.load(f)"
        findings = py_001_zip_traversal(Path("test.py"), content)
        assert len(findings) == 0


class TestPY002YamlUnsafe:
    def test_detects_unsafe_load(self):
        content = "import yaml\nyaml.load(data)"
        findings = py_002_yaml_unsafe(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_safe_load(self):
        content = "yaml.safe_load(data)"
        findings = py_002_yaml_unsafe(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_load_with_safe_loader(self):
        content = "yaml.load(data, Loader=yaml.SafeLoader)"
        findings = py_002_yaml_unsafe(Path("test.py"), content)
        assert len(findings) == 0


class TestPY003EvalExec:
    def test_detects_eval(self):
        content = "result = eval(user_input)"
        findings = py_003_eval_exec(Path("test.py"), content)
        assert len(findings) == 1

    def test_detects_exec(self):
        content = "exec(code_string)"
        findings = py_003_eval_exec(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_comments(self):
        content = "# eval(something)"
        findings = py_003_eval_exec(Path("test.py"), content)
        assert len(findings) == 0


class TestPY004StartswithPath:
    def test_detects_startswith_path(self):
        content = 'if str(filepath).startswith("/safe/dir"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_detects_base_path_variable(self):
        content = 'if base_path.startswith("/uploads"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 1

    def test_detects_resolve_startswith(self):
        content = 'if p.resolve().startswith("/var"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_non_path_startswith(self):
        content = 'if name.startswith("prefix"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 0

    def test_no_false_positive_on_direction(self):
        content = 'if direction.startswith("north"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 0

    def test_no_false_positive_on_dirty_flag(self):
        content = 'if dirty_flag.startswith("--"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 0

    def test_no_false_positive_on_directory(self):
        content = 'if directory.startswith("/tmp"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 0

    def test_no_false_positive_on_profile(self):
        content = 'if profile.startswith("admin"):'
        findings = py_004_startswith_path(Path("test.py"), content)
        assert len(findings) == 0


class TestPY005SubprocessShell:
    def test_detects_shell_true(self):
        content = "import subprocess\nsubprocess.run(cmd, shell=True)"
        findings = py_005_subprocess_shell(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_shell_false(self):
        content = 'subprocess.run(["ls"], shell=False)'
        findings = py_005_subprocess_shell(Path("test.py"), content)
        assert len(findings) == 0


class TestPY006HardcodedSecrets:
    def test_detects_api_key(self):
        content = 'api_key = "sk-live-abcdefghijklmnopqrstuvwx"'
        findings = py_006_hardcoded_secrets(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_ignores_placeholder(self):
        content = 'api_key = "your-api-key-here"'
        findings = py_006_hardcoded_secrets(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_env_var(self):
        content = 'api_key = os.environ["API_KEY"]'
        findings = py_006_hardcoded_secrets(Path("test.py"), content)
        assert len(findings) == 0


class TestPY007SqlInjection:
    def test_detects_fstring_sql(self):
        content = 'query = f"SELECT * FROM users WHERE name = \'{name}\'"'
        findings = py_007_sql_injection(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_parameterized(self):
        content = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'
        findings = py_007_sql_injection(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_sql_verb_used_as_plain_english(self):
        """A bare SQL verb in prose is not a query.

        Regression for a false positive found 2026-08-17 in ai-forge, a project
        scaffolder with no SQL anywhere: the rule matched the word "Create" in a
        help message and reported CWE-89.
        """
        content = (
            'print(f"""\n'
            "  3. Create remote and push (private):\n"
            "       gh repo create {owner}/{name} --private --source=. --push\n"
            '""")\n'
        )
        findings = py_007_sql_injection(Path("test.py"), content)
        assert findings == []

    def test_ignores_other_sql_verbs_as_english(self):
        for text in (
            'msg = f"Update the {thing} before you continue"',
            'msg = f"Select a {option} from the menu"',
            'msg = f"Grant access to {user} in the console"',
            'msg = f"Drop the {item} into the folder"',
            'msg = f"Alter your {setting} in preferences"',
        ):
            findings = py_007_sql_injection(Path("test.py"), text)
            assert findings == [], f"false positive on: {text}"

    def test_still_detects_real_sql_statements(self):
        for text in (
            'q = f"SELECT id FROM users WHERE name = \'{name}\'"',
            'q = f"INSERT INTO users (name) VALUES (\'{name}\')"',
            'q = f"UPDATE users SET name = \'{name}\' WHERE id = {uid}"',
            'q = f"DELETE FROM users WHERE id = {uid}"',
            'q = f"DROP TABLE {table}"',
            'q = f"CREATE TABLE {table} (id INT)"',
            'q = f"ALTER TABLE {table} ADD COLUMN x INT"',
        ):
            findings = py_007_sql_injection(Path("test.py"), text)
            assert len(findings) == 1, f"missed real SQL injection: {text}"
            assert findings[0].severity == Severity.HIGH

    def test_detects_sql_built_with_format(self):
        content = 'q = "SELECT id FROM users WHERE name = \'{}\'".format(name)'
        findings = py_007_sql_injection(Path("test.py"), content)
        assert len(findings) == 1


class TestPY008PickleLoad:
    def test_detects_pickle_load(self):
        content = "data = pickle.load(f)"
        findings = py_008_pickle_load(Path("test.py"), content)
        assert len(findings) == 1

    def test_detects_pickle_loads(self):
        content = "data = pickle.loads(raw)"
        findings = py_008_pickle_load(Path("test.py"), content)
        assert len(findings) == 1


class TestPY009TempfileMktemp:
    def test_detects_mktemp(self):
        content = "path = tempfile.mktemp()"
        findings = py_009_tempfile_mktemp(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_mkstemp(self):
        content = "fd, path = tempfile.mkstemp()"
        findings = py_009_tempfile_mktemp(Path("test.py"), content)
        assert len(findings) == 0


class TestPY010OsSystem:
    def test_detects_os_system(self):
        content = "import os\nos.system('ls -la')"
        findings = py_010_os_system(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PY-010"
        assert findings[0].severity == Severity.HIGH

    def test_detects_os_system_with_variable(self):
        content = "os.system(cmd)"
        findings = py_010_os_system(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_comment(self):
        content = "# os.system('dangerous')"
        findings = py_010_os_system(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_subprocess(self):
        content = "subprocess.run(['ls', '-la'], shell=False)"
        findings = py_010_os_system(Path("test.py"), content)
        assert len(findings) == 0


class TestPY011InsecureRandom:
    def test_detects_random_for_token(self):
        content = "import random\ntoken = random.randint(0, 100000)"
        findings = py_011_insecure_random(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PY-011"
        assert findings[0].severity == Severity.MEDIUM

    def test_detects_random_for_password(self):
        content = "import random\npassword = random.choice(chars)"
        findings = py_011_insecure_random(Path("test.py"), content)
        assert len(findings) == 1

    def test_detects_random_for_session_key(self):
        content = "import random\nsession_key = random.random()"
        findings = py_011_insecure_random(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_non_crypto_random(self):
        content = "import random\nindex = random.randint(0, 10)"
        findings = py_011_insecure_random(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_without_random_import(self):
        content = "import secrets\ntoken = secrets.token_hex(32)"
        findings = py_011_insecure_random(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_comment(self):
        content = "import random\n# token = random.randint(0, 100)"
        findings = py_011_insecure_random(Path("test.py"), content)
        assert len(findings) == 0


class TestPY012TempfileDeleteFalse:
    def test_detects_delete_false(self):
        content = "f = tempfile.NamedTemporaryFile(delete=False)"
        findings = py_012_tempfile_delete_false(Path("test.py"), content)
        assert len(findings) == 1
        assert findings[0].rule_id == "PY-012"
        assert findings[0].severity == Severity.MEDIUM

    def test_detects_delete_false_with_other_args(self):
        content = "f = tempfile.NamedTemporaryFile(suffix='.tmp', delete=False)"
        findings = py_012_tempfile_delete_false(Path("test.py"), content)
        assert len(findings) == 1

    def test_ignores_delete_true(self):
        content = "f = tempfile.NamedTemporaryFile(delete=True)"
        findings = py_012_tempfile_delete_false(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_default_no_delete_arg(self):
        content = "f = tempfile.NamedTemporaryFile(suffix='.tmp')"
        findings = py_012_tempfile_delete_false(Path("test.py"), content)
        assert len(findings) == 0

    def test_ignores_comment(self):
        content = "# f = tempfile.NamedTemporaryFile(delete=False)"
        findings = py_012_tempfile_delete_false(Path("test.py"), content)
        assert len(findings) == 0


class TestPythonFixtureFiles:
    def test_vulnerable_fixture(self, python_fixtures):
        content = (python_fixtures / "vulnerable.py").read_text()
        path = python_fixtures / "vulnerable.py"

        all_findings = []
        all_findings.extend(py_001_zip_traversal(path, content))
        all_findings.extend(py_002_yaml_unsafe(path, content))
        all_findings.extend(py_003_eval_exec(path, content))
        all_findings.extend(py_004_startswith_path(path, content))
        all_findings.extend(py_005_subprocess_shell(path, content))
        all_findings.extend(py_006_hardcoded_secrets(path, content))
        all_findings.extend(py_007_sql_injection(path, content))
        all_findings.extend(py_008_pickle_load(path, content))
        all_findings.extend(py_009_tempfile_mktemp(path, content))

        assert len(all_findings) >= 9

    def test_safe_fixture(self, python_fixtures):
        content = (python_fixtures / "safe.py").read_text()
        path = python_fixtures / "safe.py"

        findings = []
        findings.extend(py_001_zip_traversal(path, content))
        findings.extend(py_002_yaml_unsafe(path, content))
        findings.extend(py_003_eval_exec(path, content))
        findings.extend(py_005_subprocess_shell(path, content))
        findings.extend(py_007_sql_injection(path, content))
        findings.extend(py_008_pickle_load(path, content))
        findings.extend(py_009_tempfile_mktemp(path, content))

        assert len(findings) == 0
