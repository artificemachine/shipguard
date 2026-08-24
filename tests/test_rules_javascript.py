"""Tests for JavaScript security rules."""

from pathlib import Path

from shipguard.models import Severity
from shipguard.rules.javascript import (
    js_001_eval,
    js_002_path_traversal,
    js_003_symlink_following,
    js_004_prototype_pollution,
    js_005_regex_dos,
    js_006_xss_innerhtml,
    js_007_no_csp,
    js_008_console_secrets,
)

FIXTURES = Path(__file__).parent / "fixtures" / "javascript"


class TestJS001Eval:
    def test_detects_eval(self):
        content = "const result = eval(userInput);"
        findings = js_001_eval(Path("test.js"), content)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_ignores_comments(self):
        content = "// eval(something)"
        findings = js_001_eval(Path("test.js"), content)
        assert len(findings) == 0

    def test_ignores_dotted_method_call_named_eval(self):
        """A `.eval()` member call (PyTorch's model.eval(), a custom
        object's eval method, etc.) is not the global eval() function and
        cannot execute arbitrary code the way eval() can. Real false
        positive found 2026-08-24 on a Python heredoc embedded in a .mjs
        file: `model.eval()` (sets a torch model to evaluation mode)."""
        content = "model.eval();"
        findings = js_001_eval(Path("test.js"), content)
        assert len(findings) == 0

    def test_still_detects_eval_after_whitespace(self):
        content = "const x =  eval (userInput);"
        findings = js_001_eval(Path("test.js"), content)
        assert len(findings) == 1


class TestJS002PathTraversal:
    def test_detects_unchecked_path_join(self):
        content = "const p = path.join('/uploads', userInput);\nfs.readFileSync(p);"
        findings = js_002_path_traversal(Path("test.js"), content)
        assert len(findings) == 1

    def test_ignores_checked_path(self):
        content = (
            "const p = path.join('/uploads', userInput);\n"
            "if (!p.startsWith('/uploads')) throw new Error();\n"
            "fs.readFileSync(p);"
        )
        findings = js_002_path_traversal(Path("test.js"), content)
        assert len(findings) == 0


class TestJS003SymlinkFollowing:
    def test_detects_readdir_no_symlink_check(self):
        content = "const files = fs.readdirSync(dir);\nfiles.forEach(f => process(f));"
        findings = js_003_symlink_following(Path("test.js"), content)
        assert len(findings) == 1

    def test_ignores_with_symlink_check(self):
        content = (
            "const files = fs.readdirSync(dir);\n"
            "files.forEach(f => {\n"
            "  const stat = fs.lstatSync(f);\n"
            "  if (stat.isSymbolicLink()) return;\n"
            "});"
        )
        findings = js_003_symlink_following(Path("test.js"), content)
        assert len(findings) == 0


class TestJS004PrototypePollution:
    def test_detects_deep_merge(self):
        content = "function deepMerge(target, source) {\n  for (const key in source) {}\n}"
        findings = js_004_prototype_pollution(Path("test.js"), content)
        assert len(findings) == 1

    def test_ignores_with_proto_check(self):
        content = (
            "function deepMerge(target, source) {\n"
            "  for (const key in source) {\n"
            "    if (key === '__proto__') continue;\n"
            "  }\n"
            "}"
        )
        findings = js_004_prototype_pollution(Path("test.js"), content)
        assert len(findings) == 0

    def test_ignores_array_spread_dedup(self):
        """Object/array spread (`{...a, ...b}` / `[...a, ...b]`) copies own
        enumerable properties via CopyDataProperties -> [[DefineOwnProperty]],
        which does NOT invoke Object.prototype's inherited __proto__ setter
        the way Object.assign's [[Set]] semantics can. It is not the same
        vulnerability class as a hand-rolled recursive deep-merge function.
        Real false positives found 2026-08-24: array-spread dedup idioms
        (`[...new Set([...a, ...b])]`) and header-merging object spreads,
        neither reachable via any real prototype-pollution path."""
        content = "const merged = [...new Set([...explicit, ...mentioned])];"
        findings = js_004_prototype_pollution(Path("test.js"), content)
        assert findings == []

    def test_still_detects_object_assign_empty_target(self):
        """Object.assign({}, source) uses [[Set]] semantics and DOES invoke
        the inherited __proto__ setter for an own "__proto__" key in
        source — unlike spread, this pattern is a real risk and must stay
        detected."""
        content = "const merged = Object.assign({}, untrustedInput);"
        findings = js_004_prototype_pollution(Path("test.js"), content)
        assert len(findings) == 1


class TestJS005ReDoS:
    def test_detects_nested_quantifier(self):
        content = "const re = /(a+)+$/;"
        findings = js_005_regex_dos(Path("test.js"), content)
        assert len(findings) == 1

    def test_ignores_safe_regex(self):
        content = "const re = /^[a-z]+$/;"
        findings = js_005_regex_dos(Path("test.js"), content)
        assert len(findings) == 0


class TestJS006XssInnerHtml:
    def test_detects_innerhtml(self):
        content = "el.innerHTML = userInput;"
        findings = js_006_xss_innerhtml(Path("test.js"), content)
        assert len(findings) == 1

    def test_detects_dangerously_set(self):
        content = '<div dangerouslySetInnerHTML={{ __html: data }} />'
        findings = js_006_xss_innerhtml(Path("test.jsx"), content)
        assert len(findings) == 1


class TestJS007NoCsp:
    def test_detects_express_no_csp(self):
        content = "const express = require('express');\nconst app = express();"
        findings = js_007_no_csp(Path("test.js"), content)
        assert len(findings) == 1

    def test_ignores_with_helmet(self):
        content = (
            "const express = require('express');\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet());"
        )
        findings = js_007_no_csp(Path("test.js"), content)
        assert len(findings) == 0


class TestJS008ConsoleSecrets:
    def test_detects_logged_token(self):
        content = 'console.log("Token:", token);'
        findings = js_008_console_secrets(Path("test.js"), content)
        assert len(findings) == 1

    def test_ignores_safe_log(self):
        content = 'console.log("Hello world");'
        findings = js_008_console_secrets(Path("test.js"), content)
        assert len(findings) == 0


class TestJSFixtureFiles:
    def test_vulnerable_fixture(self, js_fixtures):
        content = (js_fixtures / "vulnerable.js").read_text()
        path = js_fixtures / "vulnerable.js"

        all_findings = []
        all_findings.extend(js_001_eval(path, content))
        all_findings.extend(js_002_path_traversal(path, content))
        all_findings.extend(js_003_symlink_following(path, content))
        all_findings.extend(js_004_prototype_pollution(path, content))
        all_findings.extend(js_006_xss_innerhtml(path, content))
        all_findings.extend(js_008_console_secrets(path, content))

        assert len(all_findings) >= 5

    def test_safe_fixture(self, js_fixtures):
        content = (js_fixtures / "safe.js").read_text()
        path = js_fixtures / "safe.js"

        findings = []
        findings.extend(js_001_eval(path, content))
        findings.extend(js_006_xss_innerhtml(path, content))

        assert len(findings) == 0
