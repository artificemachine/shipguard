"""Tests for rule dispatch behavior."""

from pathlib import Path

from shipguard.rules import get_rules_for_file, load_builtin_rules, load_custom_rules


class TestRuleDispatch:
    def test_cfg_002_applies_to_dotenv(self):
        load_builtin_rules()
        rule_ids = {r.id for r in get_rules_for_file(Path(".env"))}
        assert "CFG-002" in rule_ids

    def test_cfg_002_applies_to_dotenv_variants(self):
        load_builtin_rules()
        rule_ids = {r.id for r in get_rules_for_file(Path(".env.local"))}
        assert "CFG-002" in rule_ids

    def test_load_custom_rule_module(self, tmp_path):
        load_builtin_rules()
        custom_dir = tmp_path / "custom_rules"
        custom_dir.mkdir()
        (custom_dir / "sample_rule.py").write_text(
            """
from shipguard.models import Finding, Severity
from shipguard.rules import register

@register(
    id="CUST-777",
    name="sample-custom",
    severity=Severity.LOW,
    description="custom",
    extensions=[".txt"],
)
def custom_rule(file_path, content, config=None):
    return []
""".strip()
        )
        load_custom_rules([custom_dir])
        rule_ids = {r.id for r in get_rules_for_file(Path("x.txt"))}
        assert "CUST-777" in rule_ids

    def test_pii_001_applies_to_python_and_yaml(self):
        load_builtin_rules()
        py_ids = {r.id for r in get_rules_for_file(Path("x.py"))}
        yml_ids = {r.id for r in get_rules_for_file(Path("x.yml"))}
        assert "PII-001" in py_ids
        assert "PII-001" in yml_ids
