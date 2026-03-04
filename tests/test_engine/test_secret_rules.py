"""Tests for secret detection rules."""

from threatcode.engine.secrets.builtin import get_builtin_rules


class TestBuiltinRules:
    def test_rules_loaded(self) -> None:
        rules = get_builtin_rules()
        assert len(rules) >= 20

    def test_all_rules_have_required_fields(self) -> None:
        rules = get_builtin_rules()
        for rule in rules:
            assert rule.id, "Rule missing id"
            assert rule.category, f"Rule {rule.id} missing category"
            assert rule.title, f"Rule {rule.id} missing title"
            assert rule.severity in ("critical", "high", "medium", "low")
            assert rule.regex is not None

    def test_unique_rule_ids(self) -> None:
        rules = get_builtin_rules()
        ids = [r.id for r in rules]
        assert len(ids) == len(set(ids))

    def test_aws_key_pattern(self) -> None:
        rules = get_builtin_rules()
        aws_rule = next(r for r in rules if r.id == "SECRET_AWS_ACCESS_KEY")
        assert aws_rule.regex.search("AKIAIOSFODNN7EXAMPLE")
        assert not aws_rule.regex.search("not_a_key")

    def test_github_pat_pattern(self) -> None:
        rules = get_builtin_rules()
        gh_rule = next(r for r in rules if r.id == "SECRET_GITHUB_PAT")
        assert gh_rule.regex.search("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234")

    def test_private_key_pattern(self) -> None:
        rules = get_builtin_rules()
        pk_rule = next(r for r in rules if r.id == "SECRET_PRIVATE_KEY")
        assert pk_rule.regex.search("-----BEGIN RSA PRIVATE KEY-----")
        assert pk_rule.regex.search("-----BEGIN EC PRIVATE KEY-----")
        assert not pk_rule.regex.search("-----BEGIN CERTIFICATE-----")
