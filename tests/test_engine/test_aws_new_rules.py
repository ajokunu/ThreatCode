"""Tests for new AWS security rules (WAF, Secrets Manager, GuardDuty, Config, SSM, WAFv2)."""

from __future__ import annotations

import pytest

from threatcode.engine.rules.loader import load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule


@pytest.fixture
def all_rules():
    return load_all_rules()


@pytest.fixture
def aws_new_rule_ids():
    return {
        # WAF
        "WAF_NO_DEFAULT_BLOCK",
        "WAF_NO_LOGGING",
        "WAF_NO_RATE_LIMITING",
        "WAF_NO_MANAGED_RULES",
        "WAF_EMPTY_RULES",
        # Secrets Manager
        "SM_NO_ROTATION",
        "SM_NO_KMS_KEY",
        "SM_LONG_ROTATION",
        "SM_NO_RESOURCE_POLICY",
        # GuardDuty
        "GUARDDUTY_NOT_ENABLED",
        "GUARDDUTY_NO_S3_PROTECTION",
        "GUARDDUTY_NO_EKS_PROTECTION",
        "GUARDDUTY_NO_MALWARE_SCAN",
        # Config
        "CONFIG_NOT_ENABLED",
        "CONFIG_NOT_ALL_RESOURCES",
        "CONFIG_NO_DELIVERY_CHANNEL",
        "CONFIG_NO_AGGREGATION",
        # SSM
        "SSM_UNENCRYPTED_PARAMETER",
        "SSM_NO_DESCRIPTION",
        "SSM_STANDARD_TIER_SECRET",
        "SSM_NO_ALLOWED_PATTERN",
        # WAFv2
        "WAFV2_NO_SQL_INJECTION_RULE",
        "WAFV2_NO_XSS_RULE",
        "WAFV2_RATE_LIMIT_HIGH",
        "WAFV2_NO_IP_REPUTATION",
        "WAFV2_NO_GEO_BLOCKING",
        # EKS node group
        "EKS_PUBLIC_NODE_GROUP",
        "EKS_SSH_ACCESS_NODES",
        "EKS_UNENCRYPTED_NODE_AMI",
        "EKS_NO_FARGATE_LOGGING",
    }


class TestAwsNewRulesExist:
    def test_all_new_rules_loaded(self, all_rules, aws_new_rule_ids) -> None:
        loaded_ids = {r.id for r in all_rules}
        for rule_id in aws_new_rule_ids:
            assert rule_id in loaded_ids, f"Rule {rule_id} not found in loaded rules"

    def test_no_duplicate_ids(self, all_rules) -> None:
        ids = [r.id for r in all_rules]
        assert len(ids) == len(set(ids)), (
            f"Duplicate rule IDs: {[i for i in ids if ids.count(i) > 1]}"
        )


class TestAwsNewRulesFire:
    def test_waf_no_logging_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "WAF_NO_LOGGING")
        bad_props = {"name": "test-waf"}
        assert evaluate_rule(rule.condition, bad_props)

    def test_waf_no_logging_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "WAF_NO_LOGGING")
        good_props = {"logging_configuration": {"log_destination_configs": ["arn:aws:s3:::logs"]}}
        assert not evaluate_rule(rule.condition, good_props)

    def test_sm_no_rotation_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SM_NO_ROTATION")
        bad_props = {"name": "my-secret"}
        assert evaluate_rule(rule.condition, bad_props)

    def test_sm_no_rotation_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SM_NO_ROTATION")
        good_props = {"rotation_rules": {"automatically_after_days": 30}}
        assert not evaluate_rule(rule.condition, good_props)

    def test_guardduty_not_enabled_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "GUARDDUTY_NOT_ENABLED")
        bad_props = {"enable": False}
        assert evaluate_rule(rule.condition, bad_props)

    def test_ssm_unencrypted_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SSM_UNENCRYPTED_PARAMETER")
        bad_props = {"type": "String", "name": "/app/config"}
        assert evaluate_rule(rule.condition, bad_props)

    def test_ssm_encrypted_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SSM_UNENCRYPTED_PARAMETER")
        good_props = {"type": "SecureString", "name": "/app/secret"}
        assert not evaluate_rule(rule.condition, good_props)
