"""Tests for new Azure security rules."""

from __future__ import annotations

import pytest

from threatcode.engine.rules.loader import load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule


@pytest.fixture
def all_rules():
    return load_all_rules()


@pytest.fixture
def azure_new_rule_ids():
    return {
        # Key Vault
        "KEYVAULT_NO_SOFT_DELETE",
        "KEYVAULT_NO_PURGE_PROTECTION",
        "KEYVAULT_NO_NETWORK_ACLS",
        "KEYVAULT_PUBLIC_ACCESS",
        "KEYVAULT_NO_DIAGNOSTICS",
        # App Service
        "APPSVC_HTTP_ONLY",
        "APPSVC_NO_MANAGED_IDENTITY",
        "APPSVC_OLD_TLS",
        "APPSVC_FTP_ENABLED",
        "APPSVC_NO_AUTH",
        # Functions
        "FUNC_NO_MANAGED_IDENTITY",
        "FUNC_HTTP_V1",
        "FUNC_NO_HTTPS",
        "FUNC_PUBLIC_ACCESS",
        # SQL
        "MSSQL_NO_AUDITING",
        "MSSQL_NO_TDE",
        "MSSQL_NO_THREAT_DETECTION",
        "MSSQL_PUBLIC_ACCESS",
        # Cosmos DB
        "COSMOS_PUBLIC_ACCESS",
        "COSMOS_NO_VNET_RULES",
        "COSMOS_NO_CMK",
        "COSMOS_NO_ANALYTICAL_STORAGE",
        # Monitor
        "MONITOR_NO_ACTIVITY_LOG_ALERT",
        "MONITOR_NO_DIAGNOSTIC_SETTING",
        "MONITOR_SHORT_RETENTION",
    }


class TestAzureNewRulesExist:
    def test_all_new_rules_loaded(self, all_rules, azure_new_rule_ids) -> None:
        loaded_ids = {r.id for r in all_rules}
        for rule_id in azure_new_rule_ids:
            assert rule_id in loaded_ids, f"Rule {rule_id} not found"


class TestAzureNewRulesFire:
    def test_keyvault_no_purge_protection_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "KEYVAULT_NO_PURGE_PROTECTION")
        bad_props = {"purge_protection_enabled": False}
        assert evaluate_rule(rule.condition, bad_props)

    def test_keyvault_purge_protection_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "KEYVAULT_NO_PURGE_PROTECTION")
        good_props = {"purge_protection_enabled": True}
        assert not evaluate_rule(rule.condition, good_props)

    def test_appsvc_http_only_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "APPSVC_HTTP_ONLY")
        bad_props = {"https_only": False}
        assert evaluate_rule(rule.condition, bad_props)

    def test_mssql_public_access_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "MSSQL_PUBLIC_ACCESS")
        bad_props = {"public_network_access_enabled": True}
        assert evaluate_rule(rule.condition, bad_props)

    def test_cosmos_public_access_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "COSMOS_PUBLIC_ACCESS")
        bad_props = {"public_network_access_enabled": True}
        assert evaluate_rule(rule.condition, bad_props)
