"""Tests for new Azure security rules."""

from __future__ import annotations

import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import detect_and_parse
from threatcode.parsers.terraform_plan import TerraformPlanParser


@pytest.fixture
def all_rules():
    return load_all_rules()


def _findings(graph: InfraGraph) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for threat in HybridEngine().analyze(graph).threats:
        if threat.rule_id:
            found[threat.resource_address].add(threat.rule_id)
    return found


def _scan_hcl(tmp_path: Path, source: str) -> dict[str, set[str]]:
    """Rule ids per resource address for a Terraform HCL snippet."""
    path = tmp_path / "main.tf"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return _findings(InfraGraph.from_parsed(detect_and_parse(path)))


def _scan_plan(*resources: tuple[str, str, dict[str, Any]]) -> dict[str, set[str]]:
    """Rule ids per resource address for (type, name, values) entries of a plan JSON."""
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [
                    {
                        "address": f"{rtype}.{name}",
                        "type": rtype,
                        "name": name,
                        "provider_name": "registry.terraform.io/hashicorp/azurerm",
                        "values": values,
                    }
                    for rtype, name, values in resources
                ]
            }
        },
    }
    return _findings(InfraGraph.from_parsed(TerraformPlanParser().parse(plan)))


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


class TestAppService:
    HCL = """
        resource "azurerm_app_service" "modern" {
          name = "modern"
          site_config {
            min_tls_version = "1.2"
            ftps_state      = "FtpsOnly"
          }
        }
        resource "azurerm_app_service" "legacy" {
          name = "legacy"
          site_config {
            ftps_state = "AllAllowed"
          }
        }
        resource "azurerm_app_service" "bare" {
          name = "bare"
        }
    """

    def test_old_tls_is_silent_when_min_tls_version_is_set(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.HCL)
        assert "APPSVC_OLD_TLS" not in found["azurerm_app_service.modern"]
        assert "APPSVC_OLD_TLS" in found["azurerm_app_service.legacy"]
        assert "APPSVC_OLD_TLS" in found["azurerm_app_service.bare"]

    def test_ftp_state_is_read_from_the_site_config_block(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.HCL)
        assert "APPSVC_FTP_ENABLED" in found["azurerm_app_service.legacy"]
        assert "APPSVC_FTP_ENABLED" not in found["azurerm_app_service.modern"]

    def test_plan_json_with_site_config_as_a_block_list(self) -> None:
        found = _scan_plan(
            ("azurerm_app_service", "a", {"site_config": [{"min_tls_version": "1.2"}]}),
            ("azurerm_app_service", "b", {"site_config": [{"min_tls_version": None}]}),
            ("azurerm_app_service", "c", {"site_config": []}),
        )
        assert "APPSVC_OLD_TLS" not in found["azurerm_app_service.a"]
        assert "APPSVC_OLD_TLS" in found["azurerm_app_service.b"]
        assert "APPSVC_OLD_TLS" in found["azurerm_app_service.c"]

    def test_auth_settings_block(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_app_service" "off" {
              name = "off"
              auth_settings {
                enabled = false
              }
            }
            resource "azurerm_app_service" "on" {
              name = "on"
              auth_settings {
                enabled = true
              }
            }
            """,
        )
        assert "APPSVC_NO_AUTH" in found["azurerm_app_service.off"]
        assert "APPSVC_NO_AUTH" not in found["azurerm_app_service.on"]


class TestFunctionApp:
    def test_http2_is_read_from_the_site_config_block(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_function_app" "old" {
              name = "old"
              site_config {
                http2_enabled = false
              }
            }
            resource "azurerm_function_app" "new" {
              name = "new"
              site_config {
                http2_enabled = true
              }
            }
            """,
        )
        assert "FUNC_HTTP_V1" in found["azurerm_function_app.old"]
        assert "FUNC_HTTP_V1" not in found["azurerm_function_app.new"]


class TestMonitor:
    def test_retention_days_inside_the_log_block(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_monitor_diagnostic_setting" "short" {
              name = "short"
              log {
                category = "Audit"
                retention_policy {
                  enabled = true
                  days    = 30
                }
              }
            }
            resource "azurerm_monitor_diagnostic_setting" "long" {
              name = "long"
              log {
                category = "Audit"
                retention_policy {
                  enabled = true
                  days    = 365
                }
              }
            }
            resource "azurerm_monitor_diagnostic_setting" "none" {
              name = "none"
            }
            """,
        )
        assert "MONITOR_SHORT_RETENTION" in found["azurerm_monitor_diagnostic_setting.short"]
        assert "MONITOR_SHORT_RETENTION" not in found["azurerm_monitor_diagnostic_setting.long"]
        assert (
            "MONITOR_NO_DIAGNOSTIC_SETTING" not in found["azurerm_monitor_diagnostic_setting.short"]
        )
        assert "MONITOR_NO_DIAGNOSTIC_SETTING" in found["azurerm_monitor_diagnostic_setting.none"]


class TestAzureTypingBoundaries:
    def test_key_vault_companions_do_not_get_vault_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_key_vault" "kv" {
              name = "kv"
            }
            resource "azurerm_key_vault_access_policy" "policy" {
              key_vault_id = "id"
              tenant_id    = "t"
              object_id    = "o"
            }
            resource "azurerm_key_vault_secret" "secret" {
              name         = "s"
              key_vault_id = "id"
            }
            """,
        )
        assert "KEYVAULT_NO_NETWORK_ACLS" in found["azurerm_key_vault.kv"]
        assert not found.get("azurerm_key_vault_access_policy.policy")
        assert not found.get("azurerm_key_vault_secret.secret")

    def test_aks_node_pools_do_not_get_cluster_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_kubernetes_cluster" "aks" {
              name = "aks"
            }
            resource "azurerm_kubernetes_cluster_node_pool" "pool" {
              name = "pool"
              kubernetes_cluster_id = "id"
            }
            """,
        )
        assert "AKS_NO_NETWORK_POLICY" in found["azurerm_kubernetes_cluster.aks"]
        assert not found.get("azurerm_kubernetes_cluster_node_pool.pool")

    def test_vm_extensions_and_scale_sets_do_not_get_vm_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_virtual_machine" "vm" {
              name = "vm"
            }
            resource "azurerm_virtual_machine_extension" "ext" {
              name = "ext"
            }
            resource "azurerm_virtual_machine_scale_set" "set" {
              name = "set"
            }
            """,
        )
        assert "AZURE_VM_NO_DISK_ENCRYPTION" in found["azurerm_virtual_machine.vm"]
        assert not found.get("azurerm_virtual_machine_extension.ext")
        assert not found.get("azurerm_virtual_machine_scale_set.set")

    def test_storage_account_companions_do_not_get_account_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_storage_account" "sa" {
              name = "sa"
            }
            resource "azurerm_storage_account_network_rules" "rules" {
              storage_account_id = "id"
            }
            resource "azurerm_storage_container" "c" {
              name = "c"
            }
            """,
        )
        assert "AZURE_STORAGE_NO_NETWORK_RULES" in found["azurerm_storage_account.sa"]
        assert not found.get("azurerm_storage_account_network_rules.rules")
        assert not found.get("azurerm_storage_container.c")

    def test_network_security_group_is_not_a_network_security_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_network_security_group" "nsg" {
              name = "nsg"
            }
            resource "azurerm_network_security_rule" "ssh" {
              name                       = "ssh"
              direction                  = "Inbound"
              access                     = "Allow"
              destination_port_range     = "22"
              source_address_prefix      = "*"
            }
            """,
        )
        assert not found.get("azurerm_network_security_group.nsg")
        assert {"AZURE_NSG_SSH_OPEN", "AZURE_NSG_ALLOW_ALL_INBOUND"} <= found[
            "azurerm_network_security_rule.ssh"
        ]
