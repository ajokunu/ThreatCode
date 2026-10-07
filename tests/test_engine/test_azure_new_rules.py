"""Azure rules: network logic, provider versions, joined facts, defaults and calibration."""

from __future__ import annotations

import json
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import is_deprecated, is_revoked, lookup_technique
from threatcode.engine.rules.loader import (
    CONFIDENCE_LEVELS,
    Rule,
    deprecated_rule_ids,
    load_builtin_rules,
)
from threatcode.ir.enrich import DERIVED, apply_defaults, enrich
from threatcode.ir.enrichment import azure as azure_enrichment
from threatcode.ir.graph import InfraGraph
from threatcode.ir.references import ReferenceIndex
from threatcode.parsers import detect_and_parse
from threatcode.parsers.terraform_plan import TerraformPlanParser
from threatcode.values import Unknown

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
AZURE_RULE_DIR = REPO_ROOT / "src" / "threatcode" / "engine" / "rules" / "builtin" / "azure"


def _azure_rules() -> list[Rule]:
    return [r for r in load_builtin_rules() if r.source_group.startswith("azure__")]


def _findings(graph: InfraGraph) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for threat in HybridEngine().analyze(graph).threats:
        if threat.rule_id:
            found[threat.resource_address].add(threat.rule_id)
    return found


def _with_defaults(graph: InfraGraph, format_type: str) -> InfraGraph:
    """Enrich the graph again as a graph that records its parser format would.

    The graph builder does not record node formats yet, so provider defaults stay inert in a
    plain scan; this is the one place the tests switch them on.
    """
    graph.node_formats = {  # type: ignore[attr-defined]
        node_id: format_type for node_id in graph.nodes
    }
    for node in graph.nodes.values():
        node.properties.pop(DERIVED, None)
    enrich(graph, ReferenceIndex(graph.nodes))
    return graph


def _scan_hcl(tmp_path: Path, source: str, *, defaults: bool = False) -> dict[str, set[str]]:
    """Rule ids per resource address for a Terraform HCL snippet."""
    path = tmp_path / "main.tf"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    parsed = detect_and_parse(path)
    graph = InfraGraph.from_parsed(parsed)
    if defaults:
        graph = _with_defaults(graph, parsed.format_type)
    return _findings(graph)


def _plan_document(*resources: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    return {
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


def _scan_plan(*resources: tuple[str, str, dict[str, Any]]) -> dict[str, set[str]]:
    """Rule ids per resource address for (type, name, values) entries of a plan JSON."""
    plan = _plan_document(*resources)
    return _findings(InfraGraph.from_parsed(TerraformPlanParser().parse(plan)))


def _graph_for(tmp_path: Path, source: str, *, defaults: bool = False) -> InfraGraph:
    path = tmp_path / "main.tf"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    parsed = detect_and_parse(path)
    graph = InfraGraph.from_parsed(parsed)
    return _with_defaults(graph, parsed.format_type) if defaults else graph


def _derived(graph: InfraGraph, node_id: str) -> dict[str, Any]:
    derived = graph.nodes[node_id].properties[DERIVED]
    assert isinstance(derived, dict)
    return derived


# ---------------------------------------------------------------------------
# The rule set
# ---------------------------------------------------------------------------

AZURE_RULE_IDS = {
    # Network
    "AZURE_NSG_ALLOW_ALL_INBOUND",
    "AZURE_NSG_SSH_OPEN",
    "AZURE_NSG_RDP_OPEN",
    "AZURE_NSG_DATABASE_PORT_OPEN",
    "AZURE_NSG_WEB_PORT_OPEN",
    "AZURE_VNET_NO_DDOS",
    # Storage
    "AZURE_STORAGE_NO_HTTPS",
    "AZURE_STORAGE_PUBLIC_ACCESS",
    "AZURE_STORAGE_CONTAINER_PUBLIC",
    "AZURE_STORAGE_NO_NETWORK_RULES",
    "AZURE_STORAGE_NO_SOFT_DELETE",
    # Key Vault
    "KEYVAULT_SHORT_SOFT_DELETE_RETENTION",
    "KEYVAULT_NO_PURGE_PROTECTION",
    "KEYVAULT_NO_NETWORK_ACLS",
    "KEYVAULT_PUBLIC_ACCESS",
    "KEYVAULT_NO_DIAGNOSTICS",
    # App Service and Functions
    "APPSVC_HTTP_ONLY",
    "APPSVC_NO_MANAGED_IDENTITY",
    "APPSVC_OLD_TLS",
    "APPSVC_FTP_ENABLED",
    "APPSVC_NO_AUTH",
    "FUNC_NO_MANAGED_IDENTITY",
    "FUNC_NO_HTTPS",
    "FUNC_PUBLIC_ACCESS",
    # SQL
    "MSSQL_NO_AUDITING",
    "MSSQL_NO_TDE",
    "MSSQL_NO_THREAT_DETECTION",
    "MSSQL_PUBLIC_ACCESS",
    "AZURE_SQL_NO_AUDIT",
    "AZURE_SQL_NO_THREAT_DETECTION",
    # Cosmos DB
    "COSMOS_PUBLIC_ACCESS",
    "COSMOS_NO_VNET_RULES",
    "COSMOS_NO_CMK",
    # Monitor
    "MONITOR_NO_ACTIVITY_LOG_ALERT",
    "MONITOR_NO_DIAGNOSTIC_SETTING",
    "MONITOR_SHORT_RETENTION",
    # Compute
    "AZURE_VM_NO_DISK_ENCRYPTION",
    "AZURE_VM_PASSWORD_AUTH",
    "AZURE_VM_NO_MANAGED_IDENTITY",
    "AZURE_VM_PUBLIC_IP",
    # AKS, Container Registry, Redis
    "AKS_NO_RBAC",
    "AKS_NO_NETWORK_POLICY",
    "AKS_NO_PRIVATE_CLUSTER",
    "ACR_ADMIN_ENABLED",
    "ACR_PUBLIC_NETWORK_ACCESS",
    "ACR_ANONYMOUS_PULL",
    "REDIS_NON_SSL_PORT",
    "REDIS_OLD_TLS",
    "REDIS_PUBLIC_NETWORK_ACCESS",
}

DELETED_RULE_IDS = {
    "KEYVAULT_NO_SOFT_DELETE",
    "AZURE_VM_NO_EXTENSIONS",
    "FUNC_HTTP_V1",
    "COSMOS_NO_ANALYTICAL_STORAGE",
    "AZURE_SQL_NO_ENCRYPTION",
    "AZURE_SQL_PUBLIC_ACCESS",
}


class TestRuleSet:
    def test_the_azure_rules_are_exactly_the_documented_set(self) -> None:
        assert {r.id for r in _azure_rules()} == AZURE_RULE_IDS

    def test_new_rule_files_load_as_their_own_groups(self) -> None:
        groups = {r.source_group for r in _azure_rules()}
        assert {"azure__container_registry", "azure__redis_cache"} <= groups

    def test_deleted_rules_are_gone_and_recorded_as_deprecated(self) -> None:
        loaded = {r.id for r in load_builtin_rules()}
        assert not DELETED_RULE_IDS & loaded
        assert DELETED_RULE_IDS <= deprecated_rule_ids()

    def test_the_new_provider_resource_types_have_rules(self) -> None:
        covered = {t for r in _azure_rules() for t in r.resource_types}
        assert {
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
            "azurerm_linux_function_app",
            "azurerm_windows_function_app",
            "azurerm_windows_virtual_machine",
            "azurerm_container_registry",
            "azurerm_redis_cache",
        } <= covered


class TestCalibration:
    """The rule calibration convention, applied to the Azure rules."""

    def test_every_rule_declares_its_confidence(self) -> None:
        for path in sorted(AZURE_RULE_DIR.glob("*.yml")):
            for raw in yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]:
                assert raw.get("confidence") in CONFIDENCE_LEVELS, f"{raw['id']} in {path.name}"

    def test_severity_never_exceeds_what_the_confidence_supports(self) -> None:
        caps = {"definitive": "critical", "heuristic": "high", "absence": "medium"}
        order = ["info", "low", "medium", "high", "critical"]
        for rule in _azure_rules():
            assert order.index(rule.severity) <= order.index(caps[rule.confidence]), rule.id

    def test_critical_is_reserved_for_the_two_direct_exposures(self) -> None:
        critical = {r.id for r in _azure_rules() if r.severity == "critical"}
        assert critical == {"AZURE_NSG_ALLOW_ALL_INBOUND", "AKS_NO_RBAC"}

    def test_every_technique_exists_and_is_current(self) -> None:
        for rule in _azure_rules():
            for technique in rule.metadata.get("mitre", {}).get("techniques", []):
                assert lookup_technique(technique) is not None, f"{rule.id}: {technique}"
                assert not is_revoked(technique), f"{rule.id}: {technique} is revoked"
                assert not is_deprecated(technique), f"{rule.id}: {technique} is deprecated"

    def test_tactics_are_derived_from_techniques_not_written_by_hand(self) -> None:
        for rule in _azure_rules():
            assert "tactics" not in rule.metadata.get("mitre", {}), rule.id

    def test_detection_gaps_are_repudiation_without_an_adversary_technique(self) -> None:
        detection = {
            "KEYVAULT_NO_DIAGNOSTICS",
            "MSSQL_NO_AUDITING",
            "MSSQL_NO_THREAT_DETECTION",
            "AZURE_SQL_NO_AUDIT",
            "AZURE_SQL_NO_THREAT_DETECTION",
            "MONITOR_NO_ACTIVITY_LOG_ALERT",
            "MONITOR_NO_DIAGNOSTIC_SETTING",
            "MONITOR_SHORT_RETENTION",
        }
        rules = {r.id: r for r in _azure_rules()}
        for rule_id in detection:
            assert rules[rule_id].stride_category == "repudiation", rule_id
            assert not rules[rule_id].metadata.get("mitre"), rule_id

    def test_recoverability_controls_use_denial_of_service(self) -> None:
        recoverability = {
            "KEYVAULT_SHORT_SOFT_DELETE_RETENTION",
            "KEYVAULT_NO_PURGE_PROTECTION",
            "AZURE_STORAGE_NO_SOFT_DELETE",
        }
        rules = {r.id: r for r in _azure_rules()}
        for rule_id in recoverability:
            assert rules[rule_id].stride_category == "denial_of_service", rule_id

    def test_exposed_admin_services_map_to_external_remote_services(self) -> None:
        rules = {r.id: r for r in _azure_rules()}
        for rule_id in ("AZURE_NSG_SSH_OPEN", "AZURE_NSG_RDP_OPEN"):
            assert "T1133" in rules[rule_id].metadata["mitre"]["techniques"]

    def test_absence_rules_say_so_and_are_never_above_medium(self) -> None:
        rules = {r.id: r for r in _azure_rules()}
        for rule_id in ("AKS_NO_NETWORK_POLICY", "KEYVAULT_NO_NETWORK_ACLS", "MSSQL_NO_AUDITING"):
            assert rules[rule_id].confidence == "absence", rule_id
            assert rules[rule_id].severity in {"low", "medium"}, rule_id

    def test_findings_that_share_a_cause_share_a_root_cause(self) -> None:
        by_cause: dict[str, set[str]] = defaultdict(set)
        for rule in _azure_rules():
            if rule.root_cause:
                by_cause[rule.root_cause].add(rule.id)
        assert by_cause["nsg-world-ingress"] == {
            "AZURE_NSG_ALLOW_ALL_INBOUND",
            "AZURE_NSG_SSH_OPEN",
            "AZURE_NSG_RDP_OPEN",
            "AZURE_NSG_DATABASE_PORT_OPEN",
            "AZURE_NSG_WEB_PORT_OPEN",
        }


# ---------------------------------------------------------------------------
# Network security groups
# ---------------------------------------------------------------------------

NSG_RULES = {
    "AZURE_NSG_ALLOW_ALL_INBOUND",
    "AZURE_NSG_SSH_OPEN",
    "AZURE_NSG_RDP_OPEN",
    "AZURE_NSG_DATABASE_PORT_OPEN",
    "AZURE_NSG_WEB_PORT_OPEN",
}
SSH, RDP, DB, WEB, ALL = (
    "AZURE_NSG_SSH_OPEN",
    "AZURE_NSG_RDP_OPEN",
    "AZURE_NSG_DATABASE_PORT_OPEN",
    "AZURE_NSG_WEB_PORT_OPEN",
    "AZURE_NSG_ALLOW_ALL_INBOUND",
)

# (case id, rule attributes, the NSG rules that fire)
NSG_TABLE: list[tuple[str, dict[str, Any], set[str]]] = [
    ("https from anywhere is only a web port", {"port": "443", "source": "*"}, {WEB}),
    ("https from the internet tag", {"port": "443", "source": "Internet"}, {WEB}),
    ("https from a service tag", {"port": "443", "source": "AzureFrontDoor.Backend"}, set()),
    ("ssh from a private range", {"port": "22", "source": "10.0.0.0/24"}, set()),
    ("ssh from anywhere", {"port": "22", "source": "*"}, {SSH}),
    ("ssh from 0.0.0.0/0", {"port": "22", "source": "0.0.0.0/0"}, {SSH}),
    ("rdp from ::/0", {"port": "3389", "source": "::/0"}, {RDP}),
    (
        "a port list holding ssh and rdp",
        {"ports": ["3389", "22"], "source": "0.0.0.0/0"},
        {SSH, RDP},
    ),
    ("a port range holding ssh", {"port": "20-25", "source": "Internet"}, {SSH}),
    ("a port range around rdp", {"port": "3380-3400", "source": "*"}, {RDP}),
    (
        "a source list holding the internet",
        {"port": "22", "sources": ["10.1.0.0/16", "Any"]},
        {SSH},
    ),
    (
        "a source list of private ranges",
        {"port": "22", "sources": ["10.1.0.0/16", "172.16.0.0/12"]},
        set(),
    ),
    ("sql server from anywhere", {"port": "1433", "source": "*"}, {DB}),
    ("redis and mongodb in a list", {"ports": ["6379", "27017"], "source": "Internet"}, {DB}),
    ("web and database in a list", {"ports": ["80", "1433"], "source": "*"}, {WEB, DB}),
    ("a wide range", {"port": "1-1000", "source": "*"}, {SSH, WEB}),
    ("every port with a star", {"port": "*", "protocol": "*", "source": "*"}, {ALL}),
    ("every port over tcp", {"port": "*", "protocol": "Tcp", "source": "Internet"}, {ALL}),
    ("the full numeric range", {"port": "0-65535", "source": "*"}, {ALL}),
    ("a list holding the star", {"ports": ["443", "*"], "source": "*"}, {ALL}),
    (
        "every port from a private range",
        {"port": "*", "protocol": "*", "source": "10.0.0.0/8"},
        set(),
    ),
    ("every port from the virtual network", {"port": "*", "source": "VirtualNetwork"}, set()),
    ("a deny rule", {"port": "22", "source": "*", "access": "Deny"}, set()),
    ("a deny all rule", {"port": "*", "protocol": "*", "source": "*", "access": "Deny"}, set()),
    ("an outbound rule", {"port": "22", "source": "*", "direction": "Outbound"}, set()),
    (
        "an outbound allow all",
        {"port": "*", "protocol": "*", "source": "*", "direction": "Outbound"},
        set(),
    ),
    ("ssh over udp", {"port": "22", "source": "*", "protocol": "Udp"}, set()),
    ("icmp from anywhere", {"port": "*", "source": "*", "protocol": "Icmp"}, set()),
    (
        "lower case direction and access",
        {"port": "22", "source": "*", "direction": "inbound", "access": "allow"},
        {SSH},
    ),
]

_NSG_DEFAULTS: dict[str, Any] = {
    "port": "22",
    "ports": None,
    "source": "*",
    "sources": None,
    "protocol": "Tcp",
    "access": "Allow",
    "direction": "Inbound",
}


def _hcl_value(value: Any) -> str:
    return json.dumps(value)


def _nsg_attributes(spec: dict[str, Any], indent: str) -> str:
    merged = {**_NSG_DEFAULTS, **spec}
    lines = [
        f"{indent}name                       = {_hcl_value('r')}",
        f"{indent}priority                   = 100",
        f"{indent}direction                  = {_hcl_value(merged['direction'])}",
        f"{indent}access                     = {_hcl_value(merged['access'])}",
        f"{indent}protocol                   = {_hcl_value(merged['protocol'])}",
        f'{indent}source_port_range          = "*"',
        f'{indent}destination_address_prefix = "*"',
    ]
    if merged["ports"]:
        lines.append(f"{indent}destination_port_ranges    = {_hcl_value(merged['ports'])}")
    else:
        lines.append(f"{indent}destination_port_range     = {_hcl_value(merged['port'])}")
    if merged["sources"]:
        lines.append(f"{indent}source_address_prefixes    = {_hcl_value(merged['sources'])}")
    else:
        lines.append(f"{indent}source_address_prefix       = {_hcl_value(merged['source'])}")
    return "\n".join(lines) + "\n"


def _inline_nsg(spec: dict[str, Any]) -> str:
    return (
        'resource "azurerm_network_security_group" "nsg" {\n'
        '  name                = "nsg"\n'
        '  location            = "eastus"\n'
        '  resource_group_name = "rg"\n\n'
        "  security_rule {\n" + _nsg_attributes(spec, "    ") + "  }\n}\n"
    )


def _standalone_nsg(spec: dict[str, Any]) -> str:
    return (
        'resource "azurerm_network_security_rule" "rule" {\n'
        + _nsg_attributes(spec, "  ")
        + '  resource_group_name         = "rg"\n'
        '  network_security_group_name = "nsg"\n}\n'
    )


class TestNetworkSecurityRules:
    @pytest.mark.parametrize(("case", "spec", "expected"), NSG_TABLE, ids=[c[0] for c in NSG_TABLE])
    def test_an_inline_security_rule_block(
        self, tmp_path: Path, case: str, spec: dict[str, Any], expected: set[str]
    ) -> None:
        found = _scan_hcl(tmp_path, _inline_nsg(spec))
        assert found["azurerm_network_security_group.nsg"] & NSG_RULES == expected, case

    @pytest.mark.parametrize(("case", "spec", "expected"), NSG_TABLE, ids=[c[0] for c in NSG_TABLE])
    def test_a_standalone_security_rule_gives_the_same_answer(
        self, tmp_path: Path, case: str, spec: dict[str, Any], expected: set[str]
    ) -> None:
        found = _scan_hcl(tmp_path, _standalone_nsg(spec))
        assert found["azurerm_network_security_rule.rule"] & NSG_RULES == expected, case

    def test_443_from_anywhere_is_not_an_allow_all_finding(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, _standalone_nsg({"port": "443", "source": "*"}))
        assert ALL not in found["azurerm_network_security_rule.rule"]

    def test_a_group_is_judged_on_each_of_its_blocks(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_network_security_group" "nsg" {
              name                = "nsg"
              location            = "eastus"
              resource_group_name = "rg"

              security_rule {
                name                       = "web"
                priority                   = 100
                direction                  = "Inbound"
                access                     = "Allow"
                protocol                   = "Tcp"
                source_port_range          = "*"
                destination_port_range     = "443"
                source_address_prefix      = "Internet"
                destination_address_prefix = "*"
              }
              security_rule {
                name                       = "ssh"
                priority                   = 110
                direction                  = "Inbound"
                access                     = "Allow"
                protocol                   = "Tcp"
                source_port_range          = "*"
                destination_port_range     = "22"
                source_address_prefix      = "10.50.10.0/24"
                destination_address_prefix = "*"
              }
              security_rule {
                name                       = "rdp"
                priority                   = 120
                direction                  = "Inbound"
                access                     = "Allow"
                protocol                   = "Tcp"
                source_port_range          = "*"
                destination_port_range     = "3389"
                source_address_prefix      = "*"
                destination_address_prefix = "*"
              }
            }
            """,
        )
        assert found["azurerm_network_security_group.nsg"] & NSG_RULES == {WEB, RDP}

    def test_a_group_with_a_standalone_rule_is_not_double_reported(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            _inline_nsg({"port": "22", "source": "10.0.0.0/24"})
            + _standalone_nsg({"port": "22", "source": "*"}),
        )
        assert found["azurerm_network_security_group.nsg"] & NSG_RULES == set()
        assert found["azurerm_network_security_rule.rule"] & NSG_RULES == {SSH}

    def test_a_group_is_not_a_security_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_network_security_group" "nsg" {
              name                = "nsg"
              location            = "eastus"
              resource_group_name = "rg"
            }
            """,
        )
        assert not found.get("azurerm_network_security_group.nsg")

    def test_plan_json_inline_rules_are_a_list_of_objects(self) -> None:
        def rule(name: str, port: str, source: str) -> dict[str, Any]:
            return {
                "name": name,
                "direction": "Inbound",
                "access": "Allow",
                "protocol": "Tcp",
                "destination_port_range": port,
                "destination_port_ranges": [],
                "source_address_prefix": source,
                "source_address_prefixes": [],
            }

        found = _scan_plan(
            (
                "azurerm_network_security_group",
                "app",
                {"security_rule": [rule("ssh", "22", "*"), rule("https", "443", "Internet")]},
            ),
            (
                "azurerm_network_security_group",
                "private",
                {"security_rule": [rule("ssh", "22", "10.50.10.0/24")]},
            ),
        )
        assert found["azurerm_network_security_group.app"] & NSG_RULES == {SSH, WEB}
        assert found["azurerm_network_security_group.private"] & NSG_RULES == set()

    def test_plan_json_port_lists_are_read(self) -> None:
        found = _scan_plan(
            (
                "azurerm_network_security_rule",
                "admin",
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "destination_port_range": None,
                    "destination_port_ranges": ["3389", "22"],
                    "source_address_prefix": "0.0.0.0/0",
                    "source_address_prefixes": None,
                },
            )
        )
        assert found["azurerm_network_security_rule.admin"] & NSG_RULES == {SSH, RDP}

    def test_an_unknown_source_never_fires(self) -> None:
        found = _scan_plan(
            (
                "azurerm_network_security_rule",
                "ssh",
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": "Tcp",
                    "destination_port_range": "22",
                    "source_address_prefix": Unknown("var.admin_cidr"),
                },
            )
        )
        assert not found.get("azurerm_network_security_rule.ssh", set()) & NSG_RULES


class TestRealisticNetworkInputs:
    def _scan(self, name: str) -> dict[str, set[str]]:
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES / "realistic" / name))
        return _findings(graph)

    def test_the_planted_allow_all_in_the_web_app_group_fires(self) -> None:
        found = self._scan("07_azure_webapp_java.tf")
        assert ALL in found["azurerm_network_security_group.app"]

    def test_the_management_subnet_ssh_rule_does_not_fire(self, tmp_path: Path) -> None:
        # The group's other findings come from TempAllowAll_RemoveMe, so isolate the SSH rule
        source = (FIXTURES / "realistic" / "07_azure_webapp_java.tf").read_text(encoding="utf-8")
        start = source.index('  security_rule {\n    name                       = "TempAllowAll')
        end = source.index('  security_rule {\n    name                       = "AllowSSHFromMgmt"')
        without_temp = source[:start] + source[end:]
        found = _scan_hcl(tmp_path, without_temp)
        assert found["azurerm_network_security_group.app"] & NSG_RULES == set()

    def test_the_all_ports_block_is_reported_once_not_once_per_port(self) -> None:
        found = self._scan("07_azure_webapp_java.tf")
        assert found["azurerm_network_security_group.app"] & NSG_RULES == {ALL}

    def test_the_cluster_group_reports_the_open_http_port(self) -> None:
        found = self._scan("02_azure_kubernetes_cluster.tf")
        assert found["azurerm_network_security_group.aks"] & NSG_RULES == {WEB}

    def test_the_plan_with_an_open_group_and_an_open_rdp_rule(self) -> None:
        path = FIXTURES / "real_shapes" / "terraform" / "plan" / "azure_network.plan.json"
        found = _findings(InfraGraph.from_parsed(detect_and_parse(path)))
        assert found["azurerm_network_security_group.app"] & NSG_RULES == {SSH, WEB}
        assert found["azurerm_network_security_rule.rdp"] & NSG_RULES == {RDP}


# ---------------------------------------------------------------------------
# azurerm 3.x and 4.x
# ---------------------------------------------------------------------------


class TestStorageAttributeNames:
    def test_both_https_names_fire(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_storage_account" "v3" {
              name                      = "v3"
              enable_https_traffic_only = false
            }
            resource "azurerm_storage_account" "v4" {
              name                       = "v4"
              https_traffic_only_enabled = false
            }
            resource "azurerm_storage_account" "ok3" {
              name                      = "ok3"
              enable_https_traffic_only = true
            }
            resource "azurerm_storage_account" "ok4" {
              name                       = "ok4"
              https_traffic_only_enabled = true
            }
            resource "azurerm_storage_account" "default" {
              name = "default"
            }
            """,
        )
        assert "AZURE_STORAGE_NO_HTTPS" in found["azurerm_storage_account.v3"]
        assert "AZURE_STORAGE_NO_HTTPS" in found["azurerm_storage_account.v4"]
        assert "AZURE_STORAGE_NO_HTTPS" not in found["azurerm_storage_account.ok3"]
        assert "AZURE_STORAGE_NO_HTTPS" not in found["azurerm_storage_account.ok4"]
        assert "AZURE_STORAGE_NO_HTTPS" not in found["azurerm_storage_account.default"]

    def test_both_public_access_names_fire(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_storage_account" "v2" {
              name                     = "v2"
              allow_blob_public_access = true
            }
            resource "azurerm_storage_account" "v3" {
              name                            = "v3"
              allow_nested_items_to_be_public = true
            }
            resource "azurerm_storage_account" "closed" {
              name                            = "closed"
              allow_nested_items_to_be_public = false
              allow_blob_public_access        = false
            }
            """,
        )
        assert "AZURE_STORAGE_PUBLIC_ACCESS" in found["azurerm_storage_account.v2"]
        assert "AZURE_STORAGE_PUBLIC_ACCESS" in found["azurerm_storage_account.v3"]
        assert "AZURE_STORAGE_PUBLIC_ACCESS" not in found["azurerm_storage_account.closed"]

    def test_an_omitted_public_access_attribute_fires_once_defaults_apply(
        self, tmp_path: Path
    ) -> None:
        source = """
            resource "azurerm_storage_account" "bare" {
              name = "bare"
            }
        """
        assert (
            "AZURE_STORAGE_PUBLIC_ACCESS"
            not in _scan_hcl(tmp_path, source)["azurerm_storage_account.bare"]
        )
        found = _scan_hcl(tmp_path, source, defaults=True)
        assert "AZURE_STORAGE_PUBLIC_ACCESS" in found["azurerm_storage_account.bare"]

    def test_public_containers_are_flagged_and_private_ones_are_not(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_storage_container" "blob" {
              name                  = "a"
              container_access_type = "blob"
            }
            resource "azurerm_storage_container" "container" {
              name                  = "b"
              container_access_type = "container"
            }
            resource "azurerm_storage_container" "private" {
              name                  = "c"
              container_access_type = "private"
            }
            resource "azurerm_storage_container" "default" {
              name = "d"
            }
            """,
        )
        assert "AZURE_STORAGE_CONTAINER_PUBLIC" in found["azurerm_storage_container.blob"]
        assert "AZURE_STORAGE_CONTAINER_PUBLIC" in found["azurerm_storage_container.container"]
        assert not found.get("azurerm_storage_container.private")
        assert not found.get("azurerm_storage_container.default")


class TestAppService:
    HCL = """
        resource "azurerm_app_service" "old_tls" {
          name = "old"
          site_config {
            min_tls_version = "1.0"
          }
        }
        resource "azurerm_app_service" "modern" {
          name = "modern"
          site_config {
            min_tls_version = "1.2"
            ftps_state      = "FtpsOnly"
          }
        }
        resource "azurerm_app_service" "bare" {
          name = "bare"
        }
        resource "azurerm_linux_web_app" "old_tls" {
          name = "old"
          site_config {
            minimum_tls_version = "1.1"
          }
        }
        resource "azurerm_linux_web_app" "modern" {
          name = "modern"
          site_config {
            minimum_tls_version = "1.2"
          }
        }
        resource "azurerm_windows_web_app" "bare" {
          name        = "bare"
          site_config {}
        }
    """

    def test_old_tls_fires_for_an_explicit_old_version_in_either_attribute_name(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(tmp_path, self.HCL)
        assert "APPSVC_OLD_TLS" in found["azurerm_app_service.old_tls"]
        assert "APPSVC_OLD_TLS" in found["azurerm_linux_web_app.old_tls"]
        assert "APPSVC_OLD_TLS" not in found["azurerm_app_service.modern"]
        assert "APPSVC_OLD_TLS" not in found["azurerm_linux_web_app.modern"]

    def test_an_omitted_minimum_tls_version_is_the_secure_default(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.HCL)
        assert "APPSVC_OLD_TLS" not in found["azurerm_app_service.bare"]
        assert "APPSVC_OLD_TLS" not in found["azurerm_windows_web_app.bare"]

    def test_plan_json_with_site_config_as_a_block_list(self) -> None:
        found = _scan_plan(
            ("azurerm_app_service", "a", {"site_config": [{"min_tls_version": "1.2"}]}),
            ("azurerm_app_service", "b", {"site_config": [{"min_tls_version": "1.0"}]}),
            ("azurerm_app_service", "c", {"site_config": []}),
            ("azurerm_linux_web_app", "d", {"site_config": [{"minimum_tls_version": "1.0"}]}),
        )
        assert "APPSVC_OLD_TLS" not in found["azurerm_app_service.a"]
        assert "APPSVC_OLD_TLS" in found["azurerm_app_service.b"]
        assert "APPSVC_OLD_TLS" not in found["azurerm_app_service.c"]
        assert "APPSVC_OLD_TLS" in found["azurerm_linux_web_app.d"]

    def test_ftp_state_is_read_from_the_site_config_block_of_every_type(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_app_service" "legacy" {
              name = "legacy"
              site_config {
                ftps_state = "AllAllowed"
              }
            }
            resource "azurerm_windows_web_app" "new" {
              name = "new"
              site_config {
                ftps_state = "AllAllowed"
              }
            }
            resource "azurerm_linux_web_app" "closed" {
              name = "closed"
              site_config {
                ftps_state = "Disabled"
              }
            }
            """,
        )
        assert "APPSVC_FTP_ENABLED" in found["azurerm_app_service.legacy"]
        assert "APPSVC_FTP_ENABLED" in found["azurerm_windows_web_app.new"]
        assert "APPSVC_FTP_ENABLED" not in found["azurerm_linux_web_app.closed"]

    def test_https_only_false_fires_on_every_app_type(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_app_service" "legacy" {
              name       = "legacy"
              https_only = false
            }
            resource "azurerm_linux_web_app" "linux" {
              name       = "linux"
              https_only = false
            }
            resource "azurerm_windows_web_app" "windows" {
              name       = "windows"
              https_only = false
            }
            resource "azurerm_linux_web_app" "safe" {
              name       = "safe"
              https_only = true
            }
            """,
        )
        for address in (
            "azurerm_app_service.legacy",
            "azurerm_linux_web_app.linux",
            "azurerm_windows_web_app.windows",
        ):
            assert "APPSVC_HTTP_ONLY" in found[address], address
        assert "APPSVC_HTTP_ONLY" not in found["azurerm_linux_web_app.safe"]

    def test_an_omitted_https_only_fires_once_defaults_apply(self, tmp_path: Path) -> None:
        source = """
            resource "azurerm_linux_web_app" "bare" {
              name = "bare"
            }
        """
        assert "APPSVC_HTTP_ONLY" not in _scan_hcl(tmp_path, source)["azurerm_linux_web_app.bare"]
        found = _scan_hcl(tmp_path, source, defaults=True)
        assert "APPSVC_HTTP_ONLY" in found["azurerm_linux_web_app.bare"]

    def test_authentication_is_read_in_both_block_shapes(self, tmp_path: Path) -> None:
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
            resource "azurerm_linux_web_app" "v2_off" {
              name = "v2off"
              auth_settings_v2 {
                auth_enabled = false
              }
            }
            resource "azurerm_linux_web_app" "v2_on" {
              name = "v2on"
              auth_settings_v2 {
                auth_enabled = true
              }
            }
            """,
        )
        assert "APPSVC_NO_AUTH" in found["azurerm_app_service.off"]
        assert "APPSVC_NO_AUTH" not in found["azurerm_app_service.on"]
        assert "APPSVC_NO_AUTH" in found["azurerm_linux_web_app.v2_off"]
        assert "APPSVC_NO_AUTH" not in found["azurerm_linux_web_app.v2_on"]

    def test_managed_identity_on_the_new_types(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_linux_web_app" "bare" {
              name = "bare"
            }
            resource "azurerm_windows_web_app" "with_identity" {
              name = "with"
              identity {
                type = "SystemAssigned"
              }
            }
            """,
        )
        assert "APPSVC_NO_MANAGED_IDENTITY" in found["azurerm_linux_web_app.bare"]
        assert "APPSVC_NO_MANAGED_IDENTITY" not in found["azurerm_windows_web_app.with_identity"]


class TestFunctionApp:
    def test_https_only_on_every_function_app_type(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_function_app" "legacy" {
              name       = "legacy"
              https_only = false
            }
            resource "azurerm_linux_function_app" "linux" {
              name       = "linux"
              https_only = false
            }
            resource "azurerm_windows_function_app" "windows" {
              name       = "windows"
              https_only = true
            }
            """,
        )
        assert "FUNC_NO_HTTPS" in found["azurerm_function_app.legacy"]
        assert "FUNC_NO_HTTPS" in found["azurerm_linux_function_app.linux"]
        assert "FUNC_NO_HTTPS" not in found["azurerm_windows_function_app.windows"]

    def test_public_access_is_softened_by_an_ip_restriction(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_linux_function_app" "open" {
              name                          = "open"
              public_network_access_enabled = true
              site_config {}
            }
            resource "azurerm_windows_function_app" "restricted" {
              name                          = "restricted"
              public_network_access_enabled = true
              site_config {
                ip_restriction {
                  ip_address = "203.0.113.0/24"
                  action     = "Allow"
                  priority   = 100
                }
              }
            }
            """,
        )
        assert "FUNC_PUBLIC_ACCESS" in found["azurerm_linux_function_app.open"]
        assert "FUNC_PUBLIC_ACCESS" not in found["azurerm_windows_function_app.restricted"]

    def test_the_http2_setting_is_no_longer_a_finding(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_function_app" "old" {
              name = "old"
              site_config {
                http2_enabled = false
              }
            }
            """,
        )
        assert "FUNC_HTTP_V1" not in found["azurerm_function_app.old"]


class TestVirtualMachines:
    def test_a_windows_machine_gets_the_same_rules_as_a_linux_one(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_windows_virtual_machine" "win" {
              name                  = "win"
              admin_username        = "azureadmin"
              admin_password        = var.admin_password
              network_interface_ids = []
            }
            resource "azurerm_windows_virtual_machine" "safe" {
              name                       = "safe"
              admin_username             = "azureadmin"
              admin_password             = var.admin_password
              network_interface_ids      = []
              encryption_at_host_enabled = true
              identity {
                type = "SystemAssigned"
              }
            }
            """,
        )
        assert {"AZURE_VM_NO_DISK_ENCRYPTION", "AZURE_VM_NO_MANAGED_IDENTITY"} <= found[
            "azurerm_windows_virtual_machine.win"
        ]
        assert not found.get("azurerm_windows_virtual_machine.safe")

    def test_a_disk_encryption_set_satisfies_the_disk_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_linux_virtual_machine" "cmk" {
              name                  = "cmk"
              admin_username        = "azureadmin"
              network_interface_ids = []
              os_disk {
                caching                = "ReadWrite"
                storage_account_type   = "Premium_LRS"
                disk_encryption_set_id = "/subscriptions/0/diskEncryptionSets/des"
              }
            }
            """,
        )
        assert "AZURE_VM_NO_DISK_ENCRYPTION" not in found["azurerm_linux_virtual_machine.cmk"]

    def test_password_authentication_on_the_legacy_machine_type(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_virtual_machine" "legacy" {
              name = "legacy"
              os_profile_linux_config {
                disable_password_authentication = false
              }
            }
            resource "azurerm_virtual_machine" "keys" {
              name = "keys"
              os_profile_linux_config {
                disable_password_authentication = true
              }
            }
            """,
        )
        assert "AZURE_VM_PASSWORD_AUTH" in found["azurerm_virtual_machine.legacy"]
        assert "AZURE_VM_PASSWORD_AUTH" not in found["azurerm_virtual_machine.keys"]

    def test_an_omitted_disable_password_authentication_is_the_secure_default(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_linux_virtual_machine" "vm" {
              name                  = "vm"
              network_interface_ids = []
            }
            """,
        )
        assert "AZURE_VM_PASSWORD_AUTH" not in found["azurerm_linux_virtual_machine.vm"]


class TestMonitor:
    def test_a_setting_with_an_enabled_log_block_is_not_empty(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_monitor_diagnostic_setting" "current" {
              name               = "current"
              target_resource_id = "id"
              enabled_log {
                category = "AuditEvent"
              }
            }
            resource "azurerm_monitor_diagnostic_setting" "legacy" {
              name               = "legacy"
              target_resource_id = "id"
              log {
                category = "AuditEvent"
              }
            }
            resource "azurerm_monitor_diagnostic_setting" "metrics" {
              name               = "metrics"
              target_resource_id = "id"
              metric {
                category = "AllMetrics"
              }
            }
            """,
        )
        assert (
            "MONITOR_NO_DIAGNOSTIC_SETTING"
            not in found["azurerm_monitor_diagnostic_setting.current"]
        )
        assert (
            "MONITOR_NO_DIAGNOSTIC_SETTING"
            not in found["azurerm_monitor_diagnostic_setting.legacy"]
        )
        assert (
            "MONITOR_NO_DIAGNOSTIC_SETTING" in found["azurerm_monitor_diagnostic_setting.metrics"]
        )

    def test_retention_days_inside_either_log_block(self, tmp_path: Path) -> None:
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
            resource "azurerm_monitor_diagnostic_setting" "short_enabled" {
              name = "short-enabled"
              enabled_log {
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
            resource "azurerm_monitor_diagnostic_setting" "forever" {
              name = "forever"
              enabled_log {
                category = "Audit"
                retention_policy {
                  enabled = true
                  days    = 0
                }
              }
            }
            resource "azurerm_monitor_diagnostic_setting" "disabled_policy" {
              name = "disabled"
              enabled_log {
                category = "Audit"
                retention_policy {
                  enabled = false
                  days    = 7
                }
              }
            }
            """,
        )
        prefix = "azurerm_monitor_diagnostic_setting."
        assert "MONITOR_SHORT_RETENTION" in found[prefix + "short"]
        assert "MONITOR_SHORT_RETENTION" in found[prefix + "short_enabled"]
        assert "MONITOR_SHORT_RETENTION" not in found[prefix + "long"]
        assert "MONITOR_SHORT_RETENTION" not in found[prefix + "forever"]
        assert "MONITOR_SHORT_RETENTION" not in found[prefix + "disabled_policy"]

    def test_a_setting_with_no_retention_block_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_monitor_diagnostic_setting" "plain" {
              name = "plain"
              enabled_log {
                category = "Audit"
              }
            }
            """,
        )
        assert not found.get("azurerm_monitor_diagnostic_setting.plain")


# ---------------------------------------------------------------------------
# Joined facts
# ---------------------------------------------------------------------------


class TestDiagnosticSettings:
    SOURCE = """
        resource "azurerm_key_vault" "logged" {
          name = "logged"
        }
        resource "azurerm_key_vault" "bare" {
          name = "bare"
        }
        resource "azurerm_monitor_diagnostic_setting" "logged" {
          name               = "logged"
          target_resource_id = azurerm_key_vault.logged.id
          enabled_log {
            category = "AuditEvent"
          }
        }
    """

    def test_a_vault_with_a_diagnostic_setting_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.SOURCE)
        assert "KEYVAULT_NO_DIAGNOSTICS" not in found["azurerm_key_vault.logged"]
        assert "KEYVAULT_NO_DIAGNOSTICS" in found["azurerm_key_vault.bare"]

    def test_a_setting_whose_target_cannot_be_resolved_leaves_every_vault_unknown(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_key_vault" "a" {
              name = "a"
            }
            resource "azurerm_key_vault" "b" {
              name = "b"
            }
            resource "azurerm_monitor_diagnostic_setting" "any" {
              name               = "any"
              target_resource_id = var.target
              enabled_log {
                category = "AuditEvent"
              }
            }
            """,
        )
        assert "KEYVAULT_NO_DIAGNOSTICS" not in found["azurerm_key_vault.a"]
        assert "KEYVAULT_NO_DIAGNOSTICS" not in found["azurerm_key_vault.b"]


class TestSqlServerCompanions:
    def test_auditing_and_alert_policies_are_joined_by_server_id(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_mssql_server" "covered" {
              name = "covered"
            }
            resource "azurerm_mssql_server" "bare" {
              name = "bare"
            }
            resource "azurerm_mssql_server_extended_auditing_policy" "covered" {
              server_id = azurerm_mssql_server.covered.id
            }
            resource "azurerm_mssql_server_security_alert_policy" "covered" {
              server_id = azurerm_mssql_server.covered.id
              state     = "Enabled"
            }
            """,
        )
        assert not found.get("azurerm_mssql_server.covered")
        assert {"MSSQL_NO_AUDITING", "MSSQL_NO_THREAT_DETECTION"} <= found[
            "azurerm_mssql_server.bare"
        ]

    def test_a_disabled_alert_policy_is_not_protection(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_mssql_server" "s" {
              name = "s"
            }
            resource "azurerm_mssql_server_security_alert_policy" "s" {
              server_id = azurerm_mssql_server.s.id
              state     = "Disabled"
            }
            """,
        )
        assert "MSSQL_NO_THREAT_DETECTION" in found["azurerm_mssql_server.s"]

    def test_an_inline_auditing_block_counts(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_mssql_server" "s" {
              name = "s"
              extended_auditing_policy {
                storage_endpoint = "https://audit.blob.core.windows.net/"
              }
            }
            """,
        )
        assert "MSSQL_NO_AUDITING" not in found["azurerm_mssql_server.s"]

    def test_transparent_data_encryption_is_judged_on_the_database(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_mssql_server" "s" {
              name = "s"
            }
            resource "azurerm_mssql_database" "off" {
              name                                = "off"
              server_id                           = azurerm_mssql_server.s.id
              transparent_data_encryption_enabled = false
            }
            resource "azurerm_mssql_database" "default" {
              name      = "default"
              server_id = azurerm_mssql_server.s.id
            }
            """,
        )
        assert "MSSQL_NO_TDE" in found["azurerm_mssql_database.off"]
        assert not found.get("azurerm_mssql_database.default")
        assert "MSSQL_NO_TDE" not in found["azurerm_mssql_server.s"]


class TestStorageNetworkRules:
    def test_a_separate_network_rules_resource_restricts_the_account(self, tmp_path: Path) -> None:
        graph = _graph_for(
            tmp_path,
            """
            resource "azurerm_storage_account" "separate" {
              name = "separate"
            }
            resource "azurerm_storage_account" "open" {
              name = "open"
            }
            resource "azurerm_storage_account_network_rules" "separate" {
              storage_account_id = azurerm_storage_account.separate.id
              default_action     = "Deny"
            }
            """,
        )
        assert _derived(graph, "azurerm_storage_account.separate")["network_default_deny"] is True
        assert _derived(graph, "azurerm_storage_account.open")["network_default_deny"] is False
        found = _findings(graph)
        assert "AZURE_STORAGE_NO_NETWORK_RULES" not in found["azurerm_storage_account.separate"]
        assert "AZURE_STORAGE_NO_NETWORK_RULES" in found["azurerm_storage_account.open"]

    def test_an_allow_rule_is_not_a_restriction(self, tmp_path: Path) -> None:
        graph = _graph_for(
            tmp_path,
            """
            resource "azurerm_storage_account" "a" {
              name = "a"
              network_rules {
                default_action = "Allow"
              }
            }
            resource "azurerm_storage_account" "d" {
              name = "d"
              network_rules {
                default_action = "Deny"
              }
            }
            """,
        )
        assert _derived(graph, "azurerm_storage_account.a")["network_default_deny"] is False
        assert _derived(graph, "azurerm_storage_account.d")["network_default_deny"] is True

    def test_an_account_with_public_network_access_off_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_storage_account" "private" {
              name                          = "private"
              public_network_access_enabled = false
            }
            """,
        )
        assert "AZURE_STORAGE_NO_NETWORK_RULES" not in found["azurerm_storage_account.private"]

    def test_an_unresolvable_rules_resource_makes_the_answer_unknown(self, tmp_path: Path) -> None:
        graph = _graph_for(
            tmp_path,
            """
            resource "azurerm_storage_account" "one" {
              name = "one"
            }
            resource "azurerm_storage_account" "two" {
              name = "two"
            }
            resource "azurerm_storage_account_network_rules" "r" {
              storage_account_id = var.account_id
              default_action     = "Deny"
            }
            """,
        )
        assert isinstance(
            _derived(graph, "azurerm_storage_account.one")["network_default_deny"], Unknown
        )
        found = _findings(graph)
        assert "AZURE_STORAGE_NO_NETWORK_RULES" not in found["azurerm_storage_account.one"]
        assert "AZURE_STORAGE_NO_NETWORK_RULES" not in found["azurerm_storage_account.two"]


class TestVirtualMachinePublicIp:
    SOURCE = """
        resource "azurerm_public_ip" "pip" {
          name = "pip"
        }
        resource "azurerm_network_interface" "public" {
          name = "public"
          ip_configuration {
            name                 = "internal"
            subnet_id            = "subnet"
            public_ip_address_id = azurerm_public_ip.pip.id
          }
        }
        resource "azurerm_network_interface" "private" {
          name = "private"
          ip_configuration {
            name                          = "internal"
            subnet_id                     = "subnet"
            private_ip_address_allocation = "Dynamic"
          }
        }
        resource "azurerm_linux_virtual_machine" "exposed" {
          name                  = "exposed"
          network_interface_ids = [azurerm_network_interface.public.id]
        }
        resource "azurerm_windows_virtual_machine" "exposed_windows" {
          name                  = "exposed-windows"
          network_interface_ids = [
            azurerm_network_interface.private.id,
            azurerm_network_interface.public.id,
          ]
        }
        resource "azurerm_linux_virtual_machine" "internal" {
          name                  = "internal"
          network_interface_ids = [azurerm_network_interface.private.id]
        }
        resource "azurerm_linux_virtual_machine" "no_interface" {
          name                  = "none"
          network_interface_ids = []
        }
        resource "azurerm_linux_virtual_machine" "elsewhere" {
          name                  = "elsewhere"
          network_interface_ids = [var.interface_id]
        }
    """

    def test_the_machine_joins_its_interfaces_public_address(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.SOURCE)
        assert "AZURE_VM_PUBLIC_IP" in found["azurerm_linux_virtual_machine.exposed"]
        assert "AZURE_VM_PUBLIC_IP" in found["azurerm_windows_virtual_machine.exposed_windows"]
        assert "AZURE_VM_PUBLIC_IP" not in found["azurerm_linux_virtual_machine.internal"]

    def test_a_machine_with_no_interface_is_not_exposed(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.SOURCE)
        assert "AZURE_VM_PUBLIC_IP" not in found["azurerm_linux_virtual_machine.no_interface"]

    def test_an_interface_outside_the_scan_is_unknown_not_private(self, tmp_path: Path) -> None:
        graph = _graph_for(tmp_path, self.SOURCE)
        derived = _derived(graph, "azurerm_linux_virtual_machine.elsewhere")
        assert isinstance(derived["has_public_ip"], Unknown)
        found = _findings(graph)
        assert "AZURE_VM_PUBLIC_IP" not in found["azurerm_linux_virtual_machine.elsewhere"]

    def test_a_conditional_public_address_is_not_assumed(self, tmp_path: Path) -> None:
        graph = _graph_for(
            tmp_path,
            """
            resource "azurerm_network_interface" "maybe" {
              name = "maybe"
              ip_configuration {
                name                 = "internal"
                subnet_id            = "subnet"
                public_ip_address_id = var.attach ? "/pips/one" : null
              }
            }
            resource "azurerm_linux_virtual_machine" "vm" {
              name                  = "vm"
              network_interface_ids = [azurerm_network_interface.maybe.id]
            }
            """,
        )
        assert isinstance(
            _derived(graph, "azurerm_linux_virtual_machine.vm")["has_public_ip"], Unknown
        )


# ---------------------------------------------------------------------------
# Provider defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_the_table_lists_only_resource_types_azure_rules_read(self) -> None:
        read_by_rules = {t for r in _azure_rules() for t in r.resource_types}
        assert set(azure_enrichment.DEFAULTS) <= read_by_rules

    def test_the_table_values_are_the_provider_defaults(self) -> None:
        defaults = azure_enrichment.DEFAULTS
        assert defaults["azurerm_kubernetes_cluster"] == {"private_cluster_enabled": False}
        assert defaults["azurerm_key_vault"]["purge_protection_enabled"] is False
        assert defaults["azurerm_key_vault"]["public_network_access_enabled"] is True
        assert defaults["azurerm_storage_account"] == {"allow_nested_items_to_be_public": True}
        for resource_type in (
            "azurerm_cosmosdb_account",
            "azurerm_mssql_server",
            "azurerm_container_registry",
            "azurerm_redis_cache",
        ):
            assert defaults[resource_type] == {"public_network_access_enabled": True}
        for resource_type in (
            "azurerm_app_service",
            "azurerm_linux_web_app",
            "azurerm_windows_web_app",
            "azurerm_function_app",
            "azurerm_linux_function_app",
            "azurerm_windows_function_app",
        ):
            assert defaults[resource_type]["https_only"] is False

    @pytest.mark.parametrize(
        ("source", "address", "rule_id"),
        [
            (
                'resource "azurerm_kubernetes_cluster" "c" {\n  name = "c"\n}\n',
                "azurerm_kubernetes_cluster.c",
                "AKS_NO_PRIVATE_CLUSTER",
            ),
            (
                'resource "azurerm_key_vault" "k" {\n  name = "k"\n}\n',
                "azurerm_key_vault.k",
                "KEYVAULT_NO_PURGE_PROTECTION",
            ),
            (
                'resource "azurerm_key_vault" "k" {\n  name = "k"\n}\n',
                "azurerm_key_vault.k",
                "KEYVAULT_PUBLIC_ACCESS",
            ),
            (
                'resource "azurerm_cosmosdb_account" "c" {\n  name = "c"\n}\n',
                "azurerm_cosmosdb_account.c",
                "COSMOS_PUBLIC_ACCESS",
            ),
            (
                'resource "azurerm_mssql_server" "s" {\n  name = "s"\n}\n',
                "azurerm_mssql_server.s",
                "MSSQL_PUBLIC_ACCESS",
            ),
            (
                'resource "azurerm_container_registry" "r" {\n  name = "r"\n}\n',
                "azurerm_container_registry.r",
                "ACR_PUBLIC_NETWORK_ACCESS",
            ),
            (
                'resource "azurerm_redis_cache" "r" {\n  name = "r"\n}\n',
                "azurerm_redis_cache.r",
                "REDIS_PUBLIC_NETWORK_ACCESS",
            ),
            (
                'resource "azurerm_linux_function_app" "f" {\n  name = "f"\n}\n',
                "azurerm_linux_function_app.f",
                "FUNC_NO_HTTPS",
            ),
        ],
    )
    def test_an_omitted_attribute_fires_the_rule_only_once_defaults_apply(
        self, tmp_path: Path, source: str, address: str, rule_id: str
    ) -> None:
        assert rule_id not in _scan_hcl(tmp_path, source)[address]
        assert rule_id in _scan_hcl(tmp_path, source, defaults=True)[address]

    def test_a_plan_is_never_defaulted_and_says_what_it_says(self) -> None:
        # A plan materialises the values, so a private cluster stays private
        found = _scan_plan(
            ("azurerm_kubernetes_cluster", "c", {"private_cluster_enabled": True}),
            ("azurerm_kubernetes_cluster", "d", {"private_cluster_enabled": False}),
            ("azurerm_kubernetes_cluster", "e", {}),
        )
        assert "AKS_NO_PRIVATE_CLUSTER" not in found["azurerm_kubernetes_cluster.c"]
        assert "AKS_NO_PRIVATE_CLUSTER" in found["azurerm_kubernetes_cluster.d"]
        assert "AKS_NO_PRIVATE_CLUSTER" not in found["azurerm_kubernetes_cluster.e"]

    def test_a_value_the_input_sets_is_kept(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_kubernetes_cluster" "private" {
              name                    = "private"
              private_cluster_enabled = true
            }
            resource "azurerm_key_vault" "safe" {
              name                          = "safe"
              purge_protection_enabled      = true
              public_network_access_enabled = false
            }
            """,
            defaults=True,
        )
        assert "AKS_NO_PRIVATE_CLUSTER" not in found["azurerm_kubernetes_cluster.private"]
        assert (
            not {"KEYVAULT_NO_PURGE_PROTECTION", "KEYVAULT_PUBLIC_ACCESS"}
            & found["azurerm_key_vault.safe"]
        )

    def test_defaults_are_recorded_and_fill_only_absent_attributes(self) -> None:
        class _Node:
            resource_type = "azurerm_key_vault"
            properties: dict[str, Any] = {"purge_protection_enabled": True}

        node = _Node()
        filled = apply_defaults(node, azure_enrichment.DEFAULTS)  # type: ignore[arg-type]
        assert filled == ["public_network_access_enabled"]
        assert node.properties["purge_protection_enabled"] is True
        assert node.properties["public_network_access_enabled"] is True

    def test_a_key_vault_firewall_that_denies_by_default_is_not_public(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_key_vault" "fenced" {
              name = "fenced"
              network_acls {
                default_action = "Deny"
                bypass         = "AzureServices"
              }
            }
            resource "azurerm_key_vault" "allow" {
              name = "allow"
              network_acls {
                default_action = "Allow"
                bypass         = "AzureServices"
              }
            }
            """,
            defaults=True,
        )
        assert "KEYVAULT_PUBLIC_ACCESS" not in found["azurerm_key_vault.fenced"]
        assert "KEYVAULT_NO_NETWORK_ACLS" not in found["azurerm_key_vault.fenced"]
        assert "KEYVAULT_PUBLIC_ACCESS" in found["azurerm_key_vault.allow"]


class TestHclPlanParity:
    """One configuration written as HCL and as the plan that materialises its defaults.

    The plan is the reference.
    HCL omits the attributes a plan fills in, so the defaults table has to make the two agree.
    """

    CASES: list[tuple[str, str, dict[str, Any], str]] = [
        (
            "azurerm_kubernetes_cluster",
            'resource "azurerm_kubernetes_cluster" "x" {\n  name = "x"\n}\n',
            {
                "name": "x",
                "private_cluster_enabled": False,
                "role_based_access_control_enabled": True,
            },
            "an AKS cluster that never sets private_cluster_enabled",
        ),
        (
            "azurerm_key_vault",
            'resource "azurerm_key_vault" "x" {\n  name = "x"\n}\n',
            {
                "name": "x",
                "purge_protection_enabled": False,
                "public_network_access_enabled": True,
                "soft_delete_retention_days": 90,
                "network_acls": [],
            },
            "a Key Vault with every default",
        ),
        (
            "azurerm_storage_account",
            'resource "azurerm_storage_account" "x" {\n  name = "x"\n}\n',
            {
                "name": "x",
                "allow_nested_items_to_be_public": True,
                "https_traffic_only_enabled": True,
                "public_network_access_enabled": True,
                "network_rules": [],
                "blob_properties": [],
            },
            "a storage account with every default",
        ),
        (
            "azurerm_cosmosdb_account",
            'resource "azurerm_cosmosdb_account" "x" {\n  name = "x"\n}\n',
            {
                "name": "x",
                "public_network_access_enabled": True,
                "is_virtual_network_filter_enabled": False,
                "virtual_network_rule": [],
            },
            "a Cosmos DB account with every default",
        ),
        (
            "azurerm_mssql_server",
            'resource "azurerm_mssql_server" "x" {\n  name = "x"\n}\n',
            {"name": "x", "public_network_access_enabled": True},
            "a SQL server with every default",
        ),
        (
            "azurerm_container_registry",
            'resource "azurerm_container_registry" "x" {\n  name = "x"\n}\n',
            {
                "name": "x",
                "admin_enabled": False,
                "anonymous_pull_enabled": False,
                "public_network_access_enabled": True,
                "network_rule_set": [],
            },
            "a registry with every default",
        ),
        (
            "azurerm_redis_cache",
            'resource "azurerm_redis_cache" "x" {\n  name = "x"\n}\n',
            {"name": "x", "public_network_access_enabled": True, "subnet_id": None},
            "a cache with every default",
        ),
        (
            "azurerm_linux_web_app",
            'resource "azurerm_linux_web_app" "x" {\n  name = "x"\n  site_config {}\n}\n',
            {"name": "x", "https_only": False, "site_config": [{}]},
            "a web app that never sets https_only",
        ),
        (
            "azurerm_linux_function_app",
            'resource "azurerm_linux_function_app" "x" {\n  name = "x"\n  site_config {}\n}\n',
            {
                "name": "x",
                "https_only": False,
                "public_network_access_enabled": True,
                "site_config": [{}],
            },
            "a function app with every default",
        ),
    ]

    @pytest.mark.parametrize(
        ("resource_type", "hcl", "plan_values", "why"), CASES, ids=[c[0] for c in CASES]
    )
    def test_hcl_with_defaults_trips_the_same_rules_as_the_plan(
        self, tmp_path: Path, resource_type: str, hcl: str, plan_values: dict[str, Any], why: str
    ) -> None:
        address = f"{resource_type}.x"
        from_hcl = _scan_hcl(tmp_path, hcl, defaults=True)[address]
        from_plan = _scan_plan((resource_type, "x", plan_values))[address]
        assert from_hcl == from_plan, why
        assert from_plan, f"{why}: the plan trips no rule, so parity proves nothing"


# ---------------------------------------------------------------------------
# Resource type boundaries and realistic inputs
# ---------------------------------------------------------------------------


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
            resource "azurerm_linux_virtual_machine" "vm" {
              name                  = "vm"
              network_interface_ids = []
            }
            resource "azurerm_virtual_machine_extension" "ext" {
              name = "ext"
            }
            resource "azurerm_linux_virtual_machine_scale_set" "set" {
              name = "set"
            }
            """,
        )
        assert "AZURE_VM_NO_DISK_ENCRYPTION" in found["azurerm_linux_virtual_machine.vm"]
        assert not found.get("azurerm_virtual_machine_extension.ext")
        assert not found.get("azurerm_linux_virtual_machine_scale_set.set")

    def test_storage_account_companions_do_not_get_account_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_storage_account" "sa" {
              name = "sa"
            }
            resource "azurerm_storage_account_network_rules" "rules" {
              storage_account_id = "id"
              default_action     = "Deny"
            }
            resource "azurerm_storage_blob" "b" {
              name = "b"
            }
            """,
        )
        assert not found.get("azurerm_storage_account_network_rules.rules")
        assert not found.get("azurerm_storage_blob.b")

    def test_sql_databases_do_not_get_server_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "azurerm_mssql_server" "s" {
              name = "s"
            }
            resource "azurerm_mssql_database" "d" {
              name      = "d"
              server_id = azurerm_mssql_server.s.id
            }
            """,
        )
        assert "MSSQL_NO_AUDITING" in found["azurerm_mssql_server.s"]
        assert not found.get("azurerm_mssql_database.d")


class TestRealisticInputs:
    def _scan(self, name: str) -> dict[str, set[str]]:
        return _findings(InfraGraph.from_parsed(detect_and_parse(FIXTURES / "realistic" / name)))

    def test_the_cluster_input_reports_the_registry_admin_account(self) -> None:
        found = self._scan("02_azure_kubernetes_cluster.tf")
        assert "ACR_ADMIN_ENABLED" in found["azurerm_container_registry.platform"]

    def test_the_cluster_input_reports_the_public_api_server_once_defaults_apply(self) -> None:
        path = FIXTURES / "realistic" / "02_azure_kubernetes_cluster.tf"
        parsed = detect_and_parse(path)
        graph = _with_defaults(InfraGraph.from_parsed(parsed), parsed.format_type)
        found = _findings(graph)
        assert "AKS_NO_PRIVATE_CLUSTER" in found["azurerm_kubernetes_cluster.platform"]
        assert "ACR_PUBLIC_NETWORK_ACCESS" in found["azurerm_container_registry.platform"]
        assert not found.get("azurerm_kubernetes_cluster_node_pool.workloads")

    def test_the_web_app_input_keeps_its_hardened_resources_quiet(self) -> None:
        found = self._scan("07_azure_webapp_java.tf")
        assert not found.get("azurerm_linux_web_app.main")
        assert found["azurerm_key_vault.main"] == {"KEYVAULT_NO_DIAGNOSTICS"}
        assert not found.get("azurerm_redis_cache.main")
        assert found["azurerm_storage_account.main"] == {"AZURE_STORAGE_NO_HTTPS"}

    def test_the_planted_https_exception_is_still_found(self) -> None:
        found = self._scan("07_azure_webapp_java.tf")
        assert "AZURE_STORAGE_NO_HTTPS" in found["azurerm_storage_account.main"]


class TestRuleFiles:
    """The Azure rule files stay valid when loaded one by one, as the harness does."""

    def test_every_file_loads_on_its_own(self) -> None:
        from threatcode.engine.rules.loader import load_rules_from_file

        for path in sorted(AZURE_RULE_DIR.glob("*.yml")):
            assert load_rules_from_file(path), path.name

    def test_deprecated_ids_do_not_overlap_loaded_rules(self) -> None:
        loaded = {r.id for r in load_builtin_rules()}
        assert not deprecated_rule_ids() & loaded
