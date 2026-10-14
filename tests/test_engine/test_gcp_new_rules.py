"""Tests for the GCP security rules, run through the whole scan path on real Terraform syntax."""

from __future__ import annotations

import textwrap
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.scan import scan_real_shape, scan_text
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import TECHNIQUE_DB, is_revoked
from threatcode.engine.rules.loader import (
    CONFIDENCE_LEVELS,
    Rule,
    deprecated_rule_ids,
    load_builtin_rules,
)
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity
from threatcode.parsers.terraform_plan import TerraformPlanParser


def gcp_rules() -> list[Rule]:
    return [r for r in load_builtin_rules() if r.source_group.startswith("gcp__")]


def _scan_hcl(tmp_path: Path, source: str) -> dict[str, set[str]]:
    """Rule ids per resource address for a Terraform HCL snippet."""
    result = scan_text(textwrap.dedent(source), "main.tf", tmp_path)
    return {
        address: result.rule_ids_for(address)
        for address in {t.resource_address for t in result.threats}
    }


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
                        "provider_name": "registry.terraform.io/hashicorp/google",
                        "values": values,
                    }
                    for rtype, name, values in resources
                ]
            }
        },
    }
    graph = InfraGraph.from_parsed(TerraformPlanParser().parse(plan))
    found: dict[str, set[str]] = {}
    for threat in HybridEngine().analyze(graph).threats:
        if threat.rule_id:
            found.setdefault(threat.resource_address, set()).add(threat.rule_id)
    return found


def _ids(found: dict[str, set[str]], address: str, prefix: str = "") -> set[str]:
    return {i for i in found.get(address, set()) if i.startswith(prefix)}


NEW_AND_KEPT_IDS = {
    "GCP_FW_ALLOW_ALL",
    "GCP_FW_SSH_OPEN",
    "GCP_FW_RDP_OPEN",
    "CLOUDSQL_NO_SSL",
    "CLOUDSQL_PUBLIC_IP",
    "CLOUDSQL_NO_BACKUP",
    "CLOUDSQL_NO_ENCRYPTION",
    "CLOUDSQL_NO_MAINTENANCE_WINDOW",
    "CLOUDRUN_UNAUTHENTICATED",
    "CLOUDRUN_NO_VPC_CONNECTOR",
    "CLOUDRUN_NO_CPU_LIMIT",
    "CLOUDRUN_NO_MAX_INSTANCES",
    "GCFUNC_PUBLIC_INVOKER",
    "GCFUNC_PUBLIC_INGRESS",
    "GCFUNC_NO_VPC_CONNECTOR",
    "GCFUNC_HTTP_NO_AUTH",
    "GCFUNC_NO_MAX_INSTANCES",
    "BQ_PUBLIC_ACCESS",
    "BQ_NO_ENCRYPTION",
    "BQ_NO_ACCESS_POLICY",
    "PUBSUB_NO_ENCRYPTION",
    "GCP_VM_PUBLIC_IP",
    "GCP_VM_DEFAULT_SA",
    "GCP_VM_SERIAL_PORT",
    "GCP_VM_NO_SHIELDED",
    "GKE_NO_PRIVATE_CLUSTER",
    "GKE_LEGACY_ABAC",
    "GKE_NO_NETWORK_POLICY",
    "GKE_NO_MASTER_AUTHORIZED_NETWORKS",
    "GKE_MASTER_WORLD_ACCESS",
    "GKE_NO_WORKLOAD_IDENTITY",
    "GKE_NO_SHIELDED_NODES",
    "GKE_NODE_DEFAULT_SA",
    "GCP_IAM_ADMIN_SA",
    "GCP_IAM_SA_TOKEN_CREATOR",
    "GCP_IAM_PUBLIC_MEMBER",
    "GCP_IAM_SA_KEY",
    "GCP_BUCKET_PUBLIC",
    "GCP_BUCKET_NO_VERSIONING",
    "GCP_BUCKET_NO_LOGGING",
}
DELETED_IDS = {"BQ_NO_LOCATION", "PUBSUB_NO_DEAD_LETTER", "PUBSUB_NO_RETENTION"}


class TestRuleSet:
    def test_the_gcp_rules_are_exactly_the_expected_set(self) -> None:
        assert {r.id for r in gcp_rules()} == NEW_AND_KEPT_IDS

    def test_hygiene_rules_with_no_attacker_are_deleted_and_recorded(self) -> None:
        assert not DELETED_IDS & {r.id for r in load_builtin_rules()}
        assert DELETED_IDS <= deprecated_rule_ids()

    def test_no_gcp_rule_reads_a_synthetic_property(self) -> None:
        # has_public_access and has_allow_unauthenticated were never produced by any parser
        text = "".join(
            p.read_text(encoding="utf-8")
            for p in (Path(__file__).parents[2] / "src/threatcode/engine/rules/builtin/gcp").glob(
                "*.yml"
            )
        )
        assert "has_public_access" not in text
        assert "has_allow_unauthenticated" not in text


class TestCalibration:
    def test_every_rule_declares_a_confidence_the_convention_allows(self) -> None:
        for rule in gcp_rules():
            assert rule.confidence in CONFIDENCE_LEVELS, rule.id
            if rule.confidence == "absence":
                assert Severity(rule.severity) <= Severity.MEDIUM, rule.id
            if rule.confidence == "heuristic":
                assert Severity(rule.severity) <= Severity.HIGH, rule.id

    def test_critical_is_reserved_for_definitive_direct_exposure(self) -> None:
        critical = {r.id for r in gcp_rules() if r.severity == "critical"}
        assert critical == {"GCP_FW_ALLOW_ALL", "BQ_PUBLIC_ACCESS", "GCP_BUCKET_PUBLIC"}
        assert all(r.confidence == "definitive" for r in gcp_rules() if r.id in critical)

    def test_customer_managed_key_preferences_are_low_and_say_so(self) -> None:
        by_id = {r.id: r for r in gcp_rules()}
        for rule_id in (
            "CLOUDSQL_NO_ENCRYPTION",
            "BQ_NO_ENCRYPTION",
            "PUBSUB_NO_ENCRYPTION",
        ):
            assert by_id[rule_id].severity == "low", rule_id
            assert by_id[rule_id].confidence == "absence", rule_id
            assert "customer-managed key" in by_id[rule_id].title, rule_id

    def test_recoverability_controls_use_denial_of_service(self) -> None:
        by_id = {r.id: r for r in gcp_rules()}
        for rule_id in ("CLOUDSQL_NO_BACKUP", "GCP_BUCKET_NO_VERSIONING"):
            assert by_id[rule_id].stride_category == "denial_of_service", rule_id

    def test_missing_logging_is_repudiation_with_no_adversary_technique(self) -> None:
        rule = next(r for r in gcp_rules() if r.id == "GCP_BUCKET_NO_LOGGING")
        assert rule.stride_category == "repudiation"
        assert not (rule.metadata.get("mitre") or {}).get("techniques")

    def test_every_technique_exists_and_none_is_revoked(self) -> None:
        for rule in gcp_rules():
            for technique in (rule.metadata.get("mitre") or {}).get("techniques", []):
                assert technique in TECHNIQUE_DB, (rule.id, technique)
                assert not is_revoked(technique), (rule.id, technique)

    def test_tactics_are_derived_not_written_by_hand(self) -> None:
        for rule in gcp_rules():
            assert "tactics" not in (rule.metadata.get("mitre") or {}), rule.id

    def test_internet_facing_remote_access_maps_to_external_remote_services(self) -> None:
        by_id = {r.id: r for r in gcp_rules()}
        for rule_id in ("GCP_FW_SSH_OPEN", "GCP_FW_RDP_OPEN"):
            assert by_id[rule_id].metadata["mitre"]["techniques"] == ["T1133"]

    def test_related_rules_share_a_root_cause(self) -> None:
        by_id = {r.id: r for r in gcp_rules()}
        firewall = {by_id[i].root_cause for i in ("GCP_FW_ALLOW_ALL", "GCP_FW_SSH_OPEN")}
        assert len(firewall) == 1 and "" not in firewall
        public = {
            by_id[i].root_cause
            for i in (
                "GCP_BUCKET_PUBLIC",
                "BQ_PUBLIC_ACCESS",
                "CLOUDRUN_UNAUTHENTICATED",
                "GCFUNC_PUBLIC_INVOKER",
                "GCP_IAM_PUBLIC_MEMBER",
            )
        }
        assert len(public) == 1 and "" not in public

    def test_the_http_function_rule_is_about_plain_http_not_authentication(self) -> None:
        rule = next(r for r in gcp_rules() if r.id == "GCFUNC_HTTP_NO_AUTH")
        assert rule.title == "HTTP trigger allows plain HTTP"
        assert rule.severity == "low"

    def test_findings_carry_the_derived_tactics(self, tmp_path: Path) -> None:
        result = scan_text(
            textwrap.dedent(
                """
                resource "google_compute_firewall" "ssh" {
                  name    = "ssh"
                  network = "default"
                  allow {
                    protocol = "tcp"
                    ports    = ["22"]
                  }
                  source_ranges = ["0.0.0.0/0"]
                }
                """
            ),
            "main.tf",
            tmp_path,
        )
        threat = next(t for t in result.threats if t.rule_id == "GCP_FW_SSH_OPEN")
        assert threat.mitre_techniques == ["T1133"]
        assert "TA0001" in threat.mitre_tactics


FIREWALL = """
    resource "google_compute_firewall" "fw" {
      name    = "fw"
      network = "default"
      %s
    }
"""
FW_RULES = {"GCP_FW_ALLOW_ALL", "GCP_FW_SSH_OPEN", "GCP_FW_RDP_OPEN"}
EVERYTHING = {"GCP_FW_ALLOW_ALL", "GCP_FW_SSH_OPEN", "GCP_FW_RDP_OPEN"}


class TestFirewall:
    ADDRESS = "google_compute_firewall.fw"

    @pytest.mark.parametrize(
        ("body", "expected"),
        [
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["443"] }\n source_ranges = ["0.0.0.0/0"]',
                set(),
                id="https-from-the-world-fires-nothing",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="ssh-from-the-world-fires-only-ssh",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["3389"] }\n source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_RDP_OPEN"},
                id="rdp-from-the-world-fires-only-rdp",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n source_ranges = ["10.0.0.0/8"]',
                set(),
                id="ssh-from-a-private-range-is-silent",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n source_ranges = ["35.235.240.0/20"]',
                set(),
                id="ssh-from-the-iap-range-is-silent",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["20-25"] }\n source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="a-range-containing-22-fires-ssh",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["3380-3400", "80"] }\n'
                ' source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_RDP_OPEN"},
                id="a-range-containing-3389-fires-rdp",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["3389", "22"] }\n'
                ' source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN", "GCP_FW_RDP_OPEN"},
                id="both-admin-ports-fire-both",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["21", "23-24"] }\n'
                ' source_ranges = ["0.0.0.0/0"]',
                set(),
                id="neighbouring-ports-do-not-overlap",
            ),
            pytest.param(
                'allow { protocol = "udp"\n ports = ["22"] }\n source_ranges = ["0.0.0.0/0"]',
                set(),
                id="udp-22-is-not-ssh",
            ),
            pytest.param(
                'allow { protocol = "icmp" }\n source_ranges = ["0.0.0.0/0"]',
                set(),
                id="icmp-from-the-world-is-silent",
            ),
            pytest.param(
                'allow { protocol = "all" }\n source_ranges = ["0.0.0.0/0"]',
                EVERYTHING,
                id="all-protocols-from-the-world-fires-all-three",
            ),
            pytest.param(
                'allow { protocol = "tcp" }\n source_ranges = ["0.0.0.0/0"]',
                EVERYTHING,
                id="tcp-without-ports-means-every-port",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["0-65535"] }\n source_ranges = ["0.0.0.0/0"]',
                EVERYTHING,
                id="the-full-port-range-is-every-port",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["0-1023", "1024-65535"] }\n'
                ' source_ranges = ["0.0.0.0/0"]',
                EVERYTHING,
                id="ranges-that-together-cover-every-port-count",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["1-65535"] }\n source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN", "GCP_FW_RDP_OPEN"},
                id="a-range-missing-port-zero-is-not-every-port",
            ),
            pytest.param(
                'allow { protocol = "6"\n ports = ["22"] }\n source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="the-ip-protocol-number-for-tcp-is-tcp",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n source_ranges = ["::/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="ipv6-world-counts",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }',
                {"GCP_FW_SSH_OPEN"},
                id="no-source-at-all-admits-every-address",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n source_tags = ["office"]',
                set(),
                id="a-source-tag-alone-is-not-the-world",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n'
                ' source_service_accounts = ["a@p.iam.gserviceaccount.com"]',
                set(),
                id="a-source-service-account-alone-is-not-the-world",
            ),
            pytest.param(
                'direction = "EGRESS"\n allow { protocol = "all" }\n'
                ' destination_ranges = ["0.0.0.0/0"]',
                set(),
                id="an-egress-rule-is-silent",
            ),
            pytest.param(
                'direction = "INGRESS"\n allow { protocol = "tcp"\n ports = ["22"] }\n'
                ' source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="explicit-ingress-fires",
            ),
            pytest.param(
                'disabled = true\n allow { protocol = "all" }\n source_ranges = ["0.0.0.0/0"]',
                set(),
                id="a-disabled-rule-is-silent",
            ),
            pytest.param(
                'disabled = false\n allow { protocol = "tcp"\n ports = ["22"] }\n'
                ' source_ranges = ["0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="an-enabled-rule-fires",
            ),
            pytest.param(
                'deny { protocol = "all" }\n source_ranges = ["0.0.0.0/0"]',
                set(),
                id="a-deny-rule-never-fires",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["443"] }\n'
                ' allow { protocol = "tcp"\n ports = ["22"] }\n'
                ' source_ranges = ["10.0.0.0/8", "0.0.0.0/0"]',
                {"GCP_FW_SSH_OPEN"},
                id="one-world-range-among-private-ones-with-one-ssh-block",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = var.ports }\n source_ranges = ["0.0.0.0/0"]',
                set(),
                id="ports-nobody-set-are-not-guessed",
            ),
            pytest.param(
                'allow { protocol = "tcp"\n ports = ["22"] }\n source_ranges = var.sources',
                set(),
                id="sources-nobody-set-are-not-guessed",
            ),
        ],
    )
    def test_table(self, tmp_path: Path, body: str, expected: set[str]) -> None:
        found = _scan_hcl(tmp_path, FIREWALL % body)
        assert _ids(found, self.ADDRESS) & FW_RULES == expected

    def test_a_lowercase_direction_is_read(self, tmp_path: Path) -> None:
        body = 'direction = "egress"\n allow { protocol = "all" }\n source_ranges = ["0.0.0.0/0"]'
        assert not _ids(_scan_hcl(tmp_path, FIREWALL % body), self.ADDRESS) & FW_RULES

    def test_plan_json_agrees_with_hcl(self) -> None:
        base: dict[str, Any] = {
            "name": "fw",
            "network": "default",
            "direction": "INGRESS",
            "disabled": None,
            "deny": [],
            "source_ranges": ["0.0.0.0/0"],
            "source_tags": None,
        }
        address = "google_compute_firewall.fw"
        ssh = {**base, "allow": [{"protocol": "tcp", "ports": ["22"]}]}
        assert _ids(_scan_plan(("google_compute_firewall", "fw", ssh)), address) & FW_RULES == {
            "GCP_FW_SSH_OPEN"
        }
        https = {**base, "allow": [{"protocol": "tcp", "ports": ["443"]}]}
        assert not _ids(_scan_plan(("google_compute_firewall", "fw", https)), address) & FW_RULES
        egress = {**ssh, "direction": "EGRESS"}
        assert not _ids(_scan_plan(("google_compute_firewall", "fw", egress)), address) & FW_RULES
        disabled = {**ssh, "disabled": True}
        assert not _ids(_scan_plan(("google_compute_firewall", "fw", disabled)), address) & FW_RULES
        icmp = {**base, "allow": [{"protocol": "icmp", "ports": []}]}
        assert not _ids(_scan_plan(("google_compute_firewall", "fw", icmp)), address) & FW_RULES

    def test_the_real_shape_plan_fires_only_ssh_on_the_ssh_rule(self) -> None:
        result = scan_real_shape("terraform/plan/gcp_network.plan.json")
        assert result.rule_ids_for("google_compute_firewall.ssh") & FW_RULES == {"GCP_FW_SSH_OPEN"}
        assert not result.rule_ids_for("google_compute_firewall.internal") & FW_RULES

    def test_derived_facts_are_written_under_the_reserved_namespace(self, tmp_path: Path) -> None:
        body = 'allow { protocol = "tcp"\n ports = ["22", "3000-3010"] }\n'
        body += 'allow { protocol = "icmp" }\n source_ranges = ["0.0.0.0/0"]'
        result = scan_text(textwrap.dedent(FIREWALL % body), "main.tf", tmp_path)
        node = result.graph.nodes[self.ADDRESS]
        derived = node.properties["derived"]
        assert derived["world_source"] is True
        assert derived["ingress_allow"] == [
            {"protocol": "tcp", "port_range": ["22", "3000-3010"], "all_ports": False},
            {"protocol": "icmp", "all_ports": False},
        ]
        # The attributes the author wrote are untouched
        assert node.properties["allow"][0]["ports"] == ["22", "3000-3010"]

    def test_a_forged_derived_block_in_the_input_is_replaced(self) -> None:
        values = {
            "name": "fw",
            "direction": "INGRESS",
            "source_ranges": ["10.0.0.0/8"],
            "allow": [{"protocol": "tcp", "ports": ["22"]}],
            "derived": {"world_source": True, "ingress_allow": [{"protocol": "all"}]},
        }
        found = _scan_plan(("google_compute_firewall", "fw", values))
        assert not _ids(found, "google_compute_firewall.fw") & FW_RULES


class TestFirewallFacts:
    """The facts the deriver writes, for inputs a rule table does not reach."""

    def _derived(self, tmp_path: Path, body: str) -> dict[str, Any]:
        result = scan_text(textwrap.dedent(FIREWALL % body), "main.tf", tmp_path)
        derived: dict[str, Any] = result.graph.nodes["google_compute_firewall.fw"].properties[
            "derived"
        ]
        return derived

    def test_malformed_ports_are_kept_but_never_count_as_every_port(self, tmp_path: Path) -> None:
        body = 'allow { protocol = "tcp"\n ports = ["abc", "22-", "70000", "-5"] }'
        derived = self._derived(tmp_path, body)
        assert derived["ingress_allow"][0]["all_ports"] is False
        assert derived["ingress_allow"][0]["port_range"] == ["abc", "22-", "70000", "-5"]

    def test_an_allow_block_without_a_protocol_admits_nothing(self, tmp_path: Path) -> None:
        derived = self._derived(
            tmp_path, 'allow { ports = ["22"] }\n source_ranges = ["0.0.0.0/0"]'
        )
        assert derived["ingress_allow"] == [{"protocol": "", "all_ports": False}]

    def test_a_firewall_with_no_allow_block_has_nothing_to_admit(self, tmp_path: Path) -> None:
        derived = self._derived(tmp_path, 'source_ranges = ["0.0.0.0/0"]')
        assert derived["ingress_allow"] == []
        assert derived["world_source"] is True

    def test_an_egress_rule_has_no_source(self, tmp_path: Path) -> None:
        derived = self._derived(tmp_path, 'direction = "EGRESS"\n allow { protocol = "all" }')
        assert derived["ingress_allow"] == []
        assert derived["world_source"] is False

    def test_a_known_world_range_beats_an_unknown_one(self, tmp_path: Path) -> None:
        derived = self._derived(
            tmp_path,
            'allow { protocol = "all" }\n source_ranges = ["0.0.0.0/0", var.extra]',
        )
        assert derived["world_source"] is True

    def test_other_resource_types_get_no_firewall_facts(self, tmp_path: Path) -> None:
        result = scan_text(
            'resource "google_compute_network" "n" {\n  name = "n"\n}\n', "main.tf", tmp_path
        )
        assert "ingress_allow" not in result.graph.nodes["google_compute_network.n"].properties.get(
            "derived", {}
        )


class TestCloudSql:
    BAD = """
        resource "google_sql_database_instance" "db" {
          name = "db"
          settings {
            tier = "db-f1-micro"
            ip_configuration {
              ipv4_enabled = true
              require_ssl  = false
              authorized_networks {
                name  = "everyone"
                value = "0.0.0.0/0"
              }
            }
            backup_configuration {
              enabled = false
            }
          }
        }
    """
    GOOD = """
        resource "google_sql_database_instance" "db" {
          name                = "db"
          encryption_key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
          settings {
            tier = "db-custom-2-7680"
            ip_configuration {
              ipv4_enabled    = false
              private_network = "projects/p/global/networks/n"
              ssl_mode        = "ENCRYPTED_ONLY"
            }
            backup_configuration {
              enabled = true
            }
            maintenance_window {
              day  = 7
              hour = 3
            }
          }
        }
    """
    ADDRESS = "google_sql_database_instance.db"
    ALL = {
        "CLOUDSQL_NO_SSL",
        "CLOUDSQL_PUBLIC_IP",
        "CLOUDSQL_NO_BACKUP",
        "CLOUDSQL_NO_ENCRYPTION",
        "CLOUDSQL_NO_MAINTENANCE_WINDOW",
    }

    def test_insecure_instance_fires_the_settings_rules(self, tmp_path: Path) -> None:
        assert self.ALL <= _ids(_scan_hcl(tmp_path, self.BAD), self.ADDRESS)

    def test_hardened_instance_is_silent(self, tmp_path: Path) -> None:
        assert not _ids(_scan_hcl(tmp_path, self.GOOD), self.ADDRESS, "CLOUDSQL_")

    def test_a_maintenance_window_silences_only_that_rule(self, tmp_path: Path) -> None:
        with_window = self.BAD.replace(
            "backup_configuration {",
            "maintenance_window {\n day = 7\n hour = 3\n }\n backup_configuration {",
        )
        found = _ids(_scan_hcl(tmp_path, with_window), self.ADDRESS)
        assert "CLOUDSQL_NO_MAINTENANCE_WINDOW" not in found
        assert "CLOUDSQL_NO_SSL" in found

    def test_a_public_address_needs_a_world_open_authorized_network(self, tmp_path: Path) -> None:
        narrow = self.BAD.replace("0.0.0.0/0", "203.0.113.7/32")
        assert "CLOUDSQL_PUBLIC_IP" not in _ids(_scan_hcl(tmp_path, narrow), self.ADDRESS)
        assert "CLOUDSQL_PUBLIC_IP" in _ids(_scan_hcl(tmp_path, self.BAD), self.ADDRESS)

    def test_ipv4_enabled_defaults_to_true_when_the_block_omits_it(self, tmp_path: Path) -> None:
        omitted = self.BAD.replace("ipv4_enabled = true\n", "")
        assert "CLOUDSQL_PUBLIC_IP" in _ids(_scan_hcl(tmp_path, omitted), self.ADDRESS)

    def test_a_private_instance_with_a_world_network_is_not_public(self, tmp_path: Path) -> None:
        private = self.BAD.replace("ipv4_enabled = true", "ipv4_enabled = false")
        assert "CLOUDSQL_PUBLIC_IP" not in _ids(_scan_hcl(tmp_path, private), self.ADDRESS)

    @pytest.mark.parametrize(
        ("ip_configuration", "fires"),
        [
            ("require_ssl = false", True),
            ("require_ssl = true", False),
            ('ssl_mode = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"', True),
            ('ssl_mode = "ENCRYPTED_ONLY"', False),
            ('ssl_mode = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"', False),
            ("ipv4_enabled = true", True),
        ],
    )
    def test_ssl_enforcement_table(
        self, tmp_path: Path, ip_configuration: str, fires: bool
    ) -> None:
        source = f"""
            resource "google_sql_database_instance" "db" {{
              name = "db"
              settings {{
                tier = "db-f1-micro"
                ip_configuration {{
                  {ip_configuration}
                }}
              }}
            }}
        """
        found = _ids(_scan_hcl(tmp_path, source), self.ADDRESS)
        assert ("CLOUDSQL_NO_SSL" in found) is fires

    def test_a_read_replica_is_not_judged_for_backups(self, tmp_path: Path) -> None:
        source = """
            resource "google_sql_database_instance" "db" {
              name                 = "db"
              master_instance_name = "primary"
              settings {
                tier = "db-f1-micro"
              }
            }
        """
        assert "CLOUDSQL_NO_BACKUP" not in _ids(_scan_hcl(tmp_path, source), self.ADDRESS)

    def test_plan_json_with_block_lists_agrees_with_hcl(self) -> None:
        bad = {
            "name": "db",
            "settings": [
                {
                    "tier": "db-f1-micro",
                    "ip_configuration": [
                        {
                            "ipv4_enabled": True,
                            "require_ssl": False,
                            "ssl_mode": None,
                            "authorized_networks": [{"name": "all", "value": "0.0.0.0/0"}],
                        }
                    ],
                    "backup_configuration": [{"enabled": False}],
                    "maintenance_window": [],
                }
            ],
        }
        found = _ids(_scan_plan(("google_sql_database_instance", "db", bad)), self.ADDRESS)
        assert self.ALL <= found

    def test_plan_json_with_a_maintenance_window_is_silent(self) -> None:
        good = {
            "name": "db",
            "settings": [{"maintenance_window": [{"day": 7, "hour": 3, "update_track": "stable"}]}],
        }
        found = _ids(_scan_plan(("google_sql_database_instance", "db", good)), self.ADDRESS)
        assert "CLOUDSQL_NO_MAINTENANCE_WINDOW" not in found

    def test_plan_json_with_a_hardened_instance_is_silent(self) -> None:
        good = {
            "name": "db",
            "encryption_key_name": "projects/p/locations/l/keyRings/r/cryptoKeys/k",
            "settings": [
                {
                    "ip_configuration": [
                        {"ipv4_enabled": False, "ssl_mode": "ENCRYPTED_ONLY"},
                    ],
                    "backup_configuration": [{"enabled": True}],
                    "maintenance_window": [{"day": 7, "hour": 3}],
                }
            ],
        }
        found = _scan_plan(("google_sql_database_instance", "db", good))
        assert not _ids(found, self.ADDRESS, "CLOUDSQL_")


class TestCloudRun:
    V1 = """
        resource "google_cloud_run_service" "svc" {
          name     = "svc"
          location = "us-central1"
          template {
            %s
            spec {
              containers {
                image = "gcr.io/p/app"
                %s
              }
            }
          }
        }
    """
    CONNECTOR = """metadata {
              annotations = {
                "run.googleapis.com/vpc-access-connector" = "conn"
                "autoscaling.knative.dev/maxScale"        = "5"
              }
            }"""
    LIMITS = """resources {
                  limits = {
                    cpu = "1000m"
                  }
                }"""
    ADDRESS = "google_cloud_run_service.svc"
    SETTINGS = {"CLOUDRUN_NO_VPC_CONNECTOR", "CLOUDRUN_NO_CPU_LIMIT", "CLOUDRUN_NO_MAX_INSTANCES"}

    def test_a_service_with_none_of_it_fires_all_three(self, tmp_path: Path) -> None:
        found = _ids(_scan_hcl(tmp_path, self.V1 % ("", "")), self.ADDRESS)
        assert self.SETTINGS <= found

    def test_a_vpc_connector_annotation_with_dots_and_a_slash_is_found(
        self, tmp_path: Path
    ) -> None:
        found = _ids(_scan_hcl(tmp_path, self.V1 % (self.CONNECTOR, "")), self.ADDRESS)
        assert "CLOUDRUN_NO_VPC_CONNECTOR" not in found
        assert "CLOUDRUN_NO_MAX_INSTANCES" not in found
        assert "CLOUDRUN_NO_CPU_LIMIT" in found

    def test_a_cpu_limit_is_found_inside_nested_blocks(self, tmp_path: Path) -> None:
        found = _ids(_scan_hcl(tmp_path, self.V1 % ("", self.LIMITS)), self.ADDRESS)
        assert "CLOUDRUN_NO_CPU_LIMIT" not in found
        assert "CLOUDRUN_NO_VPC_CONNECTOR" in found

    def test_a_fully_configured_service_is_silent_on_all_four(self, tmp_path: Path) -> None:
        found = _ids(_scan_hcl(tmp_path, self.V1 % (self.CONNECTOR, self.LIMITS)), self.ADDRESS)
        assert not (self.SETTINGS | {"CLOUDRUN_UNAUTHENTICATED"}) & found

    def test_a_second_container_without_a_limit_is_found(self, tmp_path: Path) -> None:
        source = """
            resource "google_cloud_run_service" "svc" {
              name = "svc"
              template {
                spec {
                  containers {
                    image = "gcr.io/p/app"
                    resources {
                      limits = {
                        cpu = "1000m"
                      }
                    }
                  }
                  containers {
                    image = "gcr.io/p/sidecar"
                  }
                }
              }
            }
        """
        assert "CLOUDRUN_NO_CPU_LIMIT" in _ids(_scan_hcl(tmp_path, source), self.ADDRESS)

    def test_second_generation_services_are_judged_in_their_own_layout(
        self, tmp_path: Path
    ) -> None:
        bare = """
            resource "google_cloud_run_v2_service" "svc" {
              name     = "svc"
              location = "us-central1"
              template {
                containers {
                  image = "gcr.io/p/app"
                }
              }
            }
        """
        configured = """
            resource "google_cloud_run_v2_service" "svc" {
              name     = "svc"
              location = "us-central1"
              template {
                scaling {
                  max_instance_count = 5
                }
                vpc_access {
                  connector = "projects/p/locations/l/connectors/c"
                }
                containers {
                  image = "gcr.io/p/app"
                  resources {
                    limits = {
                      cpu    = "1"
                      memory = "512Mi"
                    }
                  }
                }
              }
            }
        """
        address = "google_cloud_run_v2_service.svc"
        assert self.SETTINGS <= _ids(_scan_hcl(tmp_path, bare), address)
        assert not self.SETTINGS & _ids(_scan_hcl(tmp_path, configured), address)

    @pytest.mark.parametrize(
        ("member", "fires"),
        [
            ('"allUsers"', True),
            ('"allAuthenticatedUsers"', True),
            ('"group:web@example.com"', False),
            ('"serviceAccount:gw@p.iam.gserviceaccount.com"', False),
        ],
    )
    def test_invoker_through_an_iam_member(self, tmp_path: Path, member: str, fires: bool) -> None:
        source = (
            self.V1 % ("", "")
            + f"""
        resource "google_cloud_run_service_iam_member" "invoker" {{
          service  = google_cloud_run_service.svc.name
          location = google_cloud_run_service.svc.location
          role     = "roles/run.invoker"
          member   = {member}
        }}
        """
        )
        found = _scan_hcl(tmp_path, source)
        assert ("CLOUDRUN_UNAUTHENTICATED" in _ids(found, self.ADDRESS)) is fires
        # The grant resource itself is not the service
        assert "CLOUDRUN_UNAUTHENTICATED" not in _ids(
            found, "google_cloud_run_service_iam_member.invoker"
        )

    def test_a_binding_with_allusers_among_its_members_fires(self, tmp_path: Path) -> None:
        source = (
            self.V1 % ("", "")
            + """
        resource "google_cloud_run_service_iam_binding" "invoker" {
          service  = google_cloud_run_service.svc.name
          location = google_cloud_run_service.svc.location
          role     = "roles/run.invoker"
          members  = ["group:web@example.com", "allUsers"]
        }
        """
        )
        assert "CLOUDRUN_UNAUTHENTICATED" in _ids(_scan_hcl(tmp_path, source), self.ADDRESS)

    def test_allusers_with_another_role_is_not_an_invoker(self, tmp_path: Path) -> None:
        source = (
            self.V1 % ("", "")
            + """
        resource "google_cloud_run_service_iam_member" "viewer" {
          service  = google_cloud_run_service.svc.name
          location = google_cloud_run_service.svc.location
          role     = "roles/run.viewer"
          member   = "allUsers"
        }
        """
        )
        assert "CLOUDRUN_UNAUTHENTICATED" not in _ids(_scan_hcl(tmp_path, source), self.ADDRESS)

    def test_a_second_generation_service_with_a_public_invoker_fires(self, tmp_path: Path) -> None:
        source = """
            resource "google_cloud_run_v2_service" "svc" {
              name     = "svc"
              location = "us-central1"
              template {
                containers {
                  image = "gcr.io/p/app"
                }
              }
            }
            resource "google_cloud_run_v2_service_iam_member" "invoker" {
              name     = google_cloud_run_v2_service.svc.name
              location = google_cloud_run_v2_service.svc.location
              role     = "roles/run.invoker"
              member   = "allUsers"
            }
        """
        found = _scan_hcl(tmp_path, source)
        assert "CLOUDRUN_UNAUTHENTICATED" in _ids(found, "google_cloud_run_v2_service.svc")

    def test_a_service_with_no_grants_is_not_public(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.V1 % ("", ""))
        assert "CLOUDRUN_UNAUTHENTICATED" not in _ids(found, self.ADDRESS)


class TestCloudFunctions:
    V1 = """
        resource "google_cloudfunctions_function" "fn" {
          name        = "fn"
          runtime     = "python312"
          %s
        }
    """
    ADDRESS = "google_cloudfunctions_function.fn"

    def test_an_http_function_with_default_ingress_fires(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.V1 % "trigger_http = true")
        assert "GCFUNC_PUBLIC_INGRESS" in _ids(found, self.ADDRESS)

    def test_explicit_allow_all_fires_and_internal_only_is_silent(self, tmp_path: Path) -> None:
        wide = _scan_hcl(tmp_path, self.V1 % 'trigger_http = true\n ingress_settings = "ALLOW_ALL"')
        assert "GCFUNC_PUBLIC_INGRESS" in _ids(wide, self.ADDRESS)
        for setting in ("ALLOW_INTERNAL_ONLY", "ALLOW_INTERNAL_AND_GCLB"):
            body = f'trigger_http = true\n ingress_settings = "{setting}"'
            assert "GCFUNC_PUBLIC_INGRESS" not in _ids(
                _scan_hcl(tmp_path, self.V1 % body), self.ADDRESS
            )

    def test_an_event_triggered_function_has_no_url_to_expose(self, tmp_path: Path) -> None:
        body = 'event_trigger {\n event_type = "google.pubsub.topic.publish"\n resource = "t"\n }'
        found = _scan_hcl(tmp_path, self.V1 % body)
        assert "GCFUNC_PUBLIC_INGRESS" not in _ids(found, self.ADDRESS)

    def test_plain_http_is_a_low_finding_about_https_not_authentication(
        self, tmp_path: Path
    ) -> None:
        optional = _scan_hcl(
            tmp_path,
            self.V1 % 'trigger_http = true\n https_trigger_security_level = "SECURE_OPTIONAL"',
        )
        assert "GCFUNC_HTTP_NO_AUTH" in _ids(optional, self.ADDRESS)
        always = _scan_hcl(
            tmp_path,
            self.V1 % 'trigger_http = true\n https_trigger_security_level = "SECURE_ALWAYS"',
        )
        assert "GCFUNC_HTTP_NO_AUTH" not in _ids(always, self.ADDRESS)

    def test_limits_and_connector_settings(self, tmp_path: Path) -> None:
        bare = _ids(_scan_hcl(tmp_path, self.V1 % "trigger_http = true"), self.ADDRESS)
        assert {"GCFUNC_NO_MAX_INSTANCES", "GCFUNC_NO_VPC_CONNECTOR"} <= bare
        unlimited = _ids(
            _scan_hcl(tmp_path, self.V1 % "trigger_http = true\n max_instances = 0"), self.ADDRESS
        )
        assert "GCFUNC_NO_MAX_INSTANCES" in unlimited
        body = 'trigger_http = true\n max_instances = 10\n vpc_connector = "c"'
        configured = _ids(_scan_hcl(tmp_path, self.V1 % body), self.ADDRESS)
        assert not {"GCFUNC_NO_MAX_INSTANCES", "GCFUNC_NO_VPC_CONNECTOR"} & configured

    @pytest.mark.parametrize(
        ("member", "fires"),
        [("allUsers", True), ("allAuthenticatedUsers", True), ("group:web@example.com", False)],
    )
    def test_public_invoker_on_a_first_generation_function(
        self, tmp_path: Path, member: str, fires: bool
    ) -> None:
        source = (
            self.V1 % "trigger_http = true"
            + f"""
        resource "google_cloudfunctions_function_iam_member" "invoker" {{
          cloud_function = google_cloudfunctions_function.fn.name
          role           = "roles/cloudfunctions.invoker"
          member         = "{member}"
        }}
        """
        )
        found = _scan_hcl(tmp_path, source)
        assert ("GCFUNC_PUBLIC_INVOKER" in _ids(found, self.ADDRESS)) is fires

    def test_public_invoker_on_a_second_generation_function(self, tmp_path: Path) -> None:
        source = """
            resource "google_cloudfunctions2_function" "fn" {
              name     = "fn"
              location = "us-central1"
              build_config {
                runtime     = "python312"
                entry_point = "main"
              }
              service_config {
                ingress_settings = "ALLOW_INTERNAL_ONLY"
                max_instance_count = 3
                vpc_connector      = "c"
                security_level     = "SECURE_ALWAYS"
              }
            }
            resource "google_cloudfunctions2_function_iam_member" "invoker" {
              cloud_function = google_cloudfunctions2_function.fn.name
              role           = "roles/cloudfunctions.invoker"
              member         = "allUsers"
            }
        """
        found = _ids(_scan_hcl(tmp_path, source), "google_cloudfunctions2_function.fn")
        assert found == {"GCFUNC_PUBLIC_INVOKER"}

    def test_a_bare_second_generation_function_is_judged_by_its_defaults(
        self, tmp_path: Path
    ) -> None:
        source = """
            resource "google_cloudfunctions2_function" "fn" {
              name     = "fn"
              location = "us-central1"
              build_config {
                runtime     = "python312"
                entry_point = "main"
              }
            }
        """
        found = _ids(_scan_hcl(tmp_path, source), "google_cloudfunctions2_function.fn")
        assert {
            "GCFUNC_PUBLIC_INGRESS",
            "GCFUNC_NO_MAX_INSTANCES",
            "GCFUNC_NO_VPC_CONNECTOR",
        } <= found
        assert "GCFUNC_PUBLIC_INVOKER" not in found


class TestBigQuery:
    ADDRESS = "google_bigquery_dataset.ds"

    def _dataset(self, access: str = "", extra: str = "") -> str:
        return f"""
            resource "google_bigquery_dataset" "ds" {{
              dataset_id = "ds"
              location   = "US"
              {access}
            }}
            {extra}
        """

    @pytest.mark.parametrize(
        ("attribute", "value", "fires"),
        [
            ("special_group", "allAuthenticatedUsers", True),
            ("special_group", "projectReaders", False),
            ("iam_member", "allUsers", True),
            ("iam_member", "allAuthenticatedUsers", True),
            ("user_by_email", "analyst@example.com", False),
            ("group_by_email", "data@example.com", False),
        ],
    )
    def test_dataset_access_blocks(
        self, tmp_path: Path, attribute: str, value: str, fires: bool
    ) -> None:
        access = f'access {{\n role = "READER"\n {attribute} = "{value}"\n }}'
        found = _scan_hcl(tmp_path, self._dataset(access))
        assert ("BQ_PUBLIC_ACCESS" in _ids(found, self.ADDRESS)) is fires

    def test_public_access_through_a_dataset_iam_member(self, tmp_path: Path) -> None:
        extra = """
            resource "google_bigquery_dataset_iam_member" "viewer" {
              dataset_id = google_bigquery_dataset.ds.dataset_id
              role       = "roles/bigquery.dataViewer"
              member     = "allUsers"
            }
        """
        found = _scan_hcl(tmp_path, self._dataset("", extra))
        assert "BQ_PUBLIC_ACCESS" in _ids(found, self.ADDRESS)

    def test_public_access_through_a_dataset_access_resource(self, tmp_path: Path) -> None:
        extra = """
            resource "google_bigquery_dataset_access" "everyone" {
              dataset_id    = google_bigquery_dataset.ds.dataset_id
              role          = "READER"
              special_group = "allAuthenticatedUsers"
            }
        """
        found = _scan_hcl(tmp_path, self._dataset("", extra))
        assert "BQ_PUBLIC_ACCESS" in _ids(found, self.ADDRESS)

    def test_a_private_member_through_iam_member_is_silent(self, tmp_path: Path) -> None:
        extra = """
            resource "google_bigquery_dataset_iam_member" "viewer" {
              dataset_id = google_bigquery_dataset.ds.dataset_id
              role       = "roles/bigquery.dataViewer"
              member     = "group:data@example.com"
            }
        """
        found = _scan_hcl(tmp_path, self._dataset("", extra))
        assert "BQ_PUBLIC_ACCESS" not in _ids(found, self.ADDRESS)
        # The grant counts as an explicit access policy
        assert "BQ_NO_ACCESS_POLICY" not in _ids(found, self.ADDRESS)

    def test_the_access_policy_rule_needs_no_access_at_all(self, tmp_path: Path) -> None:
        assert "BQ_NO_ACCESS_POLICY" in _ids(_scan_hcl(tmp_path, self._dataset()), self.ADDRESS)
        view = 'access {\n view {\n project_id = "p"\n dataset_id = "d"\n table_id = "t"\n }\n }'
        assert "BQ_NO_ACCESS_POLICY" not in _ids(
            _scan_hcl(tmp_path, self._dataset(view)), self.ADDRESS
        )

    def test_a_customer_managed_key_silences_the_key_preference(self, tmp_path: Path) -> None:
        key = 'default_encryption_configuration {\n kms_key_name = "projects/p/k"\n }'
        assert "BQ_NO_ENCRYPTION" in _ids(_scan_hcl(tmp_path, self._dataset()), self.ADDRESS)
        assert "BQ_NO_ENCRYPTION" not in _ids(_scan_hcl(tmp_path, self._dataset(key)), self.ADDRESS)

    def test_plan_json_dataset_with_a_special_group_fires(self) -> None:
        values = {
            "dataset_id": "ds",
            "access": [{"role": "READER", "special_group": "allAuthenticatedUsers"}],
        }
        found = _scan_plan(("google_bigquery_dataset", "ds", values))
        assert "BQ_PUBLIC_ACCESS" in _ids(found, self.ADDRESS)


class TestPubSub:
    def test_topic_without_a_key_gets_the_preference_and_nothing_else(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_pubsub_topic" "t" {
              name = "t"
            }
            resource "google_pubsub_subscription" "s" {
              name  = "s"
              topic = google_pubsub_topic.t.name
            }
            """,
        )
        assert _ids(found, "google_pubsub_topic.t") == {"PUBSUB_NO_ENCRYPTION"}
        assert not _ids(found, "google_pubsub_subscription.s")

    def test_a_key_silences_the_preference(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_pubsub_topic" "t" {
              name         = "t"
              kms_key_name = "projects/p/locations/l/keyRings/r/cryptoKeys/k"
            }
            """,
        )
        assert not _ids(found, "google_pubsub_topic.t")


class TestComputeInstance:
    def test_serial_port_is_matched_case_insensitively_and_as_a_boolean(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_compute_instance" "upper" {
              name     = "upper"
              metadata = {
                serial-port-enable = "TRUE"
              }
            }
            resource "google_compute_instance" "lower" {
              name     = "lower"
              metadata = {
                serial-port-enable = "true"
              }
            }
            resource "google_compute_instance" "flag" {
              name     = "flag"
              metadata = {
                serial-port-enable = true
              }
            }
            resource "google_compute_instance" "off" {
              name     = "off"
              metadata = {
                serial-port-enable = "false"
              }
            }
            """,
        )
        assert "GCP_VM_SERIAL_PORT" in found["google_compute_instance.upper"]
        assert "GCP_VM_SERIAL_PORT" in found["google_compute_instance.lower"]
        assert "GCP_VM_SERIAL_PORT" in found["google_compute_instance.flag"]
        assert "GCP_VM_SERIAL_PORT" not in found["google_compute_instance.off"]

    def test_default_service_account_rule_covers_instance_templates(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_compute_instance" "vm" {
              name = "vm"
            }
            resource "google_compute_instance_template" "tpl" {
              name_prefix = "tpl"
            }
            resource "google_compute_instance_group_manager" "mig" {
              name = "mig"
            }
            """,
        )
        assert "GCP_VM_DEFAULT_SA" in found["google_compute_instance.vm"]
        assert "GCP_VM_DEFAULT_SA" in found["google_compute_instance_template.tpl"]
        assert not found.get("google_compute_instance_group_manager.mig")

    def test_a_service_account_block_silences_the_default_sa_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_compute_instance" "vm" {
              name = "vm"
              service_account {
                email  = "sa@p.iam.gserviceaccount.com"
                scopes = ["cloud-platform"]
              }
            }
            """,
        )
        assert "GCP_VM_DEFAULT_SA" not in found["google_compute_instance.vm"]

    def test_naming_the_default_account_explicitly_still_counts_as_the_default(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_compute_instance" "vm" {
              name = "vm"
              service_account {
                email  = "123456789-compute@developer.gserviceaccount.com"
                scopes = ["cloud-platform"]
              }
            }
            """,
        )
        assert "GCP_VM_DEFAULT_SA" in found["google_compute_instance.vm"]

    def test_other_instance_rules_do_not_run_on_templates(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            'resource "google_compute_instance_template" "tpl" {\n  name_prefix = "t"\n}\n',
        )
        assert found["google_compute_instance_template.tpl"] == {"GCP_VM_DEFAULT_SA"}

    def test_public_address_through_ipv4_or_ipv6(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_compute_instance" "v4" {
              name = "v4"
              network_interface {
                network = "default"
                access_config {}
              }
            }
            resource "google_compute_instance" "v6" {
              name = "v6"
              network_interface {
                network = "default"
                ipv6_access_config {
                  network_tier = "PREMIUM"
                }
              }
            }
            resource "google_compute_instance" "private" {
              name = "private"
              network_interface {
                network = "default"
              }
            }
            resource "google_compute_instance" "second" {
              name = "second"
              network_interface {
                network = "a"
              }
              network_interface {
                network = "b"
                access_config {}
              }
            }
            """,
        )
        assert "GCP_VM_PUBLIC_IP" in found["google_compute_instance.v4"]
        assert "GCP_VM_PUBLIC_IP" in found["google_compute_instance.v6"]
        assert "GCP_VM_PUBLIC_IP" in found["google_compute_instance.second"]
        assert "GCP_VM_PUBLIC_IP" not in found["google_compute_instance.private"]

    def test_secure_boot_silences_the_shielded_vm_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_compute_instance" "plain" {
              name = "plain"
            }
            resource "google_compute_instance" "off" {
              name = "off"
              shielded_instance_config {
                enable_secure_boot = false
              }
            }
            resource "google_compute_instance" "on" {
              name = "on"
              shielded_instance_config {
                enable_secure_boot          = true
                enable_vtpm                 = true
                enable_integrity_monitoring = true
              }
            }
            """,
        )
        assert "GCP_VM_NO_SHIELDED" in found["google_compute_instance.plain"]
        assert "GCP_VM_NO_SHIELDED" in found["google_compute_instance.off"]
        assert "GCP_VM_NO_SHIELDED" not in found["google_compute_instance.on"]


class TestGke:
    CLUSTER = """
        resource "google_container_cluster" "c" {
          name     = "c"
          location = "us-central1"
          %s
        }
    """
    ADDRESS = "google_container_cluster.c"
    HARDENED = """
        private_cluster_config {
          enable_private_nodes    = true
          enable_private_endpoint = false
          master_ipv4_cidr_block  = "172.16.0.0/28"
        }
        master_authorized_networks_config {
          cidr_blocks {
            cidr_block   = "203.0.113.0/24"
            display_name = "office"
          }
        }
        workload_identity_config {
          workload_pool = "p.svc.id.goog"
        }
        datapath_provider = "ADVANCED_DATAPATH"
    """

    def test_a_default_cluster_fires_the_hardening_rules(self, tmp_path: Path) -> None:
        found = _ids(_scan_hcl(tmp_path, self.CLUSTER % ""), self.ADDRESS)
        assert {
            "GKE_NO_PRIVATE_CLUSTER",
            "GKE_NO_NETWORK_POLICY",
            "GKE_NO_MASTER_AUTHORIZED_NETWORKS",
            "GKE_NO_WORKLOAD_IDENTITY",
        } <= found
        # Shielded Nodes are on by default, and ABAC is off by default
        assert not {"GKE_NO_SHIELDED_NODES", "GKE_LEGACY_ABAC", "GKE_MASTER_WORLD_ACCESS"} & found

    def test_a_hardened_cluster_is_silent(self, tmp_path: Path) -> None:
        found = _ids(_scan_hcl(tmp_path, self.CLUSTER % self.HARDENED), self.ADDRESS, "GKE_")
        assert not found

    def test_dataplane_v2_enforces_network_policy_without_the_network_policy_block(
        self, tmp_path: Path
    ) -> None:
        body = 'datapath_provider = "ADVANCED_DATAPATH"'
        assert "GKE_NO_NETWORK_POLICY" not in _ids(
            _scan_hcl(tmp_path, self.CLUSTER % body), self.ADDRESS
        )

    def test_the_network_policy_block_enables_enforcement(self, tmp_path: Path) -> None:
        body = 'network_policy {\n enabled = true\n provider = "CALICO"\n }'
        assert "GKE_NO_NETWORK_POLICY" not in _ids(
            _scan_hcl(tmp_path, self.CLUSTER % body), self.ADDRESS
        )

    def test_legacy_abac_and_shielded_nodes_off_fire(self, tmp_path: Path) -> None:
        body = "enable_legacy_abac = true\n enable_shielded_nodes = false"
        found = _ids(_scan_hcl(tmp_path, self.CLUSTER % body), self.ADDRESS)
        assert {"GKE_LEGACY_ABAC", "GKE_NO_SHIELDED_NODES"} <= found

    def test_the_world_in_the_authorized_networks_fires_only_the_world_rule(
        self, tmp_path: Path
    ) -> None:
        body = """
            master_authorized_networks_config {
              cidr_blocks {
                cidr_block = "0.0.0.0/0"
              }
              cidr_blocks {
                cidr_block = "10.0.0.0/8"
              }
            }
        """
        found = _ids(_scan_hcl(tmp_path, self.CLUSTER % body), self.ADDRESS)
        assert "GKE_MASTER_WORLD_ACCESS" in found
        assert "GKE_NO_MASTER_AUTHORIZED_NETWORKS" not in found

    def test_a_private_endpoint_needs_no_authorized_networks(self, tmp_path: Path) -> None:
        body = """
            private_cluster_config {
              enable_private_nodes    = true
              enable_private_endpoint = true
            }
        """
        assert "GKE_NO_MASTER_AUTHORIZED_NETWORKS" not in _ids(
            _scan_hcl(tmp_path, self.CLUSTER % body), self.ADDRESS
        )

    def test_autopilot_always_has_workload_identity(self, tmp_path: Path) -> None:
        found = _ids(_scan_hcl(tmp_path, self.CLUSTER % "enable_autopilot = true"), self.ADDRESS)
        assert "GKE_NO_WORKLOAD_IDENTITY" not in found

    def test_node_pool_service_accounts(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_container_node_pool" "default" {
              name    = "default"
              cluster = "c"
            }
            resource "google_container_node_pool" "named_default" {
              name    = "named"
              cluster = "c"
              node_config {
                service_account = "123-compute@developer.gserviceaccount.com"
              }
            }
            resource "google_container_node_pool" "custom" {
              name    = "custom"
              cluster = "c"
              node_config {
                service_account = "nodes@p.iam.gserviceaccount.com"
                oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
              }
            }
            """,
        )
        assert "GKE_NODE_DEFAULT_SA" in found["google_container_node_pool.default"]
        assert "GKE_NODE_DEFAULT_SA" in found["google_container_node_pool.named_default"]
        assert "GKE_NODE_DEFAULT_SA" not in found.get("google_container_node_pool.custom", set())

    def test_plan_json_cluster(self) -> None:
        values = {
            "name": "c",
            "enable_legacy_abac": False,
            "enable_shielded_nodes": True,
            "private_cluster_config": [
                {"enable_private_nodes": True, "enable_private_endpoint": False}
            ],
            "master_authorized_networks_config": [
                {"cidr_blocks": [{"cidr_block": "0.0.0.0/0", "display_name": "all"}]}
            ],
            "workload_identity_config": [{"workload_pool": "p.svc.id.goog"}],
            "network_policy": [],
            "datapath_provider": "ADVANCED_DATAPATH",
        }
        found = _ids(_scan_plan(("google_container_cluster", "c", values)), self.ADDRESS)
        assert found == {"GKE_MASTER_WORLD_ACCESS"}


class TestIam:
    @pytest.mark.parametrize(
        ("rtype", "scope", "role", "expected"),
        [
            ("google_project_iam_member", "project", "roles/owner", True),
            ("google_project_iam_member", "project", "roles/editor", True),
            ("google_project_iam_member", "project", "roles/viewer", False),
            ("google_project_iam_binding", "project", "roles/owner", True),
            ("google_folder_iam_member", "folder", "roles/editor", True),
            ("google_folder_iam_binding", "folder", "roles/viewer", False),
            ("google_organization_iam_binding", "org_id", "roles/owner", True),
        ],
    )
    def test_primitive_roles_on_every_scope(
        self, tmp_path: Path, rtype: str, scope: str, role: str, expected: bool
    ) -> None:
        if rtype.endswith("_member"):
            principal = 'member = "user:a@example.com"'
        else:
            principal = 'members = ["user:a@example.com"]'
        source = f"""
            resource "{rtype}" "g" {{
              {scope} = "x"
              role    = "{role}"
              {principal}
            }}
        """
        found = _ids(_scan_hcl(tmp_path, source), f"{rtype}.g")
        assert ("GCP_IAM_ADMIN_SA" in found) is expected

    def test_token_creator_above_a_single_service_account(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_project_iam_member" "creator" {
              project = "p"
              role    = "roles/iam.serviceAccountTokenCreator"
              member  = "serviceAccount:ci@p.iam.gserviceaccount.com"
            }
            resource "google_service_account_iam_member" "scoped" {
              service_account_id = "projects/p/serviceAccounts/target@p.iam.gserviceaccount.com"
              role               = "roles/iam.serviceAccountTokenCreator"
              member             = "serviceAccount:ci@p.iam.gserviceaccount.com"
            }
            """,
        )
        assert "GCP_IAM_SA_TOKEN_CREATOR" in found["google_project_iam_member.creator"]
        assert "GCP_IAM_SA_TOKEN_CREATOR" not in found.get(
            "google_service_account_iam_member.scoped", set()
        )

    @pytest.mark.parametrize(
        ("rtype", "attribute", "target"),
        [
            ("google_project_iam_member", "member", 'project = "p"'),
            ("google_project_iam_binding", "members", 'project = "p"'),
            ("google_kms_crypto_key_iam_member", "member", 'crypto_key_id = "k"'),
            ("google_secret_manager_secret_iam_member", "member", 'secret_id = "s"'),
            ("google_pubsub_topic_iam_binding", "members", 'topic = "t"'),
            ("google_service_account_iam_member", "member", 'service_account_id = "sa"'),
        ],
    )
    def test_public_principals_on_any_grant_type(
        self, tmp_path: Path, rtype: str, attribute: str, target: str
    ) -> None:
        for principal in ("allUsers", "allAuthenticatedUsers"):
            value = (
                f'"{principal}"' if attribute == "member" else f'["group:g@e.com", "{principal}"]'
            )
            source = f"""
                resource "{rtype}" "g" {{
                  {target}
                  role = "roles/viewer"
                  {attribute} = {value}
                }}
            """
            assert "GCP_IAM_PUBLIC_MEMBER" in _ids(_scan_hcl(tmp_path, source), f"{rtype}.g")
        private = f"""
            resource "{rtype}" "g" {{
              {target}
              role = "roles/viewer"
              {attribute} = {'"group:g@e.com"' if attribute == "member" else '["group:g@e.com"]'}
            }}
        """
        assert "GCP_IAM_PUBLIC_MEMBER" not in _ids(_scan_hcl(tmp_path, private), f"{rtype}.g")

    def test_a_bucket_grant_is_reported_once_by_the_bucket_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_storage_bucket_iam_member" "public" {
              bucket = "b"
              role   = "roles/storage.objectViewer"
              member = "allUsers"
            }
            """,
        )
        assert found["google_storage_bucket_iam_member.public"] == {"GCP_BUCKET_PUBLIC"}

    def test_service_account_key(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_service_account_key" "generated" {
              service_account_id = "sa"
            }
            resource "google_service_account_key" "uploaded" {
              service_account_id = "sa"
              public_key_data    = filebase64("sa.pub")
            }
            """,
        )
        assert found["google_service_account_key.generated"] == {"GCP_IAM_SA_KEY"}
        assert not found.get("google_service_account_key.uploaded")


class TestStorage:
    def test_storage_bucket_companions_do_not_get_bucket_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_storage_bucket" "b" {
              name = "b"
            }
            resource "google_storage_bucket_object" "o" {
              name   = "o"
              bucket = "b"
            }
            """,
        )
        assert {"GCP_BUCKET_NO_VERSIONING", "GCP_BUCKET_NO_LOGGING"} <= found[
            "google_storage_bucket.b"
        ]
        assert not found.get("google_storage_bucket_object.o")

    @pytest.mark.parametrize(
        ("rtype", "body"),
        [
            (
                "google_storage_bucket_iam_member",
                'role = "roles/storage.objectViewer"\n member = "allUsers"',
            ),
            (
                "google_storage_bucket_iam_member",
                'role = "roles/storage.objectViewer"\n member = "allAuthenticatedUsers"',
            ),
            (
                "google_storage_bucket_iam_binding",
                'role = "roles/storage.objectViewer"\n members = ["group:g@e.com", "allUsers"]',
            ),
            ("google_storage_bucket_access_control", 'role = "READER"\n entity = "allUsers"'),
            (
                "google_storage_default_object_access_control",
                'role = "READER"\n entity = "allAuthenticatedUsers"',
            ),
            (
                "google_storage_bucket_acl",
                'role_entity = ["OWNER:project-owners-1", "READER:allUsers"]',
            ),
        ],
    )
    def test_public_bucket_grants_in_every_form(
        self, tmp_path: Path, rtype: str, body: str
    ) -> None:
        source = f'resource "{rtype}" "g" {{\n bucket = "b"\n {body}\n }}\n'
        assert _ids(_scan_hcl(tmp_path, source), f"{rtype}.g") == {"GCP_BUCKET_PUBLIC"}

    @pytest.mark.parametrize(
        ("rtype", "body"),
        [
            (
                "google_storage_bucket_iam_member",
                'role = "roles/storage.objectViewer"\n member = "group:g@e.com"',
            ),
            (
                "google_storage_bucket_iam_binding",
                'role = "roles/storage.objectViewer"\n members = ["group:g@e.com"]',
            ),
            ("google_storage_bucket_access_control", 'role = "READER"\n entity = "group-g@e.com"'),
            ("google_storage_bucket_acl", 'role_entity = ["OWNER:project-owners-1"]'),
        ],
    )
    def test_private_bucket_grants_are_silent(self, tmp_path: Path, rtype: str, body: str) -> None:
        source = f'resource "{rtype}" "g" {{\n bucket = "b"\n {body}\n }}\n'
        assert not _ids(_scan_hcl(tmp_path, source), f"{rtype}.g")

    def test_versioning_and_logging_blocks(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "google_storage_bucket" "good" {
              name     = "good"
              location = "US"
              versioning {
                enabled = true
              }
              logging {
                log_bucket = "logs"
              }
            }
            resource "google_storage_bucket" "off" {
              name     = "off"
              location = "US"
              versioning {
                enabled = false
              }
            }
            """,
        )
        assert not found.get("google_storage_bucket.good")
        assert found["google_storage_bucket.off"] == {
            "GCP_BUCKET_NO_VERSIONING",
            "GCP_BUCKET_NO_LOGGING",
        }


class TestUnknownValuesNeverFire:
    """A value nobody set is not evidence in either direction."""

    @pytest.mark.parametrize(
        "source",
        [
            'resource "google_sql_database_instance" "db" {\n name = "db"\n'
            " settings {\n ip_configuration {\n ssl_mode = var.ssl_mode\n"
            " authorized_networks {\n value = var.net\n }\n }\n }\n }\n",
            'resource "google_storage_bucket_iam_member" "b" {\n bucket = "b"\n'
            ' role = "roles/viewer"\n member = var.member\n }\n',
            'resource "google_container_cluster" "c" {\n name = "c"\n'
            " enable_shielded_nodes = var.shielded\n enable_legacy_abac = var.abac\n }\n",
        ],
    )
    def test_variables_without_values_do_not_produce_the_finding(
        self, tmp_path: Path, source: str
    ) -> None:
        found: Iterable[set[str]] = _scan_hcl(tmp_path, source).values()
        fired = set().union(*found)
        assert not fired & {
            "CLOUDSQL_NO_SSL",
            "CLOUDSQL_PUBLIC_IP",
            "GCP_BUCKET_PUBLIC",
            "GKE_NO_SHIELDED_NODES",
            "GKE_LEGACY_ABAC",
        }
