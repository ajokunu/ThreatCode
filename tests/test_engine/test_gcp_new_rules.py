"""Tests for new GCP security rules."""

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
                        "provider_name": "registry.terraform.io/hashicorp/google",
                        "values": values,
                    }
                    for rtype, name, values in resources
                ]
            }
        },
    }
    return _findings(InfraGraph.from_parsed(TerraformPlanParser().parse(plan)))


@pytest.fixture
def gcp_new_rule_ids():
    return {
        # Cloud SQL
        "CLOUDSQL_NO_SSL",
        "CLOUDSQL_PUBLIC_IP",
        "CLOUDSQL_NO_BACKUP",
        "CLOUDSQL_NO_ENCRYPTION",
        "CLOUDSQL_NO_MAINTENANCE_WINDOW",
        # Cloud Functions
        "GCFUNC_PUBLIC_INGRESS",
        "GCFUNC_NO_VPC_CONNECTOR",
        "GCFUNC_HTTP_NO_AUTH",
        "GCFUNC_NO_MAX_INSTANCES",
        # BigQuery
        "BQ_PUBLIC_ACCESS",
        "BQ_NO_ENCRYPTION",
        "BQ_NO_ACCESS_POLICY",
        "BQ_NO_LOCATION",
        # Pub/Sub
        "PUBSUB_NO_ENCRYPTION",
        "PUBSUB_NO_DEAD_LETTER",
        "PUBSUB_NO_RETENTION",
        # Cloud Run
        "CLOUDRUN_UNAUTHENTICATED",
        "CLOUDRUN_NO_VPC_CONNECTOR",
        "CLOUDRUN_NO_CPU_LIMIT",
        "CLOUDRUN_NO_MAX_INSTANCES",
    }


class TestGcpNewRulesExist:
    def test_all_new_rules_loaded(self, all_rules, gcp_new_rule_ids) -> None:
        loaded_ids = {r.id for r in all_rules}
        for rule_id in gcp_new_rule_ids:
            assert rule_id in loaded_ids, f"Rule {rule_id} not found"


class TestGcpNewRulesFire:
    def test_bq_public_access_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "BQ_PUBLIC_ACCESS")
        bad_props = {"has_public_access": True}
        assert evaluate_rule(rule.condition, bad_props)

    def test_cloudrun_unauthenticated_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "CLOUDRUN_UNAUTHENTICATED")
        bad_props = {"has_allow_unauthenticated": True}
        assert evaluate_rule(rule.condition, bad_props)

    def test_pubsub_no_encryption_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "PUBSUB_NO_ENCRYPTION")
        bad_props = {"name": "test-topic"}
        assert evaluate_rule(rule.condition, bad_props)


class TestCloudSql:
    BAD = """
        resource "google_sql_database_instance" "db" {
          name = "db"
          settings {
            tier = "db-f1-micro"
            ip_configuration {
              ipv4_enabled = true
              require_ssl  = false
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
              ipv4_enabled = false
              require_ssl  = true
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

    def test_insecure_instance_fires_the_settings_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.BAD)[self.ADDRESS]
        assert {
            "CLOUDSQL_NO_SSL",
            "CLOUDSQL_PUBLIC_IP",
            "CLOUDSQL_NO_BACKUP",
            "CLOUDSQL_NO_MAINTENANCE_WINDOW",
            "CLOUDSQL_NO_ENCRYPTION",
        } <= found

    def test_hardened_instance_is_silent(self, tmp_path: Path) -> None:
        assert not _scan_hcl(tmp_path, self.GOOD).get(self.ADDRESS)

    def test_a_maintenance_window_silences_only_that_rule(self, tmp_path: Path) -> None:
        with_window = self.BAD.replace(
            "backup_configuration {",
            "maintenance_window {\n day = 7\n hour = 3\n }\n backup_configuration {",
        )
        found = _scan_hcl(tmp_path, with_window)[self.ADDRESS]
        assert "CLOUDSQL_NO_MAINTENANCE_WINDOW" not in found
        assert "CLOUDSQL_NO_SSL" in found

    def test_public_ip_needs_ipv4_enabled(self, tmp_path: Path) -> None:
        assert "CLOUDSQL_PUBLIC_IP" in _scan_hcl(tmp_path, self.BAD)[self.ADDRESS]
        assert "CLOUDSQL_PUBLIC_IP" not in _scan_hcl(tmp_path, self.GOOD).get(self.ADDRESS, set())

    def test_plan_json_with_block_lists_agrees_with_hcl(self) -> None:
        bad = {
            "name": "db",
            "settings": [
                {
                    "tier": "db-f1-micro",
                    "ip_configuration": [{"ipv4_enabled": True, "require_ssl": False}],
                    "backup_configuration": [{"enabled": False}],
                    "maintenance_window": [],
                }
            ],
        }
        found = _scan_plan(("google_sql_database_instance", "db", bad))[self.ADDRESS]
        assert {"CLOUDSQL_NO_SSL", "CLOUDSQL_PUBLIC_IP", "CLOUDSQL_NO_MAINTENANCE_WINDOW"} <= found

    def test_plan_json_with_a_maintenance_window_is_silent(self) -> None:
        good = {
            "name": "db",
            "settings": [{"maintenance_window": [{"day": 7, "hour": 3, "update_track": "stable"}]}],
        }
        found = _scan_plan(("google_sql_database_instance", "db", good))[self.ADDRESS]
        assert "CLOUDSQL_NO_MAINTENANCE_WINDOW" not in found


class TestCloudRun:
    BASE = """
        resource "google_cloud_run_service" "svc" {
          name = "svc"
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

    def test_a_service_with_none_of_it_fires_all_three(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.BASE % ("", ""))[self.ADDRESS]
        assert {
            "CLOUDRUN_NO_VPC_CONNECTOR",
            "CLOUDRUN_NO_CPU_LIMIT",
            "CLOUDRUN_NO_MAX_INSTANCES",
        } <= found

    def test_a_vpc_connector_annotation_with_dots_and_a_slash_is_found(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(tmp_path, self.BASE % (self.CONNECTOR, ""))[self.ADDRESS]
        assert "CLOUDRUN_NO_VPC_CONNECTOR" not in found
        assert "CLOUDRUN_NO_MAX_INSTANCES" not in found
        assert "CLOUDRUN_NO_CPU_LIMIT" in found

    def test_a_cpu_limit_is_found_inside_nested_blocks(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.BASE % ("", self.LIMITS))[self.ADDRESS]
        assert "CLOUDRUN_NO_CPU_LIMIT" not in found
        assert "CLOUDRUN_NO_VPC_CONNECTOR" in found

    def test_a_fully_configured_service_is_silent_on_all_four(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.BASE % (self.CONNECTOR, self.LIMITS)).get(
            self.ADDRESS, set()
        )
        assert (
            not {
                "CLOUDRUN_NO_VPC_CONNECTOR",
                "CLOUDRUN_NO_CPU_LIMIT",
                "CLOUDRUN_NO_MAX_INSTANCES",
            }
            & found
        )


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

    def test_other_instance_rules_do_not_run_on_templates(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            'resource "google_compute_instance_template" "tpl" {\n  name_prefix = "t"\n}\n',
        )
        assert found["google_compute_instance_template.tpl"] == {"GCP_VM_DEFAULT_SA"}


class TestGcpTypingBoundaries:
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
            resource "google_storage_bucket_access_control" "acl" {
              bucket = "b"
              role   = "READER"
              entity = "allUsers"
            }
            """,
        )
        assert {"GCP_BUCKET_NO_VERSIONING", "GCP_BUCKET_NO_LOGGING"} <= found[
            "google_storage_bucket.b"
        ]
        assert not found.get("google_storage_bucket_object.o")
        assert not found.get("google_storage_bucket_access_control.acl")

    def test_public_bucket_member_still_fires_its_own_rule(self, tmp_path: Path) -> None:
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
