"""End-to-end scan tests for Terraform HCL inputs."""

from __future__ import annotations

import textwrap
from collections import defaultdict
from pathlib import Path

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _scan(path: Path) -> dict[str, set[str]]:
    """Rule ids per resource address for a Terraform file."""
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    report = HybridEngine().analyze(graph, input_file=str(path))
    found: dict[str, set[str]] = defaultdict(set)
    for threat in report.threats:
        if threat.source == ThreatSource.RULE:
            found[threat.resource_address].add(threat.rule_id)
    return found


def _scan_text(tmp_path: Path, source: str) -> dict[str, set[str]]:
    path = tmp_path / "main.tf"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return _scan(path)


class TestSimpleModule:
    def test_bucket_and_instance_findings(self) -> None:
        found = _scan(FIXTURES_DIR / "terraform" / "simple.tf")
        assert found == {
            "aws_s3_bucket.test": {"S3_NO_ENCRYPTION", "S3_NO_LOGGING", "S3_NO_VERSIONING"},
            "aws_instance.web": {"EC2_NO_MONITORING", "EC2_UNENCRYPTED_EBS"},
        }


class TestCompanionResources:
    """The AWS provider v4+ splits bucket settings into resources of their own."""

    THREE_RESOURCES = """
        resource "aws_s3_bucket" "data" {
          bucket = "data"
        }
        resource "aws_s3_bucket_versioning" "data" {
          bucket = aws_s3_bucket.data.id
          versioning_configuration {
            status = "Enabled"
          }
        }
        resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
          bucket = aws_s3_bucket.data.id
          rule {
            apply_server_side_encryption_by_default {
              sse_algorithm = "aws:kms"
            }
          }
        }
    """

    def test_no_s3_finding_lands_on_the_companion_resources(self, tmp_path: Path) -> None:
        found = _scan_text(tmp_path, self.THREE_RESOURCES)
        assert "aws_s3_bucket_versioning.data" not in found
        assert "aws_s3_bucket_server_side_encryption_configuration.data" not in found

    def test_the_bucket_itself_is_still_checked(self, tmp_path: Path) -> None:
        found = _scan_text(tmp_path, self.THREE_RESOURCES)
        assert set(found) == {"aws_s3_bucket.data"}
        assert all(rule_id.startswith("S3_") for rule_id in found["aws_s3_bucket.data"])

    def test_findings_scale_with_buckets_not_with_companions(self, tmp_path: Path) -> None:
        found = _scan_text(tmp_path, self.THREE_RESOURCES)
        # One bucket, four S3 absence rules at most: companions must not multiply the count
        assert sum(len(ids) for ids in found.values()) <= 4

    def test_key_vault_access_policies_do_not_get_vault_findings(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            resource "azurerm_key_vault" "kv" {
              name = "kv"
            }
            resource "azurerm_key_vault_access_policy" "app" {
              key_vault_id = azurerm_key_vault.kv.id
              tenant_id    = "t"
              object_id    = "o"
            }
            """,
        )
        assert set(found) == {"azurerm_key_vault.kv"}


class TestRealisticTerraform:
    @pytest.mark.parametrize(
        "name",
        [
            "02_azure_kubernetes_cluster.tf",
            "05_hybrid_vpn_datacenter.tf",
            "07_azure_webapp_java.tf",
        ],
    )
    def test_every_finding_sits_on_a_type_the_rule_declares(self, name: str) -> None:
        path = FIXTURES_DIR / "realistic" / name
        graph = InfraGraph.from_parsed(detect_and_parse(path))
        report = HybridEngine().analyze(graph, input_file=str(path))
        rules = {r.id: r for r in load_all_rules()}
        rule_threats = [t for t in report.threats if t.source == ThreatSource.RULE]
        assert rule_threats
        for threat in rule_threats:
            assert rules[threat.rule_id].matches_type(threat.resource_type), threat.rule_id

    def test_azure_webapp_has_no_findings_on_access_policies(self) -> None:
        found = _scan(FIXTURES_DIR / "realistic" / "07_azure_webapp_java.tf")
        assert not [a for a in found if a.startswith("azurerm_key_vault_access_policy")]
        assert found["azurerm_key_vault.main"] == {"KEYVAULT_NO_DIAGNOSTICS"}

    def test_azure_cluster_has_no_findings_on_node_pools(self) -> None:
        found = _scan(FIXTURES_DIR / "realistic" / "02_azure_kubernetes_cluster.tf")
        assert not [a for a in found if "node_pool" in a]

    def test_hybrid_datacenter_buckets_only(self) -> None:
        found = _scan(FIXTURES_DIR / "realistic" / "05_hybrid_vpn_datacenter.tf")
        s3_addresses = {a for a, ids in found.items() if any(i.startswith("S3_") for i in ids)}
        assert s3_addresses
        assert all(a.startswith("aws_s3_bucket.") for a in s3_addresses)
