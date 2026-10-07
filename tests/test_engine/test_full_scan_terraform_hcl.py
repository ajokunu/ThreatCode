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
    tmp_path.mkdir(parents=True, exist_ok=True)
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


# --- directories, variables and unknown values -------------------------------------------

HCL_FIXTURES = FIXTURES_DIR / "terraform" / "hcl"


class TestVariablesDriveRules:
    """A value a variable decides is read like the literal it stands for."""

    def test_a_default_of_false_does_not_make_the_database_public(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            variable "public" {
              default = false
            }
            resource "aws_db_instance" "db" {
              publicly_accessible = var.public
              storage_encrypted   = true
            }
            """,
        )
        assert "RDS_PUBLIC_ACCESS" not in found.get("aws_db_instance.db", set())

    def test_the_same_database_with_a_literal_true_is_public(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            resource "aws_db_instance" "db" {
              publicly_accessible = true
            }
            """,
        )
        assert "RDS_PUBLIC_ACCESS" in found["aws_db_instance.db"]

    def test_a_variable_resolved_to_true_gives_the_findings_of_the_literal(
        self, tmp_path: Path
    ) -> None:
        literal = _scan_text(
            tmp_path / "literal",
            'resource "aws_db_instance" "db" {\n  publicly_accessible = true\n'
            "  storage_encrypted = false\n}\n",
        )
        (tmp_path / "var").mkdir()
        (tmp_path / "var" / "main.tf").write_text(
            textwrap.dedent(
                """
                variable "public" {
                  default = false
                }
                variable "encrypted" {
                  default = true
                }
                locals {
                  encryption = !var.encrypted
                }
                resource "aws_db_instance" "db" {
                  publicly_accessible = var.public
                  storage_encrypted   = !local.encryption
                }
                """
            ),
            encoding="utf-8",
        )
        (tmp_path / "var" / "terraform.tfvars").write_text(
            "public = true\nencrypted = false\n", encoding="utf-8"
        )
        resolved = _scan(tmp_path / "var")
        assert resolved["aws_db_instance.db"] >= {"RDS_PUBLIC_ACCESS", "RDS_NO_ENCRYPTION"}
        assert resolved["aws_db_instance.db"] == literal["aws_db_instance.db"]

    def test_the_tfvars_fixture_makes_the_database_public(self) -> None:
        found = _scan(HCL_FIXTURES / "tfvars_dir")
        assert "RDS_PUBLIC_ACCESS" in found["aws_db_instance.main"]

    def test_an_unresolved_variable_neither_passes_nor_fires(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            variable "public" {}
            variable "encrypted" {}
            resource "aws_db_instance" "db" {
              publicly_accessible = var.public
              storage_encrypted   = var.encrypted
            }
            """,
        )
        assert not found.get("aws_db_instance.db", set()) & {
            "RDS_PUBLIC_ACCESS",
            "RDS_NO_ENCRYPTION",
        }

    def test_a_resource_reference_does_not_fire_an_absence_rule(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            resource "aws_kms_key" "trail" {}
            resource "aws_cloudtrail" "audit" {
              name           = "audit"
              s3_bucket_name = "logs"
              kms_key_id     = aws_kms_key.trail.arn
            }
            """,
        )
        assert "CLOUDTRAIL_NO_ENCRYPTION" not in found["aws_cloudtrail.audit"]

    def test_the_same_trail_without_a_key_does_fire(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            'resource "aws_cloudtrail" "audit" {\n  name = "audit"\n  s3_bucket_name = "logs"\n}\n',
        )
        assert "CLOUDTRAIL_NO_ENCRYPTION" in found["aws_cloudtrail.audit"]

    def test_a_count_zero_resource_is_not_scanned(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            resource "aws_db_instance" "off" {
              count               = 0
              publicly_accessible = true
            }
            resource "aws_db_instance" "on" {
              publicly_accessible = true
            }
            """,
        )
        assert set(found) == {"aws_db_instance.on"}


class TestPolicyRules:
    def test_every_spelling_of_an_admin_policy_fires_the_wildcard_rule(self) -> None:
        found = _scan(HCL_FIXTURES / "iam_policies.tf")
        for name in ("heredoc", "jsonencode", "escaped", "indented_heredoc"):
            assert "IAM_WILDCARD_ACTION" in found[f"aws_iam_policy.{name}"], name

    def test_a_scoped_policy_does_not(self) -> None:
        found = _scan(HCL_FIXTURES / "iam_policies.tf")
        assert "IAM_WILDCARD_ACTION" not in found.get("aws_iam_policy.with_variable", set())
        assert "IAM_WILDCARD_ACTION" not in found.get("aws_iam_policy.scoped_reference", set())

    def test_a_policy_document_with_a_wildcard_action_fires_the_rule(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            """
            data "aws_iam_policy_document" "admin" {
              statement {
                actions   = ["*"]
                resources = ["*"]
              }
            }
            resource "aws_iam_policy" "admin" {
              policy = data.aws_iam_policy_document.admin.json
            }
            """,
        )
        assert "IAM_WILDCARD_ACTION" in found["aws_iam_policy.admin"]

    def test_data_nodes_are_never_findings(self, tmp_path: Path) -> None:
        found = _scan_text(
            tmp_path,
            'data "aws_s3_bucket" "existing" {\n  bucket = "x"\n}\n'
            'data "aws_db_instance" "existing" {\n  publicly_accessible = true\n}\n',
        )
        assert found == {}


class TestModuleScans:
    def test_a_local_module_with_a_public_database_is_found_from_the_root(self) -> None:
        found = _scan(HCL_FIXTURES / "local_modules")
        assert "RDS_PUBLIC_ACCESS" in found["module.db.aws_db_instance.this"]

    def test_the_whole_module_scan_graph_is_connected(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(HCL_FIXTURES / "local_modules"))
        assert all(e.source in graph.nodes and e.target in graph.nodes for e in graph.edges)
        names = set(graph.nodes)
        assert {"module.net.aws_subnet.this", "module.db.aws_db_instance.this"} <= names

    def test_a_remote_only_root_scans_to_a_report_that_is_flagged_incomplete(self) -> None:
        parsed = detect_and_parse(HCL_FIXTURES / "modules.tf")
        assert parsed.metadata["incomplete"] is True
        assert parsed.resources == []
        assert [d.code for d in parsed.diagnostics] == ["hcl.module_call_skipped"] * 2

    def test_the_diagnostics_reach_the_graph(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(HCL_FIXTURES / "modules.tf"))
        assert {d.code for d in graph.diagnostics} == {"hcl.module_call_skipped"}
