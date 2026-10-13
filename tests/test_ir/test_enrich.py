"""The enrichment layer: companion folding, derivers, role relations and defaults."""

from __future__ import annotations

import json
from collections.abc import Mapping
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

from tests.helpers.scan import scan_text
from threatcode.ir import enrich as enrich_module
from threatcode.ir.enrich import (
    CompanionSpec,
    apply_defaults,
    enrichment_modules,
    merge_value,
)
from threatcode.ir.graph import InfraGraph
from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.values import Unknown, is_unknown


def _resource(rtype: str, label: str, /, **properties: Any) -> ParsedResource:
    return ParsedResource(
        resource_type=rtype,
        address=f"{rtype}.{label}",
        name=label,
        provider=rtype.split("_", 1)[0],
        properties=dict(properties),
    )


def _graph(*resources: ParsedResource, format_type: str = "terraform_plan") -> InfraGraph:
    return InfraGraph.from_parsed(ParsedOutput(resources=list(resources), format_type=format_type))


def _derived(graph: InfraGraph, address: str) -> dict[str, Any]:
    return dict(graph.nodes[address].properties.get("derived", {}))


def _hcl(text: str) -> InfraGraph:
    return scan_text(text, "main.tf").graph


SECURE_BUCKET = """
resource "aws_s3_bucket" "b" {
  bucket = "my-bucket"
}
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.b.id
  versioning_configuration {
    status = "Enabled"
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "e" {
  bucket = aws_s3_bucket.b.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}
resource "aws_s3_bucket_logging" "l" {
  bucket = aws_s3_bucket.b.id
  target_bucket = "logs"
  target_prefix = "x/"
}
resource "aws_s3_bucket_public_access_block" "p" {
  bucket = aws_s3_bucket.b.id
  block_public_acls = true
  block_public_policy = true
}
resource "aws_s3_bucket_acl" "a" {
  bucket = aws_s3_bucket.b.id
  acl = "private"
}
resource "aws_s3_bucket_ownership_controls" "o" {
  bucket = aws_s3_bucket.b.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
resource "aws_s3_bucket_policy" "pol" {
  bucket = aws_s3_bucket.b.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Deny"
      Principal = "*"
      Action = "s3:*"
      Resource = "*"
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
}
"""


class TestS3CompanionsInHcl:
    def test_every_companion_resolves_through_its_reference(self) -> None:
        derived = _derived(_hcl(SECURE_BUCKET), "aws_s3_bucket.b")
        assert derived["versioning_enabled"] is True
        assert derived["sse_algorithm"] == "aws:kms"
        assert derived["logging_enabled"] is True
        assert derived["public_access_block"] == {
            "block_public_acls": True,
            "block_public_policy": True,
            "ignore_public_acls": False,
            "restrict_public_buckets": False,
        }
        assert derived["acl"] == "private"
        assert derived["object_ownership"] == "BucketOwnerEnforced"
        statement = derived["policy_statements"][0]
        assert statement["effect"] == "Deny"
        assert statement["condition_keys"] == ["aws:SecureTransport"]

    def test_a_bucket_without_companions_is_known_to_lack_them(self) -> None:
        derived = _derived(
            _hcl('resource "aws_s3_bucket" "b" {\n  bucket = "x"\n}\n'), "aws_s3_bucket.b"
        )
        assert derived == {
            "versioning_enabled": False,
            "sse_algorithm": None,
            "logging_enabled": False,
            "public_access_block": None,
            "acl": None,
            "policy_statements": [],
            "object_ownership": None,
        }

    def test_suspended_versioning_is_not_enabled(self) -> None:
        graph = _hcl(SECURE_BUCKET.replace('status = "Enabled"', 'status = "Suspended"'))
        assert _derived(graph, "aws_s3_bucket.b")["versioning_enabled"] is False

    def test_a_companion_of_another_bucket_does_not_satisfy_this_one(self) -> None:
        graph = _hcl(
            """
resource "aws_s3_bucket" "a" {}
resource "aws_s3_bucket" "b" {}
resource "aws_s3_bucket_versioning" "v" {
  bucket = aws_s3_bucket.a.id
  versioning_configuration {
    status = "Enabled"
  }
}
"""
        )
        assert _derived(graph, "aws_s3_bucket.a")["versioning_enabled"] is True
        assert _derived(graph, "aws_s3_bucket.b")["versioning_enabled"] is False

    def test_counted_bucket_instances_are_all_linked(self) -> None:
        graph = _hcl(
            """
resource "aws_s3_bucket" "b" {
  count = 2
}
resource "aws_s3_bucket_versioning" "v" {
  count  = 2
  bucket = aws_s3_bucket.b[count.index].id
  versioning_configuration {
    status = "Enabled"
  }
}
"""
        )
        assert _derived(graph, "aws_s3_bucket.b")["versioning_enabled"] is True

    def test_the_companion_node_stays_in_the_graph_and_is_not_rewritten(self) -> None:
        graph = _hcl(SECURE_BUCKET)
        companion = graph.nodes["aws_s3_bucket_versioning.v"]
        bucket = companion.properties["bucket"]
        assert is_unknown(bucket)
        assert bucket.reference == "aws_s3_bucket.b.id"
        assert "versioning_enabled" not in companion.properties
        assert "versioning_enabled" not in graph.nodes["aws_s3_bucket.b"].properties

    def test_the_users_own_properties_are_untouched(self) -> None:
        graph = _hcl(SECURE_BUCKET)
        assert graph.nodes["aws_s3_bucket.b"].properties["bucket"] == "my-bucket"
        assert set(graph.nodes["aws_s3_bucket.b"].properties) == {"bucket", "derived"}


class TestS3CompanionsInPlanShape:
    def test_a_literal_bucket_name_links_by_the_parent_bucket_property(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "b", bucket="my-bucket"),
            _resource("aws_s3_bucket", "other", bucket="other-bucket"),
            _resource(
                "aws_s3_bucket_versioning",
                "v",
                bucket="my-bucket",
                versioning_configuration=[{"status": "Enabled"}],
            ),
        )
        assert _derived(graph, "aws_s3_bucket.b")["versioning_enabled"] is True
        assert _derived(graph, "aws_s3_bucket.other")["versioning_enabled"] is False

    def test_an_unknown_with_a_reference_resolves_to_its_node(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "b"),
            _resource("aws_s3_bucket", "c"),
            _resource(
                "aws_s3_bucket_logging",
                "l",
                bucket=Unknown("aws_s3_bucket.c.id"),
                target_bucket="t",
            ),
        )
        assert _derived(graph, "aws_s3_bucket.c")["logging_enabled"] is True
        assert _derived(graph, "aws_s3_bucket.b")["logging_enabled"] is False

    def test_an_unknown_without_a_reference_marks_every_candidate_unknown(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a"),
            _resource("aws_s3_bucket", "b"),
            _resource("aws_s3_bucket_logging", "l", bucket=Unknown(), target_bucket="t"),
        )
        for name in ("a", "b"):
            assert is_unknown(_derived(graph, f"aws_s3_bucket.{name}")["logging_enabled"])

    def test_only_the_keys_the_companion_decides_become_unknown(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a"),
            _resource("aws_s3_bucket_logging", "l", bucket=Unknown(), target_bucket="t"),
        )
        derived = _derived(graph, "aws_s3_bucket.a")
        assert is_unknown(derived["logging_enabled"])
        assert derived["versioning_enabled"] is False
        assert derived["sse_algorithm"] is None

    def test_an_absent_link_attribute_is_unknown_not_false(self) -> None:
        # a plan omits a value that is only known after apply
        graph = _graph(
            _resource("aws_s3_bucket", "a"),
            _resource("aws_s3_bucket_logging", "l", target_bucket="t"),
        )
        assert is_unknown(_derived(graph, "aws_s3_bucket.a")["logging_enabled"])

    def test_a_variable_reference_marks_unknown_but_only_buckets(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a"),
            _resource("aws_vpc", "v"),
            _resource("aws_s3_bucket_logging", "l", bucket="${var.bucket}", target_bucket="t"),
        )
        assert is_unknown(_derived(graph, "aws_s3_bucket.a")["logging_enabled"])
        assert "derived" not in graph.nodes[
            "aws_vpc.v"
        ].properties or "logging_enabled" not in _derived(graph, "aws_vpc.v")

    def test_a_known_true_beats_an_unresolved_companion(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a", bucket="a-bucket"),
            _resource("aws_s3_bucket_logging", "known", bucket="a-bucket", target_bucket="t"),
            _resource("aws_s3_bucket_logging", "computed", bucket=Unknown(), target_bucket="t"),
        )
        assert _derived(graph, "aws_s3_bucket.a")["logging_enabled"] is True

    def test_an_unresolved_companion_beats_a_known_false(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a", bucket="a-bucket"),
            _resource(
                "aws_s3_bucket_versioning",
                "v",
                bucket=Unknown(),
                versioning_configuration=[{"status": "Enabled"}],
            ),
        )
        assert is_unknown(_derived(graph, "aws_s3_bucket.a")["versioning_enabled"])

    def test_an_orphan_companion_names_no_parent_and_changes_nothing(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a", bucket="a-bucket"),
            _resource(
                "aws_s3_bucket_versioning",
                "v",
                bucket="a-bucket-in-another-stack",
                versioning_configuration=[{"status": "Enabled"}],
            ),
        )
        assert _derived(graph, "aws_s3_bucket.a")["versioning_enabled"] is False

    def test_a_companion_naming_a_node_of_another_type_is_an_orphan(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a", bucket="a-bucket"),
            _resource("aws_kms_key", "k"),
            _resource(
                "aws_s3_bucket_logging", "l", bucket="${aws_kms_key.k.id}", target_bucket="t"
            ),
        )
        assert _derived(graph, "aws_s3_bucket.a")["logging_enabled"] is False

    def test_an_ambiguous_literal_is_unknown_for_both(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a", bucket="same"),
            _resource("aws_s3_bucket", "b", bucket="same"),
            _resource("aws_s3_bucket_logging", "l", bucket="same", target_bucket="t"),
        )
        assert is_unknown(_derived(graph, "aws_s3_bucket.a")["logging_enabled"])
        assert is_unknown(_derived(graph, "aws_s3_bucket.b")["logging_enabled"])

    def test_a_companion_with_no_parents_at_all_does_not_crash(self) -> None:
        graph = _graph(_resource("aws_s3_bucket_logging", "l", bucket=Unknown(), target_bucket="t"))
        assert "derived" not in graph.nodes["aws_s3_bucket_logging.l"].properties

    def test_a_plain_word_is_matched_as_a_literal_never_as_a_resource_label(self) -> None:
        # the bucket labelled "logs" is named "data"; a companion for the bucket NAMED "logs" must
        # not be attached to it just because the label equals the word
        graph = _graph(
            _resource("aws_s3_bucket", "logs", bucket="data"),
            _resource("aws_s3_bucket_logging", "l", bucket="logs", target_bucket="t"),
        )
        assert _derived(graph, "aws_s3_bucket.logs")["logging_enabled"] is False

    def test_a_computed_flag_in_the_public_access_block_stays_unknown(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "a", bucket="a"),
            _resource(
                "aws_s3_bucket_public_access_block",
                "p",
                bucket="a",
                block_public_acls=Unknown("var.block"),
                block_public_policy=False,
            ),
        )
        block = _derived(graph, "aws_s3_bucket.a")["public_access_block"]
        assert is_unknown(block["block_public_acls"])
        assert block["block_public_policy"] is False


class TestRealPlanDocument:
    """The same facts through the plan JSON parser, with the shapes a real plan has."""

    @staticmethod
    def _plan(resources: list[dict[str, Any]]) -> InfraGraph:
        from threatcode.parsers.terraform_plan import TerraformPlanParser

        plan = {
            "format_version": "1.2",
            "planned_values": {"root_module": {"resources": resources}},
        }
        return InfraGraph.from_parsed(TerraformPlanParser().parse(plan, source_path="plan.json"))

    @staticmethod
    def _planned(rtype: str, name: str, values: dict[str, Any]) -> dict[str, Any]:
        return {
            "address": f"{rtype}.{name}",
            "type": rtype,
            "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "values": values,
        }

    def test_literal_names_link_and_a_missing_computed_link_is_unknown(self) -> None:
        graph = self._plan(
            [
                self._planned("aws_s3_bucket", "a", {"bucket": "a-bucket"}),
                self._planned("aws_s3_bucket", "b", {"bucket": "b-bucket"}),
                self._planned(
                    "aws_s3_bucket_versioning",
                    "known",
                    {
                        "bucket": "a-bucket",
                        "versioning_configuration": [{"status": "Enabled", "mfa_delete": None}],
                    },
                ),
                # the bucket id is only known after apply, so the plan has no bucket value
                self._planned("aws_s3_bucket_logging", "computed", {"target_bucket": "t"}),
            ]
        )
        assert _derived(graph, "aws_s3_bucket.a")["versioning_enabled"] is True
        assert _derived(graph, "aws_s3_bucket.b")["versioning_enabled"] is False
        assert is_unknown(_derived(graph, "aws_s3_bucket.a")["logging_enabled"])
        assert is_unknown(_derived(graph, "aws_s3_bucket.b")["logging_enabled"])

    def test_plan_policy_strings_are_pretty_printed_json(self) -> None:
        document = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }
        graph = self._plan(
            [self._planned("aws_iam_policy", "p", {"policy": json.dumps(document, indent=2)})]
        )
        assert _derived(graph, "aws_iam_policy.p")["policy_statements"][0]["resources"] == ["*"]


class TestLegacyInlineAttributes:
    def test_provider_v3_inline_blocks_are_merged(self) -> None:
        graph = _graph(
            _resource(
                "aws_s3_bucket",
                "b",
                acl="public-read",
                versioning=[{"enabled": True}],
                logging=[{"target_bucket": "t"}],
                server_side_encryption_configuration=[
                    {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {"sse_algorithm": "AES256"}
                                ]
                            }
                        ]
                    }
                ],
            )
        )
        derived = _derived(graph, "aws_s3_bucket.b")
        assert derived["versioning_enabled"] is True
        assert derived["logging_enabled"] is True
        assert derived["sse_algorithm"] == "AES256"
        assert derived["acl"] == "public-read"

    def test_inline_versioning_disabled_is_false(self) -> None:
        graph = _graph(_resource("aws_s3_bucket", "b", versioning=[{"enabled": False}]))
        assert _derived(graph, "aws_s3_bucket.b")["versioning_enabled"] is False

    def test_the_companion_wins_over_the_inline_encryption(self) -> None:
        graph = _graph(
            _resource(
                "aws_s3_bucket",
                "b",
                bucket="bb",
                server_side_encryption_configuration=[
                    {
                        "rule": [
                            {
                                "apply_server_side_encryption_by_default": [
                                    {"sse_algorithm": "AES256"}
                                ]
                            }
                        ]
                    }
                ],
            ),
            _resource(
                "aws_s3_bucket_server_side_encryption_configuration",
                "e",
                bucket="bb",
                rule=[{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
            ),
        )
        assert _derived(graph, "aws_s3_bucket.b")["sse_algorithm"] == "aws:kms"

    def test_inline_policy_and_companion_policy_both_count(self) -> None:
        inline = json.dumps(
            {"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:Get*"}]}
        )
        companion = json.dumps(
            {"Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*"}]}
        )
        graph = _graph(
            _resource("aws_s3_bucket", "b", bucket="bb", policy=inline),
            _resource("aws_s3_bucket_policy", "p", bucket="bb", policy=companion),
        )
        effects = [s["effect"] for s in _derived(graph, "aws_s3_bucket.b")["policy_statements"]]
        assert sorted(effects) == ["Allow", "Deny"]

    def test_cloudformation_style_inline_properties(self) -> None:
        graph = _graph(
            _resource(
                "aws_s3_bucket",
                "b",
                VersioningConfiguration={"Status": "Enabled"},
                LoggingConfiguration={"DestinationBucketName": "t"},
                BucketEncryption={
                    "ServerSideEncryptionConfiguration": [
                        {"ServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}
                    ]
                },
            ),
            format_type="cloudformation",
        )
        derived = _derived(graph, "aws_s3_bucket.b")
        assert derived["versioning_enabled"] is True
        assert derived["logging_enabled"] is True
        assert derived["sse_algorithm"] == "aws:kms"


class TestOtherCompanions:
    def test_a_subnet_flow_log_is_partial_vpc_coverage(self) -> None:
        graph = _hcl(
            """
resource "aws_vpc" "a" {}
resource "aws_vpc" "b" {}
resource "aws_subnet" "s" {
  vpc_id = aws_vpc.b.id
}
resource "aws_flow_log" "fl" {
  vpc_id = aws_vpc.a.id
}
resource "aws_flow_log" "subnet_log" {
  subnet_id = aws_subnet.s.id
}
"""
        )
        assert _derived(graph, "aws_vpc.a")["has_flow_log"] is True
        # a flow log on a subnet covers part of the VPC, which is enough not to report none
        assert _derived(graph, "aws_vpc.b")["has_flow_log"] is True

    def test_secret_rotation_companion_and_inline(self) -> None:
        graph = _graph(
            _resource("aws_secretsmanager_secret", "a", name="a"),
            _resource("aws_secretsmanager_secret", "b", name="b"),
            _resource("aws_secretsmanager_secret", "c", name="c", rotation_lambda_arn="arn:x"),
            _resource("aws_secretsmanager_secret_rotation", "r", secret_id="a"),
        )
        assert _derived(graph, "aws_secretsmanager_secret.a")["rotation_enabled"] is True
        assert _derived(graph, "aws_secretsmanager_secret.b")["rotation_enabled"] is False
        assert _derived(graph, "aws_secretsmanager_secret.c")["rotation_enabled"] is True

    def test_waf_logging_configuration_and_association(self) -> None:
        graph = _hcl(
            """
resource "aws_wafv2_web_acl" "w" {
  name = "w"
}
resource "aws_wafv2_web_acl" "bare" {
  name = "bare"
}
resource "aws_wafv2_web_acl_logging_configuration" "l" {
  resource_arn = aws_wafv2_web_acl.w.arn
}
resource "aws_wafv2_web_acl_association" "a" {
  web_acl_arn  = aws_wafv2_web_acl.w.arn
  resource_arn = "arn:aws:elasticloadbalancing:x"
}
"""
        )
        derived = _derived(graph, "aws_wafv2_web_acl.w")
        assert derived["has_logging_config"] is True
        assert derived["associated_resource_arns"] == ["arn:aws:elasticloadbalancing:x"]
        assert _derived(graph, "aws_wafv2_web_acl.bare")["has_logging_config"] is False

    def test_azure_diagnostic_setting_attaches_to_any_azurerm_resource(self) -> None:
        graph = _hcl(
            """
resource "azurerm_key_vault" "kv" {
  name = "kv"
}
resource "azurerm_storage_account" "sa" {
  name = "sa"
}
resource "azurerm_monitor_diagnostic_setting" "d" {
  name               = "d"
  target_resource_id = azurerm_key_vault.kv.id
}
"""
        )
        assert _derived(graph, "azurerm_key_vault.kv")["has_diagnostic_settings"] is True
        assert _derived(graph, "azurerm_storage_account.sa")["has_diagnostic_settings"] is False
        assert "has_diagnostic_settings" not in _derived(
            graph, "azurerm_monitor_diagnostic_setting.d"
        )

    def test_mssql_auditing_and_alert_policy(self) -> None:
        graph = _hcl(
            """
resource "azurerm_mssql_server" "on" {
  name = "on"
}
resource "azurerm_mssql_server" "off" {
  name = "off"
}
resource "azurerm_mssql_server" "disabled" {
  name = "disabled"
}
resource "azurerm_mssql_server_extended_auditing_policy" "a" {
  server_id = azurerm_mssql_server.on.id
}
resource "azurerm_mssql_server_extended_auditing_policy" "d" {
  server_id = azurerm_mssql_server.disabled.id
  enabled   = false
}
resource "azurerm_mssql_server_security_alert_policy" "s" {
  server_id = azurerm_mssql_server.on.id
  state     = "Enabled"
}
"""
        )
        on = _derived(graph, "azurerm_mssql_server.on")
        assert (on["auditing_enabled"], on["alert_policy_enabled"]) == (True, True)
        off = _derived(graph, "azurerm_mssql_server.off")
        assert (off["auditing_enabled"], off["alert_policy_enabled"]) == (False, False)
        assert _derived(graph, "azurerm_mssql_server.disabled")["auditing_enabled"] is False

    def test_mssql_inline_auditing_block(self) -> None:
        graph = _graph(_resource("azurerm_mssql_server", "s", extended_auditing_policy=[{}]))
        assert _derived(graph, "azurerm_mssql_server.s")["auditing_enabled"] is True

    def test_cloud_run_invokers_by_member_and_binding(self) -> None:
        graph = _hcl(
            """
resource "google_cloud_run_service" "svc" {
  name = "svc"
}
resource "google_cloud_run_service" "private" {
  name = "private"
}
resource "google_cloud_run_service_iam_member" "pub" {
  service = google_cloud_run_service.svc.name
  role    = "roles/run.invoker"
  member  = "allUsers"
}
resource "google_cloud_run_service_iam_binding" "b" {
  service = google_cloud_run_service.svc.name
  role    = "roles/run.invoker"
  members = ["user:a@example.com"]
}
resource "google_cloud_run_service_iam_member" "viewer" {
  service = google_cloud_run_service.private.name
  role    = "roles/run.viewer"
  member  = "allUsers"
}
"""
        )
        assert _derived(graph, "google_cloud_run_service.svc")["invoker_members"] == [
            "allUsers",
            "user:a@example.com",
        ]
        assert _derived(graph, "google_cloud_run_service.private")["invoker_members"] == []

    def test_cloud_run_v2_and_functions(self) -> None:
        graph = _hcl(
            """
resource "google_cloud_run_v2_service" "svc" {
  name = "svc"
}
resource "google_cloud_run_v2_service_iam_member" "pub" {
  name   = google_cloud_run_v2_service.svc.name
  role   = "roles/run.invoker"
  member = "allUsers"
}
resource "google_cloudfunctions_function" "fn" {
  name = "fn"
}
resource "google_cloudfunctions_function_iam_member" "m" {
  cloud_function = google_cloudfunctions_function.fn.name
  role           = "roles/cloudfunctions.invoker"
  member         = "allAuthenticatedUsers"
}
resource "google_cloudfunctions2_function" "fn2" {
  name = "fn2"
}
resource "google_cloudfunctions2_function_iam_member" "m2" {
  cloud_function = google_cloudfunctions2_function.fn2.name
  role           = "roles/run.invoker"
  member         = "allUsers"
}
"""
        )
        assert _derived(graph, "google_cloud_run_v2_service.svc")["invoker_members"] == ["allUsers"]
        assert _derived(graph, "google_cloudfunctions_function.fn")["invoker_members"] == [
            "allAuthenticatedUsers"
        ]
        assert _derived(graph, "google_cloudfunctions2_function.fn2")["invoker_members"] == [
            "allUsers"
        ]

    def test_a_computed_iam_role_makes_the_invokers_unknown(self) -> None:
        graph = _graph(
            _resource("google_cloud_run_service", "svc", name="svc"),
            _resource(
                "google_cloud_run_service_iam_member",
                "m",
                service="svc",
                role=Unknown("var.role"),
                member="allUsers",
            ),
        )
        assert is_unknown(_derived(graph, "google_cloud_run_service.svc")["invoker_members"])

    def test_bigquery_members_from_every_source(self) -> None:
        graph = _hcl(
            """
resource "google_bigquery_dataset" "d" {
  dataset_id = "d"
  access {
    role           = "READER"
    special_group  = "allAuthenticatedUsers"
  }
}
resource "google_bigquery_dataset_iam_member" "m" {
  dataset_id = google_bigquery_dataset.d.dataset_id
  role       = "roles/bigquery.dataViewer"
  member     = "allUsers"
}
resource "google_bigquery_dataset_iam_binding" "b" {
  dataset_id = google_bigquery_dataset.d.dataset_id
  role       = "roles/bigquery.dataViewer"
  members    = ["group:g@example.com"]
}
resource "google_bigquery_dataset_access" "a" {
  dataset_id    = google_bigquery_dataset.d.dataset_id
  role          = "OWNER"
  user_by_email = "u@example.com"
}
"""
        )
        members = _derived(graph, "google_bigquery_dataset.d")["access_members"]
        assert sorted(members) == [
            "allAuthenticatedUsers",
            "allUsers",
            "group:g@example.com",
            "user:u@example.com",
        ]


class TestSecurityGroupFolding:
    SG = """
resource "aws_security_group" "sg" {
  name = "sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}
resource "aws_security_group" "other" {
  name = "other"
}
resource "aws_security_group_rule" "web" {
  type              = "ingress"
  security_group_id = aws_security_group.sg.id
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
}
resource "aws_security_group_rule" "from_other" {
  type                     = "ingress"
  security_group_id        = aws_security_group.sg.id
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.other.id
}
resource "aws_security_group_rule" "to_self" {
  type                     = "ingress"
  security_group_id        = aws_security_group.sg.id
  from_port                = 9000
  to_port                  = 9000
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.sg.id
}
resource "aws_security_group_rule" "out" {
  type              = "egress"
  security_group_id = aws_security_group.sg.id
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["192.168.0.0/16"]
}
resource "aws_vpc_security_group_ingress_rule" "v" {
  security_group_id = aws_security_group.sg.id
  cidr_ipv4         = "1.2.3.4/32"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}
resource "aws_vpc_security_group_egress_rule" "ve" {
  security_group_id            = aws_security_group.sg.id
  referenced_security_group_id = aws_security_group.other.id
  ip_protocol                  = "-1"
}
"""

    def test_inline_and_standalone_rules_fold_into_one_canonical_shape(self) -> None:
        derived = _derived(_hcl(self.SG), "aws_security_group.sg")
        ingress = {r["from_port"]: r for r in derived["ingress"]}
        assert sorted(ingress) == [22, 80, 443, 5432, 9000]
        assert ingress[22] == {
            "cidr_blocks": ["0.0.0.0/0"],
            "ipv6_cidr_blocks": [],
            "from_port": 22,
            "to_port": 22,
            "protocol": "tcp",
            "source_security_groups": [],
            "self": False,
        }
        assert ingress[80]["cidr_blocks"] == ["10.0.0.0/8"]
        assert ingress[443]["cidr_blocks"] == ["1.2.3.4/32"]
        assert ingress[443]["protocol"] == "tcp"
        assert set(ingress[22]) == {
            "cidr_blocks",
            "ipv6_cidr_blocks",
            "from_port",
            "to_port",
            "protocol",
            "source_security_groups",
            "self",
        }

    def test_a_rule_that_points_back_at_its_own_group_is_self(self) -> None:
        derived = _derived(_hcl(self.SG), "aws_security_group.sg")
        ingress = {r["from_port"]: r for r in derived["ingress"]}
        assert ingress[9000]["self"] is True
        assert ingress[9000]["source_security_groups"] == []
        assert ingress[5432]["self"] is False
        assert len(ingress[5432]["source_security_groups"]) == 1

    def test_egress_is_folded_separately(self) -> None:
        derived = _derived(_hcl(self.SG), "aws_security_group.sg")
        egress = {r["from_port"]: r for r in derived["egress"]}
        assert sorted(k for k in egress if k is not None) == [0, 443]
        assert egress[0]["ipv6_cidr_blocks"] == ["::/0"]
        unspecified = [r for r in derived["egress"] if r["from_port"] is None]
        assert unspecified[0]["protocol"] == "-1"
        assert len(unspecified[0]["source_security_groups"]) == 1

    def test_a_source_that_is_not_a_scanned_group_stays_unknown(self) -> None:
        graph = _hcl(
            """
resource "aws_security_group" "sg" {
  name = "sg"
}
resource "aws_security_group_rule" "r" {
  type                     = "ingress"
  security_group_id        = aws_security_group.sg.id
  from_port                = 22
  to_port                  = 22
  protocol                 = "tcp"
  source_security_group_id = var.upstream_group
}
"""
        )
        rule = _derived(graph, "aws_security_group.sg")["ingress"][0]
        assert is_unknown(rule["source_security_groups"])

    def test_a_group_with_no_rules_has_empty_lists(self) -> None:
        derived = _derived(_hcl(self.SG), "aws_security_group.other")
        assert derived == {"ingress": [], "egress": []}

    def test_a_rule_for_another_group_is_not_folded_here(self) -> None:
        graph = _hcl(
            """
resource "aws_security_group" "a" {}
resource "aws_security_group" "b" {}
resource "aws_security_group_rule" "r" {
  type              = "ingress"
  security_group_id = aws_security_group.a.id
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
}
"""
        )
        assert len(_derived(graph, "aws_security_group.a")["ingress"]) == 1
        assert _derived(graph, "aws_security_group.b")["ingress"] == []

    def test_an_unresolved_rule_marks_only_the_direction_it_adds_to(self) -> None:
        graph = _graph(
            _resource("aws_security_group", "a"),
            _resource(
                "aws_security_group_rule",
                "r",
                type="ingress",
                security_group_id=Unknown(),
                from_port=22,
                to_port=22,
                protocol="tcp",
                cidr_blocks=["0.0.0.0/0"],
            ),
        )
        derived = _derived(graph, "aws_security_group.a")
        # A rule resource only adds, so the list stays a list with one entry nobody can read
        assert [is_unknown(entry) for entry in derived["ingress"]] == [True]
        assert derived["egress"] == []

    def test_a_computed_rule_direction_marks_both_unknown(self) -> None:
        graph = _graph(
            _resource("aws_security_group", "a", name="a"),
            _resource(
                "aws_security_group_rule",
                "r",
                type=Unknown("var.direction"),
                security_group_id="a",
            ),
        )
        derived = _derived(graph, "aws_security_group.a")
        assert [is_unknown(entry) for entry in derived["ingress"]] == [True]
        assert [is_unknown(entry) for entry in derived["egress"]] == [True]

    def test_computed_cidr_blocks_stay_unknown_inside_the_rule(self) -> None:
        graph = _graph(
            _resource(
                "aws_security_group",
                "a",
                ingress=[
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": Unknown("var.cidrs"),
                    }
                ],
            )
        )
        (rule,) = _derived(graph, "aws_security_group.a")["ingress"]
        assert is_unknown(rule["cidr_blocks"])
        assert rule["from_port"] == 22

    def test_computed_inline_blocks_are_one_unknown_entry(self) -> None:
        graph = _graph(_resource("aws_security_group", "a", ingress=Unknown("var.rules")))
        derived = _derived(graph, "aws_security_group.a")
        assert [is_unknown(entry) for entry in derived["ingress"]] == [True]

    def test_computed_inline_blocks_leave_the_standalone_rules_readable(self) -> None:
        graph = _graph(
            _resource("aws_security_group", "a", ingress=Unknown("var.rules")),
            _resource(
                "aws_security_group_rule",
                "r",
                type="ingress",
                security_group_id="aws_security_group.a",
                from_port=22,
                to_port=22,
                protocol="tcp",
                cidr_blocks=["0.0.0.0/0"],
            ),
        )
        entries = _derived(graph, "aws_security_group.a")["ingress"]
        known = [entry for entry in entries if not is_unknown(entry)]
        assert [rule["cidr_blocks"] for rule in known] == [["0.0.0.0/0"]]
        assert any(is_unknown(entry) for entry in entries)

    def test_cloudformation_inline_spelling(self) -> None:
        graph = _graph(
            _resource(
                "aws_security_group",
                "a",
                SecurityGroupIngress=[
                    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIp": "0.0.0.0/0"}
                ],
            ),
            format_type="cloudformation",
        )
        (rule,) = _derived(graph, "aws_security_group.a")["ingress"]
        assert rule["cidr_blocks"] == ["0.0.0.0/0"]
        assert rule["protocol"] == "tcp"
        assert rule["from_port"] == 22


ROLE_HCL = """
resource "aws_iam_role" "fn" {
  name = "fn"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}
resource "aws_iam_role" "plain" {
  name = "plain"
}
resource "aws_iam_policy" "custom" {
  name = "custom"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "iam:PassRole", Resource = "*" }]
  })
}
resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.fn.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_role_policy_attachment" "custom" {
  role       = aws_iam_role.fn.name
  policy_arn = aws_iam_policy.custom.arn
}
resource "aws_iam_role_policy" "inline" {
  name = "inline"
  role = aws_iam_role.fn.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
resource "aws_lambda_function" "f" {
  function_name = "f"
  role          = aws_iam_role.fn.arn
}
resource "aws_lambda_function" "g" {
  function_name = "g"
  role          = aws_iam_role.plain.arn
}
"""


class TestRoles:
    def test_attachments_and_inline_policies_fold_into_the_role(self) -> None:
        derived = _derived(_hcl(ROLE_HCL), "aws_iam_role.fn")
        assert derived["attached_policy_arns"] == ["arn:aws:iam::aws:policy/AdministratorAccess"]
        assert [s["actions"] for s in derived["inline_policy_statements"]] == [["*"]]
        assert [s["actions"] for s in derived["attached_policy_statements"]] == [["iam:PassRole"]]
        assert derived["assume_role_statements"][0]["principals"] == ["lambda.amazonaws.com"]

    def test_a_role_without_attachments_has_empty_facts(self) -> None:
        derived = _derived(_hcl(ROLE_HCL), "aws_iam_role.plain")
        assert derived["attached_policy_arns"] == []
        assert derived["inline_policy_statements"] == []

    def test_lambda_inherits_the_policies_of_its_role(self) -> None:
        graph = _hcl(ROLE_HCL)
        derived = _derived(graph, "aws_lambda_function.f")
        assert derived["role_attached_policy_arns"] == [
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ]
        actions = sorted(a for s in derived["role_policy_statements"] for a in s["actions"])
        assert actions == ["*", "iam:PassRole"]
        assert derived["role_ids"] == ["aws_iam_role.fn"]

    def test_a_lambda_with_a_plain_role_inherits_nothing(self) -> None:
        derived = _derived(_hcl(ROLE_HCL), "aws_lambda_function.g")
        assert derived["role_attached_policy_arns"] == []
        assert derived["role_policy_statements"] == []

    def test_the_role_is_matched_by_what_it_is_not_by_its_name(self) -> None:
        # a role named admin that has no admin policy must not look like one
        graph = _graph(
            _resource("aws_iam_role", "admin", name="admin"),
            _resource("aws_lambda_function", "f", role="${aws_iam_role.admin.arn}"),
        )
        assert _derived(graph, "aws_lambda_function.f")["role_attached_policy_arns"] == []

    def test_ecs_task_definition_unions_the_task_and_execution_roles(self) -> None:
        graph = _hcl(
            """
resource "aws_iam_role" "task" {
  name = "task"
}
resource "aws_iam_role" "exec" {
  name = "exec"
}
resource "aws_iam_role_policy_attachment" "t" {
  role       = aws_iam_role.task.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}
resource "aws_iam_role_policy_attachment" "e" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}
resource "aws_ecs_task_definition" "t" {
  family             = "t"
  task_role_arn      = aws_iam_role.task.arn
  execution_role_arn = aws_iam_role.exec.arn
}
"""
        )
        derived = _derived(graph, "aws_ecs_task_definition.t")
        assert sorted(derived["role_attached_policy_arns"]) == [
            "arn:aws:iam::aws:policy/PowerUserAccess",
            "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy",
        ]
        assert derived["role_ids"] == ["aws_iam_role.exec", "aws_iam_role.task"]

    def test_instance_reaches_its_role_through_the_instance_profile(self) -> None:
        graph = _hcl(
            """
resource "aws_iam_role" "r" {
  name = "r"
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.r.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_iam_instance_profile" "p" {
  name = "p"
  role = aws_iam_role.r.name
}
resource "aws_instance" "vm" {
  ami                  = "ami-1"
  iam_instance_profile = aws_iam_instance_profile.p.name
}
resource "aws_instance" "bare" {
  ami = "ami-1"
}
"""
        )
        derived = _derived(graph, "aws_instance.vm")
        assert derived["role_attached_policy_arns"] == [
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ]
        assert derived["role_ids"] == ["aws_iam_role.r"]
        # no profile attribute at all: nothing is claimed
        assert "derived" not in graph.nodes["aws_instance.bare"].properties

    def test_sagemaker_and_eks_node_groups_follow_their_role_attribute(self) -> None:
        graph = _hcl(
            """
resource "aws_iam_role" "r" {
  name = "r"
}
resource "aws_iam_role_policy_attachment" "a" {
  role       = aws_iam_role.r.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
resource "aws_sagemaker_notebook_instance" "nb" {
  name     = "nb"
  role_arn = aws_iam_role.r.arn
}
resource "aws_eks_node_group" "ng" {
  node_group_name = "ng"
  node_role_arn   = aws_iam_role.r.arn
}
"""
        )
        for address in ("aws_sagemaker_notebook_instance.nb", "aws_eks_node_group.ng"):
            assert _derived(graph, address)["role_ids"] == ["aws_iam_role.r"]

    def test_a_role_from_a_variable_is_unknown_never_empty(self) -> None:
        graph = _graph(
            _resource("aws_iam_role", "r", name="r"),
            _resource("aws_lambda_function", "f", role="${var.role_arn}"),
        )
        derived = _derived(graph, "aws_lambda_function.f")
        for key in ("role_attached_policy_arns", "role_policy_statements", "role_ids"):
            assert is_unknown(derived[key])

    def test_a_role_outside_the_scan_is_unknown_never_empty(self) -> None:
        graph = _graph(
            _resource("aws_lambda_function", "f", role="arn:aws:iam::123456789012:role/external")
        )
        assert is_unknown(_derived(graph, "aws_lambda_function.f")["role_policy_statements"])

    def test_a_role_arn_known_in_a_plan_links_by_arn(self) -> None:
        graph = _graph(
            _resource("aws_iam_role", "r", name="r", arn="arn:aws:iam::1:role/r"),
            _resource(
                "aws_iam_role_policy_attachment",
                "a",
                role="r",
                policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
            _resource("aws_lambda_function", "f", role="arn:aws:iam::1:role/r"),
        )
        assert _derived(graph, "aws_lambda_function.f")["role_attached_policy_arns"] == [
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ]

    def test_an_attachment_of_a_computed_policy_is_an_unknown_arn(self) -> None:
        graph = _graph(
            _resource("aws_iam_role", "r", name="r"),
            _resource(
                "aws_iam_role_policy_attachment", "a", role="r", policy_arn=Unknown("var.arn")
            ),
        )
        (arn,) = _derived(graph, "aws_iam_role.r")["attached_policy_arns"]
        assert is_unknown(arn)

    def test_role_inline_policy_blocks_and_managed_policy_arns(self) -> None:
        graph = _graph(
            _resource(
                "aws_iam_role",
                "r",
                name="r",
                inline_policy=[
                    {
                        "name": "a",
                        "policy": json.dumps(
                            {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
                        ),
                    },
                    {
                        "name": "b",
                        "policy": json.dumps(
                            {"Statement": [{"Effect": "Allow", "Action": "sqs:*", "Resource": "*"}]}
                        ),
                    },
                ],
                managed_policy_arns=["arn:aws:iam::aws:policy/ReadOnlyAccess"],
            )
        )
        derived = _derived(graph, "aws_iam_role.r")
        assert [s["actions"] for s in derived["inline_policy_statements"]] == [["s3:*"], ["sqs:*"]]
        assert derived["attached_policy_arns"] == ["arn:aws:iam::aws:policy/ReadOnlyAccess"]

    def test_an_unreadable_inline_policy_makes_the_role_unknown(self) -> None:
        graph = _graph(
            _resource(
                "aws_iam_role", "r", name="r", inline_policy=[{"name": "a", "policy": "{broken"}]
            )
        )
        assert is_unknown(_derived(graph, "aws_iam_role.r")["inline_policy_statements"])


class TestPolicyAttributes:
    def test_every_policy_bearing_type_gets_policy_statements(self) -> None:
        document = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        types = [
            "aws_iam_policy",
            "aws_iam_role_policy",
            "aws_iam_user_policy",
            "aws_iam_group_policy",
            "aws_kms_key",
            "aws_s3_bucket_policy",
            "aws_s3_bucket",
            "aws_sqs_queue",
            "aws_sqs_queue_policy",
            "aws_sns_topic",
            "aws_sns_topic_policy",
        ]
        linked = {"aws_s3_bucket", "aws_s3_bucket_policy"}
        graph = _graph(
            *[
                _resource(t, "x", policy=document, **({"bucket": "bb"} if t in linked else {}))
                for t in types
            ]
        )
        for rtype in types:
            statements = _derived(graph, f"{rtype}.x")["policy_statements"]
            assert statements[0]["actions"] == ["*"], rtype

    def test_a_resource_without_a_policy_gets_no_policy_key(self) -> None:
        graph = _graph(_resource("aws_kms_key", "k", description="d"))
        assert "policy_statements" not in _derived(graph, "aws_kms_key.k")

    def test_hcl_spellings_of_one_policy_agree(self) -> None:
        document = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
        escaped = json.dumps(document).replace('"', '\\"')
        graph = _hcl(
            f"""
resource "aws_iam_policy" "encoded" {{
  policy = jsonencode({{
    Statement = [{{ Effect = "Allow", Action = "*", Resource = "*" }}]
  }})
}}
resource "aws_iam_policy" "heredoc" {{
  policy = <<EOT
{json.dumps(document, indent=2)}
EOT
}}
resource "aws_iam_policy" "quoted" {{
  policy = "{escaped}"
}}
"""
        )
        results = [
            _derived(graph, f"aws_iam_policy.{n}")["policy_statements"]
            for n in ("encoded", "heredoc", "quoted")
        ]
        assert results[0] == results[1] == results[2]
        assert results[0][0]["actions"] == ["*"]

    def test_a_policy_from_a_data_source_is_unknown_not_empty(self) -> None:
        graph = _hcl(
            """
resource "aws_iam_policy" "p" {
  policy = data.aws_iam_policy_document.doc.json
}
"""
        )
        assert is_unknown(_derived(graph, "aws_iam_policy.p")["policy_statements"])

    def test_the_original_policy_attribute_is_left_as_written(self) -> None:
        document = json.dumps({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
        graph = _graph(_resource("aws_iam_policy", "p", policy=document))
        assert graph.nodes["aws_iam_policy.p"].properties["policy"] == document

    def test_container_definitions_and_redrive_policy_are_parsed(self) -> None:
        graph = _graph(
            _resource(
                "aws_ecs_task_definition",
                "t",
                container_definitions=json.dumps([{"name": "a", "privileged": True}], indent=2),
            ),
            _resource(
                "aws_sqs_queue",
                "q",
                redrive_policy=json.dumps({"deadLetterTargetArn": "arn:x", "maxReceiveCount": 3}),
            ),
        )
        assert _derived(graph, "aws_ecs_task_definition.t")["container_definitions"] == [
            {"name": "a", "privileged": True}
        ]
        assert _derived(graph, "aws_sqs_queue.q")["redrive_policy"] == {
            "deadLetterTargetArn": "arn:x",
            "maxReceiveCount": 3,
        }

    def test_hcl_jsonencode_container_definitions(self) -> None:
        graph = _hcl(
            """
resource "aws_ecs_task_definition" "t" {
  family = "t"
  container_definitions = jsonencode([{
    name = "a", privileged = true, readonlyRootFilesystem = false
  }])
}
"""
        )
        (container,) = _derived(graph, "aws_ecs_task_definition.t")["container_definitions"]
        assert container["privileged"] is True
        assert container["readonlyRootFilesystem"] is False

    def test_unreadable_container_definitions_and_redrive_are_unknown(self) -> None:
        graph = _graph(
            _resource("aws_ecs_task_definition", "t", container_definitions='${file("c.json")}'),
            _resource("aws_sqs_queue", "q", redrive_policy="nope"),
        )
        assert is_unknown(_derived(graph, "aws_ecs_task_definition.t")["container_definitions"])
        assert is_unknown(_derived(graph, "aws_sqs_queue.q")["redrive_policy"])


class TestScope:
    def test_design_evidence_nodes_are_not_enriched(self) -> None:
        design = ParsedResource(
            resource_type="aws_s3_bucket",
            address="aws_s3_bucket.d",
            name="d",
            provider="aws",
            evidence="design",
        )
        graph = InfraGraph.from_parsed(ParsedOutput(resources=[design]))
        assert "derived" not in graph.nodes["aws_s3_bucket.d"].properties

    def test_data_sources_are_neither_parents_nor_companions(self) -> None:
        data = ParsedResource(
            resource_type="aws_s3_bucket",
            address="data.aws_s3_bucket.d",
            name="d",
            provider="aws",
            properties={"bucket": "shared"},
            mode="data",
        )
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    data,
                    _resource("aws_s3_bucket_logging", "l", bucket="shared", target_bucket="t"),
                ]
            )
        )
        assert "derived" not in graph.nodes["data.aws_s3_bucket.d"].properties

    def test_an_input_cannot_forge_derived_facts(self) -> None:
        graph = _graph(
            _resource("aws_s3_bucket", "b", derived={"versioning_enabled": True, "evil": 1})
        )
        derived = _derived(graph, "aws_s3_bucket.b")
        assert derived["versioning_enabled"] is False
        assert "evil" not in derived

    def test_unrelated_nodes_get_no_derived_namespace(self) -> None:
        graph = _graph(_resource("aws_dynamodb_table", "t", name="t"))
        assert "derived" not in graph.nodes["aws_dynamodb_table.t"].properties

    def test_enrichment_is_deterministic_and_repeatable(self) -> None:
        first = _graph(*_resources_for_determinism())
        second = _graph(*reversed(_resources_for_determinism()))
        assert _derived(first, "aws_s3_bucket.b") == _derived(second, "aws_s3_bucket.b")
        before = json.dumps(_derived(first, "aws_s3_bucket.b"), sort_keys=True, default=repr)
        enrich_module.enrich(first, enrich_module.ReferenceIndex(first.nodes))
        assert (
            json.dumps(_derived(first, "aws_s3_bucket.b"), sort_keys=True, default=repr) == before
        )

    def test_two_inputs_with_the_same_addresses_each_use_their_own_companions(self) -> None:
        def unit(path: str, enabled: bool) -> ParsedOutput:
            status = "Enabled" if enabled else "Suspended"
            return ParsedOutput(
                resources=[
                    _resource("aws_s3_bucket", "b"),
                    _resource(
                        "aws_s3_bucket_versioning",
                        "v",
                        bucket="${aws_s3_bucket.b.id}",
                        versioning_configuration=[{"status": status}],
                    ),
                ],
                source_path=path,
                format_type="terraform_hcl",
            )

        graph = InfraGraph.from_units([unit("a/main.tf", True), unit("b/main.tf", False)])
        by_unit = {
            node_id.split("::")[0]: node.properties["derived"]["versioning_enabled"]
            for node_id, node in graph.nodes.items()
            if node.resource_type == "aws_s3_bucket"
        }
        assert by_unit == {"a/main.tf": True, "b/main.tf": False}


def _resources_for_determinism() -> list[ParsedResource]:
    return [
        _resource("aws_s3_bucket", "b", bucket="bb"),
        _resource("aws_s3_bucket_logging", "l1", bucket="bb", target_bucket="x"),
        _resource(
            "aws_s3_bucket_server_side_encryption_configuration",
            "e1",
            bucket="bb",
            rule=[{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
        ),
        _resource(
            "aws_s3_bucket_server_side_encryption_configuration",
            "e2",
            bucket="bb",
            rule=[{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        ),
    ]


class TestMergeValue:
    def test_booleans_mean_any(self) -> None:
        assert merge_value(False, True) is True
        assert merge_value(True, False) is True
        assert merge_value(False, False) is False

    def test_a_known_true_beats_unknown_and_unknown_beats_false(self) -> None:
        assert merge_value(Unknown(), True) is True
        assert merge_value(True, Unknown()) is True
        assert is_unknown(merge_value(False, Unknown()))
        assert is_unknown(merge_value(Unknown(), False))

    def test_unknown_beats_everything_that_is_not_a_true(self) -> None:
        assert is_unknown(merge_value([1], Unknown()))
        assert is_unknown(merge_value(None, Unknown()))
        assert is_unknown(merge_value("x", Unknown()))

    def test_lists_concatenate_without_repeats_in_order(self) -> None:
        assert merge_value([1, 2], [2, 3]) == [1, 2, 3]
        assert merge_value([{"a": 1}], [{"a": 1}, {"a": 2}]) == [{"a": 1}, {"a": 2}]

    def test_the_first_scalar_wins_and_none_is_filled(self) -> None:
        assert merge_value("a", "b") == "a"
        assert merge_value(None, "b") == "b"
        assert merge_value("a", None) == "a"

    def test_mappings_merge_key_by_key(self) -> None:
        assert merge_value({"a": False, "b": 1}, {"a": True, "c": 2}) == {"a": True, "b": 1, "c": 2}

    def test_merging_does_not_alias_the_inputs(self) -> None:
        source = [{"a": 1}]
        merged = merge_value(None, source)
        merged[0]["a"] = 2
        assert source == [{"a": 1}]


# ---------------------------------------------------------------------------
# DEFAULTS
# ---------------------------------------------------------------------------

TEST_DEFAULTS: Mapping[str, Mapping[str, Any]] = {
    "aws_kms_key": {"enable_key_rotation": False},
    "aws_eks_cluster": {"vpc_config.endpoint_public_access": True},
}


def _defaults_module(table: Mapping[str, Mapping[str, Any]]) -> ModuleType:
    module = ModuleType("test_defaults")
    module.DEFAULTS = table  # type: ignore[attr-defined]
    return module


def _graph_with_formats(formats: Mapping[str, str], *resources: ParsedResource) -> InfraGraph:
    """Enrich a graph again with a format table, as a graph that records formats would."""
    graph = _graph(*resources)
    graph.node_formats = dict(formats)  # type: ignore[attr-defined]
    for node in graph.nodes.values():
        node.properties.pop("derived", None)
    enrich_module.enrich(graph, enrich_module.ReferenceIndex(graph.nodes))
    return graph


@pytest.fixture
def test_table(monkeypatch: pytest.MonkeyPatch) -> None:
    real = enrichment_modules()
    monkeypatch.setattr(
        enrich_module, "enrichment_modules", lambda: [*real, _defaults_module(TEST_DEFAULTS)]
    )


class TestDefaults:
    def test_every_shipped_table_has_the_documented_shape(self) -> None:
        for module in enrichment_modules():
            table = getattr(module, "DEFAULTS", {})
            assert isinstance(table, Mapping), module.__name__
            for resource_type, defaults in table.items():
                assert isinstance(resource_type, str) and resource_type, module.__name__
                assert isinstance(defaults, Mapping) and defaults, (module.__name__, resource_type)
                for path in defaults:
                    segments = path.split(".")
                    assert all(segments), (module.__name__, resource_type, path)

    def test_apply_defaults_fills_an_absent_attribute(self) -> None:
        node = SimpleNamespace(resource_type="aws_kms_key", properties={"description": "d"})
        assert apply_defaults(node, TEST_DEFAULTS) == ["enable_key_rotation"]  # type: ignore[arg-type]
        assert node.properties["enable_key_rotation"] is False

    def test_apply_defaults_never_replaces_a_present_value_or_an_unknown(self) -> None:
        present = SimpleNamespace(
            resource_type="aws_kms_key", properties={"enable_key_rotation": True}
        )
        computed = SimpleNamespace(
            resource_type="aws_kms_key", properties={"enable_key_rotation": Unknown("var.r")}
        )
        assert apply_defaults(present, TEST_DEFAULTS) == []  # type: ignore[arg-type]
        assert apply_defaults(computed, TEST_DEFAULTS) == []  # type: ignore[arg-type]
        assert present.properties["enable_key_rotation"] is True
        assert is_unknown(computed.properties["enable_key_rotation"])

    def test_a_nested_default_needs_its_block(self) -> None:
        without = SimpleNamespace(resource_type="aws_eks_cluster", properties={"name": "c"})
        assert apply_defaults(without, TEST_DEFAULTS) == []  # type: ignore[arg-type]
        assert "vpc_config" not in without.properties
        with_block = SimpleNamespace(
            resource_type="aws_eks_cluster", properties={"vpc_config": [{"subnet_ids": ["s"]}]}
        )
        assert apply_defaults(with_block, TEST_DEFAULTS) == ["vpc_config.endpoint_public_access"]  # type: ignore[arg-type]
        assert with_block.properties["vpc_config"][0]["endpoint_public_access"] is True

    def test_a_block_that_sets_the_attribute_is_left_alone(self) -> None:
        node = SimpleNamespace(
            resource_type="aws_eks_cluster",
            properties={"vpc_config": [{"endpoint_public_access": False}]},
        )
        assert apply_defaults(node, TEST_DEFAULTS) == []  # type: ignore[arg-type]
        assert node.properties["vpc_config"][0]["endpoint_public_access"] is False

    def test_the_default_is_copied_not_shared(self) -> None:
        table = {"aws_x": {"tags": {"a": 1}}}
        first = SimpleNamespace(resource_type="aws_x", properties={})
        second = SimpleNamespace(resource_type="aws_x", properties={})
        apply_defaults(first, table)  # type: ignore[arg-type]
        apply_defaults(second, table)  # type: ignore[arg-type]
        first.properties["tags"]["a"] = 2
        assert second.properties["tags"] == {"a": 1}

    def test_hcl_nodes_are_filled_and_the_filled_keys_are_listed(self, test_table: None) -> None:
        graph = _graph_with_formats(
            {"aws_kms_key.k": "terraform_hcl"}, _resource("aws_kms_key", "k", description="d")
        )
        node = graph.nodes["aws_kms_key.k"]
        assert node.properties["enable_key_rotation"] is False
        assert node.properties["derived"]["defaults_applied"] == ["enable_key_rotation"]

    def test_cloudformation_nodes_are_filled(self, test_table: None) -> None:
        graph = _graph_with_formats(
            {"aws_kms_key.k": "cloudformation"}, _resource("aws_kms_key", "k")
        )
        assert graph.nodes["aws_kms_key.k"].properties["enable_key_rotation"] is False

    def test_plan_json_nodes_are_never_filled(self, test_table: None) -> None:
        graph = _graph_with_formats(
            {"aws_kms_key.k": "terraform_plan"}, _resource("aws_kms_key", "k", description="d")
        )
        node = graph.nodes["aws_kms_key.k"]
        assert "enable_key_rotation" not in node.properties
        assert "derived" not in node.properties

    def test_design_nodes_are_never_filled(self, test_table: None) -> None:
        design = ParsedResource(
            resource_type="aws_kms_key",
            address="aws_kms_key.k",
            name="k",
            provider="aws",
            evidence="design",
        )
        graph = InfraGraph.from_parsed(ParsedOutput(resources=[design], format_type="design"))
        graph.node_formats = {"aws_kms_key.k": "terraform_hcl"}  # type: ignore[attr-defined]
        enrich_module.enrich(graph, enrich_module.ReferenceIndex(graph.nodes))
        assert "enable_key_rotation" not in graph.nodes["aws_kms_key.k"].properties

    def test_an_unknown_format_is_not_defaulted(self, test_table: None) -> None:
        graph = _graph_with_formats({}, _resource("aws_kms_key", "k", description="d"))
        assert "enable_key_rotation" not in graph.nodes["aws_kms_key.k"].properties

    def test_a_graph_that_records_no_formats_gets_no_defaults(self, test_table: None) -> None:
        graph = _graph(_resource("aws_kms_key", "k"))
        assert "enable_key_rotation" not in graph.nodes["aws_kms_key.k"].properties


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------


class TestModules:
    def test_modules_are_discovered_in_sorted_order(self) -> None:
        names = [m.__name__.rsplit(".", 1)[1] for m in enrichment_modules()]
        assert names == sorted(names)
        assert {"companions", "relations"} <= set(names)

    def test_a_provider_module_adds_a_companion_without_editing_the_core(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        module = ModuleType("aws_extra")
        module.COMPANIONS = (  # type: ignore[attr-defined]
            CompanionSpec(
                "aws_sns_topic",
                "aws_sns_topic_subscription",
                ("topic_arn",),
                lambda companion, parent, ctx: {"subscribed": True},
                absent={"subscribed": False},
            ),
        )
        monkeypatch.setattr(
            enrich_module, "enrichment_modules", lambda: [*enrichment_modules(), module]
        )
        graph = _hcl(
            """
resource "aws_sns_topic" "t" {}
resource "aws_sns_topic" "unused" {}
resource "aws_sns_topic_subscription" "s" {
  topic_arn = aws_sns_topic.t.arn
  protocol  = "email"
  endpoint  = "a@example.com"
}
"""
        )
        assert _derived(graph, "aws_sns_topic.t")["subscribed"] is True
        assert _derived(graph, "aws_sns_topic.unused")["subscribed"] is False


class TestAttachmentsAndRequiredLinks:
    def test_a_users_only_attachment_says_nothing_about_roles(self) -> None:
        graph = _graph(
            _resource("aws_iam_role", "r", name="r"),
            _resource(
                "aws_iam_policy_attachment",
                "users",
                name="users",
                users=["alice"],
                policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
            _resource(
                "aws_iam_policy_attachment",
                "groups",
                name="groups",
                groups=["admins"],
                policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
        )
        derived = _derived(graph, "aws_iam_role.r")
        assert derived["attached_policy_arns"] == []
        assert derived["inline_policy_statements"] == []

    def test_a_roles_attachment_applies_to_the_role_it_names(self) -> None:
        graph = _graph(
            _resource("aws_iam_role", "r", name="r"),
            _resource("aws_iam_role", "other", name="other"),
            _resource(
                "aws_iam_policy_attachment",
                "both",
                name="both",
                roles=["r"],
                users=["alice"],
                policy_arn="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
        )
        assert _derived(graph, "aws_iam_role.r")["attached_policy_arns"] == [
            "arn:aws:iam::aws:policy/AdministratorAccess"
        ]
        assert _derived(graph, "aws_iam_role.other")["attached_policy_arns"] == []

    def test_a_mandatory_role_that_a_plan_omits_is_unknown(self) -> None:
        graph = _graph(
            _resource("aws_iam_role", "r", name="r"),
            _resource("aws_lambda_function", "f", function_name="f"),
            _resource("aws_sagemaker_notebook_instance", "n", name="n"),
            _resource("aws_eks_node_group", "g", node_group_name="g"),
        )
        for address in (
            "aws_lambda_function.f",
            "aws_sagemaker_notebook_instance.n",
            "aws_eks_node_group.g",
        ):
            assert is_unknown(_derived(graph, address)["role_policy_statements"]), address

    def test_an_optional_role_that_is_omitted_stays_silent(self) -> None:
        graph = _graph(_resource("aws_ecs_task_definition", "t", family="t"))
        assert "derived" not in graph.nodes["aws_ecs_task_definition.t"].properties


class TestPartialAddressCollision:
    def test_a_companion_that_cannot_see_its_parent_never_reports_a_confident_false(self) -> None:
        """Two inputs share only the companion's address, so it is qualified and its parent is not.

        The parent is then out of the companion's scope: the known limitation is that the link is
        unresolved, and an unresolved link must not leave the parent looking unversioned.
        """

        def unit(path: str, bucket_label: str) -> ParsedOutput:
            return ParsedOutput(
                resources=[
                    _resource("aws_s3_bucket", bucket_label),
                    _resource(
                        "aws_s3_bucket_versioning",
                        "v",
                        bucket=f"${{aws_s3_bucket.{bucket_label}.id}}",
                        versioning_configuration=[{"status": "Enabled"}],
                    ),
                ],
                source_path=path,
                format_type="terraform_hcl",
            )

        graph = InfraGraph.from_units([unit("a/main.tf", "x"), unit("b/main.tf", "y")])
        assert any("::aws_s3_bucket_versioning.v" in node_id for node_id in graph.nodes)
        for address in ("aws_s3_bucket.x", "aws_s3_bucket.y"):
            value = _derived(graph, address)["versioning_enabled"]
            assert value is not False, address


class TestLiteralLinkScaling:
    BUCKETS = 2000

    def _plan_graph(self, buckets: int | None = None) -> InfraGraph:
        resources: list[ParsedResource] = []
        for i in range(self.BUCKETS if buckets is None else buckets):
            resources.append(_resource("aws_s3_bucket", f"b{i}", bucket=f"bucket-{i}"))
            resources.append(
                _resource(
                    "aws_s3_bucket_versioning",
                    f"v{i}",
                    bucket=f"bucket-{i}",
                    versioning_configuration=[{"status": "Enabled"}],
                )
            )
            resources.append(
                _resource(
                    "aws_s3_bucket_logging", f"l{i}", bucket=f"bucket-{i}", target_bucket="logs"
                )
            )
            resources.append(
                _resource(
                    "aws_s3_bucket_public_access_block",
                    f"p{i}",
                    bucket=f"bucket-{i}",
                    block_public_acls=True,
                )
            )
        return _graph(*resources)

    def test_thousands_of_literal_linked_companions_enrich_in_linear_time(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import time

        builds = {"group": 0}
        original = enrich_module.EnrichContext._group

        def counting(self: Any, prefix: str, resource_type: str) -> Any:
            builds["group"] += 1
            return original(self, prefix, resource_type)

        monkeypatch.setattr(enrich_module.EnrichContext, "_group", counting)
        # An absolute wall-clock bound fails on a loaded machine, so compare two sizes measured
        # back to back: linear growth scales about 4x for 4x the input, quadratic about 16x.
        started = time.perf_counter()
        self._plan_graph(self.BUCKETS // 4)
        small = time.perf_counter() - started
        started = time.perf_counter()
        graph = self._plan_graph()
        elapsed = time.perf_counter() - started
        assert elapsed < 10 * max(small, 0.01), (
            f"enrichment took {elapsed:.1f}s for {len(graph.nodes)} nodes, "
            f"{small:.1f}s for a quarter of them"
        )
        # Candidate lists and literal indexes are built once per type, never once per companion
        assert builds["group"] < 100
        for i in (0, self.BUCKETS // 2, self.BUCKETS - 1):
            derived = _derived(graph, f"aws_s3_bucket.b{i}")
            assert derived["versioning_enabled"] is True
            assert derived["logging_enabled"] is True

    def test_the_index_keeps_ambiguity_at_scale(self) -> None:
        resources = [_resource("aws_s3_bucket", f"b{i}", bucket=f"bucket-{i}") for i in range(500)]
        resources.append(_resource("aws_s3_bucket", "twin", bucket="bucket-7"))
        resources.append(
            _resource(
                "aws_s3_bucket_versioning",
                "ambiguous",
                bucket="bucket-7",
                versioning_configuration=[{"status": "Enabled"}],
            )
        )
        resources.append(
            _resource(
                "aws_s3_bucket_versioning",
                "orphan",
                bucket="no-such-bucket",
                versioning_configuration=[{"status": "Enabled"}],
            )
        )
        graph = _graph(*resources)
        assert is_unknown(_derived(graph, "aws_s3_bucket.b7")["versioning_enabled"])
        assert is_unknown(_derived(graph, "aws_s3_bucket.twin")["versioning_enabled"])
        assert is_unknown(_derived(graph, "aws_s3_bucket.b8")["versioning_enabled"])


COMPUTED_BUCKET = {
    "bucket": "shop-data",
    # What a real plan prints for the deprecated inline settings of a bucket nobody set inline
    "acl": Unknown(),
    "logging": Unknown(),
    "versioning": Unknown(),
    "server_side_encryption_configuration": Unknown(),
    "policy": Unknown(),
}


def _plan_bucket(*companions: ParsedResource, **inline: Any) -> dict[str, Any]:
    properties = {**COMPUTED_BUCKET, **inline}
    return _derived(
        _graph(_resource("aws_s3_bucket", "data", **properties), *companions),
        "aws_s3_bucket.data",
    )


class TestAComputedMarkerDoesNotEraseTheCompanion:
    """A plan prints the inline settings of a bucket unknown; a companion that sets one wins."""

    def test_an_encryption_companion_is_read_through_the_marker(self) -> None:
        derived = _plan_bucket(
            _resource(
                "aws_s3_bucket_server_side_encryption_configuration",
                "data",
                bucket="aws_s3_bucket.data",
                rule=[{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
            )
        )
        assert derived["sse_algorithm"] == "AES256"

    def test_a_suspended_versioning_companion_is_read_through_the_marker(self) -> None:
        derived = _plan_bucket(
            _resource(
                "aws_s3_bucket_versioning",
                "data",
                bucket="aws_s3_bucket.data",
                versioning_configuration=[{"status": "Suspended"}],
            )
        )
        assert derived["versioning_enabled"] is False

    def test_a_public_acl_companion_is_read_through_the_marker(self) -> None:
        derived = _plan_bucket(
            _resource("aws_s3_bucket_acl", "data", bucket="aws_s3_bucket.data", acl="public-read")
        )
        assert derived["acl"] == "public-read"

    def test_a_logging_companion_is_read_through_the_marker(self) -> None:
        derived = _plan_bucket(
            _resource(
                "aws_s3_bucket_logging", "data", bucket="aws_s3_bucket.data", target_bucket="logs"
            )
        )
        assert derived["logging_enabled"] is True

    def test_a_bucket_policy_companion_is_read_through_the_marker(self) -> None:
        policy = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Resource": "arn:aws:s3:::shop-data/*",
                    }
                ],
            }
        )
        derived = _plan_bucket(
            _resource("aws_s3_bucket_policy", "data", bucket="aws_s3_bucket.data", policy=policy)
        )
        assert [s["principals"] for s in derived["policy_statements"]] == [["*"]]
        assert derived["allows_any_principal"] is True

    def test_the_marker_still_keeps_a_fact_unknown_when_no_companion_gave_it(self) -> None:
        derived = _plan_bucket()
        for key in ("sse_algorithm", "versioning_enabled", "logging_enabled", "acl"):
            assert is_unknown(derived[key]), key
        assert is_unknown(derived["policy_statements"])

    def test_a_companion_for_one_setting_does_not_settle_another(self) -> None:
        derived = _plan_bucket(
            _resource(
                "aws_s3_bucket_server_side_encryption_configuration",
                "data",
                bucket="aws_s3_bucket.data",
                rule=[{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
            )
        )
        assert derived["sse_algorithm"] == "AES256"
        assert is_unknown(derived["logging_enabled"])
        assert is_unknown(derived["versioning_enabled"])

    def test_an_unknown_that_carries_a_reference_is_a_value_somebody_wrote(self) -> None:
        derived = _plan_bucket(
            _resource(
                "aws_s3_bucket_server_side_encryption_configuration",
                "data",
                bucket="aws_s3_bucket.data",
                rule=[{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}],
            ),
            server_side_encryption_configuration=Unknown("var.encryption"),
        )
        assert is_unknown(derived["sse_algorithm"])

    def test_the_finding_a_marker_used_to_hide_is_reported(self, tmp_path: Any) -> None:
        plan = {
            "format_version": "1.2",
            "terraform_version": "1.9.0",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_s3_bucket.data",
                            "mode": "managed",
                            "type": "aws_s3_bucket",
                            "name": "data",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {"bucket": "shop-data"},
                        },
                        {
                            "address": "aws_s3_bucket_server_side_encryption_configuration.data",
                            "mode": "managed",
                            "type": "aws_s3_bucket_server_side_encryption_configuration",
                            "name": "data",
                            "provider_name": "registry.terraform.io/hashicorp/aws",
                            "values": {
                                "bucket": "shop-data",
                                "rule": [
                                    {
                                        "apply_server_side_encryption_by_default": [
                                            {"sse_algorithm": "AES256"}
                                        ]
                                    }
                                ],
                            },
                        },
                    ]
                }
            },
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.data",
                    "mode": "managed",
                    "type": "aws_s3_bucket",
                    "name": "data",
                    "provider_name": "registry.terraform.io/hashicorp/aws",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {"bucket": "shop-data"},
                        "after_unknown": {
                            "server_side_encryption_configuration": True,
                            "versioning": True,
                            "logging": True,
                            "acl": True,
                        },
                    },
                }
            ],
        }
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan), encoding="utf-8")
        from tests.helpers.scan import scan_files

        result = scan_files([path])
        assert result.fired("S3_NO_ENCRYPTION", "aws_s3_bucket.data")


class TestAnUnsetLoggingBlock:
    def test_the_empty_list_a_plan_prints_for_no_block_is_not_logging(self) -> None:
        derived = _derived(
            _graph(_resource("aws_s3_bucket", "data", bucket="b", logging=[])),
            "aws_s3_bucket.data",
        )
        assert derived["logging_enabled"] is False

    def test_a_block_with_a_target_is_logging(self) -> None:
        derived = _derived(
            _graph(
                _resource("aws_s3_bucket", "data", bucket="b", logging=[{"target_bucket": "logs"}])
            ),
            "aws_s3_bucket.data",
        )
        assert derived["logging_enabled"] is True
