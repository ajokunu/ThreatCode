"""Tests for AWS data, identity and logging rules.

Covers cloudtrail, config, dynamodb, elasticache, elasticsearch, guardduty, iam, kms, rds,
s3, secrets_manager, sns, sqs and ssm.
Bad and good configurations are real Terraform HCL (or plan JSON where Terraform stores
things differently), run through the parser, the graph and the engine.
"""

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
                        "provider_name": "registry.terraform.io/hashicorp/aws",
                        "values": values,
                    }
                    for rtype, name, values in resources
                ]
            }
        },
    }
    return _findings(InfraGraph.from_parsed(TerraformPlanParser().parse(plan)))


@pytest.fixture
def aws_data_rule_ids():
    return {
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
    }


class TestAwsDataRulesExist:
    def test_all_rules_loaded(self, all_rules, aws_data_rule_ids) -> None:
        loaded_ids = {r.id for r in all_rules}
        for rule_id in aws_data_rule_ids:
            assert rule_id in loaded_ids, f"Rule {rule_id} not found in loaded rules"


class TestAwsDataRulesFire:
    def test_sm_no_rotation_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SM_NO_ROTATION")
        assert evaluate_rule(rule.condition, {"name": "my-secret"})

    def test_sm_no_rotation_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SM_NO_ROTATION")
        assert not evaluate_rule(
            rule.condition, {"rotation_rules": {"automatically_after_days": 30}}
        )

    def test_guardduty_not_enabled_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "GUARDDUTY_NOT_ENABLED")
        assert evaluate_rule(rule.condition, {"enable": False})

    def test_ssm_unencrypted_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SSM_UNENCRYPTED_PARAMETER")
        assert evaluate_rule(rule.condition, {"type": "String", "name": "/app/config"})

    def test_ssm_encrypted_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "SSM_UNENCRYPTED_PARAMETER")
        assert not evaluate_rule(rule.condition, {"type": "SecureString", "name": "/app/secret"})


class TestS3CompanionResources:
    HCL = """
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

    def test_companion_resources_carry_no_bucket_findings(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.HCL)
        assert not found.get("aws_s3_bucket_versioning.data")
        assert not found.get("aws_s3_bucket_server_side_encryption_configuration.data")
        s3_ids = {i for ids in found.values() for i in ids if i.startswith("S3_")}
        assert {a for a, ids in found.items() if any(i.startswith("S3_") for i in ids)} <= {
            "aws_s3_bucket.data"
        }, s3_ids

    @pytest.mark.parametrize(
        "companion",
        [
            "aws_s3_bucket_policy",
            "aws_s3_bucket_public_access_block",
            "aws_s3_bucket_logging",
            "aws_s3_bucket_lifecycle_configuration",
            "aws_s3_bucket_versioning",
            "aws_s3_bucket_server_side_encryption_configuration",
            "aws_s3_bucket_ownership_controls",
        ],
    )
    def test_no_s3_rule_fires_on_a_companion_type(self, tmp_path: Path, companion: str) -> None:
        found = _scan_hcl(tmp_path, f'resource "{companion}" "x" {{\n  bucket = "b"\n}}\n')
        assert not found.get(f"{companion}.x")

    def test_a_public_acl_resource_still_fires_the_public_access_rule(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_s3_bucket_acl" "public" {
              bucket = "b"
              acl    = "public-read"
            }
            resource "aws_s3_bucket_acl" "private" {
              bucket = "b"
              acl    = "private"
            }
            """,
        )
        assert found["aws_s3_bucket_acl.public"] == {"S3_PUBLIC_ACCESS"}
        assert not found.get("aws_s3_bucket_acl.private")

    def test_a_bucket_with_a_public_acl_inline_still_fires(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  acl    = "public-read"\n}\n',
        )
        assert "S3_PUBLIC_ACCESS" in found["aws_s3_bucket.b"]

    def test_plan_json_with_empty_versioning_and_logging_lists(self) -> None:
        found = _scan_plan(
            (
                "aws_s3_bucket",
                "b",
                {
                    "bucket": "b",
                    "versioning": [],
                    "logging": [],
                    "server_side_encryption_configuration": [],
                },
            )
        )
        assert {"S3_NO_VERSIONING", "S3_NO_LOGGING", "S3_NO_ENCRYPTION"} <= found["aws_s3_bucket.b"]

    def test_plan_json_with_everything_set_is_silent(self) -> None:
        found = _scan_plan(
            (
                "aws_s3_bucket",
                "b",
                {
                    "bucket": "b",
                    "versioning": [{"enabled": True, "mfa_delete": False}],
                    "logging": [{"target_bucket": "logs", "target_prefix": ""}],
                    "server_side_encryption_configuration": [
                        {
                            "rule": [
                                {
                                    "apply_server_side_encryption_by_default": [
                                        {"sse_algorithm": "aws:kms"}
                                    ]
                                }
                            ]
                        }
                    ],
                },
            )
        )
        assert not found.get("aws_s3_bucket.b")


class TestOtherTypingBoundaries:
    def test_cloudformation_trail_type_is_not_matched_by_prefix(self) -> None:
        # The CloudFormation parser spells AWS::CloudTrail::Trail aws_cloudtrail_trail until
        # it has an explicit type table; a prefix match was reporting PascalCase properties
        # as missing
        found = _scan_plan(("aws_cloudtrail_trail", "t", {"KMSKeyId": "k"}))
        assert not found.get("aws_cloudtrail_trail.t")

    def test_iam_companions_do_not_get_policy_or_role_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_iam_role_policy" "inline" {
              name = "inline"
              role = "r"
            }
            resource "aws_iam_policy_attachment" "attach" {
              name = "attach"
            }
            resource "aws_iam_user_policy" "user" {
              name = "user"
              user = "u"
            }
            """,
        )
        assert all(not ids for ids in found.values())

    def test_kms_alias_is_not_a_kms_key(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_kms_key" "k" {
              description = "k"
            }
            resource "aws_kms_alias" "a" {
              name          = "alias/k"
              target_key_id = "k"
            }
            """,
        )
        assert "KMS_NO_DELETION_PROTECTION" in found["aws_kms_key.k"]
        assert not found.get("aws_kms_alias.a")

    def test_db_instance_companions_are_not_db_instances(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_db_instance" "db" {
              identifier = "db"
            }
            resource "aws_db_instance_role_association" "assoc" {
              db_instance_identifier = "db"
            }
            """,
        )
        assert {"RDS_NO_ENCRYPTION", "RDS_NO_BACKUP"} <= found["aws_db_instance.db"]
        assert not found.get("aws_db_instance_role_association.assoc")

    def test_sns_and_sqs_policies_keep_their_own_rules(self) -> None:
        wildcard = '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"*"}]}'
        found = _scan_plan(
            ("aws_sns_topic", "t", {"name": "t"}),
            ("aws_sns_topic_policy", "p", {"arn": "arn:x", "policy": wildcard}),
            ("aws_sqs_queue_policy", "q", {"queue_url": "u", "policy": wildcard}),
        )
        assert "SNS_NO_ENCRYPTION" in found["aws_sns_topic.t"]
        assert "SNS_WORLD_SUBSCRIBABLE" not in found["aws_sns_topic.t"]
        assert found["aws_sns_topic_policy.p"] == {"SNS_WORLD_SUBSCRIBABLE"}
        assert found["aws_sqs_queue_policy.q"] == {"SQS_WILDCARD_POLICY"}


class TestNestedBlockPaths:
    """Rules that read inside nested blocks must work on the shape Terraform really gives."""

    def test_secret_rotation_days(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_secretsmanager_secret" "slow" {
              name = "slow"
              rotation_rules {
                automatically_after_days = 120
              }
            }
            resource "aws_secretsmanager_secret" "fast" {
              name = "fast"
              rotation_rules {
                automatically_after_days = 30
              }
            }
            """,
        )
        assert "SM_LONG_ROTATION" in found["aws_secretsmanager_secret.slow"]
        assert "SM_LONG_ROTATION" not in found["aws_secretsmanager_secret.fast"]
        assert "SM_NO_ROTATION" not in found["aws_secretsmanager_secret.slow"]

    def test_guardduty_datasources(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_guardduty_detector" "off" {
              enable = true
              datasources {
                s3_logs {
                  enable = false
                }
                kubernetes {
                  audit_logs {
                    enable = false
                  }
                }
                malware_protection {
                  scan_ec2_instance_with_findings {
                    ebs_volumes {
                      enable = false
                    }
                  }
                }
              }
            }
            resource "aws_guardduty_detector" "on" {
              enable = true
              datasources {
                s3_logs {
                  enable = true
                }
                kubernetes {
                  audit_logs {
                    enable = true
                  }
                }
                malware_protection {
                  scan_ec2_instance_with_findings {
                    ebs_volumes {
                      enable = true
                    }
                  }
                }
              }
            }
            """,
        )
        protections = {
            "GUARDDUTY_NO_S3_PROTECTION",
            "GUARDDUTY_NO_EKS_PROTECTION",
            "GUARDDUTY_NO_MALWARE_SCAN",
        }
        assert protections <= found["aws_guardduty_detector.off"]
        assert not protections & found.get("aws_guardduty_detector.on", set())

    def test_config_recorder_scope(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_config_configuration_recorder" "partial" {
              name     = "partial"
              role_arn = "arn:x"
              recording_group {
                all_supported = false
              }
            }
            resource "aws_config_configuration_recorder" "full" {
              name     = "full"
              role_arn = "arn:x"
              recording_group {
                all_supported = true
              }
            }
            """,
        )
        assert "CONFIG_NOT_ALL_RESOURCES" in found["aws_config_configuration_recorder.partial"]
        assert "CONFIG_NOT_ALL_RESOURCES" not in found["aws_config_configuration_recorder.full"]
        assert "CONFIG_NOT_ENABLED" not in found["aws_config_configuration_recorder.partial"]

    def test_dynamodb_blocks(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_dynamodb_table" "good" {
              name = "good"
              server_side_encryption {
                enabled = true
              }
              point_in_time_recovery {
                enabled = true
              }
              billing_mode = "PAY_PER_REQUEST"
            }
            resource "aws_dynamodb_table" "bad" {
              name = "bad"
            }
            """,
        )
        assert not found.get("aws_dynamodb_table.good")
        assert {"DYNAMODB_NO_ENCRYPTION", "DYNAMODB_NO_PITR"} <= found["aws_dynamodb_table.bad"]
