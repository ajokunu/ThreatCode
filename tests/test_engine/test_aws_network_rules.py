"""Tests for AWS network and compute rules: vpc, ec2, elb, cloudfront, waf, wafv2, eks, ecs, lambda.

Bad and good configurations are written as real Terraform HCL, and where Terraform plan JSON
stores things differently (unset blocks as empty lists) as plan JSON, then run through the
parser, the graph and the engine, so the rules are tested on the shapes they will see.
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
def aws_network_rule_ids():
    return {
        # WAF
        "WAF_NO_DEFAULT_BLOCK",
        "WAF_NO_LOGGING",
        "WAF_NO_RATE_LIMITING",
        "WAF_NO_MANAGED_RULES",
        "WAF_EMPTY_RULES",
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


class TestAwsNetworkRulesExist:
    def test_all_rules_loaded(self, all_rules, aws_network_rule_ids) -> None:
        loaded_ids = {r.id for r in all_rules}
        for rule_id in aws_network_rule_ids:
            assert rule_id in loaded_ids, f"Rule {rule_id} not found in loaded rules"

    def test_no_duplicate_ids(self, all_rules) -> None:
        ids = [r.id for r in all_rules]
        assert len(ids) == len(set(ids)), (
            f"Duplicate rule IDs: {[i for i in ids if ids.count(i) > 1]}"
        )


class TestAwsNetworkRulesFire:
    def test_waf_no_logging_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "WAF_NO_LOGGING")
        assert evaluate_rule(rule.condition, {"name": "test-waf"})

    def test_waf_no_logging_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "WAF_NO_LOGGING")
        good_props = {"logging_configuration": {"log_destination_configs": ["arn:aws:s3:::logs"]}}
        assert not evaluate_rule(rule.condition, good_props)


class TestWafDefaultAction:
    HCL = """
        resource "aws_wafv2_web_acl" "allow" {
          name  = "allow"
          scope = "REGIONAL"
          default_action {
            allow {}
          }
        }
        resource "aws_wafv2_web_acl" "block" {
          name  = "block"
          scope = "REGIONAL"
          default_action {
            block {}
          }
        }
    """

    def test_default_allow_fires_and_default_block_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.HCL)
        assert "WAF_NO_DEFAULT_BLOCK" in found["aws_wafv2_web_acl.allow"]
        assert "WAF_NO_DEFAULT_BLOCK" not in found["aws_wafv2_web_acl.block"]

    def test_plan_json_with_unset_blocks_as_empty_lists_agrees(self) -> None:
        found = _scan_plan(
            ("aws_wafv2_web_acl", "allow", {"default_action": [{"allow": [{}], "block": []}]}),
            ("aws_wafv2_web_acl", "block", {"default_action": [{"allow": [], "block": [{}]}]}),
        )
        assert "WAF_NO_DEFAULT_BLOCK" in found["aws_wafv2_web_acl.allow"]
        assert "WAF_NO_DEFAULT_BLOCK" not in found["aws_wafv2_web_acl.block"]

    def test_logging_configuration_resource_is_not_a_web_acl(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_wafv2_web_acl_logging_configuration" "log" {
              resource_arn = "arn:aws:wafv2:us-east-1:1:regional/webacl/x/y"
            }
            resource "aws_wafv2_web_acl_association" "assoc" {
              resource_arn = "arn:x"
              web_acl_arn  = "arn:y"
            }
            """,
        )
        assert all(not ids for ids in found.values())


class TestEksRules:
    def test_ssh_key_on_a_node_group_fires(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_eks_node_group" "ssh" {
              node_group_name = "ssh"
              remote_access {
                ec2_ssh_key = "ops"
              }
            }
            resource "aws_eks_node_group" "plain" {
              node_group_name = "plain"
            }
            """,
        )
        assert {"EKS_SSH_ACCESS_NODES", "EKS_PUBLIC_NODE_GROUP"} <= found["aws_eks_node_group.ssh"]
        assert not {"EKS_SSH_ACCESS_NODES", "EKS_PUBLIC_NODE_GROUP"} & found.get(
            "aws_eks_node_group.plain", set()
        )

    def test_ssh_key_in_plan_json_with_an_empty_block_list_is_silent(self) -> None:
        found = _scan_plan(("aws_eks_node_group", "n", {"remote_access": []}))
        assert "EKS_SSH_ACCESS_NODES" not in found["aws_eks_node_group.n"]

    def test_public_endpoint(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_eks_cluster" "open" {
              name = "open"
              vpc_config {
                endpoint_public_access = true
              }
            }
            resource "aws_eks_cluster" "closed" {
              name = "closed"
              vpc_config {
                endpoint_public_access = false
              }
            }
            """,
        )
        assert "EKS_PUBLIC_ENDPOINT" in found["aws_eks_cluster.open"]
        assert "EKS_PUBLIC_ENDPOINT" not in found["aws_eks_cluster.closed"]


class TestComputeRules:
    def test_root_volume_encryption(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_instance" "encrypted" {
              ami = "ami-1"
              root_block_device {
                encrypted = true
              }
            }
            resource "aws_instance" "plain" {
              ami = "ami-1"
              root_block_device {
                encrypted = false
              }
            }
            resource "aws_instance" "unset" {
              ami = "ami-1"
            }
            """,
        )
        assert "EC2_UNENCRYPTED_EBS" not in found["aws_instance.encrypted"]
        assert "EC2_UNENCRYPTED_EBS" in found["aws_instance.plain"]
        assert "EC2_UNENCRYPTED_EBS" in found["aws_instance.unset"]

    def test_lambda_in_a_vpc_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_lambda_function" "private" {
              function_name = "private"
              vpc_config {
                subnet_ids         = ["subnet-1"]
                security_group_ids = ["sg-1"]
              }
            }
            resource "aws_lambda_function" "open" {
              function_name = "open"
            }
            """,
        )
        assert "LAMBDA_NO_VPC" not in found["aws_lambda_function.private"]
        assert "LAMBDA_NO_VPC" in found["aws_lambda_function.open"]


class TestDefaultSecurityGroup:
    def test_hcl_without_rules_is_silent_and_with_rules_fires(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_default_security_group" "locked" {
              vpc_id = "vpc-1"
            }
            resource "aws_default_security_group" "open" {
              vpc_id = "vpc-1"
              ingress {
                protocol  = "-1"
                self      = true
                from_port = 0
                to_port   = 0
              }
            }
            """,
        )
        assert "VPC_DEFAULT_SG_OPEN" not in found["aws_default_security_group.locked"]
        assert "VPC_DEFAULT_SG_OPEN" in found["aws_default_security_group.open"]

    def test_plan_json_with_empty_rule_lists_is_silent(self) -> None:
        found = _scan_plan(
            (
                "aws_default_security_group",
                "locked",
                {"vpc_id": "vpc-1", "ingress": [], "egress": []},
            ),
            (
                "aws_default_security_group",
                "open",
                {"vpc_id": "vpc-1", "ingress": [{"protocol": "-1", "self": True}], "egress": []},
            ),
        )
        assert "VPC_DEFAULT_SG_OPEN" not in found["aws_default_security_group.locked"]
        assert "VPC_DEFAULT_SG_OPEN" in found["aws_default_security_group.open"]


class TestHclAndPlanJsonAgree:
    """The same configuration must give the same rule ids as HCL and as plan JSON."""

    HCL = """
        resource "aws_lambda_function" "fn" {
          function_name = "fn"
          role          = "arn:aws:iam::1:role/fn"
        }
        resource "aws_lb" "alb" {
          name = "alb"
        }
        resource "aws_cloudfront_distribution" "cdn" {
          enabled = true
        }
    """

    def test_unset_blocks_agree(self, tmp_path: Path) -> None:
        from_hcl = _scan_hcl(tmp_path, self.HCL)
        from_plan = _scan_plan(
            (
                "aws_lambda_function",
                "fn",
                {
                    "function_name": "fn",
                    "role": "arn:aws:iam::1:role/fn",
                    "vpc_config": [],
                    "dead_letter_config": [],
                    "environment": [],
                },
            ),
            ("aws_lb", "alb", {"name": "alb", "access_logs": [], "subnet_mapping": []}),
            (
                "aws_cloudfront_distribution",
                "cdn",
                {
                    "enabled": True,
                    "web_acl_id": None,
                    "default_cache_behavior": [],
                    "logging_config": [],
                    "restrictions": [],
                },
            ),
        )
        assert from_hcl == from_plan
        assert {"LAMBDA_NO_VPC", "LAMBDA_NO_DLQ"} <= from_hcl["aws_lambda_function.fn"]
        assert "ELB_NO_ACCESS_LOGS" in from_hcl["aws_lb.alb"]
        assert {"CLOUDFRONT_NO_LOGGING", "CLOUDFRONT_NO_WAF"} <= from_hcl[
            "aws_cloudfront_distribution.cdn"
        ]


class TestExactTyping:
    def test_load_balancer_companions_do_not_get_load_balancer_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_lb" "alb" {
              name = "alb"
            }
            resource "aws_lb_listener" "https" {
              load_balancer_arn = "arn:x"
              protocol          = "HTTPS"
            }
            resource "aws_lb_target_group" "tg" {
              name = "tg"
            }
            """,
        )
        assert "ELB_NO_ACCESS_LOGS" in found["aws_lb.alb"]
        assert not found.get("aws_lb_listener.https")
        assert not found.get("aws_lb_target_group.tg")

    def test_security_group_rules_do_not_get_security_group_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group_rule" "ssh" {
              type        = "ingress"
              from_port   = 22
              to_port     = 22
              protocol    = "tcp"
              cidr_blocks = ["0.0.0.0/0"]
            }
            """,
        )
        assert not found.get("aws_security_group_rule.ssh")

    def test_lambda_companions_do_not_get_function_rules(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_lambda_function" "fn" {
              function_name = "fn"
            }
            resource "aws_lambda_function_event_invoke_config" "inv" {
              function_name = "fn"
            }
            resource "aws_lambda_alias" "live" {
              name          = "live"
              function_name = "fn"
            }
            """,
        )
        assert {"LAMBDA_NO_VPC", "LAMBDA_NO_DLQ"} <= found["aws_lambda_function.fn"]
        assert not found.get("aws_lambda_function_event_invoke_config.inv")
        assert not found.get("aws_lambda_alias.live")
