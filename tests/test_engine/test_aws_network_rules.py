"""AWS network and compute rules: vpc, ec2, elb, cloudfront, waf, wafv2, eks, ecs, lambda,
api_gateway, ecr and sagemaker.

Bad and good configurations are written as real Terraform HCL, plan JSON and CloudFormation, then
run through the parser, the graph, the enrichment layer and the engine, so the rules are tested on
the shapes they will see.
The per-rule bad and good examples live in tests/test_rules/cases; this module tests what an
example cannot: the same configuration in three formats, the unknown and absent edge cases, the
derived facts the rules read, and the calibration of the twelve rule files.
"""

from __future__ import annotations

import json
import re
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest

from threatcode import vocab
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import TECHNIQUE_DB, is_revoked, tactics_for_techniques
from threatcode.engine.rules.loader import (
    Rule,
    deprecated_rule_ids,
    load_all_rules,
    load_rule_file,
)
from threatcode.ir import enrich as enrich_module
from threatcode.ir.enrichment import aws_network
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import detect_and_parse
from threatcode.parsers.terraform_plan import TerraformPlanParser
from threatcode.values import Unknown, is_unknown

BUILTIN = Path(__file__).resolve().parents[2] / "src/threatcode/engine/rules/builtin/aws"
GROUPS = (
    "vpc",
    "ec2",
    "elb",
    "cloudfront",
    "waf",
    "wafv2",
    "eks",
    "ecs",
    "lambda",
    "api_gateway",
    "ecr",
    "sagemaker",
)
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _rules() -> dict[str, Rule]:
    found: dict[str, Rule] = {}
    for group in GROUPS:
        for rule in load_rule_file(BUILTIN / f"{group}.yml").rules:
            found[rule.id] = rule
    return found


RULES = _rules()


# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------


class Ref(list[str]):
    """A plan attribute that is unknown after apply and names these references."""


def _findings(graph: InfraGraph) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for threat in HybridEngine().analyze(graph).threats:
        if threat.rule_id:
            found[threat.resource_address].add(threat.rule_id)
    return found


def _hcl_graph(tmp_path: Path, source: str) -> InfraGraph:
    path = tmp_path / "main.tf"
    path.write_text(textwrap.dedent(source), encoding="utf-8")
    return InfraGraph.from_parsed(detect_and_parse(path))


def _scan_hcl(tmp_path: Path, source: str) -> dict[str, set[str]]:
    """Rule ids per resource address for a Terraform HCL snippet."""
    return _findings(_hcl_graph(tmp_path, source))


def _cfn_graph(tmp_path: Path, resources: str) -> InfraGraph:
    path = tmp_path / "template.yaml"
    text = 'AWSTemplateFormatVersion: "2010-09-09"\nResources:\n' + textwrap.indent(
        textwrap.dedent(resources).strip("\n"), "  "
    )
    path.write_text(text + "\n", encoding="utf-8")
    return InfraGraph.from_parsed(detect_and_parse(path))


def _scan_cfn(tmp_path: Path, resources: str) -> dict[str, set[str]]:
    return _findings(_cfn_graph(tmp_path, resources))


def _plan_doc(*resources: tuple[str, str, dict[str, Any]]) -> dict[str, Any]:
    planned = []
    changes = []
    configured = []
    for rtype, name, values in resources:
        address = f"{rtype}.{name}"
        known = {k: v for k, v in values.items() if not isinstance(v, Ref)}
        unknown = {k: True for k, v in values.items() if isinstance(v, Ref)}
        planned.append(
            {
                "address": address,
                "mode": "managed",
                "type": rtype,
                "name": name,
                "provider_name": "registry.terraform.io/hashicorp/aws",
                "values": known,
            }
        )
        changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": rtype,
                "name": name,
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": known,
                    "after_unknown": unknown,
                },
            }
        )
        configured.append(
            {
                "address": address,
                "mode": "managed",
                "type": rtype,
                "name": name,
                "expressions": {
                    k: {"references": list(v)} for k, v in values.items() if isinstance(v, Ref)
                },
            }
        )
    return {
        "format_version": "1.2",
        "planned_values": {"root_module": {"resources": planned}},
        "resource_changes": changes,
        "configuration": {"root_module": {"resources": configured}},
    }


def _plan_graph(*resources: tuple[str, str, dict[str, Any]]) -> InfraGraph:
    return InfraGraph.from_parsed(TerraformPlanParser().parse(_plan_doc(*resources)))


def _scan_plan(*resources: tuple[str, str, dict[str, Any]]) -> dict[str, set[str]]:
    """Rule ids per resource address for (type, name, values) entries of a plan JSON."""
    return _findings(_plan_graph(*resources))


def _derived(graph: InfraGraph, address: str) -> dict[str, Any]:
    derived = graph.nodes[address].properties.get("derived")
    assert isinstance(derived, dict), f"{address} has no derived facts"
    return derived


def _with_formats(graph: InfraGraph, fmt: str) -> InfraGraph:
    """Return the graph after checking that the build recorded every node as the given format.

    The graph build records each node's parser format and enriches with it, so the defaults are
    already applied (or withheld, for plan JSON) by the time the graph is returned.
    """
    assert graph.node_formats
    assert set(graph.node_formats.values()) == {fmt}
    return graph


def _ingress(
    from_port: int,
    to_port: int,
    protocol: str,
    cidr: str | None = None,
    ipv6: str | None = None,
    groups: list[str] | None = None,
    self_: bool = False,
) -> dict[str, Any]:
    return {
        "cidr_blocks": [cidr] if cidr else [],
        "description": "",
        "from_port": from_port,
        "ipv6_cidr_blocks": [ipv6] if ipv6 else [],
        "prefix_list_ids": [],
        "protocol": protocol,
        "security_groups": groups or [],
        "self": self_,
        "to_port": to_port,
    }


# ---------------------------------------------------------------------------
# The rule files
# ---------------------------------------------------------------------------


class TestRuleInventory:
    EXPECTED = {
        "vpc": {
            "SG_UNRESTRICTED_INGRESS",
            "SG_WEB_PORT_OPEN_TO_WORLD",
            "SG_TEMPORARY_OPEN",
            "VPC_DEFAULT_SG_OPEN",
            "VPC_NO_FLOW_LOGS",
        },
        "ec2": {"EC2_PUBLIC_IP", "EC2_IMDSV1", "EC2_UNENCRYPTED_EBS"},
        "elb": {"ELB_NO_HTTPS", "ELB_NO_ACCESS_LOGS", "ELB_OUTDATED_TLS"},
        "cloudfront": {
            "CLOUDFRONT_NO_HTTPS",
            "CLOUDFRONT_NO_WAF",
            "CLOUDFRONT_NO_LOGGING",
            "CLOUDFRONT_NO_GEO_RESTRICTION",
        },
        "waf": {
            "WAF_NO_DEFAULT_BLOCK",
            "WAF_NO_LOGGING",
            "WAF_NO_RATE_LIMITING",
            "WAF_NO_MANAGED_RULES",
            "WAF_EMPTY_RULES",
        },
        "wafv2": {
            "WAFV2_NO_SQL_INJECTION_RULE",
            "WAFV2_NO_XSS_RULE",
            "WAFV2_RATE_LIMIT_HIGH",
            "WAFV2_NO_IP_REPUTATION",
            "WAFV2_NO_GEO_BLOCKING",
        },
        "eks": {
            "EKS_PUBLIC_ENDPOINT",
            "EKS_PUBLIC_ACCESS_ANY_CIDR",
            "EKS_NO_ENCRYPTION",
            "EKS_NO_LOGGING",
            "EKS_OUTDATED_VERSION",
            "EKS_NO_IRSA",
            "EKS_SSH_ACCESS_NODES",
        },
        "ecs": {
            "ECS_PRIVILEGED_CONTAINER",
            "ECS_NO_READONLY_FS",
            "ECS_EXEC_ENABLED",
            "ECS_NO_LOGGING",
            "ECS_HOST_NETWORKING",
        },
        "lambda": {"LAMBDA_NO_VPC", "LAMBDA_OVERPERMISSIVE_ROLE", "LAMBDA_URL_NO_AUTH"},
        "api_gateway": {
            "APIGW_METHOD_NO_AUTH",
            "APIGW_ROUTE_NO_AUTH",
            "APIGW_PUBLIC_POLICY",
            "APIGW_NO_ACCESS_LOGS",
        },
        "ecr": {"ECR_MUTABLE_TAGS", "ECR_NO_SCAN_ON_PUSH", "ECR_PUBLIC_POLICY"},
        "sagemaker": {
            "SAGEMAKER_NOTEBOOK_DIRECT_INTERNET",
            "SAGEMAKER_NOTEBOOK_ROOT_ACCESS",
            "SAGEMAKER_NOTEBOOK_NO_KMS",
        },
    }
    DELETED = {
        "ec2": {"EC2_NO_MONITORING"},
        "eks": {"EKS_PUBLIC_NODE_GROUP", "EKS_NO_FARGATE_LOGGING", "EKS_UNENCRYPTED_NODE_AMI"},
        "lambda": {"LAMBDA_NO_DLQ"},
    }

    @pytest.mark.parametrize("group", GROUPS)
    def test_each_file_holds_exactly_its_rules(self, group: str) -> None:
        loaded = load_rule_file(BUILTIN / f"{group}.yml")
        assert {r.id for r in loaded.rules} == self.EXPECTED[group]

    @pytest.mark.parametrize("group", GROUPS)
    def test_deleted_rules_are_recorded_and_gone(self, group: str) -> None:
        loaded = load_rule_file(BUILTIN / f"{group}.yml")
        assert loaded.deprecated_ids == frozenset(self.DELETED.get(group, set()))
        everywhere = {r.id for r in load_all_rules()}
        assert not loaded.deprecated_ids & everywhere

    def test_suppressions_of_a_deleted_rule_can_be_warned_about(self) -> None:
        deprecated = deprecated_rule_ids()
        for ids in self.DELETED.values():
            assert ids <= deprecated

    def test_no_rule_id_is_defined_twice(self) -> None:
        ids = [r.id for r in load_all_rules()]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------


class TestCalibration:
    def test_absence_rules_stop_at_medium_and_heuristic_rules_at_high(self) -> None:
        for rule in RULES.values():
            rank = SEVERITY_ORDER.index(rule.severity)
            if rule.confidence == "absence":
                assert rank <= SEVERITY_ORDER.index("medium"), rule.id
            if rule.confidence == "heuristic":
                assert rank <= SEVERITY_ORDER.index("high"), rule.id

    def test_critical_is_never_reached_without_a_definitive_condition(self) -> None:
        for rule in RULES.values():
            if rule.severity == "critical":
                assert rule.confidence == "definitive", rule.id

    def test_every_rule_declares_its_confidence_in_the_file(self) -> None:
        for group in GROUPS:
            text = (BUILTIN / f"{group}.yml").read_text(encoding="utf-8")
            count = len(re.findall(r"^  - id: ", text, re.M))
            assert len(re.findall(r"^    confidence: ", text, re.M)) == count, group

    def test_techniques_exist_and_are_not_revoked(self) -> None:
        for rule in RULES.values():
            for technique in (rule.metadata.get("mitre") or {}).get("techniques", []):
                assert technique in TECHNIQUE_DB, (rule.id, technique)
                assert not is_revoked(technique), (rule.id, technique)

    def test_tactics_are_derived_from_the_techniques_not_written_by_hand(self) -> None:
        for rule in RULES.values():
            mitre = rule.metadata.get("mitre") or {}
            written = mitre.get("tactics")
            if written is not None:
                assert written == tactics_for_techniques(mitre.get("techniques", [])), rule.id

    def test_missing_logging_is_a_repudiation_finding_with_no_adversary_technique(self) -> None:
        logging_rules = [r for r in RULES.values() if r.root_cause == "logging-not-enabled"]
        assert {r.id for r in logging_rules} >= {
            "VPC_NO_FLOW_LOGS",
            "ELB_NO_ACCESS_LOGS",
            "CLOUDFRONT_NO_LOGGING",
            "WAF_NO_LOGGING",
            "EKS_NO_LOGGING",
            "ECS_NO_LOGGING",
            "APIGW_NO_ACCESS_LOGS",
        }
        for rule in logging_rules:
            assert rule.stride_category == "repudiation", rule.id
            assert rule.confidence == "absence", rule.id
            assert not (rule.metadata.get("mitre") or {}).get("techniques"), rule.id

    def test_no_rule_uses_the_revoked_cloud_log_technique(self) -> None:
        for rule in RULES.values():
            assert "T1562.008" not in (rule.metadata.get("mitre") or {}).get("techniques", [])

    def test_exposed_admin_services_map_to_external_remote_services(self) -> None:
        techniques = RULES["SG_UNRESTRICTED_INGRESS"].metadata["mitre"]["techniques"]
        assert "T1133" in techniques
        assert "T1190" in techniques
        assert RULES["EC2_IMDSV1"].metadata["mitre"]["techniques"] == ["T1552.005"]

    def test_security_group_and_function_isolation_categories_are_defensible(self) -> None:
        assert RULES["SG_UNRESTRICTED_INGRESS"].stride_category == "information_disclosure"
        no_vpc = RULES["LAMBDA_NO_VPC"]
        assert no_vpc.stride_category != "elevation_of_privilege"
        assert "T1190" not in (no_vpc.metadata.get("mitre") or {}).get("techniques", [])

    def test_the_security_group_port_lists_are_the_shared_vocabulary(self) -> None:
        wanted = vocab.ADMIN_PORTS | vocab.DATABASE_PORTS

        def port_lists(node: Any) -> list[list[Any]]:
            found: list[list[Any]] = []
            if isinstance(node, dict):
                for key, value in node.items():
                    if key == "port_overlaps":
                        found.append(list(value))
                    else:
                        found.extend(port_lists(value))
            elif isinstance(node, list):
                for item in node:
                    found.extend(port_lists(item))
            return found

        admin = port_lists(RULES["SG_UNRESTRICTED_INGRESS"].condition)
        assert len(admin) == 1
        assert set(admin[0]) == wanted
        web = port_lists(RULES["SG_WEB_PORT_OPEN_TO_WORLD"].condition)
        assert sorted(map(sorted, web)) == sorted([[80, 443], sorted(wanted)])
        assert {80, 443}.isdisjoint(wanted)

    def test_rule_text_has_no_em_dash_and_no_emoji(self) -> None:
        for group in GROUPS:
            text = (BUILTIN / f"{group}.yml").read_text(encoding="utf-8")
            assert chr(0x2014) not in text, group
            pictographs = f"[{chr(0x1F300)}-{chr(0x1FAFF)}{chr(0x2600)}-{chr(0x27BF)}]"
            assert not re.search(pictographs, text), group


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

HIGH = {"SG_UNRESTRICTED_INGRESS"}
WEB = {"SG_WEB_PORT_OPEN_TO_WORLD"}
SG_RULES = HIGH | WEB | {"SG_TEMPORARY_OPEN"}

# (id, from, to, protocol, cidr v4, cidr v6, rules the group gets)
SG_CASES: list[tuple[str, int, int, str, str | None, str | None, set[str]]] = [
    ("ssh-world", 22, 22, "tcp", "0.0.0.0/0", None, HIGH),
    ("rdp-world-ipv6", 3389, 3389, "tcp", None, "::/0", HIGH),
    ("all-traffic", 0, 0, "-1", "0.0.0.0/0", None, HIGH),
    ("database-world", 5432, 5432, "tcp", "0.0.0.0/0", None, HIGH),
    ("range-over-ssh", 20, 25, "tcp", "0.0.0.0/0", None, HIGH),
    ("all-ports-tcp", 0, 65535, "tcp", "0.0.0.0/0", None, HIGH),
    ("https-world", 443, 443, "tcp", "0.0.0.0/0", None, WEB),
    ("http-world-ipv6", 80, 80, "tcp", None, "::/0", WEB),
    ("ssh-private", 22, 22, "tcp", "10.0.0.0/8", None, set()),
    ("all-traffic-private", 0, 0, "-1", "10.0.0.0/8", None, set()),
    ("game-udp-world", 7777, 7800, "udp", "0.0.0.0/0", None, set()),
    ("other-port-world", 8080, 8080, "tcp", "0.0.0.0/0", None, set()),
    ("icmp-world", -1, -1, "icmp", "0.0.0.0/0", None, set()),
]


def _hcl_sg(rows: list[tuple[int, int, str, str | None, str | None]]) -> str:
    blocks = []
    for from_port, to_port, protocol, cidr, ipv6 in rows:
        lines = [
            "  ingress {",
            f"    from_port = {from_port}",
            f"    to_port   = {to_port}",
            f'    protocol  = "{protocol}"',
        ]
        if cidr:
            lines.append(f'    cidr_blocks = ["{cidr}"]')
        if ipv6:
            lines.append(f'    ipv6_cidr_blocks = ["{ipv6}"]')
        lines.append("  }")
        blocks.append("\n".join(lines))
    return 'resource "aws_security_group" "sg" {\n  name = "sg"\n' + "\n".join(blocks) + "\n}\n"


def _cfn_sg(rows: list[tuple[int, int, str, str | None, str | None]]) -> str:
    lines = ["Sg:", "  Type: AWS::EC2::SecurityGroup", "  Properties:", "    GroupDescription: sg"]
    lines.append("    SecurityGroupIngress:")
    for from_port, to_port, protocol, cidr, ipv6 in rows:
        lines.append(f'      - IpProtocol: "{protocol}"')
        if protocol != "-1":
            lines.append(f"        FromPort: {from_port}")
            lines.append(f"        ToPort: {to_port}")
        if cidr:
            lines.append(f"        CidrIp: {cidr}")
        if ipv6:
            lines.append(f'        CidrIpv6: "{ipv6}"')
    return "\n".join(lines)


class TestSecurityGroupIngress:
    @pytest.mark.parametrize(
        ("name", "from_port", "to_port", "protocol", "cidr", "ipv6", "expected"),
        SG_CASES,
        ids=[case[0] for case in SG_CASES],
    )
    def test_the_same_group_gets_the_same_rules_in_every_format(
        self,
        tmp_path: Path,
        name: str,
        from_port: int,
        to_port: int,
        protocol: str,
        cidr: str | None,
        ipv6: str | None,
        expected: set[str],
    ) -> None:
        row = (from_port, to_port, protocol, cidr, ipv6)
        from_hcl = _scan_hcl(tmp_path, _hcl_sg([row])).get("aws_security_group.sg", set())
        from_plan = _scan_plan(
            (
                "aws_security_group",
                "sg",
                {
                    "name": "sg",
                    "ingress": [_ingress(from_port, to_port, protocol, cidr, ipv6)],
                    "egress": [],
                },
            )
        ).get("aws_security_group.sg", set())
        from_cfn = _scan_cfn(tmp_path, _cfn_sg([row])).get("Sg", set())
        assert from_hcl & SG_RULES == expected
        assert from_plan & SG_RULES == expected
        assert from_cfn & SG_RULES == expected

    def test_a_group_with_both_an_admin_port_and_a_web_port_reports_both_rules(
        self, tmp_path: Path
    ) -> None:
        rows = [(22, 22, "tcp", "0.0.0.0/0", None), (443, 443, "tcp", "0.0.0.0/0", None)]
        assert _scan_hcl(tmp_path, _hcl_sg(rows))["aws_security_group.sg"] & SG_RULES == (
            HIGH | WEB
        )

    def test_the_web_rule_is_low_and_the_admin_rule_is_high(self) -> None:
        assert RULES["SG_UNRESTRICTED_INGRESS"].severity == "high"
        assert RULES["SG_WEB_PORT_OPEN_TO_WORLD"].severity == "low"

    def test_a_world_rule_that_opens_an_admin_port_is_not_also_a_web_finding(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(tmp_path, _hcl_sg([(0, 65535, "tcp", "0.0.0.0/0", None)]))
        assert "SG_WEB_PORT_OPEN_TO_WORLD" not in found["aws_security_group.sg"]

    def test_a_source_that_is_another_security_group_is_not_the_internet(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "alb" {
              name = "alb"
            }
            resource "aws_security_group" "app" {
              name = "app"
              ingress {
                from_port       = 22
                to_port         = 22
                protocol        = "tcp"
                security_groups = [aws_security_group.alb.id]
              }
              ingress {
                from_port = 0
                to_port   = 0
                protocol  = "-1"
                self      = true
              }
            }
            """,
        )
        assert not found.get("aws_security_group.app")

    def test_a_cidr_the_scan_cannot_resolve_is_not_a_finding(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            variable "office" {}
            resource "aws_security_group" "sg" {
              name = "sg"
              ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = [var.office]
              }
            }
            """,
        )
        assert not found.get("aws_security_group.sg")

    def test_a_cidr_list_with_one_world_entry_is_reported(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "sg" {
              name = "sg"
              ingress {
                from_port   = 22
                to_port     = 22
                protocol    = "tcp"
                cidr_blocks = ["10.0.0.0/8", "0.0.0.0/0"]
              }
            }
            """,
        )
        assert "SG_UNRESTRICTED_INGRESS" in found["aws_security_group.sg"]

    def test_the_protocol_may_be_a_number_in_hcl(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "sg" {
              name = "sg"
              ingress {
                from_port   = 0
                to_port     = 0
                protocol    = -1
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """,
        )
        assert "SG_UNRESTRICTED_INGRESS" in found["aws_security_group.sg"]


class TestStandaloneSecurityGroupRules:
    def test_aws_security_group_rule_folds_into_its_group(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "sg" {
              name = "sg"
            }
            resource "aws_security_group_rule" "ssh" {
              type              = "ingress"
              security_group_id = aws_security_group.sg.id
              from_port         = 22
              to_port           = 22
              protocol          = "tcp"
              cidr_blocks       = ["0.0.0.0/0"]
            }
            """,
        )
        assert found["aws_security_group.sg"] == {"SG_UNRESTRICTED_INGRESS"}
        assert not found.get("aws_security_group_rule.ssh")

    def test_an_egress_rule_is_not_an_ingress_finding(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "sg" {
              name = "sg"
            }
            resource "aws_security_group_rule" "out" {
              type              = "egress"
              security_group_id = aws_security_group.sg.id
              from_port         = 0
              to_port           = 0
              protocol          = "-1"
              cidr_blocks       = ["0.0.0.0/0"]
            }
            """,
        )
        assert not found.get("aws_security_group.sg")

    def test_the_vpc_ingress_rule_resource_folds_in_with_ipv4_and_ipv6(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "v4" {
              name = "v4"
            }
            resource "aws_security_group" "v6" {
              name = "v6"
            }
            resource "aws_vpc_security_group_ingress_rule" "rdp" {
              security_group_id = aws_security_group.v4.id
              from_port         = 3389
              to_port           = 3389
              ip_protocol       = "tcp"
              cidr_ipv4         = "0.0.0.0/0"
            }
            resource "aws_vpc_security_group_ingress_rule" "all" {
              security_group_id = aws_security_group.v6.id
              ip_protocol       = "-1"
              cidr_ipv6         = "::/0"
            }
            """,
        )
        assert found["aws_security_group.v4"] == {"SG_UNRESTRICTED_INGRESS"}
        assert found["aws_security_group.v6"] == {"SG_UNRESTRICTED_INGRESS"}

    def test_the_plan_form_of_a_standalone_rule_agrees(self) -> None:
        found = _scan_plan(
            ("aws_security_group", "sg", {"name": "sg", "ingress": [], "egress": []}),
            (
                "aws_security_group_rule",
                "ssh",
                {
                    "type": "ingress",
                    "security_group_id": Ref(["aws_security_group.sg.id", "aws_security_group.sg"]),
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                },
            ),
        )
        assert found["aws_security_group.sg"] == {"SG_UNRESTRICTED_INGRESS"}

    def test_a_restricted_standalone_rule_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "sg" {
              name = "sg"
            }
            resource "aws_security_group_rule" "ssh" {
              type              = "ingress"
              security_group_id = aws_security_group.sg.id
              from_port         = 22
              to_port           = 22
              protocol          = "tcp"
              cidr_blocks       = ["10.0.0.0/8"]
            }
            """,
        )
        assert not found.get("aws_security_group.sg")


class TestTemporaryGroups:
    HCL = """
        resource "aws_security_group" "%s" {
          name = "%s"
          ingress {
            from_port   = 8080
            to_port     = 8080
            protocol    = "tcp"
            cidr_blocks = ["%s"]
          }
        }
        """

    @pytest.mark.parametrize(
        "name", ["TempAllowAll_RemoveMe", "game_server_test_sg", "debug-access", "tmp-ssh"]
    )
    def test_a_temporary_looking_open_group_is_flagged(self, tmp_path: Path, name: str) -> None:
        found = _scan_hcl(tmp_path, self.HCL % ("sg", name, "0.0.0.0/0"))
        assert "SG_TEMPORARY_OPEN" in found["aws_security_group.sg"]

    @pytest.mark.parametrize("name", ["latest-web", "contest-app", "attempts", "web-tier"])
    def test_a_name_that_only_contains_the_letters_is_not_flagged(
        self, tmp_path: Path, name: str
    ) -> None:
        found = _scan_hcl(tmp_path, self.HCL % ("sg", name, "0.0.0.0/0"))
        assert "SG_TEMPORARY_OPEN" not in found.get("aws_security_group.sg", set())

    def test_a_temporary_group_with_private_sources_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(tmp_path, self.HCL % ("sg", "temp-debug", "10.0.0.0/8"))
        assert not found.get("aws_security_group.sg")

    def test_a_tag_value_can_mark_the_group(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_security_group" "sg" {
              name = "web"
              tags = {
                Purpose = "debug session"
              }
              ingress {
                from_port   = 8080
                to_port     = 8080
                protocol    = "tcp"
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """,
        )
        assert "SG_TEMPORARY_OPEN" in found["aws_security_group.sg"]

    def test_words_split_names_the_way_people_write_them(self) -> None:
        assert aws_network.words("TempAllowAll_RemoveMe") == [
            "temp",
            "allow",
            "all",
            "remove",
            "me",
        ]
        assert aws_network.words("game-server_test") == ["game", "server", "test"]
        assert aws_network.words("") == []


class TestDefaultSecurityGroup:
    def test_hcl_without_rules_is_silent_and_with_a_world_rule_fires(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_default_security_group" "locked" {
              vpc_id = "vpc-1"
            }
            resource "aws_default_security_group" "open" {
              vpc_id = "vpc-1"
              ingress {
                protocol    = "-1"
                from_port   = 0
                to_port     = 0
                cidr_blocks = ["0.0.0.0/0"]
              }
            }
            """,
        )
        assert "VPC_DEFAULT_SG_OPEN" not in found.get("aws_default_security_group.locked", set())
        assert "VPC_DEFAULT_SG_OPEN" in found["aws_default_security_group.open"]

    def test_a_rule_that_only_lets_members_reach_each_other_is_silent(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_default_security_group" "self_only" {
              vpc_id = "vpc-1"
              ingress {
                protocol  = "-1"
                from_port = 0
                to_port   = 0
                self      = true
              }
              egress {
                protocol  = "-1"
                from_port = 0
                to_port   = 0
                self      = true
              }
            }
            """,
        )
        assert not found.get("aws_default_security_group.self_only")

    def test_a_rule_from_another_group_or_a_private_cidr_still_counts(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_default_security_group" "peer" {
              vpc_id = "vpc-1"
              ingress {
                protocol        = "tcp"
                from_port       = 22
                to_port         = 22
                security_groups = ["sg-0abc"]
              }
            }
            resource "aws_default_security_group" "private" {
              vpc_id = "vpc-1"
              egress {
                protocol    = "-1"
                from_port   = 0
                to_port     = 0
                cidr_blocks = ["10.0.0.0/8"]
              }
            }
            """,
        )
        assert "VPC_DEFAULT_SG_OPEN" in found["aws_default_security_group.peer"]
        assert "VPC_DEFAULT_SG_OPEN" in found["aws_default_security_group.private"]

    def test_plan_json_with_empty_rule_lists_is_silent(self) -> None:
        found = _scan_plan(
            (
                "aws_default_security_group",
                "locked",
                {"vpc_id": "vpc-1", "ingress": [], "egress": []},
            ),
            (
                "aws_default_security_group",
                "self_only",
                {
                    "vpc_id": "vpc-1",
                    "ingress": [_ingress(0, 0, "-1", self_=True)],
                    "egress": [],
                },
            ),
            (
                "aws_default_security_group",
                "open",
                {
                    "vpc_id": "vpc-1",
                    "ingress": [_ingress(0, 0, "-1", cidr="0.0.0.0/0")],
                    "egress": [],
                },
            ),
        )
        assert not found.get("aws_default_security_group.locked")
        assert not found.get("aws_default_security_group.self_only")
        assert "VPC_DEFAULT_SG_OPEN" in found["aws_default_security_group.open"]


# ---------------------------------------------------------------------------
# Flow logs
# ---------------------------------------------------------------------------


class TestFlowLogs:
    def test_a_vpc_with_its_flow_log_is_silent_and_one_without_fires(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_vpc" "logged" {
              cidr_block = "10.0.0.0/16"
            }
            resource "aws_vpc" "bare" {
              cidr_block = "10.1.0.0/16"
            }
            resource "aws_flow_log" "logged" {
              vpc_id          = aws_vpc.logged.id
              traffic_type    = "ALL"
              log_destination = "arn:aws:s3:::logs"
            }
            """,
        )
        assert "VPC_NO_FLOW_LOGS" not in found.get("aws_vpc.logged", set())
        assert "VPC_NO_FLOW_LOGS" in found["aws_vpc.bare"]

    def test_the_old_tag_is_no_evidence(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_vpc" "tagged" {
              cidr_block = "10.0.0.0/16"
              tags = {
                flow_logs_enabled = "true"
              }
            }
            """,
        )
        assert "VPC_NO_FLOW_LOGS" in found["aws_vpc.tagged"]

    def test_a_flow_log_of_a_subnet_counts_for_its_vpc_only(self, tmp_path: Path) -> None:
        graph = _hcl_graph(
            tmp_path,
            """
            resource "aws_vpc" "main" {
              cidr_block = "10.0.0.0/16"
            }
            resource "aws_vpc" "other" {
              cidr_block = "10.1.0.0/16"
            }
            resource "aws_subnet" "a" {
              vpc_id     = aws_vpc.main.id
              cidr_block = "10.0.1.0/24"
            }
            resource "aws_flow_log" "a" {
              subnet_id       = aws_subnet.a.id
              traffic_type    = "ALL"
              log_destination = "arn:aws:s3:::logs"
            }
            """,
        )
        assert _derived(graph, "aws_vpc.main")["has_flow_log"] is True
        assert _derived(graph, "aws_vpc.other")["has_flow_log"] is False
        found = _findings(graph)
        assert "VPC_NO_FLOW_LOGS" not in found.get("aws_vpc.main", set())
        assert "VPC_NO_FLOW_LOGS" in found["aws_vpc.other"]

    def test_a_flow_log_of_an_unresolvable_subnet_leaves_every_vpc_undecided(
        self, tmp_path: Path
    ) -> None:
        graph = _hcl_graph(
            tmp_path,
            """
            variable "subnet" {}
            resource "aws_vpc" "main" {
              cidr_block = "10.0.0.0/16"
            }
            resource "aws_flow_log" "a" {
              subnet_id       = var.subnet
              traffic_type    = "ALL"
              log_destination = "arn:aws:s3:::logs"
            }
            """,
        )
        assert is_unknown(_derived(graph, "aws_vpc.main")["has_flow_log"])
        assert "VPC_NO_FLOW_LOGS" not in _findings(graph).get("aws_vpc.main", set())

    def test_a_flow_log_whose_vpc_cannot_be_resolved_does_not_fire_the_rule(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            variable "vpc" {}
            resource "aws_vpc" "main" {
              cidr_block = "10.0.0.0/16"
            }
            resource "aws_flow_log" "x" {
              vpc_id          = var.vpc
              traffic_type    = "ALL"
              log_destination = "arn:aws:s3:::logs"
            }
            """,
        )
        assert "VPC_NO_FLOW_LOGS" not in found.get("aws_vpc.main", set())

    def test_the_plan_form_agrees(self) -> None:
        refs = Ref(["aws_vpc.logged.id", "aws_vpc.logged"])
        found = _scan_plan(
            ("aws_vpc", "logged", {"cidr_block": "10.0.0.0/16"}),
            ("aws_vpc", "bare", {"cidr_block": "10.1.0.0/16"}),
            (
                "aws_flow_log",
                "logged",
                {"vpc_id": refs, "traffic_type": "ALL", "log_destination": "arn:aws:s3:::logs"},
            ),
        )
        assert "VPC_NO_FLOW_LOGS" not in found.get("aws_vpc.logged", set())
        assert "VPC_NO_FLOW_LOGS" in found["aws_vpc.bare"]


# ---------------------------------------------------------------------------
# Instance metadata
# ---------------------------------------------------------------------------


class TestInstanceMetadata:
    def test_hcl_block_absent_optional_and_required(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_instance" "absent" {
              ami = "ami-1"
            }
            resource "aws_instance" "optional" {
              ami = "ami-1"
              metadata_options {
                http_tokens = "optional"
              }
            }
            resource "aws_instance" "unsaid" {
              ami = "ami-1"
              metadata_options {
                http_endpoint = "enabled"
              }
            }
            resource "aws_instance" "required" {
              ami = "ami-1"
              metadata_options {
                http_tokens = "required"
              }
            }
            """,
        )
        assert "EC2_IMDSV1" in found["aws_instance.absent"]
        assert "EC2_IMDSV1" in found["aws_instance.optional"]
        assert "EC2_IMDSV1" in found["aws_instance.unsaid"]
        assert "EC2_IMDSV1" not in found["aws_instance.required"]

    def test_each_resource_is_judged_on_its_own(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_instance" "vpn" {
              ami = "ami-1"
              metadata_options {
                http_tokens = "optional"
              }
            }
            resource "aws_instance" "proxy" {
              ami = "ami-1"
              metadata_options {
                http_tokens = "required"
              }
            }
            """,
        )
        assert "EC2_IMDSV1" in found["aws_instance.vpn"]
        assert "EC2_IMDSV1" not in found["aws_instance.proxy"]

    def test_the_block_as_a_mapping_a_list_and_a_plan_list(self) -> None:
        for shape in (
            {"http_tokens": "optional"},
            [{"http_tokens": "optional"}],
        ):
            found = _scan_plan(("aws_instance", "i", {"ami": "ami-1", "metadata_options": shape}))
            assert "EC2_IMDSV1" in found["aws_instance.i"], shape
        for shape in ({"http_tokens": "required"}, [{"http_tokens": "required"}]):
            found = _scan_plan(("aws_instance", "i", {"ami": "ami-1", "metadata_options": shape}))
            assert "EC2_IMDSV1" not in found["aws_instance.i"], shape

    def test_a_block_the_provider_computes_is_not_a_finding_in_a_plan(self) -> None:
        found = _scan_plan(
            ("aws_instance", "i", {"ami": "ami-1", "metadata_options": Ref([])}),
            (
                "aws_instance",
                "t",
                {"ami": "ami-1", "metadata_options": [{"http_tokens": Ref([])}]},
            ),
        )
        assert "EC2_IMDSV1" not in found.get("aws_instance.i", set())

    def test_a_launch_template_and_a_launch_configuration(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_launch_template" "weak" {
              name = "weak"
            }
            resource "aws_launch_template" "strong" {
              name = "strong"
              metadata_options {
                http_tokens = "required"
              }
            }
            resource "aws_launch_configuration" "weak" {
              name_prefix = "weak"
              image_id    = "ami-1"
              metadata_options {
                http_tokens = "optional"
              }
            }
            """,
        )
        assert "EC2_IMDSV1" in found["aws_launch_template.weak"]
        assert "EC2_IMDSV1" not in found["aws_launch_template.strong"]
        assert "EC2_IMDSV1" in found["aws_launch_configuration.weak"]

    def test_cloudformation_instance_and_launch_template(self, tmp_path: Path) -> None:
        found = _scan_cfn(
            tmp_path,
            """
            Weak:
              Type: AWS::EC2::Instance
              Properties:
                ImageId: ami-1
                MetadataOptions:
                  HttpTokens: optional
            Strong:
              Type: AWS::EC2::Instance
              Properties:
                ImageId: ami-1
                MetadataOptions:
                  HttpTokens: required
            Bare:
              Type: AWS::EC2::Instance
              Properties:
                ImageId: ami-1
            WeakTemplate:
              Type: AWS::EC2::LaunchTemplate
              Properties:
                LaunchTemplateData:
                  ImageId: ami-1
                  MetadataOptions:
                    HttpTokens: optional
            StrongTemplate:
              Type: AWS::EC2::LaunchTemplate
              Properties:
                LaunchTemplateData:
                  ImageId: ami-1
                  MetadataOptions:
                    HttpTokens: required
            """,
        )
        assert "EC2_IMDSV1" in found["Weak"]
        assert "EC2_IMDSV1" not in found["Strong"]
        assert "EC2_IMDSV1" in found["Bare"]
        assert "EC2_IMDSV1" in found["WeakTemplate"]
        assert "EC2_IMDSV1" not in found["StrongTemplate"]

    def test_an_unresolved_token_setting_is_not_a_finding(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            variable "tokens" {}
            resource "aws_instance" "i" {
              ami = "ami-1"
              metadata_options {
                http_tokens = var.tokens
              }
            }
            """,
        )
        assert "EC2_IMDSV1" not in found["aws_instance.i"]

    def test_the_rule_names_the_cloud_instance_metadata_technique(self) -> None:
        rule = RULES["EC2_IMDSV1"]
        assert rule.stride_category == "elevation_of_privilege"
        assert rule.metadata["mitre"]["techniques"] == ["T1552.005"]
        assert rule.severity == "medium"

    def test_the_public_ip_mitigation_does_not_tell_a_bastion_to_use_a_bastion(self) -> None:
        text = RULES["EC2_PUBLIC_IP"].mitigation.lower()
        assert "bastion" not in text
        assert "session manager" in text


# ---------------------------------------------------------------------------
# Load balancers and CloudFront
# ---------------------------------------------------------------------------


class TestLoadBalancers:
    LISTENER = """
        resource "aws_lb_listener" "%s" {
          load_balancer_arn = "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y"
          port              = 80
          protocol          = "%s"
          %s
        }
        """

    def test_an_http_listener_is_a_finding_unless_it_redirects_to_https(
        self, tmp_path: Path
    ) -> None:
        forward = 'default_action {\n type = "forward"\n target_group_arn = "arn:tg"\n }'
        redirect = (
            'default_action {\n type = "redirect"\n redirect {\n port = "443"\n'
            ' protocol = "HTTPS"\n status_code = "HTTP_301"\n }\n }'
        )
        plain_redirect = (
            'default_action {\n type = "redirect"\n redirect {\n port = "8080"\n'
            ' protocol = "HTTP"\n status_code = "HTTP_301"\n }\n }'
        )
        source = (
            self.LISTENER % ("fwd", "HTTP", forward)
            + self.LISTENER % ("redir", "HTTP", redirect)
            + self.LISTENER % ("same", "HTTP", plain_redirect)
            + self.LISTENER % ("tls", "HTTPS", forward)
        )
        found = _scan_hcl(tmp_path, source)
        assert "ELB_NO_HTTPS" in found["aws_lb_listener.fwd"]
        assert "ELB_NO_HTTPS" not in found.get("aws_lb_listener.redir", set())
        assert "ELB_NO_HTTPS" in found["aws_lb_listener.same"]
        assert "ELB_NO_HTTPS" not in found.get("aws_lb_listener.tls", set())

    def test_a_redirect_to_https_is_silent_in_all_three_formats(self, tmp_path: Path) -> None:
        redirect_action = {
            "type": "redirect",
            "redirect": [{"port": "443", "protocol": "HTTPS", "status_code": "HTTP_301"}],
        }
        plan = _scan_plan(
            (
                "aws_lb_listener",
                "r",
                {"port": 80, "protocol": "HTTP", "default_action": [redirect_action]},
            ),
            (
                "aws_lb_listener",
                "f",
                {
                    "port": 80,
                    "protocol": "HTTP",
                    "default_action": [{"type": "forward", "redirect": []}],
                },
            ),
        )
        assert "ELB_NO_HTTPS" not in plan.get("aws_lb_listener.r", set())
        assert "ELB_NO_HTTPS" in plan["aws_lb_listener.f"]
        cfn = _scan_cfn(
            tmp_path,
            """
            Redirect:
              Type: AWS::ElasticLoadBalancingV2::Listener
              Properties:
                LoadBalancerArn: arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y
                Port: 80
                Protocol: HTTP
                DefaultActions:
                  - Type: redirect
                    RedirectConfig:
                      Protocol: HTTPS
                      Port: "443"
                      StatusCode: HTTP_301
            Forward:
              Type: AWS::ElasticLoadBalancingV2::Listener
              Properties:
                LoadBalancerArn: arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/x/y
                Port: 80
                Protocol: HTTP
                DefaultActions:
                  - Type: forward
                    TargetGroupArn: arn:tg
            """,
        )
        assert "ELB_NO_HTTPS" not in cfn.get("Redirect", set())
        assert "ELB_NO_HTTPS" in cfn["Forward"]

    def test_access_logs_must_be_enabled_not_just_named(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_lb" "none" {
              name = "none"
            }
            resource "aws_lb" "named_only" {
              name = "named"
              access_logs {
                bucket = "logs"
              }
            }
            resource "aws_lb" "disabled" {
              name = "disabled"
              access_logs {
                bucket  = "logs"
                enabled = false
              }
            }
            resource "aws_lb" "enabled" {
              name = "enabled"
              access_logs {
                bucket  = "logs"
                enabled = true
              }
            }
            """,
        )
        assert "ELB_NO_ACCESS_LOGS" in found["aws_lb.none"]
        assert "ELB_NO_ACCESS_LOGS" in found["aws_lb.named_only"]
        assert "ELB_NO_ACCESS_LOGS" in found["aws_lb.disabled"]
        assert "ELB_NO_ACCESS_LOGS" not in found.get("aws_lb.enabled", set())

    @pytest.mark.parametrize(
        ("policy", "fires"),
        [
            ("ELBSecurityPolicy-2016-08", True),
            ("ELBSecurityPolicy-TLS-1-0-2015-04", True),
            ("ELBSecurityPolicy-TLS-1-1-2017-01", True),
            ("ELBSecurityPolicy-TLS-1-2-2017-01", False),
            ("ELBSecurityPolicy-TLS13-1-2-2021-06", False),
        ],
    )
    def test_tls_policies(self, policy: str, fires: bool) -> None:
        found = _scan_plan(
            ("aws_lb_listener", "l", {"port": 443, "protocol": "HTTPS", "ssl_policy": policy})
        )
        assert ("ELB_OUTDATED_TLS" in found.get("aws_lb_listener.l", set())) is fires


class TestCloudFront:
    @staticmethod
    def _distribution(**overrides: Any) -> dict[str, Any]:
        values: dict[str, Any] = {
            "enabled": True,
            "default_cache_behavior": [{"viewer_protocol_policy": "redirect-to-https"}],
            "ordered_cache_behavior": [],
            "restrictions": [{"geo_restriction": [{"restriction_type": "whitelist"}]}],
            "logging_config": [{"bucket": "logs.s3.amazonaws.com"}],
            "web_acl_id": "arn:aws:wafv2:us-east-1:1:global/webacl/a/b",
        }
        values.update(overrides)
        return values

    def test_a_clean_distribution_is_silent(self) -> None:
        found = _scan_plan(("aws_cloudfront_distribution", "d", self._distribution()))
        assert not found.get("aws_cloudfront_distribution.d")

    def test_geo_restriction_is_read_from_the_restriction_type(self) -> None:
        none = self._distribution(
            restrictions=[{"geo_restriction": [{"restriction_type": "none"}]}]
        )
        found = _scan_plan(("aws_cloudfront_distribution", "d", none))
        assert "CLOUDFRONT_NO_GEO_RESTRICTION" in found["aws_cloudfront_distribution.d"]

    def test_an_ordered_behavior_that_allows_http_is_reported(self) -> None:
        values = self._distribution(
            ordered_cache_behavior=[
                {"path_pattern": "/a", "viewer_protocol_policy": "redirect-to-https"},
                {"path_pattern": "/b", "viewer_protocol_policy": "allow-all"},
            ]
        )
        found = _scan_plan(("aws_cloudfront_distribution", "d", values))
        assert "CLOUDFRONT_NO_HTTPS" in found["aws_cloudfront_distribution.d"]

    def test_a_web_acl_id_the_scan_cannot_resolve_never_fires_the_rule(
        self, tmp_path: Path
    ) -> None:
        found = _scan_plan(
            (
                "aws_cloudfront_distribution",
                "d",
                self._distribution(web_acl_id=Ref(["aws_wafv2_web_acl.cdn.arn"])),
            )
        )
        assert "CLOUDFRONT_NO_WAF" not in found.get("aws_cloudfront_distribution.d", set())
        hcl = _scan_hcl(
            tmp_path,
            """
            variable "acl" {}
            resource "aws_cloudfront_distribution" "d" {
              enabled    = true
              web_acl_id = var.acl
            }
            """,
        )
        assert "CLOUDFRONT_NO_WAF" not in hcl["aws_cloudfront_distribution.d"]

    def test_no_web_acl_is_reported(self) -> None:
        found = _scan_plan(
            ("aws_cloudfront_distribution", "d", self._distribution(web_acl_id=None))
        )
        assert "CLOUDFRONT_NO_WAF" in found["aws_cloudfront_distribution.d"]


# ---------------------------------------------------------------------------
# WAFv2
# ---------------------------------------------------------------------------

STATEMENT_KEYS = (
    "and_statement",
    "byte_match_statement",
    "geo_match_statement",
    "managed_rule_group_statement",
    "not_statement",
    "or_statement",
    "rate_based_statement",
    "rule_group_reference_statement",
    "sqli_match_statement",
    "xss_match_statement",
)


def _statement(**kinds: Any) -> list[dict[str, Any]]:
    """A plan's statement block: every statement type present, most of them empty lists."""
    full: dict[str, Any] = {key: [] for key in STATEMENT_KEYS}
    full.update(kinds)
    return [full]


def _rule(name: str, **kinds: Any) -> dict[str, Any]:
    return {"name": name, "priority": 1, "statement": _statement(**kinds)}


def _managed(name: str) -> dict[str, Any]:
    return _rule(name, managed_rule_group_statement=[{"name": name, "vendor_name": "AWS"}])


def _rate(limit: Any) -> dict[str, Any]:
    return _rule("rate", rate_based_statement=[{"limit": limit, "aggregate_key_type": "IP"}])


def _acl(rules: Any, name: str = "acl", **extra: Any) -> tuple[str, str, dict[str, Any]]:
    return ("aws_wafv2_web_acl", name, {"name": name, "scope": "REGIONAL", "rule": rules, **extra})


def _facts(
    *resources: tuple[str, str, dict[str, Any]], address: str = "aws_wafv2_web_acl.acl"
) -> dict[str, Any]:
    return _derived(_plan_graph(*resources), address)


COMMON = "AWSManagedRulesCommonRuleSet"
SQLI = "AWSManagedRulesSQLiRuleSet"
BAD_INPUTS = "AWSManagedRulesKnownBadInputsRuleSet"
IP_REP = "AWSManagedRulesAmazonIpReputationList"


class TestWafDerivedFacts:
    def test_a_plan_lists_every_statement_type_and_the_empty_ones_do_not_count(self) -> None:
        facts = _facts(_acl([_managed(COMMON)]))
        assert facts["has_rate_based_rule"] is False
        assert facts["has_geo_match"] is False
        assert facts["has_sqli_rule"] is False
        assert facts["has_managed_rules"] is True
        assert facts["managed_rule_groups"] == [COMMON]
        assert facts["rate_limit"] is None

    def test_the_lowest_rate_limit_is_kept(self) -> None:
        facts = _facts(_acl([_rate(5000), _rate(300), _rate(1200)]))
        assert facts["has_rate_based_rule"] is True
        assert facts["rate_limit"] == 300

    def test_a_limit_given_as_text_is_read(self) -> None:
        assert _facts(_acl([_rate("750")]))["rate_limit"] == 750

    def test_an_unknown_limit_makes_the_limit_unknown_but_the_rule_known(self) -> None:
        facts = _facts(_acl([_rate(Unknown("var.limit"))]))
        assert facts["has_rate_based_rule"] is True
        assert is_unknown(facts["rate_limit"])

    def test_managed_groups_map_to_the_protections_they_hold(self) -> None:
        facts = _facts(_acl([_managed(SQLI), _managed(COMMON), _managed(IP_REP)]))
        assert facts["has_sqli_rule"] is True
        assert facts["has_xss_rule"] is True
        assert facts["has_ip_reputation"] is True
        assert facts["managed_rule_groups"] == sorted([SQLI, COMMON, IP_REP])

    def test_the_known_bad_inputs_group_is_managed_but_is_not_sql_or_script_protection(
        self,
    ) -> None:
        facts = _facts(_acl([_managed(BAD_INPUTS)]))
        assert facts["has_managed_rules"] is True
        assert facts["has_sqli_rule"] is False
        assert facts["has_xss_rule"] is False

    def test_match_statements_count_as_protection(self) -> None:
        facts = _facts(
            _acl(
                [
                    _rule("sqli", sqli_match_statement=[{"field_to_match": []}]),
                    _rule("xss", xss_match_statement=[{"field_to_match": []}]),
                    _rule("geo", geo_match_statement=[{"country_codes": ["KP"]}]),
                ]
            )
        )
        assert facts["has_sqli_rule"] is True
        assert facts["has_xss_rule"] is True
        assert facts["has_geo_match"] is True
        assert facts["has_managed_rules"] is False

    def test_statements_nested_in_and_or_not_and_scope_down_are_found(self) -> None:
        nested_geo = _statement(geo_match_statement=[{"country_codes": ["KP"]}])
        scoped_rate = _rule(
            "scoped",
            rate_based_statement=[
                {
                    "limit": 100,
                    "aggregate_key_type": "IP",
                    "scope_down_statement": [{"geo_match_statement": [{"country_codes": ["US"]}]}],
                }
            ],
        )
        rules = [
            _rule("and", and_statement=[{"statement": nested_geo + _statement()}]),
            _rule("not", not_statement=[{"statement": _statement(sqli_match_statement=[{}])}]),
            _rule(
                "or",
                or_statement=[{"statement": _statement(xss_match_statement=[{}])}],
            ),
            scoped_rate,
        ]
        facts = _facts(_acl(rules))
        assert facts["has_geo_match"] is True
        assert facts["has_sqli_rule"] is True
        assert facts["has_xss_rule"] is True
        assert facts["rate_limit"] == 100

    def test_a_rule_json_web_acl_is_undecided_not_empty(self) -> None:
        facts = _facts(_acl([], rule_json='[{"Name": "x"}]'))
        assert is_unknown(facts["has_rate_based_rule"])
        assert is_unknown(facts["has_managed_rules"])

    def test_an_unreadable_rule_list_makes_the_missing_facts_unknown(self) -> None:
        facts = _facts(_acl(Ref(["var.rules"])))
        assert is_unknown(facts["has_sqli_rule"])
        assert is_unknown(facts["has_geo_match"])

    def test_a_known_fact_wins_over_an_unreadable_part(self) -> None:
        facts = _facts(_acl([_managed(SQLI), Unknown("var.more")]))
        assert facts["has_sqli_rule"] is True
        assert is_unknown(facts["has_geo_match"])

    def test_a_referenced_rule_group_of_the_scan_contributes_its_statements(self) -> None:
        group = (
            "aws_wafv2_rule_group",
            "limits",
            {"name": "limits", "scope": "REGIONAL", "rule": [_rate(400)]},
        )
        acl = _acl(
            [
                _rule(
                    "custom",
                    rule_group_reference_statement=[
                        {"arn": Unknown("aws_wafv2_rule_group.limits.arn")}
                    ],
                )
            ]
        )
        facts = _facts(group, acl)
        assert facts["has_rate_based_rule"] is True
        assert facts["rate_limit"] == 400

    def test_a_rule_group_of_another_stack_makes_the_missing_facts_unknown(self) -> None:
        acl = _acl(
            [
                _rule(
                    "custom",
                    rule_group_reference_statement=[
                        {"arn": "arn:aws:wafv2:us-east-1:1:regional/rulegroup/x/y"}
                    ],
                )
            ]
        )
        facts = _facts(acl)
        assert is_unknown(facts["has_rate_based_rule"])
        assert is_unknown(facts["has_sqli_rule"])

    def test_a_rule_group_has_the_same_facts_without_managed_groups(self) -> None:
        facts = _facts(
            (
                "aws_wafv2_rule_group",
                "g",
                {"name": "g", "scope": "REGIONAL", "rule": [_rate(900)]},
            ),
            address="aws_wafv2_rule_group.g",
        )
        assert facts["rate_limit"] == 900
        assert facts["has_managed_rules"] is False

    def test_cloudformation_blocks_are_mappings_not_lists(self, tmp_path: Path) -> None:
        graph = _cfn_graph(
            tmp_path,
            """
            Acl:
              Type: AWS::WAFv2::WebACL
              Properties:
                Scope: REGIONAL
                DefaultAction:
                  Allow: {}
                VisibilityConfig:
                  CloudWatchMetricsEnabled: true
                  MetricName: a
                  SampledRequestsEnabled: true
                Rules:
                  - Name: rate
                    Priority: 1
                    Action:
                      Block: {}
                    Statement:
                      RateBasedStatement:
                        Limit: 600
                        AggregateKeyType: IP
                    VisibilityConfig:
                      CloudWatchMetricsEnabled: true
                      MetricName: r
                      SampledRequestsEnabled: true
                  - Name: sqli
                    Priority: 2
                    OverrideAction:
                      None: {}
                    Statement:
                      ManagedRuleGroupStatement:
                        VendorName: AWS
                        Name: AWSManagedRulesSQLiRuleSet
                    VisibilityConfig:
                      CloudWatchMetricsEnabled: true
                      MetricName: s
                      SampledRequestsEnabled: true
            """,
        )
        facts = _derived(graph, "Acl")
        assert facts["rate_limit"] == 600
        assert facts["has_sqli_rule"] is True
        assert facts["has_geo_match"] is False


class TestWafRuleLists:
    """The rule list is `rule` in Terraform and `Rules` in a CloudFormation rule group."""

    RULE_GROUP = """
        %s:
          Type: AWS::WAFv2::RuleGroup
          Properties:
            Scope: REGIONAL
            Capacity: 10
            VisibilityConfig:
              CloudWatchMetricsEnabled: true
              MetricName: r
              SampledRequestsEnabled: true
%s
        """

    RATE_RULES = """\
            Rules:
              - Name: rate
                Priority: 1
                Action:
                  Block: {}
                Statement:
                  RateBasedStatement:
                    Limit: 9000
                    AggregateKeyType: IP
                VisibilityConfig:
                  CloudWatchMetricsEnabled: true
                  MetricName: r
                  SampledRequestsEnabled: true"""

    def test_a_cloudformation_rule_group_with_rules_is_not_empty_and_has_its_limit(
        self, tmp_path: Path
    ) -> None:
        template = self.RULE_GROUP % ("Limits", self.RATE_RULES) + self.RULE_GROUP % ("Bare", "")
        graph = _cfn_graph(tmp_path, template)
        facts = _derived(graph, "Limits")
        assert facts["has_rules"] is True
        assert facts["has_rate_based_rule"] is True
        assert facts["rate_limit"] == 9000
        assert _derived(graph, "Bare")["has_rules"] is False
        found = _findings(graph)
        assert "WAF_EMPTY_RULES" not in found["Limits"]
        assert "WAFV2_RATE_LIMIT_HIGH" in found["Limits"]
        assert "WAF_EMPTY_RULES" in found["Bare"]

    def test_the_terraform_and_plan_forms_set_has_rules_too(self) -> None:
        assert _facts(_acl([_managed(COMMON)]))["has_rules"] is True
        assert _facts(_acl([]))["has_rules"] is False

    def test_rule_json_and_an_unreadable_list_leave_has_rules_undecided(self) -> None:
        assert is_unknown(_facts(_acl([], rule_json="[]"))["has_rules"])
        assert is_unknown(_facts(_acl(Ref(["var.rules"])))["has_rules"])
        found = _scan_plan(_acl([], rule_json="[]"))
        assert "WAF_EMPTY_RULES" not in found["aws_wafv2_web_acl.acl"]

    def test_a_list_with_an_unreadable_rule_still_has_a_rule(self) -> None:
        assert _facts(_acl([Unknown("var.rule")]))["has_rules"] is True


class TestWafRules:
    def test_an_empty_web_acl_gets_the_empty_rule_and_not_a_stack_of_missing_protections(
        self,
    ) -> None:
        found = _scan_plan(_acl([]))
        assert "WAF_EMPTY_RULES" in found["aws_wafv2_web_acl.acl"]
        assert not found["aws_wafv2_web_acl.acl"] & {
            "WAF_NO_RATE_LIMITING",
            "WAF_NO_MANAGED_RULES",
            "WAFV2_NO_SQL_INJECTION_RULE",
            "WAFV2_NO_XSS_RULE",
            "WAFV2_NO_IP_REPUTATION",
            "WAFV2_NO_GEO_BLOCKING",
        }

    def test_the_empty_rule_reads_the_rule_attribute(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_wafv2_web_acl" "empty" {
              name  = "empty"
              scope = "REGIONAL"
              default_action {
                allow {}
              }
            }
            resource "aws_wafv2_web_acl" "ruled" {
              name  = "ruled"
              scope = "REGIONAL"
              default_action {
                allow {}
              }
              rule {
                name     = "managed"
                priority = 1
                override_action {
                  none {}
                }
                statement {
                  managed_rule_group_statement {
                    name        = "AWSManagedRulesCommonRuleSet"
                    vendor_name = "AWS"
                  }
                }
                visibility_config {
                  cloudwatch_metrics_enabled = true
                  metric_name                = "m"
                  sampled_requests_enabled   = true
                }
              }
            }
            resource "aws_wafv2_rule_group" "none" {
              name     = "none"
              scope    = "REGIONAL"
              capacity = 10
            }
            """,
        )
        assert "WAF_EMPTY_RULES" in found["aws_wafv2_web_acl.empty"]
        assert "WAF_EMPTY_RULES" not in found["aws_wafv2_web_acl.ruled"]
        assert "WAF_EMPTY_RULES" in found["aws_wafv2_rule_group.none"]

    def test_a_web_acl_with_a_managed_set_and_a_rate_rule_has_the_protections(self) -> None:
        found = _scan_plan(_acl([_managed(COMMON), _managed(SQLI), _managed(IP_REP), _rate(500)]))
        assert not found["aws_wafv2_web_acl.acl"] - {
            "WAF_NO_DEFAULT_BLOCK",
            "WAF_NO_LOGGING",
            "WAFV2_NO_GEO_BLOCKING",
        }

    def test_logging_is_read_from_the_logging_configuration_resource(self) -> None:
        logged = _scan_plan(
            _acl([_managed(COMMON)]),
            (
                "aws_wafv2_web_acl_logging_configuration",
                "acl",
                {
                    "resource_arn": Ref(["aws_wafv2_web_acl.acl.arn", "aws_wafv2_web_acl.acl"]),
                    "log_destination_configs": ["arn:aws:logs:us-east-1:1:log-group:aws-waf-logs"],
                },
            ),
        )
        assert "WAF_NO_LOGGING" not in logged["aws_wafv2_web_acl.acl"]
        assert "WAF_NO_LOGGING" in _scan_plan(_acl([_managed(COMMON)]))["aws_wafv2_web_acl.acl"]

    def test_a_logging_configuration_of_an_unresolvable_acl_leaves_the_finding_out(
        self, tmp_path: Path
    ) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            variable "acl_arn" {}
            resource "aws_wafv2_web_acl" "acl" {
              name  = "acl"
              scope = "REGIONAL"
              default_action {
                block {}
              }
            }
            resource "aws_wafv2_web_acl_logging_configuration" "log" {
              resource_arn            = var.acl_arn
              log_destination_configs = ["arn:aws:logs:us-east-1:1:log-group:aws-waf-logs"]
            }
            """,
        )
        assert "WAF_NO_LOGGING" not in found["aws_wafv2_web_acl.acl"]

    @pytest.mark.parametrize(
        ("limit", "fires"), [(10000, True), (2001, True), (2000, False), (300, False)]
    )
    def test_the_rate_limit_threshold(self, limit: int, fires: bool) -> None:
        found = _scan_plan(_acl([_rate(limit)]))
        assert ("WAFV2_RATE_LIMIT_HIGH" in found["aws_wafv2_web_acl.acl"]) is fires

    def test_the_rate_limit_rule_looks_at_the_lowest_limit(self) -> None:
        found = _scan_plan(_acl([_rate(9000), _rate(100)]))
        assert "WAFV2_RATE_LIMIT_HIGH" not in found["aws_wafv2_web_acl.acl"]

    def test_the_rate_limit_rule_also_covers_a_rule_group(self) -> None:
        found = _scan_plan(
            (
                "aws_wafv2_rule_group",
                "g",
                {"name": "g", "scope": "REGIONAL", "rule": [_rate(9000)]},
            )
        )
        assert "WAFV2_RATE_LIMIT_HIGH" in found["aws_wafv2_rule_group.g"]

    def test_the_protection_rules_do_not_apply_to_a_rule_group(self) -> None:
        found = _scan_plan(
            (
                "aws_wafv2_rule_group",
                "g",
                {"name": "g", "scope": "REGIONAL", "rule": [_rate(100)]},
            )
        )
        assert found.get("aws_wafv2_rule_group.g", set()) <= set()

    def test_each_protection_rule_fires_and_goes_quiet_with_its_group(self) -> None:
        cases = {
            "WAFV2_NO_SQL_INJECTION_RULE": SQLI,
            "WAFV2_NO_XSS_RULE": COMMON,
            "WAFV2_NO_IP_REPUTATION": IP_REP,
        }
        other = _managed(BAD_INPUTS)
        for rule_id, group in cases.items():
            assert rule_id in _scan_plan(_acl([other]))["aws_wafv2_web_acl.acl"]
            assert (
                rule_id not in _scan_plan(_acl([other, _managed(group)]))["aws_wafv2_web_acl.acl"]
            )

    def test_geo_blocking_needs_a_geo_match_statement(self) -> None:
        geo = _rule("geo", geo_match_statement=[{"country_codes": ["KP"]}])
        assert (
            "WAFV2_NO_GEO_BLOCKING" in _scan_plan(_acl([_managed(COMMON)]))["aws_wafv2_web_acl.acl"]
        )
        assert "WAFV2_NO_GEO_BLOCKING" not in _scan_plan(_acl([geo]))["aws_wafv2_web_acl.acl"]

    def test_default_allow_is_a_note_not_a_high_finding(self) -> None:
        assert RULES["WAF_NO_DEFAULT_BLOCK"].severity == "low"
        assert RULES["WAF_NO_DEFAULT_BLOCK"].confidence == "heuristic"

    def test_a_logging_configuration_and_an_association_are_not_web_acls(
        self, tmp_path: Path
    ) -> None:
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


# ---------------------------------------------------------------------------
# EKS
# ---------------------------------------------------------------------------


class TestEksVersion:
    @pytest.mark.parametrize("version", ["1.10", "1.19", "1.23", "1.27", "1.29", "1.30"])
    def test_versions_past_the_end_of_extended_support_fire(self, version: str) -> None:
        found = _scan_plan(("aws_eks_cluster", "c", {"name": "c", "version": version}))
        assert "EKS_OUTDATED_VERSION" in found["aws_eks_cluster.c"]

    @pytest.mark.parametrize("version", ["1.31", "1.32", "1.33", "1.34", "1.35", "1.37"])
    def test_versions_in_support_are_silent(self, version: str) -> None:
        found = _scan_plan(("aws_eks_cluster", "c", {"name": "c", "version": version}))
        assert "EKS_OUTDATED_VERSION" not in found.get("aws_eks_cluster.c", set())

    def test_an_unset_or_unresolved_version_is_not_a_finding(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            variable "v" {}
            resource "aws_eks_cluster" "unset" {
              name     = "unset"
              role_arn = "arn:aws:iam::1:role/x"
              vpc_config {
                subnet_ids = ["subnet-1"]
              }
            }
            resource "aws_eks_cluster" "var" {
              name     = "var"
              role_arn = "arn:aws:iam::1:role/x"
              version  = var.v
              vpc_config {
                subnet_ids = ["subnet-1"]
              }
            }
            """,
        )
        assert "EKS_OUTDATED_VERSION" not in found["aws_eks_cluster.unset"]
        assert "EKS_OUTDATED_VERSION" not in found["aws_eks_cluster.var"]

    def test_the_list_is_documented_with_the_date_it_was_verified(self) -> None:
        text = (BUILTIN / "eks.yml").read_text(encoding="utf-8")
        assert re.search(r"verified 20\d\d-\d\d-\d\d", text)
        assert "docs.aws.amazon.com/eks" in text

    def test_the_list_is_contiguous_below_the_oldest_supported_version(self) -> None:
        condition = RULES["EKS_OUTDATED_VERSION"].condition
        listed = list(condition["version"]["matches_any"])
        assert listed == [f"1.{n}" for n in range(10, 31)]


class TestEksEndpoint:
    HCL = """
        resource "aws_eks_cluster" "%s" {
          name     = "%s"
          role_arn = "arn:aws:iam::1:role/x"
          vpc_config {
            subnet_ids = ["subnet-1"]
            %s
          }
        }
        """

    def test_the_endpoint_is_public_by_default_in_hcl(self, tmp_path: Path) -> None:
        source = (
            self.HCL % ("unset", "unset", "")
            + self.HCL % ("private", "private", "endpoint_public_access = false")
            + self.HCL % ("public", "public", "endpoint_public_access = true")
        )
        found = _scan_hcl(tmp_path, source)
        assert "EKS_PUBLIC_ENDPOINT" in found["aws_eks_cluster.unset"]
        assert "EKS_PUBLIC_ENDPOINT" not in found["aws_eks_cluster.private"]
        assert "EKS_PUBLIC_ENDPOINT" in found["aws_eks_cluster.public"]

    def test_any_cidr_covers_the_default_the_explicit_world_and_the_ipv6_world(
        self, tmp_path: Path
    ) -> None:
        source = (
            self.HCL % ("unset", "unset", "")
            + self.HCL % ("world", "world", 'public_access_cidrs = ["0.0.0.0/0"]')
            + self.HCL % ("world6", "world6", 'public_access_cidrs = ["::/0"]')
            + self.HCL % ("office", "office", 'public_access_cidrs = ["203.0.113.0/24"]')
            + self.HCL
            % (
                "closed",
                "closed",
                'endpoint_public_access = false\n public_access_cidrs = ["0.0.0.0/0"]',
            )
        )
        found = _scan_hcl(tmp_path, source)
        assert "EKS_PUBLIC_ACCESS_ANY_CIDR" in found["aws_eks_cluster.unset"]
        assert "EKS_PUBLIC_ACCESS_ANY_CIDR" in found["aws_eks_cluster.world"]
        assert "EKS_PUBLIC_ACCESS_ANY_CIDR" in found["aws_eks_cluster.world6"]
        assert "EKS_PUBLIC_ACCESS_ANY_CIDR" not in found["aws_eks_cluster.office"]
        assert "EKS_PUBLIC_ENDPOINT" in found["aws_eks_cluster.office"]
        assert "EKS_PUBLIC_ACCESS_ANY_CIDR" not in found["aws_eks_cluster.closed"]

    def test_a_plan_that_leaves_the_computed_cidrs_unknown_is_not_a_finding(self) -> None:
        found = _scan_plan(
            (
                "aws_eks_cluster",
                "c",
                {
                    "name": "c",
                    "vpc_config": [
                        {"endpoint_public_access": True, "public_access_cidrs": Unknown()}
                    ],
                },
            )
        )
        assert "EKS_PUBLIC_ACCESS_ANY_CIDR" not in found["aws_eks_cluster.c"]
        assert "EKS_PUBLIC_ENDPOINT" in found["aws_eks_cluster.c"]

    def test_cloudformation_defaults_to_a_public_endpoint(self, tmp_path: Path) -> None:
        found = _scan_cfn(
            tmp_path,
            """
            Open:
              Type: AWS::EKS::Cluster
              Properties:
                RoleArn: arn:aws:iam::1:role/x
                ResourcesVpcConfig:
                  SubnetIds: [subnet-1]
            Closed:
              Type: AWS::EKS::Cluster
              Properties:
                RoleArn: arn:aws:iam::1:role/x
                ResourcesVpcConfig:
                  SubnetIds: [subnet-1]
                  EndpointPublicAccess: false
            """,
        )
        assert {"EKS_PUBLIC_ENDPOINT", "EKS_PUBLIC_ACCESS_ANY_CIDR"} <= found["Open"]
        assert not {"EKS_PUBLIC_ENDPOINT", "EKS_PUBLIC_ACCESS_ANY_CIDR"} & found["Closed"]

    def test_the_two_rules_share_a_root_cause(self) -> None:
        assert (
            RULES["EKS_PUBLIC_ENDPOINT"].root_cause
            == RULES["EKS_PUBLIC_ACCESS_ANY_CIDR"].root_cause
            != ""
        )


class TestEksIdentity:
    CLUSTER = """
        resource "aws_eks_cluster" "main" {
          name     = "main"
          role_arn = "arn:aws:iam::1:role/x"
          vpc_config {
            subnet_ids = ["subnet-1"]
          }
        }
        """

    def test_a_provider_that_names_the_cluster_issuer_gives_it_service_account_roles(
        self, tmp_path: Path
    ) -> None:
        graph = _hcl_graph(
            tmp_path,
            self.CLUSTER
            + """
            resource "aws_iam_openid_connect_provider" "main" {
              url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
              client_id_list  = ["sts.amazonaws.com"]
              thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
            }
            """,
        )
        assert _derived(graph, "aws_eks_cluster.main")["has_oidc_provider"] is True
        assert "EKS_NO_IRSA" not in _findings(graph)["aws_eks_cluster.main"]

    def test_a_cluster_with_no_provider_is_reported(self, tmp_path: Path) -> None:
        assert "EKS_NO_IRSA" in _scan_hcl(tmp_path, self.CLUSTER)["aws_eks_cluster.main"]

    def test_the_issuer_read_through_a_certificate_data_source_is_undecided(
        self, tmp_path: Path
    ) -> None:
        graph = _hcl_graph(
            tmp_path,
            self.CLUSTER
            + """
            data "tls_certificate" "eks" {
              url = aws_eks_cluster.main.identity[0].oidc[0].issuer
            }
            resource "aws_iam_openid_connect_provider" "main" {
              url             = data.tls_certificate.eks.url
              client_id_list  = ["sts.amazonaws.com"]
              thumbprint_list = [data.tls_certificate.eks.certificates[0].sha1_fingerprint]
            }
            """,
        )
        assert is_unknown(_derived(graph, "aws_eks_cluster.main")["has_oidc_provider"])
        assert "EKS_NO_IRSA" not in _findings(graph).get("aws_eks_cluster.main", set())

    def test_a_provider_of_another_identity_provider_says_nothing(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            self.CLUSTER
            + """
            resource "aws_iam_openid_connect_provider" "github" {
              url             = "https://token.actions.githubusercontent.com"
              client_id_list  = ["sts.amazonaws.com"]
              thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
            }
            """,
        )
        assert "EKS_NO_IRSA" in found["aws_eks_cluster.main"]

    def test_a_provider_for_another_cluster_does_not_count(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            self.CLUSTER
            + """
            resource "aws_eks_cluster" "other" {
              name     = "other"
              role_arn = "arn:aws:iam::1:role/x"
              vpc_config {
                subnet_ids = ["subnet-1"]
              }
            }
            resource "aws_iam_openid_connect_provider" "other" {
              url             = aws_eks_cluster.other.identity[0].oidc[0].issuer
              client_id_list  = ["sts.amazonaws.com"]
              thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
            }
            """,
        )
        assert "EKS_NO_IRSA" in found["aws_eks_cluster.main"]
        assert "EKS_NO_IRSA" not in found["aws_eks_cluster.other"]

    def test_a_written_out_eks_issuer_is_undecided_between_clusters(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            self.CLUSTER
            + """
            resource "aws_iam_openid_connect_provider" "x" {
              url             = "https://oidc.eks.us-east-1.amazonaws.com/id/ABCDEF"
              client_id_list  = ["sts.amazonaws.com"]
              thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
            }
            """,
        )
        assert "EKS_NO_IRSA" not in found["aws_eks_cluster.main"]

    def test_the_cloudformation_provider_is_found(self, tmp_path: Path) -> None:
        graph = _cfn_graph(
            tmp_path,
            """
            Main:
              Type: AWS::EKS::Cluster
              Properties:
                RoleArn: arn:aws:iam::1:role/x
                ResourcesVpcConfig:
                  SubnetIds: [subnet-1]
            Oidc:
              Type: AWS::IAM::OIDCProvider
              Properties:
                Url: !GetAtt Main.OpenIdConnectIssuerUrl
                ClientIdList: [sts.amazonaws.com]
            """,
        )
        assert _derived(graph, "Main")["has_oidc_provider"] is True

    def test_ssh_on_a_node_group(self, tmp_path: Path) -> None:
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
        assert "EKS_SSH_ACCESS_NODES" in found["aws_eks_node_group.ssh"]
        assert "EKS_SSH_ACCESS_NODES" not in found.get("aws_eks_node_group.plain", set())

    def test_ssh_in_plan_json_with_an_empty_block_list_is_silent(self) -> None:
        found = _scan_plan(("aws_eks_node_group", "n", {"remote_access": []}))
        assert "EKS_SSH_ACCESS_NODES" not in found.get("aws_eks_node_group.n", set())


# ---------------------------------------------------------------------------
# ECS
# ---------------------------------------------------------------------------


def _task(containers: list[dict[str, Any]], **extra: Any) -> tuple[str, str, dict[str, Any]]:
    return (
        "aws_ecs_task_definition",
        "t",
        {"family": "t", "container_definitions": json.dumps(containers), **extra},
    )


GOOD_CONTAINER: dict[str, Any] = {
    "name": "app",
    "image": "app:1",
    "readonlyRootFilesystem": True,
    "logConfiguration": {"logDriver": "awslogs"},
}


class TestEcs:
    def test_the_container_definition_forms_all_reach_the_rules(self, tmp_path: Path) -> None:
        bad = {**GOOD_CONTAINER, "privileged": True}
        encoded = _scan_hcl(
            tmp_path,
            f"""
            resource "aws_ecs_task_definition" "t" {{
              family                = "t"
              container_definitions = jsonencode({json.dumps([bad])})
            }}
            """,
        )
        assert "ECS_PRIVILEGED_CONTAINER" in encoded["aws_ecs_task_definition.t"]
        heredoc = _scan_hcl(
            tmp_path,
            'resource "aws_ecs_task_definition" "t" {\n  family = "t"\n'
            "  container_definitions = <<DEF\n" + json.dumps([bad], indent=2) + "\nDEF\n}\n",
        )
        assert "ECS_PRIVILEGED_CONTAINER" in heredoc["aws_ecs_task_definition.t"]
        plan = _scan_plan(_task([bad]))
        assert "ECS_PRIVILEGED_CONTAINER" in plan["aws_ecs_task_definition.t"]
        pretty = _scan_plan(
            (
                "aws_ecs_task_definition",
                "t",
                {"family": "t", "container_definitions": json.dumps([bad], indent=4)},
            )
        )
        assert "ECS_PRIVILEGED_CONTAINER" in pretty["aws_ecs_task_definition.t"]

    def test_a_clean_container_is_silent(self) -> None:
        found = _scan_plan(_task([GOOD_CONTAINER]))
        assert not found.get("aws_ecs_task_definition.t")

    def test_privileged_false_and_omitted_are_both_fine(self) -> None:
        found = _scan_plan(_task([{**GOOD_CONTAINER, "privileged": False}, GOOD_CONTAINER]))
        assert "ECS_PRIVILEGED_CONTAINER" not in found.get("aws_ecs_task_definition.t", set())

    def test_an_omitted_read_only_setting_counts_as_writable(self) -> None:
        container = {k: v for k, v in GOOD_CONTAINER.items() if k != "readonlyRootFilesystem"}
        assert "ECS_NO_READONLY_FS" in _scan_plan(_task([container]))["aws_ecs_task_definition.t"]
        explicit = {**GOOD_CONTAINER, "readonlyRootFilesystem": False}
        assert "ECS_NO_READONLY_FS" in _scan_plan(_task([explicit]))["aws_ecs_task_definition.t"]

    def test_one_weak_container_among_good_ones_is_enough(self) -> None:
        weak = {"name": "sidecar", "image": "x:1"}
        found = _scan_plan(_task([GOOD_CONTAINER, weak]))
        assert {"ECS_NO_READONLY_FS", "ECS_NO_LOGGING"} <= found["aws_ecs_task_definition.t"]

    def test_a_missing_log_configuration_is_reported(self) -> None:
        container = {k: v for k, v in GOOD_CONTAINER.items() if k != "logConfiguration"}
        assert "ECS_NO_LOGGING" in _scan_plan(_task([container]))["aws_ecs_task_definition.t"]
        assert "ECS_NO_LOGGING" not in _scan_plan(_task([GOOD_CONTAINER])).get(
            "aws_ecs_task_definition.t", set()
        )

    def test_cloudformation_container_lists(self, tmp_path: Path) -> None:
        found = _scan_cfn(
            tmp_path,
            """
            Weak:
              Type: AWS::ECS::TaskDefinition
              Properties:
                Family: weak
                ContainerDefinitions:
                  - Name: app
                    Image: app:1
                    Privileged: true
            Strong:
              Type: AWS::ECS::TaskDefinition
              Properties:
                Family: strong
                ContainerDefinitions:
                  - Name: app
                    Image: app:1
                    ReadonlyRootFilesystem: true
                    LogConfiguration:
                      LogDriver: awslogs
            """,
        )
        assert {"ECS_PRIVILEGED_CONTAINER", "ECS_NO_READONLY_FS", "ECS_NO_LOGGING"} <= found["Weak"]
        assert not found.get("Strong")

    def test_definitions_the_scan_cannot_read_are_not_findings(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            variable "definitions" {}
            resource "aws_ecs_task_definition" "t" {
              family                = "t"
              container_definitions = var.definitions
            }
            """,
        )
        assert not found.get("aws_ecs_task_definition.t")

    def test_execute_command_and_host_networking(self) -> None:
        found = _scan_plan(
            ("aws_ecs_service", "svc", {"name": "svc", "enable_execute_command": True}),
            ("aws_ecs_service", "quiet", {"name": "quiet", "enable_execute_command": False}),
            _task([GOOD_CONTAINER], network_mode="host"),
        )
        assert "ECS_EXEC_ENABLED" in found["aws_ecs_service.svc"]
        assert "ECS_EXEC_ENABLED" not in found.get("aws_ecs_service.quiet", set())
        assert "ECS_HOST_NETWORKING" in found["aws_ecs_task_definition.t"]


# ---------------------------------------------------------------------------
# Lambda
# ---------------------------------------------------------------------------

ASSUME = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole",'
    '"Principal":{"Service":"lambda.amazonaws.com"}}]}'
)


def _function(role: Any = None) -> tuple[str, str, dict[str, Any]]:
    return (
        "aws_lambda_function",
        "fn",
        {
            "function_name": "fn",
            "handler": "h",
            "runtime": "python3.12",
            "role": role or Ref(["aws_iam_role.exec.arn", "aws_iam_role.exec"]),
            "vpc_config": [{"subnet_ids": ["subnet-1"], "security_group_ids": ["sg-1"]}],
        },
    )


def _role(name: str = "exec") -> tuple[str, str, dict[str, Any]]:
    return (
        "aws_iam_role",
        "exec",
        {"name": name, "assume_role_policy": ASSUME, "managed_policy_arns": None},
    )


def _attach(arn: str) -> tuple[str, str, dict[str, Any]]:
    return (
        "aws_iam_role_policy_attachment",
        "a",
        {
            "policy_arn": arn,
            "role": Ref(["aws_iam_role.exec.name", "aws_iam_role.exec"]),
        },
    )


class TestLambdaRole:
    def test_an_admin_policy_attached_to_a_role_with_a_harmless_name_fires(self) -> None:
        found = _scan_plan(
            _function(),
            _role("exec"),
            _attach("arn:aws:iam::aws:policy/AdministratorAccess"),
        )
        assert "LAMBDA_OVERPERMISSIVE_ROLE" in found["aws_lambda_function.fn"]

    @pytest.mark.parametrize("policy", ["PowerUserAccess", "IAMFullAccess"])
    def test_the_other_broad_managed_policies_fire(self, policy: str) -> None:
        found = _scan_plan(_function(), _role(), _attach(f"arn:aws:iam::aws:policy/{policy}"))
        assert "LAMBDA_OVERPERMISSIVE_ROLE" in found["aws_lambda_function.fn"]

    def test_a_role_named_admin_with_no_admin_policy_does_not_fire(self) -> None:
        found = _scan_plan(
            _function(),
            _role("admin-readonly"),
            _attach("arn:aws:iam::aws:policy/ReadOnlyAccess"),
        )
        assert "LAMBDA_OVERPERMISSIVE_ROLE" not in found.get("aws_lambda_function.fn", set())

    def test_a_role_outside_the_scan_is_undecided_even_when_it_says_admin(self) -> None:
        found = _scan_plan(_function(role="arn:aws:iam::123456789012:role/admin-lambda-role"))
        assert "LAMBDA_OVERPERMISSIVE_ROLE" not in found.get("aws_lambda_function.fn", set())

    def test_an_inline_wildcard_policy_fires_and_a_scoped_one_does_not(
        self, tmp_path: Path
    ) -> None:
        template = """
            resource "aws_iam_role" "exec" {
              name               = "exec"
              assume_role_policy = jsonencode({
                Version   = "2012-10-17"
                Statement = [{
                  Effect    = "Allow"
                  Action    = "sts:AssumeRole"
                  Principal = { Service = "lambda.amazonaws.com" }
                }]
              })
            }
            resource "aws_iam_role_policy" "p" {
              name   = "p"
              role   = aws_iam_role.exec.id
              policy = jsonencode({
                Version   = "2012-10-17"
                Statement = [{ Effect = "Allow", Action = %s, Resource = %s }]
              })
            }
            resource "aws_lambda_function" "fn" {
              function_name = "fn"
              role          = aws_iam_role.exec.arn
              handler       = "h"
              runtime       = "python3.12"
              filename      = "f.zip"
              vpc_config {
                subnet_ids         = ["subnet-1"]
                security_group_ids = ["sg-1"]
              }
            }
            """
        wild = _scan_hcl(tmp_path, template % ('"*"', '"*"'))
        assert "LAMBDA_OVERPERMISSIVE_ROLE" in wild["aws_lambda_function.fn"]
        iam = _scan_hcl(tmp_path, template % ('"iam:*"', '"*"'))
        assert "LAMBDA_OVERPERMISSIVE_ROLE" in iam["aws_lambda_function.fn"]
        scoped = _scan_hcl(tmp_path, template % ('"s3:GetObject"', '"arn:aws:s3:::b/*"'))
        assert "LAMBDA_OVERPERMISSIVE_ROLE" not in scoped.get("aws_lambda_function.fn", set())
        deny_like = _scan_hcl(tmp_path, template % ('"*"', '"arn:aws:s3:::b/*"'))
        assert "LAMBDA_OVERPERMISSIVE_ROLE" not in deny_like.get("aws_lambda_function.fn", set())

    def test_a_deny_statement_never_makes_a_role_admin(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_iam_role" "exec" {
              name               = "exec"
              assume_role_policy = "{}"
            }
            resource "aws_iam_role_policy" "p" {
              name   = "p"
              role   = aws_iam_role.exec.id
              policy = jsonencode({
                Version   = "2012-10-17"
                Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
              })
            }
            resource "aws_lambda_function" "fn" {
              function_name = "fn"
              role          = aws_iam_role.exec.arn
              handler       = "h"
              runtime       = "python3.12"
              filename      = "f.zip"
            }
            """,
        )
        assert "LAMBDA_OVERPERMISSIVE_ROLE" not in found.get("aws_lambda_function.fn", set())

    def test_cloudformation_managed_policies_on_the_role(self, tmp_path: Path) -> None:
        found = _scan_cfn(
            tmp_path,
            """
            AdminRole:
              Type: AWS::IAM::Role
              Properties:
                AssumeRolePolicyDocument:
                  Version: "2012-10-17"
                  Statement:
                    - Effect: Allow
                      Action: sts:AssumeRole
                      Principal:
                        Service: lambda.amazonaws.com
                ManagedPolicyArns: [arn:aws:iam::aws:policy/AdministratorAccess]
            ReadRole:
              Type: AWS::IAM::Role
              Properties:
                AssumeRolePolicyDocument:
                  Version: "2012-10-17"
                  Statement:
                    - Effect: Allow
                      Action: sts:AssumeRole
                      Principal:
                        Service: lambda.amazonaws.com
                ManagedPolicyArns: [arn:aws:iam::aws:policy/ReadOnlyAccess]
            Admin:
              Type: AWS::Lambda::Function
              Properties:
                Handler: h
                Runtime: python3.12
                Role: !GetAtt AdminRole.Arn
                Code: {ZipFile: "x"}
            Reader:
              Type: AWS::Lambda::Function
              Properties:
                Handler: h
                Runtime: python3.12
                Role: !GetAtt ReadRole.Arn
                Code: {ZipFile: "x"}
            """,
        )
        assert "LAMBDA_OVERPERMISSIVE_ROLE" in found["Admin"]
        assert "LAMBDA_OVERPERMISSIVE_ROLE" not in found.get("Reader", set())


class TestLambdaOther:
    def test_a_function_url_without_authentication(self) -> None:
        found = _scan_plan(
            ("aws_lambda_function_url", "open", {"authorization_type": "NONE"}),
            ("aws_lambda_function_url", "iam", {"authorization_type": "AWS_IAM"}),
        )
        assert "LAMBDA_URL_NO_AUTH" in found["aws_lambda_function_url.open"]
        assert "LAMBDA_URL_NO_AUTH" not in found.get("aws_lambda_function_url.iam", set())

    def test_reliability_only_rules_are_gone(self) -> None:
        assert "LAMBDA_NO_DLQ" not in {r.id for r in load_all_rules()}
        assert "EC2_NO_MONITORING" not in {r.id for r in load_all_rules()}

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
        assert "LAMBDA_NO_VPC" not in found.get("aws_lambda_function.private", set())
        assert "LAMBDA_NO_VPC" in found["aws_lambda_function.open"]

    def test_companions_do_not_get_function_rules(self, tmp_path: Path) -> None:
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
        assert "LAMBDA_NO_VPC" in found["aws_lambda_function.fn"]
        assert not found.get("aws_lambda_function_event_invoke_config.inv")
        assert not found.get("aws_lambda_alias.live")


# ---------------------------------------------------------------------------
# API Gateway, ECR and SageMaker
# ---------------------------------------------------------------------------

OPEN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "*"}
    ],
}


def _with_condition(policy: dict[str, Any]) -> dict[str, Any]:
    statement = {
        **policy["Statement"][0],
        "Condition": {"IpAddress": {"aws:SourceIp": ["1.2.3.4/32"]}},
    }
    return {**policy, "Statement": [statement]}


class TestApiGateway:
    def test_options_methods_are_not_reported_for_cors_preflight(self) -> None:
        found = _scan_plan(
            ("aws_api_gateway_method", "get", {"http_method": "GET", "authorization": "NONE"}),
            (
                "aws_api_gateway_method",
                "options",
                {"http_method": "OPTIONS", "authorization": "NONE"},
            ),
            ("aws_api_gateway_method", "iam", {"http_method": "GET", "authorization": "AWS_IAM"}),
        )
        assert "APIGW_METHOD_NO_AUTH" in found["aws_api_gateway_method.get"]
        assert "APIGW_METHOD_NO_AUTH" not in found.get("aws_api_gateway_method.options", set())
        assert "APIGW_METHOD_NO_AUTH" not in found.get("aws_api_gateway_method.iam", set())

    def test_a_route_without_an_authorization_type_defaults_to_none(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_apigatewayv2_route" "default" {
              api_id    = "abc"
              route_key = "GET /x"
            }
            resource "aws_apigatewayv2_route" "jwt" {
              api_id             = "abc"
              route_key          = "GET /y"
              authorization_type = "JWT"
              authorizer_id      = "auth"
            }
            """,
        )
        assert "APIGW_ROUTE_NO_AUTH" in found["aws_apigatewayv2_route.default"]
        assert "APIGW_ROUTE_NO_AUTH" not in found.get("aws_apigatewayv2_route.jwt", set())

    def test_a_policy_in_the_rest_api_attribute_fires_and_a_conditioned_one_does_not(self) -> None:
        found = _scan_plan(
            (
                "aws_api_gateway_rest_api",
                "open",
                {"name": "open", "policy": json.dumps(OPEN_POLICY)},
            ),
            (
                "aws_api_gateway_rest_api",
                "ip",
                {"name": "ip", "policy": json.dumps(_with_condition(OPEN_POLICY))},
            ),
        )
        assert "APIGW_PUBLIC_POLICY" in found["aws_api_gateway_rest_api.open"]
        assert "APIGW_PUBLIC_POLICY" not in found.get("aws_api_gateway_rest_api.ip", set())

    def test_a_policy_resource_folds_into_the_rest_api(self) -> None:
        refs = Ref(["aws_api_gateway_rest_api.api.id", "aws_api_gateway_rest_api.api"])
        found = _scan_plan(
            ("aws_api_gateway_rest_api", "api", {"name": "api", "policy": Ref([])}),
            (
                "aws_api_gateway_rest_api_policy",
                "api",
                {"rest_api_id": refs, "policy": json.dumps(OPEN_POLICY)},
            ),
        )
        assert "APIGW_PUBLIC_POLICY" in found["aws_api_gateway_rest_api.api"]

    def test_a_policy_that_names_an_account_is_silent(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "execute-api:Invoke",
                    "Resource": "*",
                }
            ],
        }
        found = _scan_plan(
            ("aws_api_gateway_rest_api", "api", {"name": "api", "policy": json.dumps(policy)})
        )
        assert not found.get("aws_api_gateway_rest_api.api")

    def test_stage_logging_for_rest_and_http_apis(self) -> None:
        found = _scan_plan(
            ("aws_api_gateway_stage", "rest", {"stage_name": "p", "access_log_settings": []}),
            (
                "aws_apigatewayv2_stage",
                "http",
                {"name": "p", "access_log_settings": [{"destination_arn": "arn:aws:logs:x"}]},
            ),
            ("aws_apigatewayv2_stage", "bare", {"name": "q"}),
        )
        assert "APIGW_NO_ACCESS_LOGS" in found["aws_api_gateway_stage.rest"]
        assert "APIGW_NO_ACCESS_LOGS" not in found.get("aws_apigatewayv2_stage.http", set())
        assert "APIGW_NO_ACCESS_LOGS" in found["aws_apigatewayv2_stage.bare"]


class TestEcr:
    def test_mutability_defaults_to_mutable(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_ecr_repository" "default" {
              name = "default"
            }
            resource "aws_ecr_repository" "fixed" {
              name                 = "fixed"
              image_tag_mutability = "IMMUTABLE"
              image_scanning_configuration {
                scan_on_push = true
              }
            }
            """,
        )
        assert {"ECR_MUTABLE_TAGS", "ECR_NO_SCAN_ON_PUSH"} <= found["aws_ecr_repository.default"]
        assert not found.get("aws_ecr_repository.fixed")

    def test_the_policy_resource_folds_into_the_repository(self, tmp_path: Path) -> None:
        open_policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": ["ecr:BatchGetImage"]}],
        }
        graph = _hcl_graph(
            tmp_path,
            f"""
            resource "aws_ecr_repository" "app" {{
              name                 = "app"
              image_tag_mutability = "IMMUTABLE"
              image_scanning_configuration {{
                scan_on_push = true
              }}
            }}
            resource "aws_ecr_repository_policy" "app" {{
              repository = aws_ecr_repository.app.name
              policy     = jsonencode({json.dumps(open_policy)})
            }}
            """,
        )
        assert [
            s["principals"] for s in _derived(graph, "aws_ecr_repository.app")["policy_statements"]
        ] == [["*"]]
        assert _findings(graph)["aws_ecr_repository.app"] == {"ECR_PUBLIC_POLICY"}

    def test_a_policy_with_an_organization_condition_is_silent(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["ecr:BatchGetImage"],
                    "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-abc"}},
                }
            ],
        }
        found = _scan_plan(
            (
                "aws_ecr_repository",
                "app",
                {
                    "name": "app",
                    "image_tag_mutability": "IMMUTABLE",
                    "image_scanning_configuration": [{"scan_on_push": True}],
                },
            ),
            (
                "aws_ecr_repository_policy",
                "app",
                {
                    "repository": Ref(["aws_ecr_repository.app.name", "aws_ecr_repository.app"]),
                    "policy": json.dumps(policy),
                },
            ),
        )
        assert not found.get("aws_ecr_repository.app")

    def test_a_policy_for_a_repository_outside_the_scan_is_ignored(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_ecr_repository_policy" "p" {
              repository = "elsewhere"
              policy     = "{}"
            }
            """,
        )
        assert not found.get("aws_ecr_repository_policy.p")


class TestSageMaker:
    def test_the_defaults_are_enabled(self, tmp_path: Path) -> None:
        found = _scan_hcl(
            tmp_path,
            """
            resource "aws_sagemaker_notebook_instance" "default" {
              name          = "default"
              instance_type = "ml.t3.medium"
              role_arn      = "arn:aws:iam::1:role/s"
            }
            resource "aws_sagemaker_notebook_instance" "locked" {
              name                   = "locked"
              instance_type          = "ml.t3.medium"
              role_arn               = "arn:aws:iam::1:role/s"
              direct_internet_access = "Disabled"
              root_access            = "Disabled"
              kms_key_id             = "arn:aws:kms:us-east-1:1:key/k"
              subnet_id              = "subnet-1"
              security_groups        = ["sg-1"]
            }
            """,
        )
        assert found["aws_sagemaker_notebook_instance.default"] == {
            "SAGEMAKER_NOTEBOOK_DIRECT_INTERNET",
            "SAGEMAKER_NOTEBOOK_ROOT_ACCESS",
            "SAGEMAKER_NOTEBOOK_NO_KMS",
        }
        assert not found.get("aws_sagemaker_notebook_instance.locked")

    def test_the_comparison_ignores_case(self) -> None:
        found = _scan_plan(
            (
                "aws_sagemaker_notebook_instance",
                "n",
                {"direct_internet_access": "enabled", "root_access": "disabled"},
            )
        )
        assert "SAGEMAKER_NOTEBOOK_DIRECT_INTERNET" in found["aws_sagemaker_notebook_instance.n"]
        assert "SAGEMAKER_NOTEBOOK_ROOT_ACCESS" not in found["aws_sagemaker_notebook_instance.n"]


# ---------------------------------------------------------------------------
# Provider defaults
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_the_table_lists_exactly_the_documented_attributes(self) -> None:
        assert aws_network.DEFAULTS == {
            "aws_eks_cluster": {"vpc_config.endpoint_public_access": True},
            "aws_instance": {"metadata_options.http_tokens": "optional"},
            "aws_launch_template": {"metadata_options.http_tokens": "optional"},
            "aws_launch_configuration": {"metadata_options.http_tokens": "optional"},
            "aws_lb": {"internal": False},
        }

    def test_hcl_and_cloudformation_get_the_defaults_when_the_graph_records_the_format(
        self, tmp_path: Path
    ) -> None:
        graph = _with_formats(
            _hcl_graph(
                tmp_path,
                """
                resource "aws_eks_cluster" "c" {
                  name     = "c"
                  role_arn = "arn:aws:iam::1:role/x"
                  vpc_config {
                    subnet_ids = ["subnet-1"]
                  }
                }
                resource "aws_instance" "i" {
                  ami = "ami-1"
                  metadata_options {
                    http_endpoint = "enabled"
                  }
                }
                resource "aws_instance" "bare" {
                  ami = "ami-1"
                }
                resource "aws_lb" "front" {
                  name = "front"
                }
                resource "aws_lb" "private" {
                  name     = "private"
                  internal = true
                }
                """,
            ),
            "terraform_hcl",
        )
        cluster = graph.nodes["aws_eks_cluster.c"].properties
        assert cluster["vpc_config"][0]["endpoint_public_access"] is True
        assert cluster["derived"]["defaults_applied"] == ["vpc_config.endpoint_public_access"]
        instance = graph.nodes["aws_instance.i"].properties
        assert instance["metadata_options"][0]["http_tokens"] == "optional"
        assert "metadata_options" not in graph.nodes["aws_instance.bare"].properties
        assert graph.nodes["aws_lb.front"].properties["internal"] is False
        assert graph.nodes["aws_lb.private"].properties["internal"] is True

    def test_plan_json_is_never_defaulted(self) -> None:
        graph = _with_formats(
            _plan_graph(
                (
                    "aws_eks_cluster",
                    "c",
                    {"name": "c", "vpc_config": [{"subnet_ids": ["subnet-1"]}]},
                ),
                ("aws_lb", "front", {"name": "front"}),
            ),
            "terraform_plan",
        )
        assert (
            "endpoint_public_access"
            not in graph.nodes["aws_eks_cluster.c"].properties["vpc_config"][0]
        )
        assert "internal" not in graph.nodes["aws_lb.front"].properties

    def test_the_rules_give_the_same_answer_with_and_without_the_defaults(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        source = """
            resource "aws_eks_cluster" "c" {
              name     = "c"
              role_arn = "arn:aws:iam::1:role/x"
              vpc_config {
                subnet_ids = ["subnet-1"]
              }
            }
            resource "aws_instance" "i" {
              ami = "ami-1"
              metadata_options {
                http_endpoint = "enabled"
              }
            }
            """
        with monkeypatch.context() as patch:
            patch.setattr(enrich_module, "DEFAULT_FORMATS", frozenset())
            plain_graph = _hcl_graph(tmp_path, source)
        assert "defaults_applied" not in plain_graph.nodes["aws_eks_cluster.c"].properties.get(
            "derived", {}
        )
        plain = _findings(plain_graph)
        defaulted = _findings(_with_formats(_hcl_graph(tmp_path, source), "terraform_hcl"))
        assert plain == defaulted
        assert {"EKS_PUBLIC_ENDPOINT", "EKS_PUBLIC_ACCESS_ANY_CIDR"} <= plain["aws_eks_cluster.c"]
        assert "EC2_IMDSV1" in plain["aws_instance.i"]


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
        assert "LAMBDA_NO_VPC" in from_hcl["aws_lambda_function.fn"]
        assert "ELB_NO_ACCESS_LOGS" in from_hcl["aws_lb.alb"]
        assert {"CLOUDFRONT_NO_LOGGING", "CLOUDFRONT_NO_WAF"} <= from_hcl[
            "aws_cloudfront_distribution.cdn"
        ]


def test_every_rule_in_the_twelve_groups_has_a_title_a_mitigation_and_a_description() -> None:
    for rule in RULES.values():
        assert rule.title.strip() and rule.mitigation.strip() and len(rule.description) > 40, (
            rule.id
        )
