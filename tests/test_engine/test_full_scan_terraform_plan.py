"""End-to-end scan tests for Terraform plan JSON fixtures."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.scan import scan_real_shape, scan_text
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource
from threatcode.parsers.terraform_plan import TerraformPlanParser
from threatcode.values import is_unknown

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

# The rules the insecure fixture trips today. The security group rules are checked by
# test_the_open_security_groups_are_reported, because they report on specific groups.
FIRING_RULE_IDS = {
    "S3_NO_ENCRYPTION",
    "S3_PUBLIC_ACCESS",
    "S3_NO_VERSIONING",
    "S3_NO_LOGGING",
    "IAM_WILDCARD_ACTION",
    "IAM_NO_MFA",
    "IAM_OVERPERMISSIVE_ROLE",
    "EC2_PUBLIC_IP",
    "EC2_NO_MONITORING",
    "EC2_UNENCRYPTED_EBS",
    "VPC_DEFAULT_SG_OPEN",
    "VPC_NO_FLOW_LOGS",
    "RDS_PUBLIC_ACCESS",
    "RDS_NO_ENCRYPTION",
    "RDS_NO_BACKUP",
    "LAMBDA_NO_VPC",
    "LAMBDA_OVERPERMISSIVE_ROLE",
    "LAMBDA_NO_DLQ",
}


class TestInsecureFixture:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "terraform" / "multi_service_insecure.plan.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        from threatcode.parsers.terraform_plan import TerraformPlanParser

        parsed = TerraformPlanParser().parse(data, source_path=str(path))
        graph = InfraGraph.from_parsed(parsed)
        engine = HybridEngine()
        self.report = engine.analyze(graph, input_file=str(path))

    def test_the_rules_the_fixture_trips_fire(self) -> None:
        fired_rule_ids = {t.rule_id for t in self.report.threats if t.rule_id}
        missing = FIRING_RULE_IDS - fired_rule_ids
        assert not missing, f"Rules did not fire: {missing}"

    def test_the_open_security_groups_are_reported(self) -> None:
        def flagged(rule_id: str) -> set[str]:
            return {t.resource_address for t in self.report.threats if t.rule_id == rule_id}

        # wide_open allows the world to SSH (22) and HTTPS (443); ipv6_open allows ::/0 to port 80
        assert flagged("SG_UNRESTRICTED_INGRESS") == {"aws_security_group.wide_open"}
        assert flagged("SG_WEB_PORT_OPEN_TO_WORLD") == {
            "aws_security_group.wide_open",
            "aws_security_group.ipv6_open",
        }

    def test_total_threats_reasonable(self) -> None:
        # At minimum 18 rule-based + some boundary threats
        assert len(self.report.threats) >= 18

    def test_mitre_techniques_populated(self) -> None:
        rule_threats = [t for t in self.report.threats if t.source == ThreatSource.RULE]
        with_mitre = [t for t in rule_threats if t.mitre_techniques]
        assert len(with_mitre) == len(rule_threats), "All rule threats should have MITRE techniques"

    def test_mitre_tactics_populated(self) -> None:
        rule_threats = [t for t in self.report.threats if t.source == ThreatSource.RULE]
        with_tactics = [t for t in rule_threats if t.mitre_tactics]
        assert len(with_tactics) == len(rule_threats), "All rule threats should have MITRE tactics"

    def test_boundary_threats_have_mitre(self) -> None:
        boundary_threats = [t for t in self.report.threats if t.source == ThreatSource.BOUNDARY]
        for bt in boundary_threats:
            assert bt.mitre_techniques, f"Boundary threat missing MITRE techniques: {bt.title}"

    def test_report_serialization(self) -> None:
        data = self.report.to_dict()
        for t in data["threats"]:
            assert "mitre_techniques" in t
            assert "mitre_tactics" in t


class TestSecureFixture:
    @pytest.fixture(autouse=True)
    def setup(self) -> None:
        path = FIXTURES_DIR / "terraform" / "multi_service_secure.plan.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        from threatcode.parsers.terraform_plan import TerraformPlanParser

        parsed = TerraformPlanParser().parse(data, source_path=str(path))
        graph = InfraGraph.from_parsed(parsed)
        engine = HybridEngine()
        self.report = engine.analyze(graph, input_file=str(path))

    def test_zero_rule_threats(self) -> None:
        rule_threats = [t for t in self.report.threats if t.source == ThreatSource.RULE]
        if rule_threats:
            fired = {t.rule_id for t in rule_threats}
            pytest.fail(f"Secure fixture should trigger 0 rules, but fired: {fired}")

    def test_scanned_resources(self) -> None:
        assert self.report.scanned_resources > 0


class TestFindingsStayOnTheirOwnType:
    """A rule may only report resources of a type it declares."""

    @pytest.mark.parametrize(
        "name",
        [
            "multi_service_insecure.plan.json",
            "multi_service_secure.plan.json",
            "simple_s3.plan.json",
        ],
    )
    def test_no_rule_finding_lands_on_a_sibling_type(self, name: str) -> None:
        from threatcode.parsers.terraform_plan import TerraformPlanParser

        path = FIXTURES_DIR / "terraform" / name
        parsed = TerraformPlanParser().parse(json.loads(path.read_text(encoding="utf-8")))
        report = HybridEngine().analyze(InfraGraph.from_parsed(parsed), input_file=str(path))
        rules = {r.id: r for r in load_all_rules()}
        offenders = [
            (t.rule_id, t.resource_type)
            for t in report.threats
            if t.source == ThreatSource.RULE and not rules[t.rule_id].matches_type(t.resource_type)
        ]
        assert not offenders

    def test_s3_findings_in_the_insecure_plan_sit_on_buckets_only(self) -> None:
        from threatcode.parsers.terraform_plan import TerraformPlanParser

        path = FIXTURES_DIR / "terraform" / "multi_service_insecure.plan.json"
        parsed = TerraformPlanParser().parse(json.loads(path.read_text(encoding="utf-8")))
        report = HybridEngine().analyze(InfraGraph.from_parsed(parsed), input_file=str(path))
        s3 = [t for t in report.threats if t.rule_id and t.rule_id.startswith("S3_")]
        assert s3
        assert {t.resource_type for t in s3} == {"aws_s3_bucket"}


def _all_plan_fixture_paths() -> list[Path]:
    return sorted((FIXTURES_DIR / "terraform").glob("*.plan.json"))


def _security_group_rule_lists(data: dict[str, Any]) -> list[tuple[str, str, Any]]:
    """Every (address, attribute, value) of an ingress or egress attribute in a plan."""
    found: list[tuple[str, str, Any]] = []

    def walk(module: dict[str, Any]) -> None:
        for res in module.get("resources", []):
            for attribute in ("ingress", "egress"):
                if attribute in res.get("values", {}):
                    found.append((res["address"], attribute, res["values"][attribute]))
        for child in module.get("child_modules", []):
            walk(child)

    walk(data["planned_values"]["root_module"])
    return found


class TestSecurityGroupRulesAreTheRealShape:
    """The plan fixtures hold ingress and egress as `terraform show -json` prints them."""

    REAL_KEYS = {
        "cidr_blocks",
        "description",
        "from_port",
        "ipv6_cidr_blocks",
        "prefix_list_ids",
        "protocol",
        "security_groups",
        "self",
        "to_port",
    }

    @pytest.mark.parametrize("path", _all_plan_fixture_paths(), ids=lambda p: p.name)
    def test_no_rule_list_is_a_string(self, path: Path) -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        for address, attribute, value in _security_group_rule_lists(data):
            assert isinstance(value, list), f"{address}.{attribute} is {type(value).__name__}"

    @pytest.mark.parametrize(
        "name", ["multi_service_insecure.plan.json", "multi_service_secure.plan.json"]
    )
    def test_every_rule_object_has_every_key_the_provider_writes(self, name: str) -> None:
        data = json.loads((FIXTURES_DIR / "terraform" / name).read_text(encoding="utf-8"))
        rules = [
            rule
            for _, _, value in _security_group_rule_lists(data)
            for rule in value
            if isinstance(rule, dict)
        ]
        assert rules
        for rule in rules:
            assert set(rule) == self.REAL_KEYS

    def test_the_cidr_lists_are_lists_and_ipv6_lives_in_its_own_key(self) -> None:
        path = FIXTURES_DIR / "terraform" / "multi_service_insecure.plan.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        by_address = {a: v for a, attr, v in _security_group_rule_lists(data) if attr == "ingress"}
        (ipv6_rule,) = by_address["aws_security_group.ipv6_open"]
        assert ipv6_rule["cidr_blocks"] == []
        assert ipv6_rule["ipv6_cidr_blocks"] == ["::/0"]
        wide = by_address["aws_security_group.wide_open"]
        assert [r["from_port"] for r in wide] == [22, 443]
        assert all(r["cidr_blocks"] == ["0.0.0.0/0"] for r in wide)

    def test_the_secure_fixture_still_reports_nothing(self) -> None:
        path = FIXTURES_DIR / "terraform" / "multi_service_secure.plan.json"
        parsed = TerraformPlanParser().parse(json.loads(path.read_text(encoding="utf-8")))
        report = HybridEngine().analyze(InfraGraph.from_parsed(parsed), input_file=str(path))
        assert [t for t in report.threats if t.source == ThreatSource.RULE] == []


class TestUnknownValuesThroughTheLibraryPath:
    """A value known only after apply must not read as a value that is not configured."""

    def test_a_trail_whose_key_is_known_after_apply_is_not_reported(self) -> None:
        result = scan_real_shape("terraform/plan/unknown_values.plan.json")
        assert not result.fired("CLOUDTRAIL_NO_ENCRYPTION", "aws_cloudtrail.encrypted")

    def test_a_trail_with_no_key_at_all_is_reported(self) -> None:
        result = scan_real_shape("terraform/plan/unknown_values.plan.json")
        assert result.fired("CLOUDTRAIL_NO_ENCRYPTION", "aws_cloudtrail.plain")

    def test_the_same_holds_inside_a_module_where_the_key_arrives_as_a_variable(self) -> None:
        result = scan_real_shape("terraform/plan/unknown_values.plan.json")
        assert not result.fired("CLOUDTRAIL_NO_ENCRYPTION", "module.audit.aws_cloudtrail.this")
        assert result.fired("CLOUDTRAIL_NO_ENCRYPTION", "module.audit.aws_cloudtrail.bare")

    def test_a_queue_key_known_after_apply_is_not_reported_and_a_plain_queue_is(self) -> None:
        result = scan_real_shape("terraform/plan/unknown_values.plan.json")
        assert not result.fired("SQS_NO_ENCRYPTION", "aws_sqs_queue.orders")
        assert result.fired("SQS_NO_ENCRYPTION", "aws_sqs_queue.plain")

    def test_other_findings_on_the_unknown_resources_are_unaffected(self) -> None:
        result = scan_real_shape("terraform/plan/unknown_values.plan.json")
        assert result.fired("SQS_NO_DLQ", "aws_sqs_queue.orders")

    def test_buckets_whose_settings_are_all_unknown_report_no_absence(self) -> None:
        result = scan_real_shape("terraform/plan/unknown_values.plan.json")
        assert result.rule_ids_for("aws_s3_bucket.trail_logs") == set()

    def test_an_inline_trail_with_an_unresolved_reference_and_no_resource_changes(self) -> None:
        # A plan without resource_changes still shows the reference in the configuration
        plan = {
            "format_version": "1.2",
            "planned_values": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_cloudtrail.t",
                            "mode": "managed",
                            "type": "aws_cloudtrail",
                            "name": "t",
                            "values": {"name": "t", "is_multi_region_trail": True},
                        }
                    ]
                }
            },
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "type": "aws_cloudtrail",
                            "name": "t",
                            "expressions": {
                                "kms_key_id": {"references": ["aws_kms_key.k.arn", "aws_kms_key.k"]}
                            },
                        }
                    ]
                }
            },
        }
        result = scan_text(json.dumps(plan), "unresolved.plan.json")
        assert is_unknown(result.graph.nodes["aws_cloudtrail.t"].properties["kms_key_id"])
        assert not result.fired("CLOUDTRAIL_NO_ENCRYPTION")


class TestRealShapePlansThroughTheEngine:
    def test_the_web_application_plan_scans_without_a_finding_on_a_data_source(self) -> None:
        result = scan_real_shape("terraform/plan/webapp.plan.json")
        assert result.threats_for("data.aws_iam_policy_document.assume") == []

    def test_nothing_the_unknown_values_hide_is_reported_on_the_web_application(self) -> None:
        result = scan_real_shape("terraform/plan/webapp.plan.json")
        # The bucket's encryption, versioning and logging are settings the provider fills in at
        # apply and sibling resources configure: the plan cannot say they are missing
        assert result.rule_ids_for("aws_s3_bucket.data") == set()

    def test_findings_that_the_plan_does_prove_still_fire(self) -> None:
        result = scan_real_shape("terraform/plan/webapp.plan.json")
        assert result.fired("EC2_NO_MONITORING", "aws_instance.app[0]")
        assert result.fired("EC2_NO_MONITORING", "aws_instance.app[1]")
        assert result.fired("VPC_NO_FLOW_LOGS", "aws_vpc.main")

    def test_scanning_twice_gives_the_same_findings(self) -> None:
        first = scan_real_shape("terraform/plan/modules.plan.json")
        second = scan_real_shape("terraform/plan/modules.plan.json")
        assert [t.id for t in first.threats] == [t.id for t in second.threats]


class TestProviderConformancePlans:
    """Plans of the azurerm and google providers parse, and the rules read their shapes."""

    def test_the_open_rdp_rule_fires_on_the_azure_rule_and_nothing_hides_it(self) -> None:
        result = scan_real_shape("terraform/plan/azure_network.plan.json")
        assert result.fired("AZURE_NSG_RDP_OPEN", "azurerm_network_security_rule.rdp")
        assert result.fired("AZURE_NSG_ALLOW_ALL_INBOUND", "azurerm_network_security_rule.rdp")
        assert result.fired("AZURE_VNET_NO_DDOS", "azurerm_virtual_network.main")

    def test_inline_security_rules_are_a_list_of_objects_no_rule_reads_yet(self) -> None:
        result = scan_real_shape("terraform/plan/azure_network.plan.json")
        node = result.graph.nodes["azurerm_network_security_group.app"]
        assert isinstance(node.properties["security_rule"], list)
        assert result.rule_ids_for("azurerm_network_security_group.app") == set()

    def test_the_open_firewall_is_reported_and_the_internal_one_is_not(self) -> None:
        result = scan_real_shape("terraform/plan/gcp_network.plan.json")
        assert result.fired("GCP_FW_ALLOW_ALL", "google_compute_firewall.ssh")
        assert result.rule_ids_for("google_compute_firewall.internal") == set()

    def test_a_restricted_source_range_stays_a_plain_list(self) -> None:
        result = scan_real_shape("terraform/plan/gcp_network.plan.json")
        ranges = result.graph.nodes["google_compute_firewall.internal"].properties["source_ranges"]
        assert ranges == ["10.40.0.0/24"]
