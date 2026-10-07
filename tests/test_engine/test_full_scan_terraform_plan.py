"""End-to-end scan tests for Terraform plan JSON fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"

ALL_19_RULE_IDS = {
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
    "SG_UNRESTRICTED_INGRESS",
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

    def test_all_19_rules_fire(self) -> None:
        fired_rule_ids = {t.rule_id for t in self.report.threats if t.rule_id}
        missing = ALL_19_RULE_IDS - fired_rule_ids
        assert not missing, f"Rules did not fire: {missing}"

    def test_total_threats_reasonable(self) -> None:
        # At minimum 19 rule-based + some boundary threats
        assert len(self.report.threats) >= 19

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
