"""End-to-end scan tests with multi-service fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from threatcode.engine.hybrid import HybridEngine
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource
from threatcode.parsers import detect_and_parse

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


class TestCloudFormationFixture:
    def test_cfn_insecure_stack(self) -> None:
        path = FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"
        parsed = detect_and_parse(str(path))
        graph = InfraGraph.from_parsed(parsed)
        engine = HybridEngine()
        report = engine.analyze(graph, input_file=str(path))

        fired_ids = {t.rule_id for t in report.threats if t.rule_id}
        # CFN parser converts resource types but not property names (PascalCase vs snake_case),
        # so rules that check for absence of TF-named properties will fire (they don't exist).
        # Rules checking property VALUES (e.g., acl, policy, publicly_accessible) won't match
        # because CFN uses different property names (AccessControl, PolicyDocument, etc.).
        expected_subset = {
            "S3_NO_ENCRYPTION",  # server_side_encryption_configuration not_exists → True
            "S3_NO_VERSIONING",  # versioning not_exists → True
            "S3_NO_LOGGING",     # logging not_exists → True
            "RDS_NO_BACKUP",     # backup_retention_period not_exists → True
            "RDS_NO_ENCRYPTION", # storage_encrypted not_exists → True
        }
        missing = expected_subset - fired_ids
        assert not missing, f"CFN fixture should trigger these rules but didn't: {missing}"
