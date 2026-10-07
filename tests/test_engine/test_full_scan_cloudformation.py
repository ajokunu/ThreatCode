"""End-to-end scan tests for CloudFormation templates."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from threatcode.engine.hybrid import HybridEngine
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _scan(path: Path) -> dict[str, set[str]]:
    graph = InfraGraph.from_parsed(detect_and_parse(str(path)))
    report = HybridEngine().analyze(graph, input_file=str(path))
    found: dict[str, set[str]] = defaultdict(set)
    for threat in report.threats:
        if threat.source == ThreatSource.RULE:
            found[threat.resource_address].add(threat.rule_id)
    return found


class TestCloudFormationFixture:
    def test_cfn_insecure_stack(self) -> None:
        path = FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"
        graph = InfraGraph.from_parsed(detect_and_parse(str(path)))
        engine = HybridEngine()
        report = engine.analyze(graph, input_file=str(path))

        fired_ids = {t.rule_id for t in report.threats if t.rule_id}
        # CFN parser converts resource types but not property names (PascalCase vs snake_case),
        # so rules that check for absence of TF-named properties will fire (they don't exist).
        # Rules checking property VALUES (e.g., acl, policy, publicly_accessible) won't match
        # because CFN uses different property names (AccessControl, PolicyDocument, etc.).
        expected_subset = {
            "S3_NO_ENCRYPTION",  # server_side_encryption_configuration not_exists -> True
            "S3_NO_VERSIONING",  # versioning not_exists -> True
            "S3_NO_LOGGING",  # logging not_exists -> True
            "RDS_NO_BACKUP",  # backup_retention_period not_exists -> True
            "RDS_NO_ENCRYPTION",  # storage_encrypted not_exists -> True
        }
        missing = expected_subset - fired_ids
        assert not missing, f"CFN fixture should trigger these rules but didn't: {missing}"

    def test_cfn_findings_sit_on_the_resources_that_declare_the_type(self) -> None:
        found = _scan(FIXTURES_DIR / "cloudformation" / "insecure_stack.yml")
        s3 = {a for a, ids in found.items() if any(i.startswith("S3_") for i in ids)}
        rds = {a for a, ids in found.items() if any(i.startswith("RDS_") for i in ids)}
        assert s3
        assert rds
        graph = InfraGraph.from_parsed(
            detect_and_parse(str(FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"))
        )
        assert {graph.nodes[a].resource_type for a in s3} == {"aws_s3_bucket"}
        assert {graph.nodes[a].resource_type for a in rds} == {"aws_db_instance"}


class TestBucketPoliciesAreNotBuckets:
    def test_serverless_stack_bucket_policy_gets_no_bucket_findings(self) -> None:
        found = _scan(FIXTURES_DIR / "realistic" / "06_aws_serverless_api.yaml")
        assert "PartnerDocsBucketPolicy" not in found
        assert any(i.startswith("S3_") for ids in found.values() for i in ids)

    def test_healthcare_stack_bucket_policy_gets_no_bucket_findings(self) -> None:
        found = _scan(FIXTURES_DIR / "realistic" / "09_aws_healthcare_hipaa.yaml")
        assert "CloudTrailBucketPolicy" not in found


class TestCloudTrailTemplateTypes:
    def test_a_trail_with_a_key_and_a_bucket_is_not_reported_as_unencrypted(self) -> None:
        # AWS::CloudTrail::Trail becomes aws_cloudtrail_trail, which is not the Terraform type
        # the cloudtrail rules are written for; they used to match by prefix and flagged the
        # PascalCase KMSKeyId and S3BucketName as missing
        found = _scan(FIXTURES_DIR / "realistic" / "09_aws_healthcare_hipaa.yaml")
        flagged = found.get("HIPAACloudTrail", set())
        assert "CLOUDTRAIL_NO_ENCRYPTION" not in flagged
        assert "CLOUDTRAIL_NO_S3_ACCESS_LOGGING" not in flagged
