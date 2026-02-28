"""Tests for the hybrid threat engine."""

from __future__ import annotations

from threatcode.engine.hybrid import HybridEngine
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, ThreatSource


class TestHybridEngine:
    def test_rules_only_finds_threats(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph, input_file="test.json")

        assert len(report.threats) > 0
        assert report.scanned_resources == 7

    def test_s3_public_access_detected(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        public_threats = [t for t in report.threats if t.rule_id == "S3_PUBLIC_ACCESS"]
        assert len(public_threats) == 1
        assert public_threats[0].severity == Severity.CRITICAL
        assert public_threats[0].resource_address == "aws_s3_bucket.public_assets"

    def test_s3_no_encryption_detected(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        enc_threats = [t for t in report.threats if t.rule_id == "S3_NO_ENCRYPTION"]
        # data and public_assets buckets lack encryption
        assert len(enc_threats) >= 1

    def test_iam_wildcard_detected(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        wildcard_threats = [t for t in report.threats if t.rule_id == "IAM_WILDCARD_ACTION"]
        assert len(wildcard_threats) == 1
        assert wildcard_threats[0].resource_address == "aws_iam_policy.s3_full"

    def test_ec2_public_ip_detected(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        ec2_threats = [t for t in report.threats if t.rule_id == "EC2_PUBLIC_IP"]
        assert len(ec2_threats) == 1

    def test_rds_public_access_detected(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        rds_threats = [t for t in report.threats if t.rule_id == "RDS_PUBLIC_ACCESS"]
        assert len(rds_threats) == 1
        assert rds_threats[0].severity == Severity.CRITICAL

    def test_boundary_threats_generated(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        boundary_threats = [t for t in report.threats if t.source == ThreatSource.BOUNDARY]
        assert len(boundary_threats) > 0

    def test_secure_bucket_has_fewer_threats(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        logs_threats = [
            t
            for t in report.threats
            if t.resource_address == "aws_s3_bucket.logs" and t.source == ThreatSource.RULE
        ]
        data_threats = [
            t
            for t in report.threats
            if t.resource_address == "aws_s3_bucket.data" and t.source == ThreatSource.RULE
        ]
        # Logs bucket is well-configured, should have fewer rule-based threats
        assert len(logs_threats) < len(data_threats)

    def test_report_to_dict(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        data = report.to_dict()
        assert "threats" in data
        assert "summary" in data
        assert "total_threats" in data
        assert data["total_threats"] == len(report.threats)

    def test_filter_by_severity(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        critical_only = report.filter_by_severity(Severity.CRITICAL)
        all_threats = report.threats
        assert len(critical_only) <= len(all_threats)
        for t in critical_only:
            assert t.severity >= Severity.CRITICAL
