"""Tests for the hybrid threat engine."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from threatcode.engine import boundaries, hybrid, paths, severity
from threatcode.engine.context import AnalysisContext
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import Rule
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


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


def _threat(tid: str, source: ThreatSource, **overrides: Any) -> Threat:
    fields: dict[str, Any] = {
        "id": tid,
        "title": f"Threat {tid}",
        "description": "d",
        "stride_category": "information_disclosure",
        "severity": Severity.HIGH,
        "source": source,
        "resource_type": "aws_s3_bucket",
        "resource_address": "aws_s3_bucket.public_assets",
    }
    fields.update(overrides)
    return Threat(**fields)


class TestPhaseOrder:
    def test_phases_run_in_the_documented_order(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[str] = []
        original_run_rules = HybridEngine._run_rules

        def fake_rules(self: HybridEngine, graph: InfraGraph, report: ThreatReport) -> list[Threat]:
            calls.append("rules")
            return original_run_rules(self, graph, report)

        def fake_boundaries(graph: InfraGraph) -> list[Threat]:
            calls.append("boundaries")
            return []

        def fake_severity(report: ThreatReport, graph: InfraGraph) -> None:
            calls.append("severity")

        def fake_paths(graph: InfraGraph, threats: list[Threat]) -> list[AttackPath]:
            calls.append("paths")
            return []

        def fake_llm(
            graph: InfraGraph, threats: list[Threat], client: Any, config: Any
        ) -> tuple[list[Threat], dict[str, Any]]:
            calls.append("llm")
            return [], {"status": "skipped"}

        monkeypatch.setattr(HybridEngine, "_run_rules", fake_rules)
        monkeypatch.setattr(boundaries, "analyze", fake_boundaries)
        monkeypatch.setattr(severity, "apply", fake_severity)
        monkeypatch.setattr(paths, "find", fake_paths)
        monkeypatch.setattr(hybrid, "run_llm_phase", fake_llm)

        HybridEngine().analyze(simple_s3_graph)

        assert calls == ["rules", "boundaries", "severity", "paths", "llm"]

    def test_secret_findings_land_between_rule_and_boundary_threats(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        ctx = AnalysisContext(secret_findings=[_threat("s1", ThreatSource.SECRET)])
        report = HybridEngine().analyze(simple_s3_graph, context=ctx)

        sources = [t.source for t in report.threats]
        first_secret = sources.index(ThreatSource.SECRET)
        assert all(s == ThreatSource.RULE for s in sources[:first_secret])
        assert first_secret > 0
        assert sources[first_secret + 1] == ThreatSource.BOUNDARY

    def test_severity_phase_sees_every_non_llm_threat(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[int] = []
        monkeypatch.setattr(
            severity, "apply", lambda report, graph: seen.append(len(report.threats))
        )
        report = HybridEngine().analyze(
            simple_s3_graph,
            context=AnalysisContext(external_findings=[_threat("e1", ThreatSource.SCANNER)]),
        )
        assert seen == [len(report.threats)]

    def test_attack_paths_from_the_paths_phase_land_on_the_report(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = AttackPath(id="p1", entry="internet", target="aws_db_instance.db")
        received: list[list[Threat]] = []

        def fake_paths(graph: InfraGraph, threats: list[Threat]) -> list[AttackPath]:
            received.append(list(threats))
            return [path]

        monkeypatch.setattr(paths, "find", fake_paths)
        report = HybridEngine().analyze(simple_s3_graph)

        assert report.attack_paths == [path]
        assert report.to_dict()["attack_paths"][0]["id"] == "p1"
        assert received and len(received[0]) == len(report.threats)

    def test_stub_phases_leave_the_report_unchanged(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        data = report.to_dict()
        assert report.attack_paths == []
        assert report.rule_errors == []
        assert all(t.effective_severity is None for t in report.threats)
        assert "attack_paths" not in data
        assert "rule_errors" not in data
        assert "llm" not in data

    def test_rules_only_run_records_a_skipped_llm_status(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        assert report.llm is not None
        assert report.llm["status"] == "skipped"
        assert report.llm["threat_count"] == 0

    def test_threat_order_and_ids_are_deterministic(self, simple_s3_graph: InfraGraph) -> None:
        a = HybridEngine().analyze(simple_s3_graph)
        b = HybridEngine().analyze(simple_s3_graph)
        assert [t.id for t in a.threats] == [t.id for t in b.threats]
        assert len({t.id for t in a.threats}) == len(a.threats)


class TestContextMerge:
    def test_secret_and_external_findings_are_added(self, simple_s3_graph: InfraGraph) -> None:
        base = HybridEngine().analyze(simple_s3_graph)
        ctx = AnalysisContext(
            input_label="scan",
            secret_findings=[_threat("s1", ThreatSource.SECRET)],
            external_findings=[_threat("e1", ThreatSource.SCANNER, tool="trivy")],
        )
        report = HybridEngine().analyze(simple_s3_graph, context=ctx)

        assert len(report.threats) == len(base.threats) + 2
        by_id = {t.id: t for t in report.threats}
        assert by_id["s1"].source == ThreatSource.SECRET
        assert by_id["e1"].tool == "trivy"
        # Secret findings come before ingested findings.
        ids = [t.id for t in report.threats]
        assert ids.index("s1") < ids.index("e1")

    def test_duplicate_ids_are_dropped(self, simple_s3_graph: InfraGraph) -> None:
        rule_threat_id = HybridEngine().analyze(simple_s3_graph).threats[0].id
        ctx = AnalysisContext(
            secret_findings=[
                _threat("s1", ThreatSource.SECRET),
                _threat("s1", ThreatSource.SECRET, title="again"),
            ],
            external_findings=[
                _threat("s1", ThreatSource.SCANNER),
                _threat(rule_threat_id, ThreatSource.SCANNER),
            ],
        )
        report = HybridEngine().analyze(simple_s3_graph, context=ctx)

        ids = [t.id for t in report.threats]
        assert ids.count("s1") == 1
        assert ids.count(rule_threat_id) == 1
        kept = next(t for t in report.threats if t.id == "s1")
        assert kept.source == ThreatSource.SECRET
        assert kept.title == "Threat s1"

    def test_no_context_means_no_extra_findings(self, simple_s3_graph: InfraGraph) -> None:
        with_ctx = HybridEngine().analyze(simple_s3_graph, context=AnalysisContext())
        without = HybridEngine().analyze(simple_s3_graph)
        assert [t.id for t in with_ctx.threats] == [t.id for t in without.threats]

    def test_context_defaults(self) -> None:
        ctx = AnalysisContext()
        assert ctx.input_label == ""
        assert ctx.secret_findings == []
        assert ctx.external_findings == []
        other = AnalysisContext()
        ctx.secret_findings.append(_threat("s", ThreatSource.SECRET))
        assert other.secret_findings == []


class TestRuleIsolation:
    @staticmethod
    def _raise_for(rule_id: str, monkeypatch: pytest.MonkeyPatch) -> None:
        original = hybrid.matches_rule

        def flaky(rule: Rule, node: InfraNode) -> bool:
            if rule.id == rule_id and node.resource_type.startswith(rule.resource_type):
                raise TypeError("boom")
            return original(rule, node)

        monkeypatch.setattr(hybrid, "matches_rule", flaky)

    def test_failing_rule_does_not_abort_the_analysis(
        self,
        simple_s3_graph: InfraGraph,
        monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.delenv("THREATCODE_STRICT_RULES", raising=False)
        baseline = HybridEngine().analyze(simple_s3_graph)
        self._raise_for("S3_NO_ENCRYPTION", monkeypatch)

        with caplog.at_level("WARNING", logger="threatcode.engine.hybrid"):
            report = HybridEngine().analyze(simple_s3_graph)

        assert not [t for t in report.threats if t.rule_id == "S3_NO_ENCRYPTION"]
        # Every other rule still produced its findings.
        expected = [t.id for t in baseline.threats if t.rule_id != "S3_NO_ENCRYPTION"]
        assert [t.id for t in report.threats] == expected

        assert report.rule_errors
        for entry in report.rule_errors:
            assert entry["rule_id"] == "S3_NO_ENCRYPTION"
            assert entry["node_id"].startswith("aws_s3_bucket.")
            assert "TypeError" in entry["error"]
            assert "boom" in entry["error"]
        assert report.to_dict()["rule_errors"] == report.rule_errors

        # One warning per rule even though several nodes failed.
        assert len(report.rule_errors) > 1
        warnings = [r for r in caplog.records if "S3_NO_ENCRYPTION" in r.getMessage()]
        assert len(warnings) == 1

    def test_strict_env_reraises_for_builtin_rules(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._raise_for("S3_NO_ENCRYPTION", monkeypatch)
        monkeypatch.setenv("THREATCODE_STRICT_RULES", "1")
        with pytest.raises(TypeError, match="boom"):
            HybridEngine().analyze(simple_s3_graph)

    def test_strict_env_other_values_do_not_reraise(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._raise_for("S3_NO_ENCRYPTION", monkeypatch)
        monkeypatch.setenv("THREATCODE_STRICT_RULES", "0")
        report = HybridEngine().analyze(simple_s3_graph)
        assert report.rule_errors

    def test_strict_env_does_not_reraise_for_custom_rules(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        rule_file = tmp_path / "custom.yml"
        rule_file.write_text(
            "rules:\n"
            "  - id: CUSTOM_BUCKET_RULE\n"
            "    title: Custom\n"
            "    description: Custom rule\n"
            "    stride_category: tampering\n"
            "    severity: low\n"
            "    resource_type: aws_s3_bucket\n"
            "    condition:\n"
            "      acl: {equals: private}\n",
            encoding="utf-8",
        )
        self._raise_for("CUSTOM_BUCKET_RULE", monkeypatch)
        monkeypatch.setenv("THREATCODE_STRICT_RULES", "1")

        report = HybridEngine(extra_rule_paths=[rule_file]).analyze(simple_s3_graph)

        assert {e["rule_id"] for e in report.rule_errors} == {"CUSTOM_BUCKET_RULE"}
        assert any(t.rule_id == "S3_PUBLIC_ACCESS" for t in report.threats)

    def test_healthy_run_has_no_rule_errors(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_STRICT_RULES", "1")
        report = HybridEngine().analyze(simple_s3_graph)
        assert report.rule_errors == []


class TestRuleThreatMetadata:
    def test_threats_from_one_rule_do_not_share_metadata(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        same_rule = [t for t in report.threats if t.rule_id == "S3_NO_ENCRYPTION"]
        assert len(same_rule) >= 2
        a, b = same_rule[0], same_rule[1]
        assert a.metadata == b.metadata
        assert a.metadata is not b.metadata

        a.metadata["tampered"] = True
        a.metadata.setdefault("mitre", {}).setdefault("techniques", []).append("T0000")
        assert "tampered" not in b.metadata
        assert "T0000" not in b.metadata.get("mitre", {}).get("techniques", [])

    def test_mutating_a_threat_does_not_reach_the_rule(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)
        threat = next(t for t in report.threats if t.rule_id == "S3_NO_ENCRYPTION")
        threat.metadata["tampered"] = True
        threat.mitre_techniques.append("T0000")

        rule = next(r for r in engine._rules if r.id == "S3_NO_ENCRYPTION")
        assert "tampered" not in rule.metadata
        assert "T0000" not in rule.metadata.get("mitre", {}).get("techniques", [])
        again = engine.analyze(simple_s3_graph)
        fresh = next(t for t in again.threats if t.rule_id == "S3_NO_ENCRYPTION")
        assert "tampered" not in fresh.metadata
        assert "T0000" not in fresh.mitre_techniques
