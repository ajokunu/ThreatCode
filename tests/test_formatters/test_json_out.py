"""Tests for threatcode.formatters.json_out."""

from __future__ import annotations

import json
from typing import Any

from tests.helpers.scan import scan_files
from tests.test_formatters.test_sarif import FIXTURES
from threatcode.formatters.json_out import format_json
from threatcode.models.analysis import AnalysisResult
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource


def make_threat(index: int, severity: Severity, **fields: Any) -> Threat:
    return Threat(
        id=f"t{index}",
        title="Test",
        description="Desc",
        stride_category="tampering",
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address=fields.pop("address", f"aws_s3_bucket.b{index}"),
        **fields,
    )


def analysis_of(report: ThreatReport, **fields: Any) -> AnalysisResult:
    scan = scan_files([FIXTURES / "terraform" / "simple.tf"])
    return AnalysisResult(graph=scan.graph, report=report, **fields)


class TestFormatJson:
    def test_output_is_valid_json(self) -> None:
        data = json.loads(format_json(ThreatReport(scanned_resources=1)))
        assert "threats" in data

    def test_threats_serialized(self) -> None:
        report = ThreatReport(scanned_resources=1)
        report.add(make_threat(1, Severity.HIGH))
        data = json.loads(format_json(report))
        assert len(data["threats"]) == 1
        assert data["threats"][0]["id"] == "t1"

    def test_empty_report(self) -> None:
        data = json.loads(format_json(ThreatReport()))
        assert data["total_threats"] == 0
        assert data["threats"] == []

    def test_a_bare_report_has_no_graph(self) -> None:
        assert "graph" not in json.loads(format_json(ThreatReport()))


class TestAnalysisDocument:
    def test_the_default_document_is_exactly_the_report(self) -> None:
        report = ThreatReport(
            scanned_resources=3, version="1.0", timestamp="2026-01-01T00:00:00+00:00"
        )
        report.add(make_threat(1, Severity.HIGH))
        report.add(make_threat(2, Severity.LOW))
        analysis = analysis_of(report, ingest_sources=[{"tool": "trivy"}])
        assert json.loads(format_json(analysis)) == report.to_dict()
        assert json.loads(format_json(analysis)) == json.loads(format_json(report))

    def test_the_report_blocks_are_present(self) -> None:
        report = ThreatReport(scanned_resources=3, timestamp="2026-01-01T00:00:00+00:00")
        data = json.loads(format_json(analysis_of(report)))
        assert data["schema_version"] == ThreatReport.SCHEMA_VERSION
        assert data["timestamp"] == "2026-01-01T00:00:00+00:00"
        assert {"summary", "coverage", "threats", "attack_paths"} <= set(data)
        assert "graph" not in data

    def test_with_the_graph_option_the_document_carries_the_graph(self) -> None:
        text = format_json(analysis_of(ThreatReport()), include_graph=True)
        data = json.loads(text)
        assert set(data["graph"]) == {"nodes", "edges"}
        assert data["graph"]["nodes"]
        assert {"summary", "coverage", "threats", "attack_paths"} <= set(data)

    def test_the_graph_has_no_resource_properties(self) -> None:
        data = json.loads(format_json(analysis_of(ThreatReport()), include_graph=True))
        for node in data["graph"]["nodes"]:
            assert "properties" not in node
        assert "properties" not in json.dumps(data["graph"])

    def test_the_summary_is_given_by_effective_and_by_base_severity(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, Severity.MEDIUM, effective_severity=Severity.CRITICAL))
        report.add(make_threat(2, Severity.MEDIUM))
        data = json.loads(format_json(analysis_of(report), include_graph=True))
        assert data["summary"] == {"critical": 1, "medium": 1}
        assert data["summary_base"] == {"medium": 2}

    def test_ingest_sources_are_listed_only_when_there_are_some(self) -> None:
        sources = [{"tool": "trivy", "version": "0.50", "file": "t.json", "findings": 3}]
        full = analysis_of(ThreatReport(), ingest_sources=sources)
        assert json.loads(format_json(full, include_graph=True))["ingest"] == sources
        none = analysis_of(ThreatReport())
        assert "ingest" not in json.loads(format_json(none, include_graph=True))

    def test_the_llm_status_passes_through(self) -> None:
        report = ThreatReport(llm={"status": "failed", "error": "boom", "provider": "p"})
        data = json.loads(format_json(analysis_of(report)))
        assert data["llm"]["status"] == "failed" and data["llm"]["error"] == "boom"

    def test_threats_are_sorted_most_severe_first_whatever_the_input_order(self) -> None:
        report = ThreatReport()
        report.add(make_threat(1, Severity.LOW))
        report.add(make_threat(2, Severity.CRITICAL))
        report.add(make_threat(3, Severity.MEDIUM, effective_severity=Severity.HIGH))
        report.add(make_threat(4, Severity.HIGH, address="aws_s3_bucket.a"))
        data = json.loads(format_json(report))
        assert [t["id"] for t in data["threats"]] == ["t2", "t4", "t3", "t1"]

    def test_attack_paths_keep_the_order_the_engine_ranked_them_in(self) -> None:
        report = ThreatReport()
        for pid in ("c", "a", "b"):
            report.attack_paths.append(
                AttackPath(
                    id=pid,
                    entry="internet",
                    target="x",
                    hops=[AttackHop(node_id="internet"), AttackHop(node_id="x")],
                    severity=Severity.HIGH,
                )
            )
        data = json.loads(format_json(report))
        assert [p["id"] for p in data["attack_paths"]] == ["c", "a", "b"]

    def test_two_documents_of_one_analysis_are_identical(self) -> None:
        report = ThreatReport(timestamp="")
        for i in range(5):
            report.add(make_threat(i, Severity.MEDIUM))
        analysis = analysis_of(report)
        for graph in (False, True):
            assert format_json(analysis, include_graph=graph) == format_json(
                analysis, include_graph=graph
            )
        assert "timestamp" not in json.loads(format_json(analysis))

    def test_the_real_scan_has_a_graph_whose_nodes_match_the_threat_addresses(self) -> None:
        scan = scan_files([FIXTURES / "terraform" / "simple.tf"])
        analysis = AnalysisResult(graph=scan.graph, report=scan.report)
        data = json.loads(format_json(analysis, include_graph=True))
        node_ids = {n["id"] for n in data["graph"]["nodes"]}
        assert node_ids
        assert {t["resource_address"] for t in data["threats"]} <= node_ids
