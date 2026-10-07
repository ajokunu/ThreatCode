"""Tests for the trust boundary phase."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatcode.engine import boundaries
from threatcode.engine.boundaries import _boundary_severity
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import BOUNDARY_TACTICS, BOUNDARY_TECHNIQUES
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, ThreatSource, hash_id
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput, ParsedResource

REALISTIC = Path(__file__).parent.parent / "fixtures" / "realistic"


class TestBoundaryAnalysis:
    def test_boundary_threats_generated(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)

        boundary_threats = [t for t in report.threats if t.source == ThreatSource.BOUNDARY]
        assert len(boundary_threats) > 0

    def test_one_threat_per_crossing_edge_in_edge_order(self, simple_s3_graph: InfraGraph) -> None:
        crossings = simple_s3_graph.get_boundary_crossing_edges()
        threats = boundaries.analyze(simple_s3_graph)

        assert crossings
        assert [t.id for t in threats] == [
            hash_id(f"BOUNDARY_{e.source}_{e.target}") for e in crossings
        ]
        assert [t.resource_address for t in threats] == [e.source for e in crossings]

    def test_threat_contents(self, simple_s3_graph: InfraGraph) -> None:
        crossing = simple_s3_graph.get_boundary_crossing_edges()[0]
        threat = boundaries.analyze(simple_s3_graph)[0]
        src_zone = crossing.metadata["source_zone"]
        tgt_zone = crossing.metadata["target_zone"]

        assert threat.title == f"Trust boundary crossing: {src_zone} -> {tgt_zone}"
        assert crossing.source in threat.description
        assert crossing.target in threat.description
        assert f"{crossing.source} ({src_zone} zone)" in threat.description
        assert threat.stride_category == "tampering"
        assert threat.source == ThreatSource.BOUNDARY
        assert threat.rule_id == ""
        assert threat.confidence == 1.0
        assert threat.mitre_techniques == list(BOUNDARY_TECHNIQUES)
        assert threat.mitre_tactics == list(BOUNDARY_TACTICS)
        assert threat.severity == _boundary_severity(src_zone, tgt_zone)
        assert threat.target_address == ""

    def test_mitre_lists_are_copies(self) -> None:
        graph = InfraGraph.from_parsed(
            detect_and_parse(REALISTIC / "01_aws_ecommerce_platform.json")
        )
        threats = boundaries.analyze(graph)
        assert len(threats) >= 2
        first, second = threats[:2]
        first.mitre_techniques.append("T0000")
        assert "T0000" not in second.mitre_techniques
        assert "T0000" not in BOUNDARY_TECHNIQUES

    def test_graph_without_crossings_has_no_boundary_threats(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    ParsedResource(
                        resource_type="aws_s3_bucket",
                        address="aws_s3_bucket.only",
                        name="only",
                        provider="aws",
                    )
                ]
            )
        )
        assert graph.node_count == 1
        assert boundaries.analyze(graph) == []

    def test_matches_what_the_engine_reports(self, simple_s3_graph: InfraGraph) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        in_report = [t for t in report.threats if t.source == ThreatSource.BOUNDARY]
        assert [t.to_dict() for t in in_report] == [
            t.to_dict() for t in boundaries.analyze(simple_s3_graph)
        ]


class TestBoundarySeverity:
    @pytest.mark.parametrize(
        ("src", "tgt"),
        [
            ("internet", "private"),
            ("private", "internet"),
            ("internet", "data"),
            ("data", "internet"),
            ("dmz", "data"),
            ("data", "dmz"),
            ("internet", "management"),
            ("management", "internet"),
        ],
    )
    def test_sensitive_pairs_are_high_in_both_directions(self, src: str, tgt: str) -> None:
        assert _boundary_severity(src, tgt) == Severity.HIGH

    @pytest.mark.parametrize(
        ("src", "tgt"),
        [
            ("private", "data"),
            ("dmz", "private"),
            ("management", "data"),
            ("unknown", "unknown"),
            ("internet", "dmz"),
        ],
    )
    def test_other_pairs_are_medium(self, src: str, tgt: str) -> None:
        assert _boundary_severity(src, tgt) == Severity.MEDIUM
