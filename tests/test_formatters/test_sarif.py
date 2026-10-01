"""Tests for SARIF output formatter."""

from __future__ import annotations

import json

from threatcode.engine.hybrid import HybridEngine
from threatcode.formatters.sarif import format_sarif
from threatcode.ir.graph import InfraGraph


class TestSarifFormatter:
    def test_valid_sarif_structure(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)
        sarif_str = format_sarif(report)
        sarif = json.loads(sarif_str)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_has_rules_and_results(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)
        sarif_str = format_sarif(report)
        sarif = json.loads(sarif_str)

        run = sarif["runs"][0]
        assert len(run["tool"]["driver"]["rules"]) > 0
        assert len(run["results"]) > 0

    def test_sarif_result_levels(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)
        sarif_str = format_sarif(report)
        sarif = json.loads(sarif_str)

        results = sarif["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert levels.issubset({"error", "warning", "note"})

    def test_sarif_tool_info(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)
        sarif_str = format_sarif(report)
        sarif = json.loads(sarif_str)

        tool = sarif["runs"][0]["tool"]["driver"]
        assert tool["name"] == "ThreatCode"
        assert "version" in tool

    def test_sarif_rule_tags_include_stride(self, simple_s3_graph: InfraGraph) -> None:
        engine = HybridEngine()
        report = engine.analyze(simple_s3_graph)
        sarif_str = format_sarif(report)
        sarif = json.loads(sarif_str)

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        for rule in rules:
            tags = rule.get("properties", {}).get("tags", [])
            assert any(t.startswith("stride/") for t in tags)


class TestSarifOwaspTags:
    def test_mcp_rules_tag_owasp_ids(self) -> None:
        from pathlib import Path

        from threatcode.parsers import detect_and_parse

        path = Path(__file__).parent.parent / "fixtures" / "mcp" / "vulnerable" / ".mcp.json"
        graph = InfraGraph.from_parsed(detect_and_parse(path))
        report = HybridEngine().analyze(graph, input_file=str(path))
        sarif = json.loads(format_sarif(report))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        tags = next(
            r["properties"]["tags"]
            for r in rules
            if r["shortDescription"]["text"] == "Literal credential in MCP server configuration"
        )
        assert "owasp-mcp-top-10/MCP01:2025" in tags
        assert "owasp-agentic-top-10/ASI03" in tags

    def test_rules_without_owasp_metadata_have_no_owasp_tags(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        sarif = json.loads(format_sarif(report))
        for rule in sarif["runs"][0]["tool"]["driver"]["rules"]:
            assert not any(t.startswith("owasp-") for t in rule["properties"]["tags"])
