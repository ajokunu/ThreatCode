"""End-to-end scan tests for MCP client configurations."""

from __future__ import annotations

from pathlib import Path

from threatcode.engine.hybrid import HybridEngine
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "mcp"


def _report(relpath: str):
    path = FIXTURES_DIR / relpath
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    return graph, HybridEngine().analyze(graph, input_file=str(path))


class TestMcpScan:
    def test_vulnerable_config_findings_sit_on_server_nodes(self) -> None:
        graph, report = _report("vulnerable/.mcp.json")
        rule_threats = [t for t in report.threats if t.source == ThreatSource.RULE]
        assert len(rule_threats) == 8
        assert {graph.nodes[t.resource_address].resource_type for t in rule_threats} == {
            "mcp_server"
        }

    def test_fixed_config_has_no_findings(self) -> None:
        _graph, report = _report("fixed/.mcp.json")
        assert [t for t in report.threats if t.source == ThreatSource.RULE] == []

    def test_each_rule_id_is_reported_once_per_offending_server(self) -> None:
        _graph, report = _report("vulnerable/.mcp.json")
        pairs = [(t.resource_address, t.rule_id) for t in report.threats if t.rule_id]
        assert len(pairs) == len(set(pairs))
