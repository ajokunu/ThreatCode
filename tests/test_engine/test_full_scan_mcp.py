"""End-to-end scan tests for MCP client configurations."""

from __future__ import annotations

from pathlib import Path

from tests.helpers.scan import scan_files
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
        assert len(rule_threats) == 9
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

    def test_the_trifecta_finding_sits_on_the_agent_node(self) -> None:
        graph, report = _report("trifecta/.mcp.json")
        threats = [t for t in report.threats if t.rule_id == "MCP_LETHAL_TRIFECTA"]
        assert [t.resource_address for t in threats] == ["mcp_agent.config"]
        assert graph.nodes["mcp_agent.config"].resource_type == "mcp_agent"
        assert threats[0].resource_type == "mcp_agent"

    def test_the_scanned_resource_count_includes_the_agent(self) -> None:
        graph, _report_ = _report("vulnerable/.mcp.json")
        assert graph.node_count == 6

    def test_coverage_gaps_reach_the_graph_diagnostics(self) -> None:
        result = scan_files([FIXTURES_DIR / "unknown_servers" / ".mcp.json"])
        codes = [d.code for d in result.graph.diagnostics]
        assert codes.count("mcp.unknown_capability") == 2
        assert all(d.file.endswith(".mcp.json") and d.line for d in result.graph.diagnostics)

    def test_a_remote_server_has_boundary_edges_to_and_from_the_agent(self) -> None:
        graph, _report_ = _report("fixed/.mcp.json")
        crossing = {(e.source, e.target) for e in graph.get_boundary_crossing_edges()}
        assert ("mcp_agent.config", "mcp_server.inventory") in crossing
        assert ("mcp_server.inventory", "mcp_agent.config") in crossing
        assert ("mcp_agent.config", "mcp_server.weather") not in crossing
