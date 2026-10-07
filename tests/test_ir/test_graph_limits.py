"""Tests for the graph size limits (LLM10-05, LLM10-06 and their configuration)."""

from __future__ import annotations

import logging

import pytest

from threatcode.exceptions import ConfigError, ThreatCodeError
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import MAX_EDGES, MAX_NODES, InfraGraph
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource


def _instances(count: int) -> list[ParsedResource]:
    return [
        ParsedResource(
            address=f"aws_instance.node_{i}",
            resource_type="aws_instance",
            name=f"node_{i}",
            properties={},
            provider="aws",
        )
        for i in range(count)
    ]


def _chain(count: int, edge_count: int) -> ParsedOutput:
    """`count` instances joined by `edge_count` declared data flows."""
    return ParsedOutput(
        resources=_instances(count),
        edges=[
            ParsedEdge(f"aws_instance.node_{i}", f"aws_instance.node_{i + 1}")
            for i in range(edge_count)
        ],
    )


class TestGraphLimits:
    def test_max_nodes_raises(self) -> None:
        """LLM10-05: MAX_NODES exceeded raises ThreatCodeError."""
        parsed = ParsedOutput(resources=_instances(MAX_NODES + 1))
        with pytest.raises(ThreatCodeError, match="node limit"):
            InfraGraph.from_parsed(parsed)

    def test_max_edges_warns_and_skips(self, caplog: pytest.LogCaptureFixture) -> None:
        """LLM10-06: MAX_EDGES exceeded warns and skips."""
        graph = InfraGraph(max_edges=2)
        for resource in _instances(4):
            graph._add_resource(resource)

        with caplog.at_level(logging.WARNING):
            for i in range(3):
                graph._add_edge(
                    f"aws_instance.node_{i}", f"aws_instance.node_{i + 1}", EdgeType.DEPENDENCY
                )
            graph._flush_edge_cap()
        assert len(graph.edges) == 2
        assert any("Edge limit" in r.message for r in caplog.records)

    def test_default_limits_are_the_module_constants(self) -> None:
        graph = InfraGraph()
        assert (graph.max_nodes, graph.max_edges) == (MAX_NODES, MAX_EDGES)


class TestNodeLimitConfiguration:
    def test_constructor_argument_sets_the_limit(self) -> None:
        with pytest.raises(ThreatCodeError, match="exceeds 3 node limit"):
            InfraGraph.from_parsed(ParsedOutput(resources=_instances(4)), max_nodes=3)

    def test_graph_at_the_limit_builds(self) -> None:
        graph = InfraGraph.from_parsed(ParsedOutput(resources=_instances(3)), max_nodes=3)
        assert graph.node_count == 3

    def test_error_names_the_setting(self) -> None:
        with pytest.raises(ThreatCodeError, match="THREATCODE_MAX_NODES"):
            InfraGraph.from_parsed(ParsedOutput(resources=_instances(2)), max_nodes=1)

    def test_environment_variable_sets_the_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THREATCODE_MAX_NODES", "2")
        with pytest.raises(ThreatCodeError, match="exceeds 2 node limit"):
            InfraGraph.from_parsed(ParsedOutput(resources=_instances(3)))

    def test_constructor_argument_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_MAX_NODES", "2")
        graph = InfraGraph.from_parsed(ParsedOutput(resources=_instances(3)), max_nodes=5)
        assert graph.node_count == 3

    def test_environment_is_read_when_the_graph_is_built_not_at_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_MAX_NODES", "7")
        assert InfraGraph().max_nodes == 7
        monkeypatch.delenv("THREATCODE_MAX_NODES")
        assert InfraGraph().max_nodes == MAX_NODES

    def test_module_constant_is_still_honoured_at_construction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.ir.graph.MAX_NODES", 2)
        with pytest.raises(ThreatCodeError, match="exceeds 2 node limit"):
            InfraGraph.from_parsed(ParsedOutput(resources=_instances(3)))

    def test_graph_over_the_default_builds_when_the_limit_is_raised(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(resources=_instances(MAX_NODES + 2_001)), max_nodes=MAX_NODES + 3_000
        )
        assert graph.node_count == MAX_NODES + 2_001

    @pytest.mark.parametrize("value", ["abc", "0", "-5", "1.5"])
    def test_invalid_environment_value_is_rejected_naming_the_variable(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("THREATCODE_MAX_NODES", value)
        with pytest.raises(ConfigError, match="THREATCODE_MAX_NODES must be a positive integer"):
            InfraGraph()

    @pytest.mark.parametrize("value", ["", "  "])
    def test_blank_environment_value_means_unset(
        self, monkeypatch: pytest.MonkeyPatch, value: str
    ) -> None:
        monkeypatch.setenv("THREATCODE_MAX_NODES", value)
        assert InfraGraph().max_nodes == MAX_NODES

    @pytest.mark.parametrize("value", [0, -1])
    def test_non_positive_argument_is_rejected(self, value: int) -> None:
        with pytest.raises(ThreatCodeError, match="max_nodes must be at least 1"):
            InfraGraph(max_nodes=value)
        with pytest.raises(ThreatCodeError, match="max_edges must be at least 1"):
            InfraGraph(max_edges=value)


class TestEdgeLimitConfiguration:
    def test_constructor_argument_sets_the_limit(self) -> None:
        graph = InfraGraph.from_parsed(_chain(5, 4), max_edges=2)
        assert len(graph.edges) == 2

    def test_environment_variable_sets_the_limit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THREATCODE_MAX_EDGES", "3")
        assert len(InfraGraph.from_parsed(_chain(6, 5)).edges) == 3

    def test_constructor_argument_beats_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_MAX_EDGES", "1")
        assert len(InfraGraph.from_parsed(_chain(6, 5), max_edges=4).edges) == 4

    def test_invalid_environment_value_is_rejected_naming_the_variable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_MAX_EDGES", "lots")
        with pytest.raises(ConfigError, match="THREATCODE_MAX_EDGES must be a positive integer"):
            InfraGraph()

    def test_module_constant_is_still_honoured_at_construction(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.ir.graph.MAX_EDGES", 1)
        assert len(InfraGraph.from_parsed(_chain(4, 3)).edges) == 1


class TestEdgeCapWarning:
    def test_many_skipped_edges_log_one_aggregated_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="threatcode.ir.graph"):
            InfraGraph.from_parsed(_chain(12, 11), max_edges=3)
        warnings = [r for r in caplog.records if "Edge limit" in r.message]
        assert len(warnings) == 1
        assert "(3)" in warnings[0].message
        assert "skipped 8 further" in warnings[0].message
        assert "THREATCODE_MAX_EDGES" in warnings[0].message

    def test_the_warning_is_also_a_diagnostic(self) -> None:
        graph = InfraGraph.from_parsed(_chain(6, 5), max_edges=2)
        caps = [d for d in graph.diagnostics if d.code == "graph.edge_cap"]
        assert len(caps) == 1
        assert caps[0].level == "warning"
        assert "skipped 3 further" in caps[0].message

    def test_no_warning_when_the_limit_is_not_reached(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="threatcode.ir.graph"):
            graph = InfraGraph.from_parsed(_chain(4, 3), max_edges=3)
        assert not [r for r in caplog.records if "Edge limit" in r.message]
        assert not [d for d in graph.diagnostics if d.code == "graph.edge_cap"]

    def test_repeating_an_edge_at_the_limit_is_not_a_skip(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        parsed = ParsedOutput(
            resources=_instances(2),
            edges=[
                ParsedEdge("aws_instance.node_0", "aws_instance.node_1"),
                ParsedEdge("aws_instance.node_0", "aws_instance.node_1"),
            ],
        )
        with caplog.at_level(logging.WARNING, logger="threatcode.ir.graph"):
            graph = InfraGraph.from_parsed(parsed, max_edges=1)
        assert len(graph.edges) == 1
        assert not [r for r in caplog.records if "Edge limit" in r.message]

    def test_the_edges_kept_are_the_first_ones_added(self) -> None:
        graph = InfraGraph.from_parsed(_chain(5, 4), max_edges=2)
        assert [(e.source, e.target) for e in graph.edges] == [
            ("aws_instance.node_0", "aws_instance.node_1"),
            ("aws_instance.node_1", "aws_instance.node_2"),
        ]
