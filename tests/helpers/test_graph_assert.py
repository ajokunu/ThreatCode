"""Self-tests for the graph assertion helpers, including their failure messages."""

from __future__ import annotations

import pytest

from tests.helpers.graph_assert import (
    assert_edge,
    assert_exposure,
    assert_no_edge,
    assert_no_path,
    assert_nodes,
    assert_path,
    assert_zone,
    find_path,
)
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import TrustZone
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource


def _resource(rtype: str, name: str, **kwargs: object) -> ParsedResource:
    return ParsedResource(
        resource_type=rtype,
        address=f"{rtype}.{name}",
        name=name,
        provider="hashicorp/aws",
        **kwargs,  # type: ignore[arg-type]
    )


@pytest.fixture
def graph() -> InfraGraph:
    """lb -> app -> db over network flows, app -> role over iam, plus an orphan bucket."""
    resources = [
        _resource("aws_lb", "front"),
        _resource("aws_instance", "app"),
        _resource("aws_db_instance", "db"),
        _resource("aws_iam_role", "app_role"),
        _resource("aws_s3_bucket", "orphan"),
    ]
    edges = [
        ParsedEdge(
            "aws_lb.front",
            "aws_instance.app",
            "network_flow",
            {"protocol": "tcp", "relation": "forwards_to"},
        ),
        ParsedEdge("aws_instance.app", "aws_db_instance.db", "network_flow", {"ports": [5432]}),
        ParsedEdge("aws_instance.app", "aws_iam_role.app_role", "iam_binding"),
    ]
    return InfraGraph.from_parsed(ParsedOutput(resources=resources, edges=edges))


class TestAssertEdge:
    def test_matches_on_type_string_enum_and_relation(self, graph: InfraGraph) -> None:
        assert_edge(graph, "aws_lb.front", "aws_instance.app")
        assert_edge(graph, "aws_lb.front", "aws_instance.app", type="network_flow")
        assert_edge(graph, "aws_lb.front", "aws_instance.app", type=EdgeType.NETWORK_FLOW)
        assert_edge(
            graph, "aws_lb.front", "aws_instance.app", relation="forwards_to", protocol="tcp"
        )

    def test_returns_the_matching_edge(self, graph: InfraGraph) -> None:
        edge = assert_edge(graph, "aws_instance.app", "aws_db_instance.db", ports=[5432])
        assert edge.edge_type == EdgeType.NETWORK_FLOW

    def test_wrong_type_lists_edges_touching_either_node(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError) as info:
            assert_edge(graph, "aws_lb.front", "aws_instance.app", type="containment")
        message = str(info.value)
        assert "type=containment" in message
        assert "edges touching either node" in message
        assert "aws_lb.front -[network_flow/forwards_to]-> aws_instance.app" in message
        # An edge on the destination that is not between the two nodes is shown too
        assert "aws_instance.app -[iam_binding]-> aws_iam_role.app_role" in message

    def test_wrong_attribute_names_the_expectation(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError, match="ports=\\[22\\]"):
            assert_edge(graph, "aws_instance.app", "aws_db_instance.db", ports=[22])

    def test_reverse_edge_is_called_out(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError) as info:
            assert_edge(graph, "aws_instance.app", "aws_lb.front")
        assert "the reverse edge aws_lb.front -[network_flow/forwards_to]-> aws_instance.app" in (
            str(info.value)
        )

    def test_unknown_node_suggests_the_close_match(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError) as info:
            assert_edge(graph, "aws_instance.ap", "aws_db_instance.db")
        message = str(info.value)
        assert "'aws_instance.ap' is not in the graph" in message
        assert "Did you mean: aws_instance.app" in message


class TestAssertNoEdge:
    def test_passes_when_absent(self, graph: InfraGraph) -> None:
        assert_no_edge(graph, "aws_db_instance.db", "aws_instance.app")
        assert_no_edge(graph, "aws_lb.front", "aws_instance.app", type="containment")

    def test_fails_naming_the_edge(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError, match="unexpected edge aws_lb.front"):
            assert_no_edge(graph, "aws_lb.front", "aws_instance.app")


class TestZoneAndExposure:
    def test_zone_accepts_enum_or_string(self, graph: InfraGraph) -> None:
        assert_zone(graph, "aws_lb.front", TrustZone.DMZ)
        assert_zone(graph, "aws_s3_bucket.orphan", "data")

    def test_zone_failure_shows_actual_zone_and_edges(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError) as info:
            assert_zone(graph, "aws_instance.app", "dmz")
        message = str(info.value)
        assert "is in zone 'private', expected 'dmz'" in message
        assert "aws_lb.front -[network_flow/forwards_to]-> aws_instance.app" in message

    def test_exposure_defaults_to_unknown_for_nodes_without_the_field(
        self, graph: InfraGraph
    ) -> None:
        assert_exposure(graph, "aws_s3_bucket.orphan", "unknown")

    def test_exposure_failure_message(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError, match="has exposure 'unknown', expected 'internet'"):
            assert_exposure(graph, "aws_s3_bucket.orphan", "internet")

    def test_exposure_reads_the_field_when_present(self, graph: InfraGraph) -> None:
        node = graph.nodes["aws_lb.front"]
        node.exposure = "internet"  # type: ignore[attr-defined]
        assert_exposure(graph, "aws_lb.front", "internet")


class TestPaths:
    def test_path_is_directed_and_returns_the_hops(self, graph: InfraGraph) -> None:
        assert assert_path(graph, "aws_lb.front", "aws_db_instance.db") == [
            "aws_lb.front",
            "aws_instance.app",
            "aws_db_instance.db",
        ]
        assert_no_path(graph, "aws_db_instance.db", "aws_lb.front")

    def test_edge_type_filter_restricts_the_walk(self, graph: InfraGraph) -> None:
        assert_path(graph, "aws_lb.front", "aws_iam_role.app_role", edge_types=None)
        assert_no_path(graph, "aws_lb.front", "aws_iam_role.app_role", edge_types=["network_flow"])
        assert (
            find_path(graph, "aws_lb.front", "aws_db_instance.db", [EdgeType.IAM_BINDING]) is None
        )

    def test_missing_path_failure_lists_what_was_reachable(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError) as info:
            assert_path(graph, "aws_lb.front", "aws_s3_bucket.orphan")
        message = str(info.value)
        assert "no directed path aws_lb.front -> aws_s3_bucket.orphan" in message
        assert "4 node(s) reachable from aws_lb.front" in message
        assert "aws_instance.app -[network_flow]-> aws_db_instance.db" in message
        assert "edges touching aws_s3_bucket.orphan" in message
        assert "(none)" in message

    def test_unexpected_path_failure_prints_the_hops(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError, match="aws_lb.front -> aws_instance.app -> aws_db"):
            assert_no_path(graph, "aws_lb.front", "aws_db_instance.db")


class TestAssertNodes:
    def test_subset_and_exact(self, graph: InfraGraph) -> None:
        assert_nodes(graph, ["aws_lb.front", "aws_instance.app"])
        assert_nodes(graph, list(graph.nodes), exact=True)

    def test_missing_and_unexpected_are_reported(self, graph: InfraGraph) -> None:
        with pytest.raises(AssertionError, match="missing: aws_instance.apps"):
            assert_nodes(graph, ["aws_instance.apps"])
        with pytest.raises(AssertionError, match="unexpected: aws_iam_role.app_role"):
            assert_nodes(graph, ["aws_lb.front", "aws_instance.app", "aws_db_instance.db"], True)
