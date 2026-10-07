"""Tests for building one graph from several parse outputs (InfraGraph.from_units)."""

from __future__ import annotations

import pytest

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import ThreatCodeError
from threatcode.ir.graph import InfraGraph
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource


def _pr(rtype: str, name: str, **kwargs: object) -> ParsedResource:
    return ParsedResource(
        resource_type=rtype,
        address=f"{rtype}.{name}",
        name=name,
        provider="aws",
        **kwargs,  # type: ignore[arg-type]
    )


def _unit(path: str, *resources: ParsedResource, **kwargs: object) -> ParsedOutput:
    return ParsedOutput(resources=list(resources), source_path=path, **kwargs)  # type: ignore[arg-type]


def _edges(graph: InfraGraph) -> set[tuple[str, str, str]]:
    return {(e.source, e.target, e.edge_type.value) for e in graph.edges}


class TestAddressesAcrossUnits:
    def test_addresses_only_one_unit_uses_keep_their_id(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("net/main.tf", _pr("aws_vpc", "main")),
                _unit("app/main.tf", _pr("aws_instance", "web")),
            ]
        )
        assert list(graph.nodes) == ["aws_vpc.main", "aws_instance.web"]

    def test_a_colliding_address_is_qualified_in_every_unit_that_has_it(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("a/main.tf", _pr("aws_vpc", "main")),
                _unit("b/main.tf", _pr("aws_vpc", "main")),
            ]
        )
        assert list(graph.nodes) == ["a/main.tf::aws_vpc.main", "b/main.tf::aws_vpc.main"]

    def test_three_units_where_two_collide_qualify_only_the_colliding_two(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("aws_vpc", "main"), _pr("aws_instance", "only_a")),
                _unit("b", _pr("aws_vpc", "main")),
                _unit("c", _pr("aws_instance", "only_c")),
            ]
        )
        assert list(graph.nodes) == [
            "a::aws_vpc.main",
            "aws_instance.only_a",
            "b::aws_vpc.main",
            "aws_instance.only_c",
        ]

    def test_qualification_does_not_depend_on_which_unit_came_first(self) -> None:
        a = _unit("a", _pr("aws_vpc", "main"), _pr("aws_instance", "x"))
        b = _unit("b", _pr("aws_vpc", "main"))
        forward = InfraGraph.from_units([a, b])
        backward = InfraGraph.from_units([b, a])
        assert set(forward.nodes) == set(backward.nodes)

    def test_ids_are_deterministic_across_builds(self) -> None:
        def build() -> list[str]:
            units = [
                _unit("a", _pr("aws_vpc", "main"), _pr("aws_vpc", "main")),
                _unit("b", _pr("aws_vpc", "main")),
            ]
            return list(InfraGraph.from_units(units).nodes)

        assert build() == build() == ["a::aws_vpc.main", "a::aws_vpc.main#2", "b::aws_vpc.main"]

    def test_qualification_is_an_info_diagnostic_naming_the_inputs(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("a/main.tf", _pr("aws_vpc", "main")),
                _unit("b/main.tf", _pr("aws_vpc", "main")),
            ]
        )
        (diag,) = graph.diagnostics
        assert (diag.level, diag.code) == ("info", "graph.duplicate_address")
        assert "aws_vpc.main" in diag.message
        assert "a/main.tf" in diag.message and "b/main.tf" in diag.message

    def test_no_collision_means_no_diagnostic(self) -> None:
        graph = InfraGraph.from_units(
            [_unit("a", _pr("aws_vpc", "a")), _unit("b", _pr("aws_vpc", "b"))]
        )
        assert graph.diagnostics == []

    def test_a_unit_without_a_source_path_is_labelled_by_position(self) -> None:
        graph = InfraGraph.from_units(
            [
                ParsedOutput(resources=[_pr("aws_vpc", "main")]),
                ParsedOutput(resources=[_pr("aws_vpc", "main")]),
            ]
        )
        assert list(graph.nodes) == ["unit1::aws_vpc.main", "unit2::aws_vpc.main"]

    def test_units_sharing_a_path_fall_back_to_the_duplicate_suffix(self) -> None:
        graph = InfraGraph.from_units(
            [_unit("same.tf", _pr("aws_vpc", "main")), _unit("same.tf", _pr("aws_vpc", "main"))]
        )
        assert list(graph.nodes) == ["same.tf::aws_vpc.main", "same.tf::aws_vpc.main#2"]
        assert graph.duplicate_count == 1

    def test_a_duplicate_inside_one_unit_is_suffixed_not_qualified(self) -> None:
        graph = InfraGraph.from_units([_unit("a", _pr("aws_vpc", "main"), _pr("aws_vpc", "main"))])
        assert list(graph.nodes) == ["aws_vpc.main", "aws_vpc.main#2"]

    def test_node_limit_applies_across_units(self) -> None:
        units = [_unit("a", _pr("aws_vpc", "a")), _unit("b", _pr("aws_vpc", "b"))]
        with pytest.raises(ThreatCodeError, match="exceeds 1 node limit"):
            InfraGraph.from_units(units, max_nodes=1)

    def test_no_units_build_an_empty_graph(self) -> None:
        graph = InfraGraph.from_units([])
        assert (graph.node_count, graph.edges, graph.diagnostics) == (0, [], [])


class TestEdgesStayInsideTheirUnit:
    def test_references_resolve_to_the_unit_own_node_when_addresses_collide(self) -> None:
        def unit(path: str) -> ParsedOutput:
            return _unit(
                path,
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", references={"vpc_id": ["aws_vpc.main.id"]}),
            )

        graph = InfraGraph.from_units([unit("a"), unit("b")])
        assert _edges(graph) == {
            ("a::aws_subnet.a", "a::aws_vpc.main", "containment"),
            ("b::aws_subnet.a", "b::aws_vpc.main", "containment"),
        }

    def test_dependencies_resolve_inside_their_own_unit(self) -> None:
        def unit(path: str) -> ParsedOutput:
            return _unit(
                path,
                _pr("aws_vpc", "main"),
                _pr("aws_instance", "web", dependencies=["aws_vpc.main"]),
            )

        graph = InfraGraph.from_units([unit("a"), unit("b")])
        assert _edges(graph) == {
            ("a::aws_instance.web", "a::aws_vpc.main", "dependency"),
            ("b::aws_instance.web", "b::aws_vpc.main", "dependency"),
        }

    def test_a_reference_never_reaches_a_node_in_another_unit(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("aws_subnet", "a", references={"vpc_id": ["aws_vpc.main.id"]})),
                _unit("b", _pr("aws_vpc", "main")),
            ]
        )
        assert graph.edges == []

    def test_a_legacy_heuristic_never_binds_across_units(self) -> None:
        # The literal vpc_id would have bound the first VPC anywhere in the graph
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("aws_subnet", "a", properties={"vpc_id": "vpc-1"})),
                _unit("b", _pr("aws_vpc", "main")),
            ]
        )
        assert graph.edges == []

    def test_a_legacy_heuristic_still_binds_inside_a_unit(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit(
                    "a",
                    _pr("aws_vpc", "main"),
                    _pr("aws_subnet", "a", properties={"vpc_id": "vpc-1"}),
                ),
                _unit("b", _pr("aws_vpc", "other")),
            ]
        )
        assert _edges(graph) == {("aws_subnet.a", "aws_vpc.main", "containment")}

    def test_a_literal_subnet_or_security_group_value_never_matches_across_units(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit(
                    "a",
                    _pr(
                        "aws_instance",
                        "web",
                        properties={
                            "subnet_id": "aws_subnet.shared",
                            "vpc_security_group_ids": ["aws_security_group.shared"],
                        },
                    ),
                ),
                _unit("b", _pr("aws_subnet", "shared"), _pr("aws_security_group", "shared")),
            ]
        )
        assert graph.edges == []

    def test_a_literal_subnet_and_security_group_value_still_match_inside_a_unit(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit(
                    "a",
                    _pr("aws_subnet", "shared"),
                    _pr("aws_security_group", "shared"),
                    _pr(
                        "aws_instance",
                        "web",
                        properties={
                            "subnet_id": "aws_subnet.shared",
                            "vpc_security_group_ids": ["aws_security_group.shared"],
                        },
                    ),
                ),
                _unit("b", _pr("aws_subnet", "shared"), _pr("aws_security_group", "shared")),
            ]
        )
        assert {(e.source, e.target) for e in graph.edges} == {
            ("aws_instance.web", "a::aws_subnet.shared"),
            ("aws_instance.web", "a::aws_security_group.shared"),
        }

    def test_legacy_role_match_stays_inside_the_unit(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("aws_iam_instance_profile", "p", properties={"role": "exec"})),
                _unit("b", _pr("aws_iam_role", "exec")),
            ]
        )
        assert graph.edges == []

    def test_declared_edges_resolve_inside_their_own_unit_first(self) -> None:
        def unit(path: str) -> ParsedOutput:
            return _unit(
                path,
                _pr("design_service", "api"),
                _pr("design_database", "db"),
                edges=[ParsedEdge("design_service.api", "design_database.db")],
            )

        graph = InfraGraph.from_units([unit("a"), unit("b")])
        assert _edges(graph) == {
            ("a::design_service.api", "a::design_database.db", "data_flow"),
            ("b::design_service.api", "b::design_database.db", "data_flow"),
        }

    def test_a_declared_edge_may_name_a_qualified_id_in_another_unit(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("design_database", "db")),
                _unit("b", _pr("design_database", "db")),
                _unit(
                    "c",
                    _pr("design_service", "api"),
                    edges=[ParsedEdge("design_service.api", "b::design_database.db")],
                ),
            ]
        )
        assert _edges(graph) == {("design_service.api", "b::design_database.db", "data_flow")}

    def test_dangling_declared_edges_in_every_unit_are_reported_together(self) -> None:
        units = [
            _unit(
                "a", _pr("design_service", "x"), edges=[ParsedEdge("design_service.x", "gone.one")]
            ),
            _unit(
                "b", _pr("design_service", "y"), edges=[ParsedEdge("design_service.y", "gone.two")]
            ),
        ]
        with pytest.raises(ThreatCodeError) as excinfo:
            InfraGraph.from_units(units)
        assert "gone.one" in str(excinfo.value) and "gone.two" in str(excinfo.value)

    def test_non_strict_dangling_edges_in_units_become_warnings(self) -> None:
        units = [
            _unit(
                "a", _pr("design_service", "x"), edges=[ParsedEdge("design_service.x", "gone.one")]
            ),
        ]
        graph = InfraGraph.from_units(units, strict_edges=False)
        assert [d.code for d in graph.diagnostics] == ["graph.dangling_declared_edge"]

    def test_boundary_crossings_are_computed_over_the_merged_graph(self) -> None:
        graph = InfraGraph.from_units(
            [
                _unit("net", _pr("aws_lb", "front")),
                _unit(
                    "app",
                    _pr("aws_s3_bucket", "data"),
                    edges=[ParsedEdge("aws_s3_bucket.data", "aws_lb.front")],
                ),
            ]
        )
        (edge,) = graph.edges
        assert edge.crosses_boundary is True


class TestDiagnosticsAcrossUnits:
    def test_unit_diagnostics_are_concatenated_in_unit_order(self) -> None:
        first = Diagnostic("warning", "hcl.module_call_skipped", "first", "a.tf")
        second = Diagnostic("info", "parse.zero_resources", "second", "b.tf")
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("aws_vpc", "a"), diagnostics=[first]),
                _unit("b", _pr("aws_vpc", "b"), diagnostics=[second]),
            ]
        )
        assert graph.diagnostics == [first, second]

    def test_graph_diagnostics_come_after_all_unit_diagnostics(self) -> None:
        note = Diagnostic("warning", "hcl.module_call_skipped", "from the parser")
        graph = InfraGraph.from_units(
            [
                _unit("a", _pr("aws_vpc", "main"), diagnostics=[note]),
                _unit("b", _pr("aws_vpc", "main")),
            ]
        )
        assert [d.code for d in graph.diagnostics] == [
            "hcl.module_call_skipped",
            "graph.duplicate_address",
        ]


class TestSingleUnitEquivalence:
    def test_from_units_of_one_equals_from_parsed(self, simple_s3_parsed: ParsedOutput) -> None:
        via_units = InfraGraph.from_units([simple_s3_parsed])
        via_parsed = InfraGraph.from_parsed(simple_s3_parsed)
        assert via_units.to_dict() == via_parsed.to_dict()
        assert list(via_units.nodes) == list(via_parsed.nodes)

    def test_a_unit_with_no_collisions_matches_building_it_alone(
        self, simple_s3_parsed: ParsedOutput
    ) -> None:
        other = _unit("other.tf", _pr("custom_thing", "alone"))
        merged = InfraGraph.from_units([simple_s3_parsed, other])
        alone = InfraGraph.from_parsed(simple_s3_parsed)
        assert set(alone.nodes) <= set(merged.nodes)
        assert _edges(alone) == _edges(merged)
