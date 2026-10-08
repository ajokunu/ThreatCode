"""Tests for the trust boundary phase."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

import pytest

from tests.test_ir.test_golden import GOLDEN_INPUTS, REPO_ROOT
from threatcode.engine import boundaries
from threatcode.engine.boundaries import _boundary_severity
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.ir.edges import AGENT, FLOW_EDGE_TYPES, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource
from threatcode.values import Unknown

REALISTIC = Path(__file__).parent.parent / "fixtures" / "realistic"


def _res(rtype: str, name: str, zone: str | None = None, **kwargs: Any) -> ParsedResource:
    return ParsedResource(
        rtype, f"{rtype}.{name}", name, rtype.split("_", 1)[0], trust_zone=zone, **kwargs
    )


def _graph(
    resources: list[ParsedResource], edges: list[ParsedEdge], strict: bool = True
) -> InfraGraph:
    return InfraGraph.from_parsed(
        ParsedOutput(resources=resources, edges=edges), strict_edges=strict
    )


def _edge(source: str, target: str, edge_type: str = "data_flow", **meta: Any) -> ParsedEdge:
    return ParsedEdge(source, target, edge_type, meta)


# A dmz web tier, a private app tier and a data store: the shape of most inputs
WEB = "design_service.web"
APP = "design_service.app"
DB = "design_database.orders"


def _tiers(*edges: ParsedEdge) -> InfraGraph:
    return _graph(
        [
            _res("design_service", "web", "dmz"),
            _res("design_service", "app", "private"),
            _res("design_database", "orders", "data"),
        ],
        list(edges),
    )


def _only(graph: InfraGraph) -> Threat:
    (threat,) = boundaries.analyze(graph)
    return threat


def _from(graph: InfraGraph, source: str) -> list[Threat]:
    """The boundary threats of the flows that start at one node."""
    return [t for t in boundaries.analyze(graph) if t.metadata["source_address"] == source]


def _flow_crossings(graph: InfraGraph) -> list[InfraEdge]:
    """The edges that carry traffic across a boundary and that the phase reports."""
    return [
        e
        for e in graph.get_boundary_crossing_edges()
        if e.edge_type in FLOW_EDGE_TYPES and e.source_kind != AGENT
    ]


class TestOnlyFlowsCross:
    @pytest.mark.parametrize("edge_type", ["containment", "dependency", "iam_binding"])
    def test_a_structural_or_iam_edge_across_zones_produces_no_threat(self, edge_type: str) -> None:
        graph = _tiers(_edge(WEB, DB, edge_type))
        assert [e.crosses_trust_boundary for e in graph.edges] == [True]
        assert boundaries.analyze(graph) == []

    @pytest.mark.parametrize("edge_type", ["network_flow", "data_flow"])
    def test_a_flow_edge_across_zones_produces_one_threat(self, edge_type: str) -> None:
        threat = _only(_tiers(_edge(WEB, DB, edge_type)))
        assert (threat.resource_address, threat.target_address) == (WEB, DB)
        assert threat.source == ThreatSource.BOUNDARY

    def test_a_declared_data_flow_produces_exactly_one_threat_with_its_port(self) -> None:
        threat = _only(_tiers(_edge(WEB, DB, protocol="tcp", port=5432)))
        assert "tcp/5432" in threat.description
        assert "declares" in threat.description

    def test_a_flow_inside_one_zone_and_boundary_is_not_a_crossing(self) -> None:
        graph = _graph(
            [_res("design_service", "a", "private"), _res("design_service", "b", "private")],
            [_edge("design_service.a", "design_service.b")],
        )
        assert boundaries.analyze(graph) == []

    def test_two_declared_boundaries_in_one_zone_are_a_crossing(self) -> None:
        graph = _graph(
            [
                _res("design_service", "a", "private", boundary="tz-a"),
                _res("design_service", "b", "private", boundary="tz-b"),
            ],
            [_edge("design_service.a", "design_service.b")],
        )
        assert len(boundaries.analyze(graph)) == 1

    def test_a_subnet_in_its_vpc_and_an_internet_gateway_attached_to_it_are_not_crossings(
        self,
    ) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    ParsedResource("aws_vpc", "aws_vpc.main", "main", "aws"),
                    ParsedResource(
                        "aws_subnet",
                        "aws_subnet.pub",
                        "pub",
                        "aws",
                        properties={"map_public_ip_on_launch": True},
                    ),
                    ParsedResource("aws_internet_gateway", "aws_internet_gateway.gw", "gw", "aws"),
                ],
                edges=[
                    ParsedEdge("aws_subnet.pub", "aws_vpc.main", "containment", declared=False),
                    ParsedEdge(
                        "aws_internet_gateway.gw", "aws_vpc.main", "dependency", declared=False
                    ),
                ],
            )
        )
        assert [e.crosses_trust_boundary for e in graph.edges] == [True, True]
        assert boundaries.analyze(graph) == []

    def test_the_fixture_with_the_most_wiring_has_only_flow_threats(self) -> None:
        graph = InfraGraph.from_parsed(
            detect_and_parse(REALISTIC / "01_aws_ecommerce_platform.json")
        )
        crossings = {
            (e.source, e.target, e.edge_type)
            for e in graph.get_boundary_crossing_edges()
            if e.edge_type not in FLOW_EDGE_TYPES
        }
        assert crossings, "the fixture has wiring that crosses zones"
        threats = boundaries.analyze(graph)
        assert threats
        pairs = {(t.metadata["source_address"], t.metadata["target_address"]) for t in threats}
        assert pairs == {(e.source, e.target) for e in _flow_crossings(graph)}
        # No structural pair is a threat, even though each crosses a zone
        assert pairs.isdisjoint({(source, target) for source, target, _ in crossings})


class TestEndpointsThatCannotExchangeTraffic:
    @pytest.mark.parametrize(
        "rtype",
        [
            "aws_security_group",
            "aws_network_acl",
            "aws_route_table",
            "aws_iam_policy",
            "aws_iam_role",
            "aws_s3_bucket_policy",
            "aws_vpc",
            "aws_subnet",
            "kubernetes_namespace",
            "kubernetes_network_policy",
            "kubernetes_role_binding",
            "azurerm_network_security_group",
            "google_compute_firewall",
        ],
    )
    @pytest.mark.parametrize("end", ["source", "target"])
    def test_a_flow_to_or_from_such_a_node_produces_no_threat(self, rtype: str, end: str) -> None:
        passive = _res(rtype, "p", "data")
        actor = _res("design_service", "web", "dmz")
        edges = (
            [_edge(passive.address, WEB, "network_flow")]
            if end == "source"
            else [_edge(WEB, passive.address, "network_flow")]
        )
        assert boundaries.analyze(_graph([passive, actor], edges)) == []

    def test_an_instance_a_load_balancer_and_a_database_can(self) -> None:
        graph = _graph(
            [
                _res("aws_lb", "front", "dmz"),
                _res("aws_instance", "app", "private"),
                _res("aws_db_instance", "db", "data"),
            ],
            [
                _edge("aws_lb.front", "aws_instance.app", "network_flow"),
                _edge("aws_instance.app", "aws_db_instance.db", "network_flow"),
            ],
        )
        assert len(boundaries.analyze(graph)) == 2


class TestPairsAreMerged:
    def test_edges_between_one_pair_make_one_threat_naming_every_type(self) -> None:
        graph = _tiers(
            _edge(WEB, DB, "network_flow", protocol="tcp", port=5432),
            _edge(WEB, DB, "data_flow"),
            _edge(WEB, DB, "dependency"),
        )
        threat = _only(graph)
        assert threat.metadata["flow"]["edge_types"] == ["data_flow", "network_flow"]
        assert "data_flow and network_flow" in threat.description
        assert "5432" in threat.description

    def test_the_reverse_direction_is_a_separate_threat_with_its_own_id(self) -> None:
        threats = boundaries.analyze(_tiers(_edge(WEB, DB), _edge(DB, WEB)))
        assert len(threats) == 2
        assert len({t.id for t in threats}) == 2

    def test_the_id_seed_includes_the_pair_and_the_sorted_edge_types(self) -> None:
        both = _only(_tiers(_edge(WEB, DB, "network_flow"), _edge(WEB, DB, "data_flow")))
        assert both.id == hash_id(f"BOUNDARY|{WEB}|{DB}|data_flow+network_flow")
        only_data = _only(_tiers(_edge(WEB, DB, "data_flow")))
        assert only_data.id == hash_id(f"BOUNDARY|{WEB}|{DB}|data_flow")
        assert only_data.id != both.id

    def test_pairs_whose_names_would_run_together_keep_distinct_ids(self) -> None:
        graph = _graph(
            [
                _res("design_service", "a_b", "dmz"),
                _res("design_service", "c", "data"),
                _res("design_service", "a", "dmz"),
                _res("design_service", "b_c", "data"),
            ],
            [
                _edge("design_service.a_b", "design_service.c"),
                _edge("design_service.a", "design_service.b_c"),
            ],
        )
        threats = boundaries.analyze(graph)
        assert len(threats) == 2 and len({t.id for t in threats}) == 2

    def test_threats_follow_the_order_of_the_first_edge_of_each_pair(self) -> None:
        graph = _tiers(_edge(APP, DB), _edge(WEB, APP), _edge(APP, DB, "network_flow"))
        assert [t.resource_address for t in boundaries.analyze(graph)] == [APP, WEB]

    def test_ids_are_stable_across_builds(self) -> None:
        first = [t.id for t in boundaries.analyze(_tiers(_edge(WEB, DB), _edge(APP, DB)))]
        second = [t.id for t in boundaries.analyze(_tiers(_edge(WEB, DB), _edge(APP, DB)))]
        assert first == second


class TestWhatTheThreatSays:
    def test_the_title_names_both_endpoints_and_both_zones(self) -> None:
        assert _only(_tiers(_edge(WEB, DB))).title == (
            f"Trust boundary crossing: {WEB} (dmz) -> {DB} (data)"
        )

    def test_the_target_is_recorded_on_the_threat_and_in_the_metadata(self) -> None:
        threat = _only(_tiers(_edge(WEB, DB)))
        assert threat.target_address == DB
        assert threat.resource_address == WEB
        assert threat.resource_type == "design_service"
        assert threat.metadata["source_address"] == WEB
        assert threat.metadata["target_address"] == DB
        assert (threat.metadata["source_zone"], threat.metadata["target_zone"]) == ("dmz", "data")
        assert threat.metadata["boundary_key"] == "BOUNDARY_dmz_data"

    def test_the_description_says_what_is_known_not_a_fixed_sentence(self) -> None:
        threat = _only(_tiers(_edge(WEB, DB)))
        assert "Data flows from" not in threat.description
        assert WEB in threat.description and DB in threat.description
        assert "dmz zone" in threat.description and "data zone" in threat.description
        assert "Nothing in the input says" in threat.description

    def test_an_inferred_flow_is_worded_as_reachability(self) -> None:
        graph = _tiers(ParsedEdge(WEB, APP, "network_flow", {}, declared=False))
        threat = _only(graph)
        assert "can reach" in threat.description
        assert "declares" not in threat.description

    def test_a_port_without_a_protocol_and_a_protocol_without_a_port(self) -> None:
        with_port = _only(
            _tiers(ParsedEdge(WEB, APP, "network_flow", {"port": 8080}, declared=False))
        )
        assert "on port 8080" in with_port.description
        with_protocol = _only(
            _tiers(ParsedEdge(WEB, APP, "network_flow", {"protocol": "grpc"}, declared=False))
        )
        assert "over grpc" in with_protocol.description

    def test_several_ports_are_listed_in_order(self) -> None:
        threat = _only(
            _tiers(
                ParsedEdge(WEB, APP, "network_flow", {"ports": [443, 80]}, declared=False),
            )
        )
        assert "on port 80,443" in threat.description

    def test_the_threat_does_not_repeat_the_flow_facts_it_does_not_have(self) -> None:
        flow = _only(_tiers(_edge(WEB, DB))).metadata["flow"]
        assert flow == {
            "source": WEB,
            "target": DB,
            "edge_types": ["data_flow"],
            "relations": [],
            "protocols": [],
            "ports": [],
            "authenticated": None,
            "encrypted": None,
        }


class TestStrideFollowsTheFlow:
    @pytest.mark.parametrize(
        ("meta", "stride"),
        [
            ({"authenticated": False}, "spoofing"),
            ({"authenticated": False, "encrypted": False}, "spoofing"),
            ({"encrypted": False}, "information_disclosure"),
            ({"authenticated": True, "encrypted": False}, "information_disclosure"),
            ({"protocol": "http"}, "information_disclosure"),
            ({"protocol": "http", "authenticated": True}, "information_disclosure"),
            ({"authenticated": True, "encrypted": True}, "tampering"),
            ({"protocol": "https", "authenticated": True}, "tampering"),
            ({"protocol": "https"}, "tampering"),
            ({"authenticated": True}, "tampering"),
            ({}, "tampering"),
        ],
    )
    def test_the_category(self, meta: dict[str, Any], stride: str) -> None:
        assert _only(_tiers(_edge(WEB, DB, **meta))).stride_category == stride

    def test_an_explicit_flag_beats_the_protocol(self) -> None:
        threat = _only(_tiers(_edge(WEB, DB, protocol="https", encrypted=False)))
        assert threat.stride_category == "information_disclosure"

    def test_merged_edges_take_the_weakest_claim(self) -> None:
        graph = _tiers(
            _edge(WEB, DB, "data_flow", authenticated=True),
            _edge(WEB, DB, "network_flow", authenticated=False),
        )
        threat = _only(graph)
        assert threat.metadata["flow"]["authenticated"] is False
        assert threat.stride_category == "spoofing"

    def test_merged_edges_agree_only_when_all_say_yes(self) -> None:
        graph = _tiers(
            _edge(WEB, DB, "data_flow", authenticated=True, encrypted=True),
            _edge(WEB, DB, "network_flow"),
        )
        flow = _only(graph).metadata["flow"]
        assert flow["authenticated"] is None
        assert flow["encrypted"] is None

    def test_a_flow_without_facts_has_lower_confidence(self) -> None:
        assert _only(_tiers(_edge(WEB, DB))).confidence == 0.5
        assert _only(_tiers(_edge(WEB, DB, authenticated=False))).confidence == 1.0
        assert _only(_tiers(_edge(WEB, DB, protocol="https"))).confidence == 1.0


class TestMitreFollowsTheZonePair:
    @pytest.mark.parametrize(
        ("src_zone", "tgt_zone", "meta", "techniques"),
        [
            ("internet", "dmz", {}, ["T1190", "T1565.002"]),
            ("internet", "private", {}, ["T1565.002"]),
            ("dmz", "data", {}, ["T1530", "T1565.002"]),
            ("private", "data", {}, ["T1530", "T1565.002"]),
            ("private", "management", {}, ["T1078", "T1565.002"]),
            ("internet", "data", {}, ["T1530", "T1565.002"]),
            ("dmz", "private", {}, ["T1565.002"]),
            ("dmz", "data", {"authenticated": False}, ["T1530", "T1557"]),
            ("dmz", "data", {"encrypted": False}, ["T1530", "T1040"]),
            ("internet", "dmz", {"encrypted": False}, ["T1190", "T1040"]),
        ],
    )
    def test_techniques(
        self, src_zone: str, tgt_zone: str, meta: dict[str, Any], techniques: list[str]
    ) -> None:
        graph = _graph(
            [_res("design_service", "a", src_zone), _res("design_service", "b", tgt_zone)],
            [_edge("design_service.a", "design_service.b", **meta)],
        )
        assert _only(graph).mitre_techniques == techniques

    def test_every_technique_exists_in_the_attack_database_and_is_current(self) -> None:
        used: set[str] = set()
        for src, tgt in (("internet", "dmz"), ("dmz", "data"), ("private", "management")):
            for meta in ({}, {"authenticated": False}, {"encrypted": False}):
                graph = _graph(
                    [_res("design_service", "a", src), _res("design_service", "b", tgt)],
                    [_edge("design_service.a", "design_service.b", **meta)],
                )
                used.update(_only(graph).mitre_techniques)
        assert used >= {"T1190", "T1530", "T1078", "T1557", "T1040", "T1565.002"}
        for technique in used:
            entry = TECHNIQUE_DB[technique]
            assert not entry["revoked"] and not entry["deprecated"], technique

    def test_the_tactics_are_derived_from_the_techniques(self) -> None:
        threat = _only(
            _graph(
                [_res("design_service", "a", "internet"), _res("design_service", "b", "dmz")],
                [_edge("design_service.a", "design_service.b")],
            )
        )
        derived: set[str] = set()
        for technique in threat.mitre_techniques:
            derived.update(TECHNIQUE_DB[technique]["tactic_ids"])
        assert threat.mitre_tactics == sorted(derived)
        assert "TA0001" in threat.mitre_tactics

    def test_the_technique_lists_are_copies(self) -> None:
        threats = boundaries.analyze(_tiers(_edge(WEB, DB), _edge(APP, DB)))
        assert len(threats) == 2
        threats[0].mitre_techniques.append("T0000")
        threats[0].mitre_tactics.append("TA0000")
        assert "T0000" not in threats[1].mitre_techniques
        assert "TA0000" not in threats[1].mitre_tactics


class TestSeverity:
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

    def test_the_threat_takes_the_severity_of_its_pair(self) -> None:
        assert _only(_tiers(_edge(WEB, DB))).severity == Severity.HIGH
        assert _only(_tiers(_edge(WEB, APP))).severity == Severity.MEDIUM
        assert _only(_tiers(_edge(APP, DB))).severity == Severity.MEDIUM

    def test_a_flow_declared_encrypted_and_authenticated_is_one_level_lower(self) -> None:
        safe = {"encrypted": True, "authenticated": True}
        assert _only(_tiers(_edge(WEB, DB, **safe))).severity == Severity.MEDIUM
        assert _only(_tiers(_edge(WEB, APP, **safe))).severity == Severity.LOW

    @pytest.mark.parametrize(
        "meta",
        [{"encrypted": True}, {"authenticated": True}, {"encrypted": True, "authenticated": False}],
    )
    def test_half_the_story_does_not_lower_it(self, meta: dict[str, Any]) -> None:
        assert _only(_tiers(_edge(WEB, DB, **meta))).severity == Severity.HIGH

    def test_a_protocol_that_implies_encryption_counts(self) -> None:
        threat = _only(_tiers(_edge(WEB, DB, protocol="https", authenticated=True)))
        assert threat.severity == Severity.MEDIUM

    def test_merged_edges_lower_it_only_when_every_edge_is_safe(self) -> None:
        safe = {"encrypted": True, "authenticated": True}
        graph = _tiers(_edge(WEB, DB, "data_flow", **safe), _edge(WEB, DB, "network_flow"))
        assert _only(graph).severity == Severity.HIGH
        graph = _tiers(_edge(WEB, DB, "data_flow", **safe), _edge(WEB, DB, "network_flow", **safe))
        assert _only(graph).severity == Severity.MEDIUM

    def test_a_source_that_faces_the_internet_is_judged_as_the_internet(self) -> None:
        resources = [
            ParsedResource(
                "aws_lb", "aws_lb.front", "front", "aws", properties={"internal": False}
            ),
            ParsedResource("aws_instance", "aws_instance.app", "app", "aws"),
        ]
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=resources,
                edges=[ParsedEdge("aws_lb.front", "aws_instance.app", "network_flow", {}, False)],
            )
        )
        lb = graph.get_node("aws_lb.front")
        assert lb is not None and lb.exposure == "internet"
        # dmz -> private is MEDIUM, but a source that is internet-exposed is an internet pair
        (threat,) = _from(graph, "aws_lb.front")
        assert threat.severity == Severity.HIGH

    def test_the_same_pair_without_exposure_stays_medium(self) -> None:
        resources = [
            ParsedResource(
                "aws_lb", "aws_lb.front", "front", "aws", properties={"internal": Unknown()}
            ),
            ParsedResource("aws_instance", "aws_instance.app", "app", "aws"),
        ]
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=resources,
                edges=[ParsedEdge("aws_lb.front", "aws_instance.app", "network_flow", {}, False)],
            )
        )
        (threat,) = _from(graph, "aws_lb.front")
        assert threat.severity == Severity.MEDIUM


class TestMitigation:
    def test_the_advice_follows_the_category(self) -> None:
        spoofing = _only(_tiers(_edge(WEB, DB, authenticated=False))).mitigation
        disclosure = _only(_tiers(_edge(WEB, DB, encrypted=False))).mitigation
        tampering = _only(_tiers(_edge(WEB, DB))).mitigation
        assert "Authenticate" in spoofing
        assert "Encrypt" in disclosure
        assert "validated" in tampering
        assert len({spoofing, disclosure, tampering}) == 3


class TestEngineIntegration:
    def test_boundary_threats_are_generated_for_a_flow_input(self) -> None:
        report = HybridEngine().analyze(_tiers(_edge(WEB, DB)))
        found = [t for t in report.threats if t.source == ThreatSource.BOUNDARY]
        assert len(found) == 1

    def test_a_plan_with_only_wiring_has_no_boundary_threat_but_the_public_bucket(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        report = HybridEngine().analyze(simple_s3_graph)
        found = [t for t in report.threats if t.source == ThreatSource.BOUNDARY]
        # The wiring (roles, policies, attachments) crosses zones and says nothing about traffic.
        # The one flow is the one the reachability pass found: the internet reading a public bucket
        assert [t.metadata["flow"]["source"] for t in found] == ["internet"]
        assert [t.target_address for t in found] == [""]
        assert [t.resource_address for t in found] == ["aws_s3_bucket.public_assets"]

    def test_what_the_engine_reports_is_what_the_phase_produces(self) -> None:
        graph = _tiers(_edge(WEB, DB), _edge(WEB, APP, "network_flow"))
        report = HybridEngine().analyze(graph)
        in_report = [t for t in report.threats if t.source == ThreatSource.BOUNDARY]
        assert [t.to_dict() for t in in_report] == [t.to_dict() for t in boundaries.analyze(graph)]

    def test_the_target_address_reaches_the_serialised_threat(self) -> None:
        data = _only(_tiers(_edge(WEB, DB))).to_dict()
        assert data["target_address"] == DB
        assert data["metadata"]["flow"]["edge_types"] == ["data_flow"]

    def test_a_graph_without_crossings_has_no_boundary_threats(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[ParsedResource("aws_s3_bucket", "aws_s3_bucket.only", "only", "aws")]
            )
        )
        assert boundaries.analyze(graph) == []


class TestIdsAreUnique:
    @pytest.mark.parametrize("path", sorted(p.name for p in REALISTIC.iterdir() if p.is_file()))
    def test_a_realistic_input_has_no_duplicate_threat_id(self, path: str) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(REALISTIC / path))
        report = HybridEngine().analyze(graph, input_file=path)
        counts = Counter(t.id for t in report.threats)
        assert [tid for tid, n in counts.items() if n > 1] == []

    @pytest.mark.parametrize("relpath", GOLDEN_INPUTS)
    def test_a_golden_input_has_no_duplicate_boundary_id(self, relpath: str) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(REPO_ROOT / relpath))
        ids = [t.id for t in boundaries.analyze(graph)]
        assert len(ids) == len(set(ids))


class TestKubernetesAndMcpFlowsRemain:
    def _threats(self, relpath: str) -> list[Threat]:
        graph = InfraGraph.from_parsed(detect_and_parse(REPO_ROOT / relpath))
        return boundaries.analyze(graph)

    def test_an_exposed_service_to_its_workload_is_a_high_flow_threat(self) -> None:
        threats = self._threats("tests/fixtures/kubernetes/graph_stack.yml")
        pairs = {(t.resource_address, t.target_address): t for t in threats}
        lb = pairs[("kubernetes_service.default.web-lb", "kubernetes_deployment.default.web")]
        assert lb.metadata["flow"]["edge_types"] == ["network_flow"]
        assert lb.metadata["flow"]["relations"] == ["selects"]
        # The Service is exposed to the internet, so its flow into the cluster is an internet pair
        assert lb.severity == Severity.HIGH

    def test_a_cluster_ip_service_and_the_wiring_around_it_produce_nothing(self) -> None:
        threats = self._threats("tests/fixtures/kubernetes/graph_stack.yml")
        sources = {t.resource_address for t in threats}
        assert not any("api-internal" in s for s in sources)
        assert not any(s.startswith("kubernetes_role") for s in sources)
        assert not any("secret" in s for s in sources)

    def test_an_ingress_to_a_service_in_another_zone_is_a_flow_threat(self) -> None:
        threats = self._threats("tests/fixtures/real_shapes/kubernetes/shop_stack.yaml")
        pairs = {(t.metadata["source_address"], t.metadata["target_address"]): t for t in threats}
        threat = pairs[("kubernetes_ingress.shop.web", "kubernetes_service.shop.web")]
        # The other two flows are the internet entering the Ingress and the workload reading its
        # Secret; the Service selecting the workload stays inside the private zone
        assert set(pairs) == {
            ("kubernetes_ingress.shop.web", "kubernetes_service.shop.web"),
            ("internet", "kubernetes_ingress.shop.web"),
            ("kubernetes_deployment.shop.web", "kubernetes_secret.shop.web-db"),
        }
        assert threat.resource_address == "kubernetes_ingress.shop.web"
        assert threat.target_address == "kubernetes_service.shop.web"
        assert threat.metadata["flow"]["relations"] == ["backend"]

    def test_a_remote_mcp_server_over_plain_http_is_an_unencrypted_flow(self) -> None:
        (threat,) = self._threats("tests/fixtures/mcp/vulnerable/.mcp.json")
        assert (threat.resource_address, threat.target_address) == (
            "mcp_server.inventory",
            "mcp_agent.config",
        )
        # The scheme is evidence; whether the server asks for a sign-in is not
        assert threat.stride_category == "information_disclosure"
        assert threat.metadata["boundary_rule"] == "BOUNDARY_UNENCRYPTED_FLOW"
        assert threat.metadata["flow"]["encrypted"] is False
        assert threat.metadata["flow"]["authenticated"] is None
        assert threat.severity == Severity.HIGH
        assert "over http" in threat.description
        assert "is not authenticated" not in threat.description

    def test_a_pinned_authenticated_https_server_is_one_level_lower(self) -> None:
        (threat,) = self._threats("tests/fixtures/mcp/fixed/.mcp.json")
        assert threat.metadata["flow"]["authenticated"] is True
        assert threat.metadata["flow"]["encrypted"] is True
        assert threat.severity == Severity.MEDIUM
        assert threat.stride_category == "tampering"

    def test_the_agent_to_server_invocation_is_not_a_flow(self) -> None:
        for threat in self._threats("tests/fixtures/mcp/fixed/.mcp.json"):
            assert threat.metadata["flow"]["edge_types"] == ["data_flow"]


class TestReachabilityFlows:
    """The flows the reachability pass adds are the boundary threats of a cloud input."""

    def threats(self) -> dict[tuple[str, str], Threat]:
        graph = InfraGraph.from_parsed(
            detect_and_parse(
                REPO_ROOT / "tests/fixtures/real_shapes/terraform/plan/webapp.plan.json"
            )
        )
        return {
            (t.metadata["source_address"], t.metadata["target_address"]): t
            for t in boundaries.analyze(graph)
        }

    def test_each_tier_of_the_web_stack_is_a_threat_with_its_port_and_protocol(self) -> None:
        found = self.threats()
        entering = found[("internet", "aws_lb.front")]
        assert "from internet (internet zone) to aws_lb.front (dmz zone) over tcp/443" in (
            entering.description
        )
        inward = found[("aws_lb.front", "aws_instance.app[0]")]
        assert "over tcp/8080 crosses a trust boundary" in inward.description
        data = found[("aws_instance.app[0]", "aws_db_instance.orders")]
        assert "over tcp/5432 crosses a trust boundary" in data.description
        assert data.metadata["flow"]["ports"] == ["5432"]
        assert data.metadata["flow"]["protocols"] == ["tcp"]

    def test_no_description_calls_a_structural_edge_a_flow(self) -> None:
        for threat in self.threats().values():
            assert "Data flows from" not in threat.description

    def test_the_zone_pair_decides_the_technique_of_the_crossing(self) -> None:
        found = self.threats()
        assert "T1190" in found[("internet", "aws_lb.front")].mitre_techniques
        assert "T1530" in found[("aws_instance.app[0]", "aws_db_instance.orders")].mitre_techniques

    def test_a_flow_from_the_internet_belongs_to_the_resource_it_enters(self) -> None:
        threat = self.threats()[("internet", "aws_lb.front")]
        assert (threat.resource_address, threat.resource_type) == ("aws_lb.front", "aws_lb")
        assert threat.target_address == ""
        assert threat.metadata["flow"]["source"] == "internet"
        assert threat.title == "Trust boundary crossing: internet (internet) -> aws_lb.front (dmz)"

    def test_it_is_located_at_the_resource_it_enters_after_a_scan(self) -> None:
        from threatcode.pipeline import ScanRequest, run_scan

        result = run_scan(
            ScanRequest(
                paths=(
                    str(REPO_ROOT / "tests/fixtures/real_shapes/terraform/plan/webapp.plan.json"),
                )
            )
        )
        (threat,) = [
            t
            for t in result.report.threats
            if t.source == ThreatSource.BOUNDARY and t.metadata["source_address"] == "internet"
        ]
        assert threat.resource_address == "aws_lb.front" and threat.fingerprint

    def test_two_flows_from_one_resource_are_two_findings_with_two_fingerprints(self) -> None:
        from threatcode.fingerprint import compute_fingerprint

        found = self.threats()
        first = found[("aws_lb.front", "aws_instance.app[0]")]
        second = found[("aws_lb.front", "aws_instance.app[1]")]
        assert first.id != second.id
        assert first.metadata["fingerprint_hint"] == "aws_lb.front -> aws_instance.app[0]"
        assert compute_fingerprint(first, "main.tf") != compute_fingerprint(second, "main.tf")
        assert compute_fingerprint(first, "main.tf") == compute_fingerprint(first, "main.tf")

    def test_the_untrusted_content_an_agent_ingests_is_not_a_boundary_threat(self) -> None:
        graph = InfraGraph.from_parsed(
            detect_and_parse(REPO_ROOT / "tests/fixtures/mcp/trifecta/.mcp.json")
        )
        agent_entries = [e for e in graph.edges if e.source == "internet"]
        assert agent_entries and all(e.source_kind == AGENT for e in agent_entries)
        assert not [
            t for t in boundaries.analyze(graph) if t.metadata["source_address"] == "internet"
        ]

    def test_all_protocols_are_worded_as_such(self) -> None:
        graph = _tiers(_edge(WEB, DB, protocol="all", ports=["0-65535"]))
        assert "over all protocols and ports" in _only(graph).description

    def test_edges_that_disagree_on_the_protocol_list_all_of_them(self) -> None:
        graph = _tiers(
            _edge(WEB, DB, "data_flow", protocol="tcp"),
            _edge(WEB, DB, "network_flow", protocol="udp"),
        )
        threat = _only(graph)
        assert threat.metadata["flow"]["protocols"] == ["tcp", "udp"]
        assert "over tcp/udp" in threat.description


class TestBoundaryRules:
    @pytest.mark.parametrize(
        ("meta", "rule"),
        [
            ({"authenticated": False}, "BOUNDARY_UNAUTHENTICATED_FLOW"),
            ({"encrypted": False}, "BOUNDARY_UNENCRYPTED_FLOW"),
            ({"protocol": "http"}, "BOUNDARY_UNENCRYPTED_FLOW"),
            ({"validated": False}, "BOUNDARY_UNVALIDATED_FLOW"),
            ({}, "BOUNDARY_GENERIC_FLOW"),
            ({"encrypted": True, "authenticated": True}, "BOUNDARY_GENERIC_FLOW"),
        ],
    )
    def test_the_kind_of_a_threat_is_in_its_metadata(self, meta: dict[str, Any], rule: str) -> None:
        threat = _only(_tiers(_edge(WEB, DB, **meta)))
        assert threat.metadata["boundary_rule"] == rule
        # Rule ids belong to the rule engine, so tools that list the rules which fired skip these
        assert threat.rule_id == ""

    def test_an_unauthenticated_flow_wins_over_an_unencrypted_one(self) -> None:
        threat = _only(_tiers(_edge(WEB, DB, authenticated=False, encrypted=False)))
        assert threat.metadata["boundary_rule"] == "BOUNDARY_UNAUTHENTICATED_FLOW"

    def test_every_technique_a_crossing_can_get_is_in_the_attack_database(self) -> None:
        zones = ["internet", "dmz", "private", "data", "management"]
        for source in zones:
            for target in zones:
                for meta in ({}, {"authenticated": False}, {"encrypted": False}):
                    graph = _graph(
                        [_res("design_service", "a", source), _res("design_service", "b", target)],
                        [_edge("design_service.a", "design_service.b", **meta)],
                    )
                    for threat in boundaries.analyze(graph):
                        assert threat.mitre_techniques
                        for technique in threat.mitre_techniques:
                            assert technique in TECHNIQUE_DB, (source, target, technique)
                        assert threat.mitre_tactics


class TestAMissingMcpCredentialIsNotEvidence:
    """RW-06: a stock remote server config said "not authenticated" and failed CI."""

    STOCK = (
        '{"mcpServers": {"docs": {"type": "http", "url": "https://modelcontextprotocol.io/mcp"}}}'
    )
    WITH_HEADER = (
        '{"mcpServers": {"docs": {"type": "http", "url": "https://docs.example.org/mcp",'
        ' "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}}}}'
    )

    def _threats(self, tmp_path: Path, text: str) -> list[Threat]:
        path = tmp_path / ".mcp.json"
        path.write_text(text, encoding="utf-8")
        return boundaries.analyze(InfraGraph.from_parsed(detect_and_parse(path)))

    def test_the_flow_is_not_called_unauthenticated(self, tmp_path: Path) -> None:
        (threat,) = self._threats(tmp_path, self.STOCK)
        assert threat.metadata["flow"]["authenticated"] is None
        assert threat.metadata["flow"]["encrypted"] is True
        assert threat.stride_category == "tampering"
        assert threat.metadata["boundary_rule"] == "BOUNDARY_GENERIC_FLOW"
        assert "is not authenticated" not in threat.description
        assert "nothing says whether it is authenticated" in threat.description

    def test_the_severity_and_confidence_are_those_of_the_credential_rule(
        self, tmp_path: Path
    ) -> None:
        (threat,) = self._threats(tmp_path, self.STOCK)
        assert threat.severity == Severity.LOW
        assert threat.confidence == 0.5

    def test_a_lone_remote_server_config_does_not_fail_the_default_gate(
        self, tmp_path: Path
    ) -> None:
        from tests.helpers.cli import run_cli

        path = tmp_path / ".mcp.json"
        path.write_text(self.STOCK, encoding="utf-8")
        run = run_cli(["scan", str(path), "-f", "json"])
        assert run.exit_code == 0, run.stderr[-400:]
        ids = {(t["source"], t["severity"]) for t in run.json()["threats"]}
        assert ids == {("boundary", "low"), ("rule", "low")}

    def test_the_mitigation_does_not_ask_the_agent_to_be_authenticated(
        self, tmp_path: Path
    ) -> None:
        (threat,) = self._threats(tmp_path, self.STOCK)
        assert "Authenticate the caller" not in threat.mitigation
        assert "untrusted input to the agent" in threat.mitigation

    def test_a_plaintext_server_gets_the_transport_advice(self, tmp_path: Path) -> None:
        text = self.STOCK.replace("https://modelcontextprotocol.io", "http://mcp.example.org")
        (threat,) = self._threats(tmp_path, text)
        assert "https or wss" in threat.mitigation

    def test_a_configured_credential_is_still_read_as_authenticated(self, tmp_path: Path) -> None:
        (threat,) = self._threats(tmp_path, self.WITH_HEADER)
        assert threat.metadata["flow"]["authenticated"] is True
        assert threat.severity == Severity.MEDIUM
        assert threat.confidence == 1.0

    def test_a_declared_unauthenticated_flow_of_another_kind_is_unchanged(self) -> None:
        graph = _graph(
            [_res("aws_lb", "front", "internet"), _res("aws_instance", "app", "private")],
            [_edge("aws_lb.front", "aws_instance.app", "network_flow", authenticated=False)],
        )
        (threat,) = boundaries.analyze(graph)
        assert threat.metadata["flow"]["authenticated"] is False
        assert threat.stride_category == "spoofing"
        assert threat.severity == Severity.HIGH
        assert "Authenticate the caller" in threat.mitigation
