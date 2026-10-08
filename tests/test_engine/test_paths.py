"""The attack path phase: directed paths from the internet to the data, and what enables them.

Most tests build a small graph by hand, add the directed edges the reachability pass would add
and hand the phase findings of their own, so a path exists or not for the one reason under test.
The last classes run whole inputs.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from tests.helpers.scan import FIXTURES_DIR, scan_files, scan_real_shape
from threatcode.engine import paths
from threatcode.engine.mitre import PATH_TECHNIQUES, TECHNIQUE_DB, is_deprecated, is_revoked
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import INTERNET_ID
from threatcode.models.attack_path import AttackPath, attack_path_id
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.parsers.base import ParsedOutput, ParsedResource

REALISTIC = FIXTURES_DIR / "realistic"


# ---------------------------------------------------------------------------------------
# Building blocks
# ---------------------------------------------------------------------------------------


def res(resource_type: str, label: str, **properties: Any) -> ParsedResource:
    name = label
    return ParsedResource(
        resource_type, f"{resource_type}.{name}", name, resource_type.split("_", 1)[0],
        properties=properties,
    )  # fmt: skip


def graph_of(*resources: ParsedResource) -> InfraGraph:
    return InfraGraph.from_parsed(ParsedOutput(resources=list(resources)))


def derive(graph: InfraGraph, node_id: str, **facts: Any) -> None:
    """Set the derived facts of a node, which enrichment owns and a parsed property cannot carry."""
    graph.nodes[node_id].properties["derived"] = facts


def flow(
    graph: InfraGraph,
    source: str,
    target: str,
    *,
    edge_type: EdgeType = EdgeType.NETWORK_FLOW,
    ports: Iterable[str] = ("443",),
    world_open: bool = False,
    definite: bool = True,
    kind: str = "sg_rule",
    via: Iterable[str] = (),
    relation: str = "",
) -> None:
    if source == INTERNET_ID:
        graph.ensure_internet_node()
    graph.add_reachability_edge(
        source,
        target,
        edge_type,
        kind=kind,
        via=via,
        protocol="tcp",
        ports=ports,
        world_open=world_open or source == INTERNET_ID,
        definite=definite,
        relation=relation,
    )


def bind(graph: InfraGraph, source: str, target: str, relation: str, **attributes: Any) -> None:
    graph.add_edge(source, target, EdgeType.IAM_BINDING, attributes or None, relation=relation)


_counter = 0


def finding(
    address: str,
    severity: Severity = Severity.MEDIUM,
    *,
    stride: str = "information_disclosure",
    source: ThreatSource = ThreatSource.RULE,
    rule_id: str = "R",
    effective: Severity | None = None,
) -> Threat:
    global _counter
    _counter += 1
    return Threat(
        id=f"t{_counter:04d}",
        title=f"finding {_counter}",
        description="d",
        stride_category=stride,
        severity=severity,
        source=source,
        resource_type=address.split(".")[0],
        resource_address=address,
        rule_id=rule_id,
        effective_severity=effective,
    )


LB = "aws_lb.front"
APP = "aws_instance.app"
DB = "aws_db_instance.db"
BUCKET = "aws_s3_bucket.data"
ROLE = "aws_iam_role.app"
PROFILE = "aws_iam_instance_profile.app"


def web_stack() -> InfraGraph:
    """internet -> load balancer -> app -> database, and the app's role may read a bucket."""
    graph = graph_of(
        res("aws_lb", "front"),
        res("aws_instance", "app"),
        res("aws_db_instance", "db"),
        res("aws_s3_bucket", "data"),
        res("aws_iam_role", "app"),
        res("aws_iam_instance_profile", "app"),
    )
    flow(graph, INTERNET_ID, LB, world_open=True, via=["aws_security_group.alb"])
    flow(graph, LB, APP, ports=["8080"])
    flow(graph, APP, DB, ports=["5432"])
    bind(graph, APP, PROFILE, "instance_profile")
    bind(graph, PROFILE, ROLE, "assumes")
    bind(graph, ROLE, BUCKET, "permission", actions=["s3:GetObject"], access="read")
    return graph


def node_ids(path: AttackPath) -> list[str]:
    return path.node_ids


def by_target(found: list[AttackPath]) -> dict[str, AttackPath]:
    return {p.target: p for p in found}


# ---------------------------------------------------------------------------------------
# What a path is
# ---------------------------------------------------------------------------------------


class TestPathsFollowDirectedReachability:
    def test_a_directed_chain_gives_one_path_with_the_right_hops(self) -> None:
        graph = web_stack()
        enabler = finding(APP, Severity.HIGH)
        found = paths.find(graph, [enabler])
        path = by_target(found)[DB]
        assert node_ids(path) == [INTERNET_ID, LB, APP, DB]
        assert (path.entry, path.target) == (INTERNET_ID, DB)
        assert path.id == attack_path_id(node_ids(path))
        first = path.hops[0]
        assert first.edge_type_to_next == "network_flow"
        assert first.via["ports"] == ["443"] and first.via["world_open"] is True
        assert first.via["via"] == ["aws_security_group.alb"]
        assert path.hops[-1].edge_type_to_next is None

    def test_a_hub_joined_only_by_containment_gives_no_path(self) -> None:
        graph = graph_of(
            res("aws_vpc", "main"),
            res("aws_subnet", "public"),
            res("aws_subnet", "private"),
            res("aws_lb", "front"),
            res("aws_db_instance", "db"),
        )
        graph.add_edge("aws_subnet.public", "aws_vpc.main", EdgeType.CONTAINMENT)
        graph.add_edge("aws_subnet.private", "aws_vpc.main", EdgeType.CONTAINMENT)
        graph.add_edge(LB, "aws_subnet.public", EdgeType.CONTAINMENT)
        graph.add_edge(DB, "aws_subnet.private", EdgeType.CONTAINMENT)
        flow(graph, INTERNET_ID, LB)
        threats = [finding(LB, Severity.HIGH), finding(DB, Severity.HIGH), finding("aws_vpc.main")]
        assert paths.find(graph, threats) == []

    def test_the_direction_of_an_edge_is_respected(self) -> None:
        graph = graph_of(res("aws_lb", "front"), res("aws_instance", "app"),
                         res("aws_db_instance", "db"))  # fmt: skip
        flow(graph, INTERNET_ID, LB)
        flow(graph, LB, APP)
        flow(graph, DB, APP)  # the database calls the app, nothing calls the database
        assert paths.find(graph, [finding(DB, Severity.HIGH), finding(APP)]) == []
        flow(graph, APP, DB)
        (path,) = paths.find(graph, [finding(DB, Severity.HIGH)])
        assert node_ids(path) == [INTERNET_ID, LB, APP, DB]

    def test_a_path_is_not_found_through_an_edge_that_only_looks_like_one(self) -> None:
        """A structural edge between the app and the database is not a way to reach it."""
        graph = graph_of(res("aws_lb", "front"), res("aws_instance", "app"),
                         res("aws_db_instance", "db"))  # fmt: skip
        flow(graph, INTERNET_ID, LB)
        flow(graph, LB, APP)
        graph.add_edge(APP, DB, EdgeType.DEPENDENCY)
        graph.add_edge(APP, DB, EdgeType.CONTAINMENT)
        assert paths.find(graph, [finding(DB, Severity.HIGH), finding(APP)]) == []

    def test_a_cycle_does_not_hang_or_repeat_a_node(self) -> None:
        graph = web_stack()
        flow(graph, APP, LB)  # the app calls back into the load balancer
        flow(graph, DB, APP)
        found = paths.find(graph, [finding(APP, Severity.HIGH)])
        assert found
        for path in found:
            assert len(set(node_ids(path))) == len(node_ids(path))

    def test_without_an_internet_node_the_exposed_nodes_are_the_entries(self) -> None:
        graph = graph_of(res("aws_lb", "front"), res("aws_instance", "app"),
                         res("aws_db_instance", "db"))  # fmt: skip
        assert graph.internet_node is None
        graph.nodes[LB].exposure = "internet"  # type: ignore[index]
        flow(graph, LB, APP)
        flow(graph, APP, DB)
        (path,) = paths.find(graph, [finding(DB, Severity.HIGH)])
        assert (path.entry, node_ids(path)) == (LB, [LB, APP, DB])

    def test_a_graph_with_nothing_exposed_has_no_path(self) -> None:
        graph = graph_of(res("aws_instance", "app"), res("aws_db_instance", "db"))
        flow(graph, APP, DB)
        assert paths.find(graph, [finding(DB, Severity.CRITICAL)]) == []

    def test_a_path_ends_at_the_first_crown_jewel_it_reaches(self) -> None:
        graph = graph_of(res("aws_lb", "front"), res("aws_db_instance", "db"),
                         res("aws_s3_bucket", "data"))  # fmt: skip
        flow(graph, INTERNET_ID, LB)
        flow(graph, LB, DB)
        flow(graph, DB, BUCKET)
        found = paths.find(graph, [finding(DB), finding(BUCKET)])
        assert [node_ids(p) for p in found] == [[INTERNET_ID, LB, DB]]


class TestCrownJewels:
    def kind(self, graph: InfraGraph, node_id: str) -> str:
        return paths.crown_jewel_kind(graph, graph.nodes[node_id])

    def test_data_stores_and_secret_stores(self) -> None:
        graph = graph_of(
            res("aws_db_instance", "db"),
            res("aws_s3_bucket", "data"),
            res("aws_secretsmanager_secret", "s"),
            res("aws_kms_key", "k"),
            res("aws_dynamodb_table", "t"),
        )
        assert self.kind(graph, DB) == "data store"
        assert self.kind(graph, BUCKET) == "data store"
        assert self.kind(graph, "aws_secretsmanager_secret.s") == "secret store"
        assert self.kind(graph, "aws_kms_key.k") == "secret store"
        assert self.kind(graph, "aws_dynamodb_table.t") == "data store"

    @pytest.mark.parametrize(
        ("resource_type", "name"),
        [
            ("aws_cloudwatch_log_group", "logs"),
            ("aws_vpc", "main"),
            ("aws_subnet", "s"),
            ("aws_instance", "app"),
            ("aws_lb", "front"),
            ("aws_s3_bucket_policy", "data"),
            ("aws_s3_bucket_public_access_block", "data"),
            ("aws_secretsmanager_secret_rotation", "s"),
            ("kubernetes_config_map", "settings"),
            ("kubernetes_namespace", "prod"),
            ("dockerfile_instruction", "run"),
            ("dockerfile_copy", "app"),
            ("dockerfile_add", "archive"),
        ],
    )
    def test_monitoring_networks_compute_and_companions_are_never_targets(
        self, resource_type: str, name: str
    ) -> None:
        graph = graph_of(res(resource_type, name))
        assert self.kind(graph, f"{resource_type}.{name}") == ""

    def test_a_role_that_may_do_everything_is_an_administrator_identity(self) -> None:
        everything = {"effect": "Allow", "actions": ["*"], "resources": ["*"]}
        graph = graph_of(
            res("aws_iam_role", "admin"),
            res("aws_iam_role", "scoped"),
            res("aws_iam_role", "managed"),
            res("aws_iam_role", "none"),
        )
        derive(graph, "aws_iam_role.admin", inline_policy_statements=[everything])
        derive(
            graph,
            "aws_iam_role.scoped",
            inline_policy_statements=[
                {"effect": "Allow", "actions": ["s3:*"], "resources": ["*"]},
                {"effect": "Allow", "actions": ["*"], "resources": ["arn:aws:s3:::x/*"]},
                {**everything, "effect": "Deny"},
                {**everything, "has_condition": True},
            ],
        )
        derive(
            graph,
            "aws_iam_role.managed",
            attached_policy_arns=["arn:aws:iam::aws:policy/AdministratorAccess"],
        )
        assert self.kind(graph, "aws_iam_role.admin") == "administrator identity"
        assert self.kind(graph, "aws_iam_role.managed") == "administrator identity"
        assert self.kind(graph, "aws_iam_role.scoped") == ""
        assert self.kind(graph, "aws_iam_role.none") == ""

    def test_a_policy_the_role_holds_counts_too(self) -> None:
        graph = graph_of(res("aws_iam_role", "r"), res("aws_iam_policy", "p"))
        derive(
            graph,
            "aws_iam_policy.p",
            policy_statements=[{"effect": "Allow", "actions": ["*"], "resources": ["*"]}],
        )
        derive(graph, "aws_iam_role.r")
        bind(graph, "aws_iam_role.r", "aws_iam_policy.p", "has_policy")
        assert self.kind(graph, "aws_iam_role.r") == "administrator identity"

    def test_kubernetes_secrets_cluster_admin_bindings_and_wildcard_roles(self) -> None:
        graph = graph_of(
            res("kubernetes_secret", "s", namespace="a", name="s"),
            res("kubernetes_cluster_role_binding", "root", role_ref_name="cluster-admin"),
            res("kubernetes_cluster_role_binding", "view", role_ref_name="view"),
            res(
                "kubernetes_cluster_role",
                "all",
                has_wildcard_verbs=True,
                has_wildcard_resources=True,
            ),
            res("kubernetes_cluster_role", "verbs", has_wildcard_verbs=True),
        )
        assert self.kind(graph, "kubernetes_secret.s") == "secret store"
        assert self.kind(graph, "kubernetes_cluster_role_binding.root") == "cluster-admin grant"
        assert self.kind(graph, "kubernetes_cluster_role_binding.view") == ""
        assert self.kind(graph, "kubernetes_cluster_role.all") == "cluster-admin grant"
        assert self.kind(graph, "kubernetes_cluster_role.verbs") == ""

    def test_mcp_servers_that_read_private_data_or_credential_paths(self) -> None:
        graph = graph_of(
            res("mcp_server", "files", capability_tags=["reads_private_data"]),
            res("mcp_server", "keys", exposes_sensitive_paths=True),
            res("mcp_server", "web", capability_tags=["ingests_untrusted_content"]),
            res("mcp_server", "off", capability_tags=["reads_private_data"], disabled=True),
        )
        assert self.kind(graph, "mcp_server.files") == "private data"
        assert self.kind(graph, "mcp_server.keys") == "private data"
        assert self.kind(graph, "mcp_server.web") == ""
        assert self.kind(graph, "mcp_server.off") == ""

    def test_the_internet_node_is_not_a_target(self) -> None:
        graph = web_stack()
        assert self.kind(graph, INTERNET_ID) == ""

    def test_an_administrator_role_is_reached_through_the_instance_that_runs_as_it(self) -> None:
        graph = graph_of(
            res("aws_lb", "front"), res("aws_instance", "app"), res("aws_iam_role", "app")
        )
        derive(
            graph,
            ROLE,
            inline_policy_statements=[{"effect": "Allow", "actions": ["*"], "resources": ["*"]}],
        )
        flow(graph, INTERNET_ID, LB)
        flow(graph, LB, APP)
        bind(graph, APP, ROLE, "assumes")
        (path,) = paths.find(graph, [finding(APP, Severity.HIGH, stride="elevation_of_privilege")])
        assert node_ids(path) == [INTERNET_ID, LB, APP, ROLE]


class TestWhatIsNotFollowed:
    def stack(self, holder: ParsedResource) -> InfraGraph:
        graph = graph_of(holder, res("aws_iam_role", "r"), res("aws_s3_bucket", "data"))
        flow(graph, INTERNET_ID, f"{holder.resource_type}.{holder.name}")
        bind(graph, f"{holder.resource_type}.{holder.name}", "aws_iam_role.r", "assumes")
        bind(graph, "aws_iam_role.r", BUCKET, "permission", access="read")
        return graph

    def test_code_that_runs_as_a_role_hands_the_role_to_whoever_reaches_it(self) -> None:
        graph = self.stack(res("aws_lambda_function", "fn"))
        (path,) = paths.find(graph, [finding("aws_lambda_function.fn", Severity.HIGH)])
        assert node_ids(path) == [INTERNET_ID, "aws_lambda_function.fn", "aws_iam_role.r", BUCKET]

    @pytest.mark.parametrize(
        "holder",
        [
            res("aws_eks_cluster", "k"),
            res("aws_lb", "l"),
            res("aws_cloudfront_distribution", "c"),
        ],
    )
    def test_a_resource_that_does_not_run_code_does_not(self, holder: ParsedResource) -> None:
        graph = self.stack(holder)
        address = f"{holder.resource_type}.{holder.name}"
        assert paths.find(graph, [finding(address, Severity.CRITICAL), finding(BUCKET)]) == []

    def test_a_policy_attachment_is_not_authority_to_whoever_reaches_the_role(self) -> None:
        graph = graph_of(res("aws_lb", "front"), res("aws_iam_role", "app"),
                         res("aws_iam_policy", "p"), res("aws_s3_bucket", "data"))  # fmt: skip
        flow(graph, INTERNET_ID, LB)
        flow(graph, LB, ROLE)  # a (wrong) way to reach the role
        bind(graph, ROLE, "aws_iam_policy.p", "has_policy")
        bind(graph, "aws_iam_policy.p", BUCKET, "resource_policy")
        assert paths.find(graph, [finding(LB), finding(BUCKET)]) == []


# ---------------------------------------------------------------------------------------
# Enabling findings
# ---------------------------------------------------------------------------------------


class TestEnablingFindings:
    def test_an_architecture_with_nothing_wrong_on_the_way_has_no_path(self) -> None:
        assert paths.find(web_stack(), []) == []

    def test_a_finding_on_the_target_alone_keeps_the_path(self) -> None:
        found = paths.find(web_stack(), [finding(DB, Severity.LOW)])
        assert node_ids(by_target(found)[DB]) == [INTERNET_ID, LB, APP, DB]

    def test_a_finding_on_a_hop_enables_that_hop(self) -> None:
        threat = finding(APP)
        path = by_target(paths.find(web_stack(), [threat]))[DB]
        assert [hop.enabled_by for hop in path.hops] == [[], [], [threat.id], []]

    def test_a_finding_on_the_group_that_admits_the_traffic_enables_the_hop_it_names(self) -> None:
        threat = finding("aws_security_group.alb", Severity.LOW)
        path = by_target(paths.find(web_stack(), [threat]))[DB]
        assert [hop.enabled_by for hop in path.hops] == [[threat.id], [], [], []]

    def test_a_finding_on_the_edge_source_enables_the_edge(self) -> None:
        threat = finding(LB)
        path = by_target(paths.find(web_stack(), [threat]))[DB]
        assert path.hops[1].enabled_by == [threat.id]

    def test_a_finding_elsewhere_in_the_graph_enables_nothing(self) -> None:
        assert paths.find(web_stack(), [finding("aws_vpc.main", Severity.CRITICAL)]) == []

    @pytest.mark.parametrize("stride", ["repudiation", "denial_of_service"])
    def test_findings_that_do_not_help_an_attacker_move_are_not_enabling(self, stride: str) -> None:
        graph = web_stack()
        threats = [finding(node, Severity.HIGH, stride=stride) for node in (LB, APP, DB)]
        assert paths.find(graph, threats) == []
        assert paths.find(graph, [*threats, finding(APP, Severity.LOW)])

    def test_an_informational_finding_is_not_enabling(self) -> None:
        assert paths.find(web_stack(), [finding(APP, Severity.INFO)]) == []

    @pytest.mark.parametrize("source", [ThreatSource.BOUNDARY, ThreatSource.LLM])
    def test_boundary_and_llm_findings_are_not_enabling(self, source: ThreatSource) -> None:
        assert paths.find(web_stack(), [finding(APP, Severity.HIGH, source=source)]) == []

    @pytest.mark.parametrize(
        "source", [ThreatSource.RULE, ThreatSource.SECRET, ThreatSource.SCANNER]
    )
    def test_rule_secret_and_scanner_findings_are_(self, source: ThreatSource) -> None:
        assert paths.find(web_stack(), [finding(APP, Severity.HIGH, source=source)])

    def test_the_findings_that_enable_a_path_learn_its_id(self) -> None:
        threat, other, unrelated = finding(APP), finding(LB), finding("aws_vpc.main")
        found = paths.find(web_stack(), [threat, other, unrelated])
        assert found
        assert set(threat.path_ids) == {p.id for p in found}
        assert unrelated.path_ids == []
        assert threat.path_ids == sorted(threat.path_ids)

    def test_a_hop_lists_its_worst_finding_first(self) -> None:
        low, high = finding(APP, Severity.LOW), finding(APP, Severity.HIGH)
        path = by_target(paths.find(web_stack(), [low, high]))[DB]
        assert path.hops[2].enabled_by == [high.id, low.id]


# ---------------------------------------------------------------------------------------
# Severity, score and order
# ---------------------------------------------------------------------------------------


class TestSeverityAndScore:
    def test_the_severity_is_the_worst_enabling_finding(self) -> None:
        threats = [
            finding(LB, Severity.LOW),
            finding(APP, Severity.HIGH),
            finding(DB, Severity.MEDIUM),
        ]
        assert by_target(paths.find(web_stack(), threats))[DB].severity is Severity.HIGH

    def test_the_effective_severity_of_a_finding_is_the_one_that_counts(self) -> None:
        threat = finding(APP, Severity.MEDIUM, effective=Severity.HIGH)
        assert by_target(paths.find(web_stack(), [threat]))[DB].severity is Severity.HIGH

    def test_a_sensitive_target_raises_it_one_level(self) -> None:
        graph = web_stack()
        graph.nodes[DB].properties["tags"] = {"DataClassification": "restricted"}
        graph.nodes[BUCKET].properties["tags"] = {"DataClassification": "public"}
        found = by_target(paths.find(graph, [finding(APP, Severity.MEDIUM)]))
        assert found[DB].severity is Severity.HIGH
        assert found[BUCKET].severity is Severity.MEDIUM

    def test_critical_needs_every_edge_to_be_definite(self) -> None:
        graph = web_stack()
        threat = finding(APP, Severity.CRITICAL)
        assert by_target(paths.find(graph, [threat]))[DB].severity is Severity.CRITICAL
        flow(graph, APP, DB, definite=False)
        assert by_target(paths.find(graph, [threat]))[DB].severity is Severity.HIGH

    def test_an_iam_permission_that_a_wildcard_qualifies_is_not_definite(self) -> None:
        graph = web_stack()
        threat = finding(APP, Severity.CRITICAL)
        assert by_target(paths.find(graph, [threat]))[BUCKET].severity is Severity.CRITICAL
        bind(graph, ROLE, BUCKET, "permission", wildcard=True)
        assert by_target(paths.find(graph, [threat]))[BUCKET].severity is Severity.HIGH

    def test_a_world_open_first_hop_and_a_short_path_score_higher(self) -> None:
        graph = web_stack()
        threats = [finding(APP, Severity.HIGH)]
        found = by_target(paths.find(graph, threats))
        # same severity, so the order is the first hop, then the length: db (3 edges) before
        # the bucket (5 edges)
        assert found[DB].score > found[BUCKET].score
        assert paths.find(graph, threats)[0].target == DB

    def test_a_worse_finding_outranks_a_better_connected_path(self) -> None:
        graph = web_stack()
        threats = [finding(APP, Severity.LOW), finding(BUCKET, Severity.CRITICAL)]
        order = [p.target for p in paths.find(graph, threats)]
        assert order == [BUCKET, DB]

    def test_a_secret_store_or_sensitive_data_adds_to_the_score(self) -> None:
        plain = web_stack()
        tagged = web_stack()
        tagged.nodes[DB].properties["tags"] = {"Compliance": "PCI-DSS"}
        threats = [finding(APP, Severity.MEDIUM)]
        score = by_target(paths.find(plain, threats))[DB].score
        assert by_target(paths.find(tagged, threats))[DB].score > score

    def test_the_rationale_is_one_sentence_naming_the_route_and_the_worst_finding(self) -> None:
        threat = finding(APP, Severity.HIGH)
        threat.title = "App is weak"
        text = by_target(paths.find(web_stack(), [threat]))[DB].rationale
        assert text.startswith("The internet reaches aws_lb.front on tcp/443")
        assert "ends at aws_db_instance.db (data store)" in text
        assert "1 finding enables it, the worst being App is weak (high)" in text
        assert text.count(". ") == 0 and text.endswith(".")


class TestOrderAndIds:
    def test_the_order_and_the_ids_do_not_depend_on_the_order_of_the_input(self) -> None:
        def build(reverse: bool) -> list[tuple[str, float]]:
            resources = [
                res("aws_lb", "front"),
                res("aws_instance", "app"),
                res("aws_db_instance", "db"),
                res("aws_s3_bucket", "data"),
                res("aws_iam_role", "app"),
                res("aws_iam_instance_profile", "app"),
            ]
            graph = graph_of(*(reversed(resources) if reverse else resources))
            edges = [
                (INTERNET_ID, LB),
                (LB, APP),
                (APP, DB),
                (APP, "aws_s3_bucket.data"),
            ]
            for source, target in reversed(edges) if reverse else edges:
                flow(graph, source, target)
            threats = [finding(APP, Severity.HIGH), finding(DB, Severity.HIGH)]
            return [(p.id, p.score) for p in paths.find(graph, threats)]

        assert build(False) == build(True)
        assert len(build(False)) == 2

    def test_two_runs_give_identical_results(self) -> None:
        threats = [finding(APP, Severity.HIGH)]
        first = [p.to_dict() for p in paths.find(web_stack(), threats)]
        second = [p.to_dict() for p in paths.find(web_stack(), threats)]
        assert first == second and first

    def test_ties_are_broken_by_severity_then_length_then_id(self) -> None:
        graph = graph_of(
            res("aws_lb", "front"),
            res("aws_db_instance", "a"),
            res("aws_db_instance", "b"),
        )
        flow(graph, INTERNET_ID, LB)
        flow(graph, LB, "aws_db_instance.a")
        flow(graph, LB, "aws_db_instance.b")
        found = paths.find(graph, [finding(LB, Severity.HIGH)])
        assert [p.score for p in found] == [found[0].score] * 2
        assert [p.id for p in found] == sorted(p.id for p in found)


# ---------------------------------------------------------------------------------------
# The search
# ---------------------------------------------------------------------------------------


def chain(length: int) -> tuple[InfraGraph, list[Threat]]:
    """internet -> n1 -> ... -> n<length> -> database."""
    graph = graph_of(
        *(res("aws_instance", f"n{i}") for i in range(1, length + 1)), res("aws_db_instance", "db")
    )
    previous = INTERNET_ID
    for i in range(1, length + 1):
        flow(graph, previous, f"aws_instance.n{i}")
        previous = f"aws_instance.n{i}"
    flow(graph, previous, DB)
    return graph, [finding(DB, Severity.HIGH)]


class TestSearchLimits:
    def test_a_path_may_have_the_most_edges_the_cutoff_allows(self) -> None:
        graph, threats = chain(paths.MAX_HOPS - 1)  # MAX_HOPS edges
        assert len(paths.find(graph, threats)) == 1

    def test_a_longer_path_is_not_searched_for(self) -> None:
        graph, threats = chain(paths.MAX_HOPS)  # one edge too many
        assert paths.find(graph, threats) == []

    def test_the_cutoff_is_a_module_setting(self, monkeypatch: pytest.MonkeyPatch) -> None:
        graph, threats = chain(3)
        monkeypatch.setattr(paths, "MAX_HOPS", 3)
        assert paths.find(graph, threats) == []
        monkeypatch.setattr(paths, "MAX_HOPS", 4)
        assert len(paths.find(graph, threats)) == 1

    def parallel(self, routes: int) -> tuple[InfraGraph, list[Threat]]:
        graph = graph_of(
            res("aws_lb", "front"),
            *(res("aws_instance", f"app{chr(97 + i)}") for i in range(routes)),
            res("aws_db_instance", "db"),
        )
        flow(graph, INTERNET_ID, LB)
        for i in range(routes):
            name = f"aws_instance.app{chr(97 + i)}"
            flow(graph, LB, name)
            flow(graph, name, DB)
        return graph, [finding(DB, Severity.HIGH)]

    def test_the_routes_to_one_target_are_capped_to_the_best(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        graph, threats = self.parallel(4)
        assert len(paths.find(graph, threats)) == 4
        monkeypatch.setattr(paths, "MAX_PATHS_PER_TARGET", 2)
        found = paths.find(graph, threats)
        assert len(found) == 2

    def test_the_total_number_of_paths_is_capped_and_the_gap_is_recorded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        graph, threats = self.parallel(4)
        monkeypatch.setattr(paths, "MAX_PATHS", 3)
        assert len(paths.find(graph, threats)) == 3
        assert any(d.code == "paths.search_truncated" for d in graph.diagnostics)

    def test_a_search_that_runs_out_of_steps_says_so(self, monkeypatch: pytest.MonkeyPatch) -> None:
        graph, threats = self.parallel(6)
        monkeypatch.setattr(paths, "MAX_VISITS", 5)
        paths.find(graph, threats)
        (gap,) = [d for d in graph.diagnostics if d.code == "paths.search_truncated"]
        assert gap.level == "warning" and "steps" in gap.message

    def test_a_complete_search_records_no_gap(self) -> None:
        graph, threats = self.parallel(3)
        paths.find(graph, threats)
        assert not [d for d in graph.diagnostics if d.code == "paths.search_truncated"]

    def test_candidates_per_target_are_bounded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        graph, threats = self.parallel(5)
        monkeypatch.setattr(paths, "MAX_CANDIDATES_PER_TARGET", 2)
        assert len(paths.find(graph, threats)) == 2
        assert any("routes to" in d.message for d in graph.diagnostics)

    def test_a_path_that_is_a_part_of_a_longer_one_is_dropped(self) -> None:
        """Without an internet node two entries can lie on one route."""
        graph = graph_of(
            res("aws_lb", "front"),
            res(
                "aws_instance",
                "app",
            ),
            res("aws_db_instance", "db"),
            res("aws_instance", "edge"),
        )
        graph.nodes[LB].exposure = "internet"  # type: ignore[index]
        graph.nodes["aws_instance.edge"].exposure = "internet"  # type: ignore[index]
        flow(graph, "aws_instance.edge", LB)
        flow(graph, LB, APP)
        flow(graph, APP, DB)
        found = paths.find(graph, [finding(DB, Severity.HIGH)])
        assert [node_ids(p) for p in found] == [["aws_instance.edge", LB, APP, DB]]


class TestCountedResources:
    def test_routes_through_instances_of_one_counted_resource_are_one_path(self) -> None:
        graph = graph_of(
            res("aws_lb", "front"),
            ParsedResource("aws_instance", "aws_instance.app[0]", "app", "aws"),
            ParsedResource("aws_instance", "aws_instance.app[1]", "app", "aws"),
            ParsedResource("aws_instance", "aws_instance.app[10]", "app", "aws"),
            res("aws_db_instance", "db"),
        )
        flow(graph, INTERNET_ID, LB)
        for index in (0, 1, 10):
            flow(graph, LB, f"aws_instance.app[{index}]")
            flow(graph, f"aws_instance.app[{index}]", DB)
        (path,) = paths.find(graph, [finding(DB, Severity.HIGH)])
        assert node_ids(path) == [INTERNET_ID, LB, "aws_instance.app[0]", DB]
        assert path.alternatives == 2
        assert path.rationale.endswith(
            "2 more routes through other instances of the same resources."
        )
        assert path.to_dict()["alternatives"] == 2

    def test_a_path_says_what_makes_its_target_worth_reaching(self) -> None:
        (path,) = paths.find(web_stack(), [finding(DB, Severity.HIGH)])
        assert path.target_kind == "data store"
        assert path.to_dict()["target_kind"] == "data store"
        assert "ends at aws_db_instance.db (data store)" in path.rationale
        assert "target_kind" not in AttackPath(id="p", entry="a", target="b").to_dict()

    def test_a_path_with_no_equivalent_route_says_nothing_about_alternatives(self) -> None:
        (path,) = paths.find(web_stack(), [finding(DB, Severity.HIGH)])
        assert path.alternatives == 0
        assert "alternatives" not in path.to_dict()

    def test_two_different_resources_are_two_paths(self) -> None:
        graph = graph_of(
            res("aws_lb", "front"),
            res("aws_instance", "blue"),
            res("aws_instance", "green"),
            res("aws_db_instance", "db"),
        )
        flow(graph, INTERNET_ID, LB)
        for name in ("aws_instance.blue", "aws_instance.green"):
            flow(graph, LB, name)
            flow(graph, name, DB)
        assert len(paths.find(graph, [finding(DB, Severity.HIGH)])) == 2


# ---------------------------------------------------------------------------------------
# Techniques
# ---------------------------------------------------------------------------------------


class TestTechniques:
    def test_every_technique_of_the_table_is_current_in_the_attack_database(self) -> None:
        for kind, technique in PATH_TECHNIQUES.items():
            assert technique in TECHNIQUE_DB, kind
            assert not is_revoked(technique) and not is_deprecated(technique), kind

    def test_an_exposed_application_is_initial_access_by_t1190(self) -> None:
        path = by_target(paths.find(web_stack(), [finding(APP)]))[DB]
        assert path.hops[0].techniques == []
        assert path.hops[1].techniques == [PATH_TECHNIQUES["exposed_application"]]

    @pytest.mark.parametrize(
        ("port", "technique"),
        [("22", "T1133"), ("3389", "T1133"), ("443", "T1190"), ("8080", "T1190")],
    )
    def test_an_exposed_remote_administration_port_is_t1133(
        self, port: str, technique: str
    ) -> None:
        graph = graph_of(res("aws_instance", "app"), res("aws_db_instance", "db"))
        flow(graph, INTERNET_ID, APP, ports=[port])
        flow(graph, APP, DB)
        (path,) = paths.find(graph, [finding(APP)])
        assert path.hops[1].techniques == [technique]

    def test_imdsv1_on_a_hop_adds_the_metadata_technique_to_that_hop(self) -> None:
        threat = finding(APP, rule_id="EC2_IMDSV1", stride="elevation_of_privilege")
        path = by_target(paths.find(web_stack(), [threat]))[DB]
        assert PATH_TECHNIQUES["instance_metadata"] in path.hops[2].techniques
        assert PATH_TECHNIQUES["instance_metadata"] not in path.hops[1].techniques
        without = by_target(paths.find(web_stack(), [finding(APP, rule_id="OTHER")]))[DB]
        assert all(PATH_TECHNIQUES["instance_metadata"] not in h.techniques for h in without.hops)

    def test_assuming_a_role_and_reading_a_bucket(self) -> None:
        path = by_target(paths.find(web_stack(), [finding(APP)]))[BUCKET]
        by_hop = {hop.node_id: hop.techniques for hop in path.hops}
        assert by_hop[ROLE] == [PATH_TECHNIQUES["role_assumption"]]
        assert by_hop[BUCKET] == [PATH_TECHNIQUES["cloud_storage_data"]]
        assert by_hop[PROFILE] == []
        assert path.techniques == ["T1190", "T1078.004", "T1530"]

    def test_the_tactics_follow_from_the_techniques(self) -> None:
        path = by_target(paths.find(web_stack(), [finding(APP)]))[BUCKET]
        assert path.tactics == ["TA0001", "TA0003", "TA0004", "TA0005", "TA0009"]

    def test_a_kubernetes_secret_and_a_privileged_container(self) -> None:
        graph = graph_of(
            res("kubernetes_ingress", "web", namespace="a", name="web"),
            res("kubernetes_deployment", "app", namespace="a", name="app", privileged=True),
            res("kubernetes_secret", "s", namespace="a", name="s"),
        )
        ingress, deployment, secret = (
            "kubernetes_ingress.web",
            "kubernetes_deployment.app",
            "kubernetes_secret.s",
        )
        flow(graph, INTERNET_ID, ingress, kind="ingress")
        flow(graph, ingress, deployment, kind="ingress")
        flow(graph, deployment, secret, edge_type=EdgeType.DATA_FLOW, kind="workload", ports=[])
        (path,) = paths.find(graph, [finding(deployment)])
        by_hop = {hop.node_id: hop.techniques for hop in path.hops}
        assert by_hop[ingress] == ["T1190"]
        assert by_hop[deployment] == [PATH_TECHNIQUES["container_escape"]]
        assert by_hop[secret] == [PATH_TECHNIQUES["container_secret"]]

    def test_untrusted_content_reaching_an_agent_and_a_server_that_reads_files(self) -> None:
        graph = graph_of(
            res("mcp_server", "web", capability_tags=["ingests_untrusted_content"]),
            res("mcp_agent", "config"),
            res("mcp_server", "files", capability_tags=["reads_private_data"],
                exposes_sensitive_paths=True),
        )  # fmt: skip
        flow(
            graph,
            INTERNET_ID,
            "mcp_server.web",
            edge_type=EdgeType.DATA_FLOW,
            kind="agent",
            ports=[],
        )
        flow(
            graph,
            "mcp_server.web",
            "mcp_agent.config",
            edge_type=EdgeType.DATA_FLOW,
            kind="",
            ports=[],
        )
        bind(graph, "mcp_agent.config", "mcp_server.files", "invokes")
        (path,) = paths.find(graph, [finding("mcp_server.files", Severity.HIGH)])
        by_hop = {hop.node_id: hop.techniques for hop in path.hops}
        assert by_hop["mcp_server.web"] == [PATH_TECHNIQUES["content_injection"]]
        assert by_hop["mcp_server.files"] == [
            PATH_TECHNIQUES["local_data"],
            PATH_TECHNIQUES["credentials_in_files"],
        ]


# ---------------------------------------------------------------------------------------
# Whole inputs
# ---------------------------------------------------------------------------------------


def paths_of(*relative: str) -> list[AttackPath]:
    return list(scan_files([FIXTURES_DIR / r for r in relative]).report.attack_paths)


class TestWholeInputs:
    def test_the_web_stack_of_the_corpus_reaches_the_database_through_the_load_balancer(
        self,
    ) -> None:
        report = scan_real_shape("terraform/plan/webapp.plan.json").report
        (path,) = report.attack_paths
        assert node_ids(path) == [
            INTERNET_ID,
            "aws_lb.front",
            "aws_instance.app[0]",
            "aws_db_instance.orders",
        ]
        assert path.alternatives == 1

    def test_the_ecommerce_fixture_reaches_both_databases_and_the_public_bucket(self) -> None:
        found = paths_of("realistic/01_aws_ecommerce_platform.json")
        targets = {p.target for p in found}
        assert targets == {
            "aws_db_instance.orders",
            "aws_db_instance.sessions",
            "aws_s3_bucket.product_images",
        }
        assert all(p.entry == INTERNET_ID for p in found)

    def test_a_public_bucket_behind_an_origin_identity_is_reached_directly_not_by_the_cdn(
        self,
    ) -> None:
        # The bucket is open to everyone, so the internet reaches it itself; the distribution reads
        # it through an origin access identity, which is not another way in (RW-07)
        found = {tuple(node_ids(p)) for p in paths_of("realistic/10_aws_gaming_backend.json")}
        assert (INTERNET_ID, "aws_s3_bucket.game_assets") in found
        assert not [path for path in found if "aws_cloudfront_distribution.game_cdn" in path]

    @pytest.mark.parametrize(
        "relative",
        [
            "realistic/07_azure_webapp_java.tf",
            "realistic/09_aws_healthcare_hipaa.yaml",
            "terraform/multi_service_secure.plan.json",
            "cloudformation/secure_stack.yml",
            "kubernetes/secure_deployment.yml",
            "mcp/fixed/.mcp.json",
            "docker/secure.Dockerfile",
        ],
    )
    def test_a_hardened_input_has_no_attack_path(self, relative: str) -> None:
        assert paths_of(relative) == []

    def test_azure_and_gcp_inputs_have_no_topology_so_no_path(self) -> None:
        assert paths_of("realistic/02_azure_kubernetes_cluster.tf") == []

    def test_dockerfile_instructions_are_never_a_target(self) -> None:
        assert paths_of("docker/insecure.Dockerfile") == []

    def test_a_kubernetes_ingress_chain_ends_at_the_cluster_admin_grant(self) -> None:
        (path,) = paths_of("kubernetes/ingress_to_cluster_admin.yml")
        assert path.hops[-1].resource_type == "kubernetes_cluster_role"
        assert "kubernetes_service_account" in {h.resource_type for h in path.hops}

    def test_a_path_is_in_the_serialised_report_with_its_enabling_findings(self) -> None:
        result = scan_real_shape("terraform/plan/webapp.plan.json")
        data = result.report.to_dict()
        (entry,) = data["attack_paths"]
        threat_ids = {t["id"] for t in data["threats"]}
        enabled = [i for hop in entry["hops"] for i in hop["enabled_by"]]
        assert enabled and set(enabled) <= threat_ids
        tagged = {t["id"] for t in data["threats"] if entry["id"] in t.get("path_ids", [])}
        assert tagged == set(enabled)

    def test_the_gate_sees_the_path_severity(self) -> None:
        report = scan_files([REALISTIC / "01_aws_ecommerce_platform.json"]).report
        assert max(p.severity for p in report.attack_paths) >= Severity.HIGH
