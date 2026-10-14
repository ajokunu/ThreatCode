"""The reachability layer: directed edges from a synthetic internet node to what is exposed.

Each family is checked on small inputs written in the format a team writes them in (Terraform
HCL, Kubernetes manifests, an MCP configuration) so the graph the tests read is the graph a scan
builds, and on the real-shape corpus.
Positive controls sit next to every negative case: a test that says a resource is not reachable
first shows that the same input reaches the resource when the one fact that matters is changed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import pytest

from tests.helpers.graph_assert import (
    assert_edge,
    assert_no_edge,
    assert_no_path,
    assert_path,
)
from tests.helpers.scan import ScanResult, scan_files, scan_real_shape, scan_text
from threatcode.ir.edges import (
    REACHABILITY,
    REACHABILITY_SOURCES,
    STRUCTURAL,
    EdgeType,
    InfraEdge,
)
from threatcode.ir.graph import MAX_FANOUT, MAX_FANOUT_ENV, InfraGraph
from threatcode.ir.nodes import INTERNET_ID, NodeCategory, TrustZone
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource

FIXTURES = Path(__file__).parent.parent / "fixtures"
REALISTIC = FIXTURES / "realistic"
REAL_SHAPES = FIXTURES / "real_shapes"

# ---------------------------------------------------------------------------------------
# Terraform building blocks
# ---------------------------------------------------------------------------------------

NETWORK = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_internet_gateway" "gw" { vpc_id = aws_vpc.main.id }
resource "aws_subnet" "pub" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_route_table" "pub" {
  vpc_id = aws_vpc.main.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}
resource "aws_route_table_association" "pub" {
  subnet_id      = aws_subnet.pub.id
  route_table_id = aws_route_table.pub.id
}
resource "aws_subnet" "priv" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
}
resource "aws_route_table" "priv" { vpc_id = aws_vpc.main.id }
resource "aws_route_table_association" "priv" {
  subnet_id      = aws_subnet.priv.id
  route_table_id = aws_route_table.priv.id
}
"""


def hcl(*blocks: str) -> ScanResult:
    return scan_text(NETWORK + "\n".join(blocks), "main.tf")


def group(name: str, *rules: str) -> str:
    body = "\n".join(rules)
    return f'resource "aws_security_group" "{name}" {{\n  vpc_id = aws_vpc.main.id\n{body}\n}}\n'


def ingress(port: int, *, cidr: str = "", source: str = "", protocol: str = "tcp") -> str:
    if cidr:
        target = f'cidr_blocks = ["{cidr}"]'
    elif source:
        target = f"security_groups = [aws_security_group.{source}.id]"
    else:
        target = "self = true"
    return (
        f"  ingress {{\n    from_port = {port}\n    to_port = {port}\n"
        f'    protocol = "{protocol}"\n    {target}\n  }}'
    )


def instance(name: str, subnet: str, *groups: str, public: bool = False) -> str:
    refs = ", ".join(f"aws_security_group.{g}.id" for g in groups)
    flag = "  associate_public_ip_address = true\n" if public else ""
    return (
        f'resource "aws_instance" "{name}" {{\n  ami = "ami-1"\n'
        f"  subnet_id = aws_subnet.{subnet}.id\n  vpc_security_group_ids = [{refs}]\n{flag}}}\n"
    )


def reachability_edges(graph: InfraGraph) -> list[InfraEdge]:
    return [e for e in graph.edges if e.edge_type in REACHABILITY]


def edge_between(graph: InfraGraph, source: str, target: str) -> InfraEdge:
    (edge,) = [
        e
        for e in graph.edges
        if (e.source, e.target) == (source, target) and e.edge_type in REACHABILITY
    ]
    return edge


# ---------------------------------------------------------------------------------------
# The internet node
# ---------------------------------------------------------------------------------------


class TestInternetNode:
    def test_a_graph_that_nothing_exposes_has_no_internet_node(self) -> None:
        graph = hcl(
            group("db", ingress(5432, cidr="10.0.0.0/16")),
            instance("db", "priv", "db"),
        ).graph
        assert INTERNET_ID not in graph.nodes
        assert graph.internet_node is None
        assert not [e for e in graph.edges if e.source == INTERNET_ID]

    def test_it_is_created_when_an_edge_starts_there(self) -> None:
        graph = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")),
            instance("web", "pub", "web", public=True),
        ).graph
        node = graph.internet_node
        assert node is not None
        assert (node.id, node.resource_type) == (INTERNET_ID, "internet")
        assert node.is_internet and node.is_synthetic
        assert node.trust_zone is TrustZone.INTERNET
        assert node.category is NodeCategory.NETWORK
        assert node.exposure == "internet"

    def test_it_is_a_context_node_so_it_is_not_scanned_and_no_rule_runs_on_it(self) -> None:
        result = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")),
            instance("web", "pub", "web", public=True),
        )
        assert result.graph.nodes[INTERNET_ID].mode == "data"
        assert result.report.scanned_resources == result.graph.node_count
        assert result.threats_for(INTERNET_ID) == []

    def test_node_count_does_not_count_it(self) -> None:
        result = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")),
            instance("web", "pub", "web", public=True),
        )
        assert len(result.graph.nodes) == result.graph.node_count + 1

    def test_ensure_internet_node_is_idempotent(self) -> None:
        graph = InfraGraph.from_parsed(ParsedOutput(resources=[]))
        assert graph.internet_node is None
        first = graph.ensure_internet_node()
        assert graph.ensure_internet_node() is first
        assert graph.node_count == 0

    def test_a_declared_node_named_internet_is_the_internet_node(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("design_actor", "internet", "internet", "design"),
                ParsedResource("aws_s3_bucket", "aws_s3_bucket.b", "b", "aws"),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        declared = graph.internet_node
        assert declared is not None and declared.resource_type == "design_actor"
        assert declared.is_internet and not declared.is_synthetic
        assert graph.ensure_internet_node() is declared
        assert graph.node_count == 2  # the declared node is the input's, so it is counted


# ---------------------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------------------


class TestWorldOpenGroups:
    def test_a_world_open_group_gives_internet_to_instance_with_its_ports(self) -> None:
        graph = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")),
            instance("web", "pub", "web", public=True),
        ).graph
        edge = edge_between(graph, INTERNET_ID, "aws_instance.web")
        assert edge.edge_type is EdgeType.NETWORK_FLOW
        assert edge.ports == ["22"] and edge.protocols == ["tcp"]
        assert edge.source_kind == "sg_rule" and edge.world_open and edge.definite
        assert edge.attributes["via"] == ["aws_security_group.web"]

    def test_the_same_group_on_an_instance_in_a_private_subnet_is_not_reachable(self) -> None:
        open_group = group("web", ingress(22, cidr="0.0.0.0/0"))
        reachable = hcl(open_group, instance("web", "pub", "web", public=True)).graph
        assert_path(reachable, INTERNET_ID, "aws_instance.web", ["network_flow"])
        hidden = hcl(open_group, instance("web", "priv", "web")).graph
        assert "aws_instance.web" in hidden.nodes
        assert_no_edge(hidden, INTERNET_ID, "aws_instance.web")
        assert INTERNET_ID not in hidden.nodes

    def test_a_public_subnet_without_a_public_address_is_not_reachable(self) -> None:
        graph = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")), instance("web", "pub", "web")
        ).graph
        assert_no_edge(graph, INTERNET_ID, "aws_instance.web")

    def test_a_group_open_to_a_private_range_gives_no_internet_edge(self) -> None:
        graph = hcl(
            group("web", ingress(22, cidr="10.0.0.0/8")),
            instance("web", "pub", "web", public=True),
        ).graph
        assert INTERNET_ID not in graph.nodes

    def test_an_ipv6_world_range_counts(self) -> None:
        rule = (
            '  ingress {\n    from_port = 443\n    to_port = 443\n    protocol = "tcp"\n'
            '    ipv6_cidr_blocks = ["::/0"]\n  }'
        )
        graph = hcl(group("web", rule), instance("web", "pub", "web", public=True)).graph
        assert edge_between(graph, INTERNET_ID, "aws_instance.web").ports == ["443"]

    def test_only_the_attached_resources_are_reached(self) -> None:
        graph = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")),
            group("other", ingress(22, cidr="10.0.0.0/8")),
            instance("web", "pub", "web", public=True),
            instance("other", "pub", "other", public=True),
        ).graph
        assert_edge(graph, INTERNET_ID, "aws_instance.web")
        assert_no_edge(graph, INTERNET_ID, "aws_instance.other")

    def test_two_rules_of_one_group_merge_their_ports_into_one_edge(self) -> None:
        graph = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0"), ingress(443, cidr="0.0.0.0/0")),
            instance("web", "pub", "web", public=True),
        ).graph
        assert edge_between(graph, INTERNET_ID, "aws_instance.web").ports == ["22", "443"]

    def test_a_protocol_of_all_traffic_is_all_ports(self) -> None:
        rule = (
            '  ingress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }'
        )
        graph = hcl(group("web", rule), instance("web", "pub", "web", public=True)).graph
        edge = edge_between(graph, INTERNET_ID, "aws_instance.web")
        assert edge.protocols == ["all"] and edge.ports == ["0-65535"]

    def test_a_port_range_is_kept_as_a_range(self) -> None:
        rule = (
            '  ingress {\n    from_port = 8000\n    to_port = 8100\n    protocol = "tcp"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }'
        )
        graph = hcl(group("web", rule), instance("web", "pub", "web", public=True)).graph
        assert edge_between(graph, INTERNET_ID, "aws_instance.web").ports == ["8000-8100"]

    def test_an_unknown_port_still_gives_the_edge_but_not_a_definite_one(self) -> None:
        rule = (
            "  ingress {\n    from_port = var.port\n    to_port = var.port\n"
            '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }'
        )
        graph = hcl(group("web", rule), instance("web", "pub", "web", public=True)).graph
        edge = edge_between(graph, INTERNET_ID, "aws_instance.web")
        assert edge.ports == [] and not edge.definite


class TestGroupToGroup:
    CHAIN = (
        group("alb", ingress(443, cidr="0.0.0.0/0")),
        group("app", ingress(8080, source="alb")),
        group("db", ingress(5432, source="app")),
    )

    def chain_graph(self) -> InfraGraph:
        return hcl(
            *self.CHAIN,
            instance("alb", "pub", "alb", public=True),
            instance("app", "priv", "app"),
            instance("db", "priv", "db"),
        ).graph

    def test_a_reference_to_another_group_gives_edges_from_its_members_with_the_port(self) -> None:
        graph = self.chain_graph()
        edge = edge_between(graph, "aws_instance.alb", "aws_instance.app")
        assert (edge.ports, edge.protocols, edge.world_open) == (["8080"], ["tcp"], False)
        assert edge.attributes["via"] == ["aws_security_group.app", "aws_security_group.alb"]
        assert edge_between(graph, "aws_instance.app", "aws_instance.db").ports == ["5432"]

    def test_the_chain_is_a_directed_path_from_the_internet_to_the_database(self) -> None:
        graph = self.chain_graph()
        assert assert_path(graph, INTERNET_ID, "aws_instance.db", ["network_flow"]) == [
            INTERNET_ID,
            "aws_instance.alb",
            "aws_instance.app",
            "aws_instance.db",
        ]

    def test_nothing_runs_backwards(self) -> None:
        graph = self.chain_graph()
        assert_no_edge(graph, "aws_instance.db", "aws_instance.app")
        assert_no_edge(graph, "aws_instance.app", "aws_instance.alb")
        assert_no_path(graph, "aws_instance.db", "aws_instance.alb", ["network_flow"])
        assert_no_edge(graph, "aws_instance.alb", "aws_instance.db")  # no skipping a tier

    def test_the_database_is_not_reached_directly_from_the_internet(self) -> None:
        assert_no_edge(self.chain_graph(), INTERNET_ID, "aws_instance.db")

    def test_a_self_reference_lets_the_members_reach_each_other(self) -> None:
        graph = hcl(
            group("ring", ingress(7000, protocol="tcp")),
            instance("a", "priv", "ring"),
            instance("b", "priv", "ring"),
        ).graph
        assert edge_between(graph, "aws_instance.a", "aws_instance.b").ports == ["7000"]
        assert edge_between(graph, "aws_instance.b", "aws_instance.a").ports == ["7000"]

    def test_egress_rules_add_nothing(self) -> None:
        egress = (
            '  egress {\n    from_port = 0\n    to_port = 0\n    protocol = "-1"\n'
            '    cidr_blocks = ["0.0.0.0/0"]\n  }'
        )
        graph = hcl(
            group("a", egress),
            group("b", ingress(80, cidr="10.0.0.0/8")),
            instance("a", "priv", "a"),
            instance("b", "priv", "b"),
        ).graph
        assert not reachability_edges(graph)

    def test_a_function_can_send_to_a_group_but_never_receive_from_one(self) -> None:
        function = (
            'resource "aws_lambda_function" "fn" {\n  function_name = "fn"\n'
            '  role = "arn:aws:iam::1:role/x"\n  handler = "h"\n  runtime = "python3.12"\n'
            "  vpc_config {\n    subnet_ids = [aws_subnet.priv.id]\n"
            "    security_group_ids = [aws_security_group.fn.id]\n  }\n}\n"
        )
        graph = hcl(
            group("fn"),
            group("db", ingress(5432, source="fn")),
            group("back", ingress(443, source="db")),
            function,
            instance("db", "priv", "db"),
            instance("back", "priv", "back"),
        ).graph
        assert_edge(graph, "aws_lambda_function.fn", "aws_instance.db", type="network_flow")
        # `back` admits the database group, never the function, and nothing sends to a function
        assert_no_edge(graph, "aws_instance.db", "aws_lambda_function.fn")
        assert_no_edge(graph, "aws_lambda_function.fn", "aws_instance.back")


class TestRuleShapesAreEquivalent:
    """Nested blocks, standalone rule resources and the v5 rule resources give one graph."""

    BASE = (
        group("alb", ingress(443, cidr="0.0.0.0/0")),
        'resource "aws_security_group" "app" {\n  vpc_id = aws_vpc.main.id\n}\n',
        instance("alb", "pub", "alb", public=True),
        instance("app", "priv", "app"),
    )

    def edges(self, rule: str) -> set[tuple[str, str, tuple[str, ...]]]:
        graph = hcl(*self.BASE, rule).graph
        return {(e.source, e.target, tuple(e.ports)) for e in reachability_edges(graph)}

    def test_nested_standalone_and_v5_rules_produce_the_same_reachability(self) -> None:
        standalone = (
            'resource "aws_security_group_rule" "from_alb" {\n  type = "ingress"\n'
            "  security_group_id = aws_security_group.app.id\n"
            "  source_security_group_id = aws_security_group.alb.id\n"
            '  from_port = 8080\n  to_port = 8080\n  protocol = "tcp"\n}\n'
        )
        v5 = (
            'resource "aws_vpc_security_group_ingress_rule" "from_alb" {\n'
            "  security_group_id = aws_security_group.app.id\n"
            "  referenced_security_group_id = aws_security_group.alb.id\n"
            '  from_port = 8080\n  to_port = 8080\n  ip_protocol = "tcp"\n}\n'
        )
        inline_graph = hcl(
            group("alb", ingress(443, cidr="0.0.0.0/0")),
            group("app", ingress(8080, source="alb")),
            instance("alb", "pub", "alb", public=True),
            instance("app", "priv", "app"),
        ).graph
        inline = {(e.source, e.target, tuple(e.ports)) for e in reachability_edges(inline_graph)}
        assert ("aws_instance.alb", "aws_instance.app", ("8080",)) in inline
        assert self.edges(standalone) == inline
        assert self.edges(v5) == inline


# ---------------------------------------------------------------------------------------
# Load balancers
# ---------------------------------------------------------------------------------------

LOAD_BALANCER = """
resource "aws_lb" "front" {
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.pub.id]
}
resource "aws_lb_target_group" "app" {
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.front.arn
  port              = 443
  protocol          = "HTTPS"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
resource "aws_lb_target_group_attachment" "app" {
  target_group_arn = aws_lb_target_group.app.arn
  target_id        = aws_instance.app.id
}
"""


class TestLoadBalancers:
    def web(self, lb: str = LOAD_BALANCER) -> InfraGraph:
        return hcl(
            group("alb", ingress(443, cidr="0.0.0.0/0")),
            group("app", ingress(8080, source="alb")),
            instance("app", "priv", "app"),
            lb,
        ).graph

    def test_an_internet_facing_load_balancer_is_entered_from_the_internet(self) -> None:
        graph = self.web()
        edge = edge_between(graph, INTERNET_ID, "aws_lb.front")
        assert (edge.ports, edge.attributes["via"]) == (["443"], ["aws_security_group.alb"])

    def test_it_reaches_the_registered_target_on_the_target_group_port(self) -> None:
        graph = self.web()
        edge = edge_between(graph, "aws_lb.front", "aws_instance.app")
        assert edge.ports == ["8080"]
        assert {"sg_rule", "lb_listener"} == set(edge.attributes["sources"])
        assert "aws_lb_listener.https" in edge.attributes["via"]
        assert_path(graph, INTERNET_ID, "aws_instance.app", ["network_flow"])

    def test_an_internal_load_balancer_is_not_reachable_from_the_internet(self) -> None:
        internal = LOAD_BALANCER.replace("internal           = false", "internal = true")
        graph = self.web(internal)
        assert graph.nodes["aws_lb.front"].exposure == "internal"
        assert_no_edge(graph, INTERNET_ID, "aws_lb.front")
        assert INTERNET_ID not in graph.nodes
        # the load balancer still reaches its target, so the walk has edges to follow
        assert_edge(graph, "aws_lb.front", "aws_instance.app", type="network_flow")

    def test_a_security_group_that_does_not_admit_the_world_keeps_the_internet_out(self) -> None:
        graph = hcl(
            group("alb", ingress(443, cidr="10.0.0.0/8")),
            group("app", ingress(8080, source="alb")),
            instance("app", "priv", "app"),
            LOAD_BALANCER,
        ).graph
        assert graph.nodes["aws_lb.front"].exposure == "internet"
        assert_no_edge(graph, INTERNET_ID, "aws_lb.front")

    def test_a_network_load_balancer_without_a_group_admits_the_listener_ports(self) -> None:
        nlb = """
resource "aws_lb" "nlb" {
  internal           = false
  load_balancer_type = "network"
  subnets            = [aws_subnet.pub.id]
}
resource "aws_lb_listener" "tcp" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 5000
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.t.arn
  }
}
resource "aws_lb_target_group" "t" {
  port     = 5000
  protocol = "TCP"
  vpc_id   = aws_vpc.main.id
}
"""
        graph = hcl(nlb).graph
        edge = edge_between(graph, INTERNET_ID, "aws_lb.nlb")
        assert edge.ports == ["5000"] and edge.source_kind == "lb_listener"

    def test_an_auto_scaling_group_and_an_ecs_service_are_targets_too(self) -> None:
        extra = """
resource "aws_autoscaling_group" "workers" {
  min_size            = 1
  max_size            = 3
  vpc_zone_identifier = [aws_subnet.priv.id]
  target_group_arns   = [aws_lb_target_group.app.arn]
}
resource "aws_ecs_service" "api" {
  name            = "api"
  task_definition = "api:1"
  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "api"
    container_port   = 8080
  }
}
"""
        graph = self.web(LOAD_BALANCER + extra)
        assert_edge(graph, "aws_lb.front", "aws_autoscaling_group.workers", type="network_flow")
        assert_edge(graph, "aws_lb.front", "aws_ecs_service.api", type="network_flow")

    def test_a_listener_rule_forwards_to_its_own_target_group(self) -> None:
        extra = """
resource "aws_lb_target_group" "admin" {
  port     = 9000
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}
resource "aws_instance" "admin" {
  ami = "ami-2"
  subnet_id = aws_subnet.priv.id
}
resource "aws_lb_listener_rule" "admin" {
  listener_arn = aws_lb_listener.https.arn
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.admin.arn
  }
}
resource "aws_lb_target_group_attachment" "admin" {
  target_group_arn = aws_lb_target_group.admin.arn
  target_id        = aws_instance.admin.id
}
"""
        graph = self.web(LOAD_BALANCER + extra)
        assert edge_between(graph, "aws_lb.front", "aws_instance.admin").ports == ["9000"]

    def test_inline_targets_of_a_template_are_followed(self) -> None:
        graph = scan_real_shape("cloudformation/web_stack.json").graph
        assert_edge(graph, "LoadBalancer", "AppInstance", type="network_flow")
        assert_path(graph, INTERNET_ID, "Database", ["network_flow"])

    def test_the_real_shape_plan_resolves_its_references(self) -> None:
        graph = scan_real_shape("terraform/plan/webapp.plan.json").graph
        assert_edge(graph, INTERNET_ID, "aws_lb.front", type="network_flow", source="sg_rule")
        assert_edge(graph, "aws_lb.front", "aws_instance.app[0]", type="network_flow")


# ---------------------------------------------------------------------------------------
# Managed endpoints
# ---------------------------------------------------------------------------------------


class TestManagedEndpoints:
    def test_a_public_bucket_is_entered_from_the_internet(self) -> None:
        public = """
resource "aws_s3_bucket" "site" { bucket = "site" }
resource "aws_s3_bucket_acl" "site" {
  bucket = aws_s3_bucket.site.id
  acl    = "public-read"
}
"""
        graph = scan_text(public, "main.tf").graph
        edge = edge_between(graph, INTERNET_ID, "aws_s3_bucket.site")
        assert edge.source_kind == "public_endpoint" and edge.world_open

    def test_a_private_bucket_is_not(self) -> None:
        graph = scan_text('resource "aws_s3_bucket" "site" { bucket = "site" }', "main.tf").graph
        assert INTERNET_ID not in graph.nodes

    def test_cloudfront_reaches_its_s3_origin(self) -> None:
        text = """
resource "aws_s3_bucket" "assets" { bucket = "assets" }
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_id   = "assets"
  }
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_edge(graph, INTERNET_ID, "aws_cloudfront_distribution.cdn")
        edge = edge_between(graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.assets")
        assert edge.source_kind == "cdn_origin"
        assert_path(graph, INTERNET_ID, "aws_s3_bucket.assets", ["network_flow"])

    ORIGIN = """
resource "aws_s3_bucket" "assets" { bucket = "acme-assets" }
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = aws_s3_bucket.assets.bucket_regional_domain_name
    origin_id   = "assets"
    %s
  }
}
"""

    @pytest.mark.parametrize(
        "access",
        [
            'origin_access_control_id = "E2OAC123456789"',
            "origin_access_control_id = aws_cloudfront_origin_access_control.assets.id",
            's3_origin_config { origin_access_identity = "origin-access-identity/cloudfront/E1" }',
        ],
        ids=["oac", "oac-reference", "oai"],
    )
    def test_a_bucket_read_through_an_access_control_is_not_reached_from_the_internet(
        self, access: str
    ) -> None:
        graph = scan_text(self.ORIGIN % access, "main.tf").graph
        assert_edge(graph, INTERNET_ID, "aws_cloudfront_distribution.cdn")
        assert_no_edge(
            graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.assets", type="network_flow"
        )
        assert_no_path(graph, INTERNET_ID, "aws_s3_bucket.assets", ["network_flow"])

    @pytest.mark.parametrize(
        "access",
        [
            "",
            'origin_access_control_id = ""',
            's3_origin_config { origin_access_identity = "" }',
        ],
        ids=["none", "empty-oac", "empty-oai"],
    )
    def test_an_origin_with_no_access_control_is_still_reached(self, access: str) -> None:
        graph = scan_text(self.ORIGIN % access, "main.tf").graph
        assert_edge(graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.assets")

    def test_a_bucket_named_by_its_s3_domain_and_read_through_an_oac_is_not_reached(self) -> None:
        text = """
resource "aws_s3_bucket" "assets" { bucket = "acme-assets" }
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name              = "acme-assets.s3.us-east-1.amazonaws.com"
    origin_id                = "assets"
    origin_access_control_id = "E2OAC123456789"
  }
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_no_edge(
            graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.assets", type="network_flow"
        )

    def test_a_public_bucket_behind_an_access_control_keeps_its_own_edge(self) -> None:
        text = self.ORIGIN % 'origin_access_control_id = "E2OAC123456789"'
        text += """
resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "public-read"
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_edge(graph, INTERNET_ID, "aws_s3_bucket.assets")
        assert_no_edge(
            graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.assets", type="network_flow"
        )

    def test_an_access_control_on_one_origin_does_not_hide_another(self) -> None:
        text = """
resource "aws_s3_bucket" "private" { bucket = "acme-private" }
resource "aws_s3_bucket" "open" { bucket = "acme-open" }
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name              = aws_s3_bucket.private.bucket_regional_domain_name
    origin_id                = "private"
    origin_access_control_id = "E2OAC123456789"
  }
  origin {
    domain_name = aws_s3_bucket.open.bucket_regional_domain_name
    origin_id   = "open"
  }
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_no_edge(
            graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.private", type="network_flow"
        )
        assert_edge(graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.open")

    CFN = """\
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Content:
    Type: AWS::S3::Bucket
  Oac:
    Type: AWS::CloudFront::OriginAccessControl
    Properties:
      OriginAccessControlConfig:
        Name: oac
        OriginAccessControlOriginType: s3
        SigningBehavior: always
        SigningProtocol: sigv4
  Distribution:
    Type: AWS::CloudFront::Distribution
    Properties:
      DistributionConfig:
        Enabled: true
        DefaultCacheBehavior:
          TargetOriginId: content
          ViewerProtocolPolicy: redirect-to-https
        Origins:
          - Id: content
            DomainName: !GetAtt Content.RegionalDomainName
            %s
"""

    def test_a_template_origin_with_an_access_control_is_not_reached(self) -> None:
        text = self.CFN % (
            "OriginAccessControlId: !GetAtt Oac.Id\n"
            '            S3OriginConfig:\n              OriginAccessIdentity: ""'
        )
        graph = scan_text(text, "stack.yaml").graph
        assert_edge(graph, INTERNET_ID, "Distribution")
        assert_no_edge(graph, "Distribution", "Content", type="network_flow")

    def test_a_template_origin_with_only_an_empty_identity_is_reached(self) -> None:
        text = self.CFN % 'S3OriginConfig:\n              OriginAccessIdentity: ""'
        graph = scan_text(text, "stack.yaml").graph
        assert_edge(graph, "Distribution", "Content")

    def test_an_origin_named_by_its_s3_domain_is_found(self) -> None:
        text = """
resource "aws_s3_bucket" "assets" { bucket = "acme-assets" }
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "acme-assets.s3.us-east-1.amazonaws.com"
    origin_id   = "assets"
  }
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_edge(graph, "aws_cloudfront_distribution.cdn", "aws_s3_bucket.assets")

    def test_an_origin_that_names_no_node_adds_no_edge(self) -> None:
        text = """
resource "aws_cloudfront_distribution" "cdn" {
  enabled = true
  origin {
    domain_name = "origin.example.com"
    origin_id   = "custom"
  }
}
"""
        graph = scan_text(text, "main.tf").graph
        assert [e.target for e in reachability_edges(graph)] == ["aws_cloudfront_distribution.cdn"]

    URL = """
resource "aws_lambda_function" "fn" {
  function_name = "fn"
  role          = "arn:aws:iam::1:role/x"
  handler       = "h"
  runtime       = "python3.12"
}
resource "aws_lambda_function_url" "url" {
  function_name      = aws_lambda_function.fn.function_name
  authorization_type = "%s"
}
"""

    def test_a_function_url_without_authentication_reaches_its_function(self) -> None:
        graph = scan_text(self.URL % "NONE", "main.tf").graph
        assert_edge(graph, INTERNET_ID, "aws_lambda_function_url.url", type="network_flow")
        assert assert_path(graph, INTERNET_ID, "aws_lambda_function.fn", ["network_flow"]) == [
            INTERNET_ID,
            "aws_lambda_function_url.url",
            "aws_lambda_function.fn",
        ]

    def test_a_function_url_with_iam_authentication_is_not_entered(self) -> None:
        graph = scan_text(self.URL % "AWS_IAM", "main.tf").graph
        assert INTERNET_ID not in graph.nodes

    def test_an_api_reaches_the_function_its_integration_names(self) -> None:
        text = """
resource "aws_api_gateway_rest_api" "api" { name = "api" }
resource "aws_lambda_function" "fn" {
  function_name = "fn"
  role          = "arn:aws:iam::1:role/x"
  handler       = "h"
  runtime       = "python3.12"
}
resource "aws_api_gateway_integration" "fn" {
  rest_api_id = aws_api_gateway_rest_api.api.id
  resource_id = "r"
  http_method = "GET"
  type        = "AWS_PROXY"
  uri         = aws_lambda_function.fn.invoke_arn
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_edge(graph, INTERNET_ID, "aws_api_gateway_rest_api.api")
        edge = edge_between(graph, "aws_api_gateway_rest_api.api", "aws_lambda_function.fn")
        assert edge.source_kind == "api_integration"
        assert edge.attributes["via"] == ["aws_api_gateway_integration.fn"]

    def test_sam_permissions_join_the_api_to_the_function(self) -> None:
        graph = scan_files([FIXTURES / "cloudformation" / "sam_function.yaml"]).graph
        assert_path(graph, INTERNET_ID, "AdminFunction", ["network_flow"])

    def test_a_public_eks_endpoint_is_entered_from_the_internet(self) -> None:
        text = """
resource "aws_eks_cluster" "k" {
  name     = "k"
  role_arn = "arn:aws:iam::1:role/eks"
  vpc_config {
    subnet_ids              = ["subnet-1"]
    endpoint_public_access  = true
    endpoint_private_access = false
  }
}
"""
        graph = scan_text(text, "main.tf").graph
        assert edge_between(graph, INTERNET_ID, "aws_eks_cluster.k").ports == ["443"]


class TestIdentitiesAreRunByWhatRunsThem:
    def test_a_group_launches_the_instances_of_its_template_and_a_service_runs_its_task(
        self,
    ) -> None:
        text = """
resource "aws_launch_template" "lt" { name = "lt" }
resource "aws_autoscaling_group" "asg" {
  min_size = 1
  max_size = 2
  launch_template { id = aws_launch_template.lt.id }
}
resource "aws_ecs_task_definition" "task" { family = "task" }
resource "aws_ecs_service" "svc" {
  name            = "svc"
  task_definition = aws_ecs_task_definition.task.arn
}
"""
        graph = scan_text(text, "main.tf").graph
        assert_edge(graph, "aws_autoscaling_group.asg", "aws_launch_template.lt", relation="runs")
        assert_edge(graph, "aws_ecs_service.svc", "aws_ecs_task_definition.task", relation="runs")

    def test_a_task_definition_written_as_an_interpolation_string_is_found(self) -> None:
        graph = scan_files([REALISTIC / "04_aws_java_microservices.json"]).graph
        assert_edge(
            graph,
            "aws_ecs_service.user_service",
            "aws_ecs_task_definition.user_service",
            type="iam_binding",
            relation="runs",
        )
        assert_path(
            graph,
            "aws_ecs_service.user_service",
            "aws_iam_role.user_service_task_role",
            ["iam_binding"],
        )


# ---------------------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------------------

INGRESS = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {name: web, namespace: shop}
spec:
  tls: [{hosts: [shop.example.com], secretName: tls}]
  rules:
    - host: shop.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend: {service: {name: web, port: {number: 80}}}
"""
SERVICE = """
apiVersion: v1
kind: Service
metadata: {name: web, namespace: shop}
spec:
  type: %s
  selector: {app: web}
  ports: [{port: 80, targetPort: 8080}]
"""
DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: shop}
spec:
  selector: {matchLabels: {app: web}}
  template:
    metadata: {labels: {app: web}}
    spec:
      serviceAccountName: web
      containers:
        - name: web
          image: registry.example.com/shop/web:1.2.3
          env:
            - name: TOKEN
              valueFrom: {secretKeyRef: {name: token, key: value}}
"""
SECRET = """
apiVersion: v1
kind: Secret
metadata: {name: token, namespace: shop}
stringData: {value: x}
"""
OTHER_SECRET = """
apiVersion: v1
kind: Secret
metadata: {name: token, namespace: billing}
stringData: {value: y}
"""
ACCOUNT = """
apiVersion: v1
kind: ServiceAccount
metadata: {name: web, namespace: shop}
"""


def manifests(tmp_path: Path, **files: str) -> ScanResult:
    """Scan each document as a file of its own: the parser links one input only."""
    paths = []
    for name, text in files.items():
        path = tmp_path / f"{name}.yaml"
        path.write_text(text, encoding="utf-8")
        paths.append(path)
    return scan_files(paths)


class TestKubernetesFlows:
    def stack(self, tmp_path: Path, service_type: str = "ClusterIP") -> InfraGraph:
        return manifests(
            tmp_path,
            ingress=INGRESS,
            service=SERVICE % service_type,
            deployment=DEPLOYMENT,
            secret=SECRET,
            account=ACCOUNT,
        ).graph

    def test_an_ingress_with_rules_is_entered_from_the_internet_on_https(
        self, tmp_path: Path
    ) -> None:
        edge = edge_between(self.stack(tmp_path), INTERNET_ID, "kubernetes_ingress.shop.web")
        assert (edge.ports, edge.protocols, edge.source_kind) == (["443"], ["https"], "ingress")

    def test_the_flows_join_manifests_that_live_in_different_files(self, tmp_path: Path) -> None:
        graph = self.stack(tmp_path)
        assert assert_path(
            graph, INTERNET_ID, "kubernetes_secret.shop.token", ["network_flow", "data_flow"]
        ) == [
            INTERNET_ID,
            "kubernetes_ingress.shop.web",
            "kubernetes_service.shop.web",
            "kubernetes_deployment.shop.web",
            "kubernetes_secret.shop.token",
        ]
        backend = edge_between(graph, "kubernetes_ingress.shop.web", "kubernetes_service.shop.web")
        assert backend.relation == "backend" and backend.ports == ["80"]
        selects = edge_between(
            graph, "kubernetes_service.shop.web", "kubernetes_deployment.shop.web"
        )
        assert selects.relation == "selects" and selects.ports == ["8080"]

    def test_a_cluster_ip_service_is_not_entered_but_a_load_balancer_and_a_node_port_are(
        self, tmp_path: Path
    ) -> None:
        for service_type, entered in (
            ("ClusterIP", False),
            ("LoadBalancer", True),
            ("NodePort", True),
        ):
            graph = self.stack(tmp_path, service_type)
            has_edge = any(
                e.source == INTERNET_ID and e.target == "kubernetes_service.shop.web"
                for e in graph.edges
            )
            assert has_edge is entered, service_type

    def test_the_service_reaches_only_workloads_of_its_namespace_that_carry_its_labels(
        self, tmp_path: Path
    ) -> None:
        elsewhere = DEPLOYMENT.replace("namespace: shop", "namespace: billing")
        unlabeled = DEPLOYMENT.replace("{app: web}", "{app: other}").replace(
            "name: web, namespace", "name: other, namespace"
        )
        graph = manifests(
            tmp_path,
            service=SERVICE % "ClusterIP",
            deployment=DEPLOYMENT,
            billing=elsewhere,
            other=unlabeled,
        ).graph
        assert_edge(graph, "kubernetes_service.shop.web", "kubernetes_deployment.shop.web")
        assert_no_edge(graph, "kubernetes_service.shop.web", "kubernetes_deployment.billing.web")
        assert_no_edge(graph, "kubernetes_service.shop.web", "kubernetes_deployment.shop.other")

    def test_a_workload_reads_the_secret_of_its_own_namespace_only(self, tmp_path: Path) -> None:
        graph = manifests(tmp_path, deployment=DEPLOYMENT, secret=SECRET, other=OTHER_SECRET).graph
        edge = edge_between(graph, "kubernetes_deployment.shop.web", "kubernetes_secret.shop.token")
        assert edge.edge_type is EdgeType.DATA_FLOW and edge.relation == "reads_secret"
        assert_no_edge(graph, "kubernetes_deployment.shop.web", "kubernetes_secret.billing.token")

    def test_a_missing_service_account_adds_no_edge(self, tmp_path: Path) -> None:
        graph = manifests(tmp_path, deployment=DEPLOYMENT).graph
        assert [e for e in graph.edges if e.relation == "runs_as"] == []


ROLE = """
apiVersion: rbac.authorization.k8s.io/v1
kind: %s
metadata: {name: reader%s}
rules:
  - {apiGroups: [""], resources: [secrets], verbs: [get, list]}
"""
BINDING = """
apiVersion: rbac.authorization.k8s.io/v1
kind: %s
metadata: {name: reader-binding%s}
subjects: [{kind: ServiceAccount, name: web, namespace: shop}]
roleRef: {kind: %s, name: reader, apiGroup: rbac.authorization.k8s.io}
"""


class TestKubernetesRbac:
    def rbac(self, tmp_path: Path, role: str, binding: str, namespace: str = "shop") -> InfraGraph:
        return manifests(
            tmp_path,
            account=ACCOUNT,
            deployment=DEPLOYMENT,
            secret=SECRET,
            other=OTHER_SECRET,
            role=role,
            binding=binding,
        ).graph

    def cluster(self, tmp_path: Path) -> InfraGraph:
        return self.rbac(
            tmp_path,
            ROLE % ("ClusterRole", ""),
            BINDING % ("ClusterRoleBinding", "", "ClusterRole"),
        )

    def test_the_service_account_holds_the_role_its_binding_grants(self, tmp_path: Path) -> None:
        graph = self.cluster(tmp_path)
        edge = edge_between(
            graph, "kubernetes_service_account.shop.web", "kubernetes_cluster_role.reader"
        )
        assert edge.relation == "bound_role" and edge.attributes["via"] == [
            "kubernetes_cluster_role_binding.reader-binding"
        ]

    def test_a_cluster_role_binding_reaches_the_secrets_of_every_namespace(
        self, tmp_path: Path
    ) -> None:
        graph = self.cluster(tmp_path)
        for secret in ("kubernetes_secret.shop.token", "kubernetes_secret.billing.token"):
            edge = edge_between(graph, "kubernetes_cluster_role.reader", secret)
            assert edge.relation == "permission"
            assert edge.attributes["actions"] == ["secrets:get", "secrets:list"]
            assert edge.attributes["access"] == "read"

    def test_a_role_binding_reaches_the_secrets_of_its_namespace_only(self, tmp_path: Path) -> None:
        graph = self.rbac(
            tmp_path,
            ROLE % ("ClusterRole", ""),
            (BINDING % ("RoleBinding", "", "ClusterRole")).replace(
                "metadata: {name: reader-binding}",
                "metadata: {name: reader-binding, namespace: shop}",
            ),
        )
        assert_edge(graph, "kubernetes_cluster_role.reader", "kubernetes_secret.shop.token")
        assert_no_edge(graph, "kubernetes_cluster_role.reader", "kubernetes_secret.billing.token")

    def test_the_walk_from_the_workload_through_its_account_and_role_to_the_secret(
        self, tmp_path: Path
    ) -> None:
        graph = self.cluster(tmp_path)
        path = assert_path(
            graph, "kubernetes_deployment.shop.web", "kubernetes_secret.billing.token"
        )
        assert path == [
            "kubernetes_deployment.shop.web",
            "kubernetes_service_account.shop.web",
            "kubernetes_cluster_role.reader",
            "kubernetes_secret.billing.token",
        ]

    def test_a_role_nobody_is_bound_to_reaches_nothing(self, tmp_path: Path) -> None:
        graph = manifests(tmp_path, secret=SECRET, role=ROLE % ("ClusterRole", "")).graph
        assert not [e for e in graph.edges if e.relation == "permission"]

    def test_a_role_that_cannot_read_secrets_reaches_none(self, tmp_path: Path) -> None:
        pods_only = (ROLE % ("ClusterRole", "")).replace("secrets", "pods")
        graph = self.rbac(tmp_path, pods_only, BINDING % ("ClusterRoleBinding", "", "ClusterRole"))
        assert_edge(graph, "kubernetes_service_account.shop.web", "kubernetes_cluster_role.reader")
        assert not [e for e in graph.edges if e.relation == "permission"]

    def test_a_binding_to_the_builtin_cluster_admin_role_is_reached_itself(
        self, tmp_path: Path
    ) -> None:
        binding = (BINDING % ("ClusterRoleBinding", "", "ClusterRole")).replace(
            "name: reader, apiGroup", "name: cluster-admin, apiGroup"
        )
        graph = manifests(tmp_path, account=ACCOUNT, binding=binding).graph
        edge = edge_between(
            graph,
            "kubernetes_service_account.shop.web",
            "kubernetes_cluster_role_binding.reader-binding",
        )
        assert edge.relation == "bound_role"

    def test_malformed_rules_and_labels_do_not_stop_the_pass(self, tmp_path: Path) -> None:
        broken = ROLE % ("ClusterRole", "") + "  - {resources: 5, verbs: oops}\n"
        graph = self.rbac(tmp_path, broken, BINDING % ("ClusterRoleBinding", "", "ClusterRole"))
        assert_edge(graph, "kubernetes_cluster_role.reader", "kubernetes_secret.shop.token")


# ---------------------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------------------


def mcp(servers: dict[str, Any], tmp_path: Path) -> InfraGraph:
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return scan_files([path]).graph


FETCH = {"command": "uvx", "args": ["mcp-server-fetch"]}
FILES = {
    "command": "npx",
    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/Users/dev"],
}
REMOTE = {"type": "http", "url": "https://tools.example.com/mcp"}


class TestMcpEntry:
    def test_a_server_that_ingests_untrusted_content_is_entered_from_the_internet(
        self, tmp_path: Path
    ) -> None:
        graph = mcp({"fetch": FETCH, "files": FILES}, tmp_path)
        edge = edge_between(graph, INTERNET_ID, "mcp_server.fetch")
        assert edge.edge_type is EdgeType.DATA_FLOW
        assert (edge.source_kind, edge.relation, edge.world_open) == (
            "agent",
            "untrusted_content",
            True,
        )
        assert_no_edge(graph, INTERNET_ID, "mcp_server.files")

    def test_untrusted_content_reaches_the_server_that_reads_private_data_through_the_agent(
        self, tmp_path: Path
    ) -> None:
        graph = mcp({"fetch": FETCH, "files": FILES}, tmp_path)
        assert assert_path(graph, INTERNET_ID, "mcp_server.files") == [
            INTERNET_ID,
            "mcp_server.fetch",
            "mcp_agent.config",
            "mcp_server.files",
        ]

    def test_without_a_server_that_ingests_content_nothing_reaches_the_files(
        self, tmp_path: Path
    ) -> None:
        graph = mcp({"files": FILES}, tmp_path)
        assert INTERNET_ID not in graph.nodes

    def test_a_remote_server_is_entered_but_not_definitely(self, tmp_path: Path) -> None:
        graph = mcp({"remote": REMOTE, "files": FILES}, tmp_path)
        edge = edge_between(graph, INTERNET_ID, "mcp_server.remote")
        assert edge.relation == "remote_server"
        assert not edge.definite and edge.protocols == ["https"]

    def test_a_disabled_server_is_not_entered(self, tmp_path: Path) -> None:
        graph = mcp({"fetch": {**FETCH, "disabled": True}, "files": FILES}, tmp_path)
        assert INTERNET_ID not in graph.nodes


# ---------------------------------------------------------------------------------------
# The edge classes and the subgraph
# ---------------------------------------------------------------------------------------


class TestEdgeClasses:
    def test_structural_and_reachability_edge_types_do_not_overlap(self) -> None:
        assert STRUCTURAL.isdisjoint(REACHABILITY)
        assert STRUCTURAL | REACHABILITY == set(EdgeType)

    def test_the_pass_only_writes_known_sources_and_reachability_types(self) -> None:
        result = scan_real_shape("terraform/plan/webapp.plan.json")
        sources = {
            e.attributes["source"]
            for e in result.graph.edges
            if "source" in e.attributes and e.attributes.get("world_open") is not None
        }
        assert sources and sources <= REACHABILITY_SOURCES
        for edge in result.graph.edges:
            if edge.source == INTERNET_ID:
                assert edge.edge_type in REACHABILITY

    def test_the_subgraph_holds_the_internet_and_only_directed_reachability_edges(self) -> None:
        graph = TestGroupToGroup().chain_graph()
        view = graph.reachability_subgraph()
        assert isinstance(view, nx.DiGraph)
        assert INTERNET_ID in view
        assert nx.has_path(view, INTERNET_ID, "aws_instance.db")
        assert not nx.has_path(view, "aws_instance.db", INTERNET_ID)
        kinds = {k for _u, _v, k in view.edges(keys=True)}
        assert kinds <= {t.value for t in REACHABILITY}

    def test_containment_alone_never_joins_two_nodes(self) -> None:
        """A public subnet and a private one in one VPC are not connected by the VPC."""
        graph = hcl(
            group("web", ingress(22, cidr="0.0.0.0/0")),
            instance("web", "pub", "web", public=True),
            instance("db", "priv", "web"),
        ).graph
        view = graph.reachability_subgraph()
        assert nx.has_path(view, INTERNET_ID, "aws_instance.web")
        assert not nx.has_path(view, INTERNET_ID, "aws_subnet.priv")
        assert not nx.has_path(view, INTERNET_ID, "aws_vpc.main")

    def test_two_vpcs_with_no_connection_have_no_path_between_them(self) -> None:
        graph = scan_real_shape("terraform/plan/two_vpcs.plan.json").graph
        assert_no_path(graph, "aws_instance.prod", "aws_instance.dev", ["network_flow"])
        assert_no_path(graph, "aws_instance.dev", "aws_instance.prod", ["network_flow"])


class TestAddReachabilityEdge:
    def graph(self) -> InfraGraph:
        return InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    ParsedResource("aws_instance", "aws_instance.a", "a", "aws"),
                    ParsedResource("aws_instance", "aws_instance.b", "b", "aws"),
                ]
            )
        )

    def add(self, graph: InfraGraph, **kwargs: Any) -> InfraEdge:
        defaults: dict[str, Any] = {"kind": "sg_rule"}
        graph.add_reachability_edge(
            "aws_instance.a", "aws_instance.b", EdgeType.NETWORK_FLOW, **{**defaults, **kwargs}
        )
        return edge_between(graph, "aws_instance.a", "aws_instance.b")

    def test_a_second_fact_about_the_pair_merges_into_the_edge(self) -> None:
        graph = self.graph()
        self.add(graph, ports=["443"], protocol="tcp", via=["sg.a"])
        edge = self.add(graph, kind="lb_listener", ports=["80", "443"], protocol="udp", via=["lb"])
        assert len(reachability_edges(graph)) == 1
        assert edge.ports == ["80", "443"]
        assert edge.attributes["via"] == ["sg.a", "lb"]
        assert edge.attributes["source"] == "sg_rule"
        assert edge.attributes["sources"] == ["sg_rule", "lb_listener"]
        assert edge.protocols == ["tcp", "udp"]

    def test_world_open_is_true_if_either_is_and_definite_false_if_either_is(self) -> None:
        graph = self.graph()
        self.add(graph, world_open=True, definite=True)
        edge = self.add(graph, world_open=False, definite=False)
        assert edge.world_open and not edge.definite
        again = self.add(graph, definite=True)
        assert not again.definite  # a later sure fact does not make an unsure edge sure

    def test_what_a_parser_stated_is_not_overwritten(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    ParsedResource("aws_instance", "aws_instance.a", "a", "aws"),
                    ParsedResource("aws_instance", "aws_instance.b", "b", "aws"),
                ],
                edges=[
                    ParsedEdge(
                        "aws_instance.a",
                        "aws_instance.b",
                        "network_flow",
                        {"protocol": "grpc", "authenticated": True},
                    )
                ],
            )
        )
        edge = self.add(graph, protocol="tcp", ports=["9000"])
        assert edge.attributes["protocol"] == "grpc"
        assert edge.protocols == ["grpc", "tcp"]
        assert edge.attributes["authenticated"] is True

    def test_extra_attributes_never_replace_existing_ones(self) -> None:
        graph = self.graph()
        self.add(graph, extra={"access": "read", "note": "first"})
        edge = self.add(graph, extra={"access": "admin", "other": 1})
        assert (edge.attributes["access"], edge.attributes["other"]) == ("read", 1)

    def test_an_unknown_endpoint_is_an_error(self) -> None:
        from threatcode.exceptions import ThreatCodeError

        graph = self.graph()
        with pytest.raises(ThreatCodeError, match="unknown node"):
            graph.add_reachability_edge(
                "aws_instance.a", "nope", EdgeType.NETWORK_FLOW, kind="sg_rule"
            )


# ---------------------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------------------


def wide_rule(senders: int, receivers: int) -> str:
    blocks = [group("src"), group("dst", ingress(80, source="src"))]
    for i in range(senders):
        blocks.append(instance(f"s{i}", "priv", "src"))
    for i in range(receivers):
        blocks.append(instance(f"r{i}", "priv", "dst"))
    return "\n".join(blocks)


class TestFanOutCap:
    def test_a_rule_adds_at_most_the_limit_and_the_graph_says_so(self) -> None:
        parsed = scan_text(NETWORK + wide_rule(6, 6), "main.tf").parsed
        graph = InfraGraph.from_units(parsed, max_fanout=10)
        edges = [e for e in reachability_edges(graph) if e.source.startswith("aws_instance.s")]
        assert len(edges) == 10
        (gap,) = [d for d in graph.diagnostics if d.code == "graph.edge_cap"]
        assert gap.level == "warning"
        assert "fan-out limit of 10" in gap.message and "aws_security_group.dst" in gap.message
        assert "(+26)" in gap.message

    def test_under_the_limit_there_is_no_diagnostic(self) -> None:
        parsed = scan_text(NETWORK + wide_rule(3, 3), "main.tf").parsed
        graph = InfraGraph.from_units(parsed, max_fanout=10)
        assert [d for d in graph.diagnostics if d.code == "graph.edge_cap"] == []
        assert (
            len([e for e in reachability_edges(graph) if e.source.startswith("aws_instance.s")])
            == 9
        )

    def test_the_default_is_five_hundred_and_the_environment_overrides_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        parsed = scan_text(NETWORK + wide_rule(2, 2), "main.tf").parsed
        assert InfraGraph.from_units(parsed).max_fanout == MAX_FANOUT == 500
        monkeypatch.setenv(MAX_FANOUT_ENV, "3")
        graph = InfraGraph.from_units(parsed)
        assert graph.max_fanout == 3
        assert any(d.code == "graph.edge_cap" for d in graph.diagnostics)

    def test_a_limit_below_one_is_refused(self) -> None:
        from threatcode.exceptions import ThreatCodeError

        with pytest.raises(ThreatCodeError, match="max_fanout"):
            InfraGraph(max_fanout=0)

    def test_the_edge_limit_of_the_graph_still_applies(self) -> None:
        parsed = scan_text(NETWORK + wide_rule(4, 4), "main.tf").parsed
        graph = InfraGraph.from_units(parsed, max_edges=1000)
        full = len(graph.edges)
        small = InfraGraph.from_units(parsed, max_edges=full - 3)
        assert len(small.edges) == full - 3
        assert any(
            d.code == "graph.edge_cap" and "Edge limit" in d.message for d in small.diagnostics
        )


class TestDeterminism:
    def test_two_builds_of_one_input_give_the_same_reachability_edges(self) -> None:
        def snapshot() -> list[tuple[str, str, str, str]]:
            graph = scan_real_shape("terraform/plan/webapp.plan.json").graph
            return [
                (e.source, e.target, e.edge_type.value, json.dumps(e.attributes, sort_keys=True))
                for e in reachability_edges(graph)
            ]

        assert snapshot() == snapshot()
        fresh = scan_files([REAL_SHAPES / "terraform" / "plan" / "webapp.plan.json"]).graph
        assert [
            (e.source, e.target, e.edge_type.value, json.dumps(e.attributes, sort_keys=True))
            for e in reachability_edges(fresh)
        ] == snapshot()
