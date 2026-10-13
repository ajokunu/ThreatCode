"""Tests for the Mermaid formats: the graph by trust zone and the attack path flowchart."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.helpers.scan import scan_files
from threatcode.formatters import render
from threatcode.formatters.mermaid import (
    MAX_EDGES,
    MAX_NODES,
    attack_path_flowchart,
    format_mermaid,
    mermaid_label,
)
from threatcode.ir.graph import InfraGraph
from threatcode.models.analysis import AnalysisResult
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

LABEL = r'"[^"<>`\[\]{}|\\\n]*"'
DASH = r"(,stroke-dasharray:\d \d)?"
GRAMMAR = [
    re.compile(r"^flowchart TB$"),
    # Comments carry fixed wording only: no input text can reach one
    re.compile(r"^  %% [A-Za-z0-9 .,:()'-]+$"),
    re.compile(rf"^  subgraph z\d+\[{LABEL}\]$"),
    re.compile(rf"^    n\d+\[{LABEL}\]$"),
    re.compile(r"^  end$"),
    re.compile(rf"^  n\d+ (-->|-\.->|==>|<-->|<-\.->)(\|{LABEL}\|)? n\d+$"),
    re.compile(rf"^  linkStyle \d+(,\d+)* stroke:#[0-9a-f]{{6}},stroke-width:\d+px{DASH}$"),
    re.compile(
        rf"^  classDef (entry|target|onpath|alt) stroke:#[0-9a-f]{{6}},stroke-width:\dpx{DASH}$"
    ),
    re.compile(r"^  class n\d+(,n\d+)* (entry|target|onpath|alt)$"),
    re.compile(rf"^  n1\[{LABEL}\]$"),
]


def assert_mermaid_grammar(text: str) -> None:
    """Every line is one of the statements the formatter writes; nothing else can be injected."""
    lines = text.rstrip("\n").split("\n")
    assert lines[0] == "flowchart TB"
    for line in lines:
        assert any(g.match(line) for g in GRAMMAR), f"unexpected Mermaid line: {line!r}"


def resource(rtype: str, name: str, zone: str | None = None) -> ParsedResource:
    return ParsedResource(
        resource_type=rtype,
        name=name,
        provider="aws",
        address=f"{rtype}.{name}",
        source_location="main.tf",
        start_line=1,
        trust_zone=zone,
    )


def graph_of(
    resources: list[ParsedResource], edges: list[tuple[str, str, str]] | None = None
) -> InfraGraph:
    return InfraGraph.from_parsed(
        ParsedOutput(
            source_path="main.tf",
            format_type="terraform_hcl",
            resources=resources,
            edges=[ParsedEdge(source=s, target=t, edge_type=e) for s, t, e in edges or []],
        )
    )


def path_of(*node_ids: str, zones: tuple[str, ...] | None = None) -> AttackPath:
    zones = zones or tuple("dmz" for _ in node_ids)
    hops = [
        AttackHop(
            node_id=n, zone=z, edge_type_to_next="network_flow" if i < len(node_ids) - 1 else None
        )
        for i, (n, z) in enumerate(zip(node_ids, zones, strict=True))
    ]
    return AttackPath(
        id="0123456789ab",
        entry=node_ids[0],
        target=node_ids[-1],
        hops=hops,
        severity=Severity.CRITICAL,
    )


class TestAttackPathFlowchart:
    def test_zones_are_subgraphs_and_hops_are_thick_edges(self) -> None:
        text = attack_path_flowchart(
            [path_of("internet", "lb", "db", zones=("internet", "dmz", "data"))]
        )
        assert_mermaid_grammar(text)
        assert 'subgraph z1["internet"]' in text
        assert 'subgraph z2["dmz"]' in text and 'subgraph z3["data"]' in text
        assert 'n1 ==>|"traffic"| n2' in text
        assert "linkStyle 0,1 stroke:#d1242f" in text
        assert "class n1 entry" in text and "class n3 target" in text and "class n2 onpath" in text

    def test_ids_are_generated_never_taken_from_the_input(self) -> None:
        text = attack_path_flowchart([path_of("aws_lb.web", "aws_db.main")])
        assert re.findall(r"\bn\d+\b", text)
        assert not re.search(r"\b(aws_lb|aws_db)\b[^\"]*\s*(-->|==>)", text)

    def test_a_shared_node_is_drawn_once(self) -> None:
        text = attack_path_flowchart(
            [path_of("internet", "lb", "a"), path_of("internet", "lb", "b")]
        )
        assert text.count('["lb"]') == 1 and text.count('["internet"]') == 1
        assert text.count("==>") == 3

    def test_the_first_five_paths_are_drawn(self) -> None:
        paths = [path_of("internet", f"t{i}") for i in range(8)]
        text = attack_path_flowchart(paths, limit=5)
        assert '["t4"]' in text and '["t5"]' not in text

    def test_nothing_to_draw_gives_an_empty_string(self) -> None:
        assert attack_path_flowchart([]) == ""
        assert attack_path_flowchart([path_of("only")]) == ""

    @pytest.mark.parametrize(
        "hostile",
        [
            'a"]; click n1 call alert(1)',
            "<img src=x onerror=alert(1)>",
            "`code` and ``more``",
            "x[0]\nsecond line\r\nthird",
            "%%{init: {'securityLevel':'loose'}}%%",
            "a --> b; c",
            "{{hex}} (round) |pipe| \\back",
            '"quoted" #35; #quot; &amp;',
        ],
    )
    def test_a_hostile_address_cannot_inject_a_statement(self, hostile: str) -> None:
        text = attack_path_flowchart([path_of("internet", hostile, "db")])
        assert_mermaid_grammar(text)
        statements = [ln for ln in text.splitlines() if ln.strip()]
        assert not any(ln.lstrip().startswith("click ") for ln in statements)

    def test_a_long_address_is_cut(self) -> None:
        text = attack_path_flowchart([path_of("internet", "x" * 500)])
        assert max(len(ln) for ln in text.splitlines()) < 120


class TestFormatMermaid:
    def test_the_graph_is_drawn_by_zone_with_flow_edges(self) -> None:
        graph = graph_of(
            [
                resource("aws_lb", "web", "dmz"),
                resource("aws_instance", "app", "private"),
                resource("aws_db_instance", "main", "data"),
                resource("aws_vpc", "unrelated"),
            ],
            [
                ("aws_lb.web", "aws_instance.app", "network_flow"),
                ("aws_instance.app", "aws_db_instance.main", "data_flow"),
            ],
        )
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        assert_mermaid_grammar(text)
        assert 'subgraph z1["dmz"]' in text
        assert 'subgraph z2["private"]' in text and 'subgraph z3["data"]' in text
        assert text.count("-->") == 2
        assert "unrelated" not in text

    def test_iam_bindings_are_dotted(self) -> None:
        graph = graph_of(
            [resource("aws_instance", "app"), resource("aws_iam_role", "r")],
            [("aws_instance.app", "aws_iam_role.r", "iam_binding")],
        )
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        assert_mermaid_grammar(text)
        assert "-.->" in text

    def test_attack_paths_are_highlighted_over_the_graph_edges(self) -> None:
        graph = graph_of(
            [
                resource("aws_lb", "web", "dmz"),
                resource("aws_db_instance", "main", "data"),
                resource("aws_instance", "other", "private"),
            ],
            [
                ("aws_lb.web", "aws_db_instance.main", "network_flow"),
                ("aws_lb.web", "aws_instance.other", "network_flow"),
            ],
        )
        report = ThreatReport()
        report.attack_paths.append(
            path_of("aws_lb.web", "aws_db_instance.main", zones=("dmz", "data"))
        )
        text = format_mermaid(AnalysisResult(graph=graph, report=report))
        assert_mermaid_grammar(text)
        assert text.count("==>") == 1 and text.count("-->") == 1
        assert "linkStyle 0 stroke:#d1242f" in text
        assert "class n1 entry" in text and "class n2 target" in text

    def test_without_a_graph_only_the_paths_are_drawn(self) -> None:
        report = ThreatReport()
        report.attack_paths.append(path_of("a", "b"))
        text = format_mermaid(report)
        assert_mermaid_grammar(text)
        assert text.count("==>") == 1

    def test_an_empty_scan_still_parses(self) -> None:
        text = format_mermaid(ThreatReport())
        assert_mermaid_grammar(text)
        assert 'n1["nothing to draw"]' in text

    def test_the_output_is_deterministic(self) -> None:
        scan = scan_files([FIXTURES / "terraform" / "multi_service_insecure.plan.json"])
        analysis = AnalysisResult(graph=scan.graph, report=scan.report)
        assert format_mermaid(analysis) == format_mermaid(analysis)

    def test_a_real_scan_produces_the_grammar_and_the_registry_name(self) -> None:
        scan = scan_files([FIXTURES / "terraform" / "multi_service_insecure.plan.json"])
        analysis = AnalysisResult(graph=scan.graph, report=scan.report)
        text = render("mermaid", analysis)
        assert_mermaid_grammar(text)
        assert text.startswith("flowchart TB\n")
        assert "subgraph z1" in text

    def test_a_big_graph_is_capped_and_says_so(self) -> None:
        count = MAX_NODES + 40
        resources = [resource("aws_instance", f"i{i}", "private") for i in range(count)]
        edges = [
            (f"aws_instance.i{i}", f"aws_instance.i{(i + 1) % count}", "network_flow")
            for i in range(count)
        ]
        text = format_mermaid(
            AnalysisResult(graph=graph_of(resources, edges), report=ThreatReport())
        )
        assert_mermaid_grammar(text)
        assert len(re.findall(r"^    n\d+\[", text, flags=re.MULTILINE)) == MAX_NODES
        assert text.count("-->") <= MAX_EDGES
        assert "not drawn (size cap)" in text

    def test_hostile_resource_names_in_the_graph_are_inert(self) -> None:
        graph = graph_of(
            [
                resource("aws_s3_bucket", 'a"];click n1 call x()'),
                resource("aws_s3_bucket", "<b>x</b>"),
            ],
            [('aws_s3_bucket.a"];click n1 call x()', "aws_s3_bucket.<b>x</b>", "network_flow")],
        )
        assert_mermaid_grammar(format_mermaid(AnalysisResult(graph=graph, report=ThreatReport())))


def hop_of(
    node_id: str,
    next_edge: str | None,
    *,
    zone: str = "private",
    via: dict[str, object] | None = None,
    resource_type: str = "",
) -> AttackHop:
    return AttackHop(
        node_id=node_id,
        zone=zone,
        resource_type=resource_type,
        edge_type_to_next=next_edge,
        via=via or {},
    )


def labels_of(text: str) -> list[str]:
    return re.findall(r'\|"([^"]*)"\|', text)


def node_labels_of(text: str) -> dict[str, str]:
    return dict(re.findall(r'^    (n\d+)\["([^"]*)"\]$', text, flags=re.MULTILINE))


class TestEdgeWords:
    """FV-21: edge labels are words, not the engine's tokens."""

    def test_a_path_says_what_each_hop_does(self) -> None:
        path = AttackPath(
            id="0123456789ab",
            entry="internet",
            target="aws_s3_bucket.data",
            severity=Severity.HIGH,
            hops=[
                hop_of("internet", "network_flow", zone="internet", via={"ports": ["443"]}),
                hop_of("aws_lb.front", "network_flow", zone="dmz", via={"ports": ["8080"]}),
                hop_of("aws_instance.app", "iam_binding", via={"relation": "instance_profile"}),
                hop_of("aws_iam_instance_profile.app", "iam_binding", via={"relation": "assumes"}),
                hop_of(
                    "aws_iam_role.app",
                    "iam_binding",
                    via={"relation": "permission", "access": "read"},
                ),
                hop_of("aws_s3_bucket.data", None, zone="data"),
            ],
        )
        text = attack_path_flowchart([path])
        assert_mermaid_grammar(text)
        assert labels_of(text) == [
            "HTTPS 443",
            "tcp/8080",
            "uses profile",
            "assumes",
            "can read",
        ]

    @pytest.mark.parametrize("token", ["network_flow", "iam_binding", "data_flow"])
    def test_no_edge_token_is_a_label(self, token: str) -> None:
        graph = graph_of(
            [resource("aws_lb", "web", "dmz"), resource("aws_instance", "app", "private")],
            [("aws_lb.web", "aws_instance.app", token)],
        )
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        assert token not in text

    def test_a_relation_word_is_not_prefixed_with_the_edge_type(self) -> None:
        graph = graph_of(
            [resource("aws_iam_role", "r"), resource("aws_iam_policy", "p")],
            [("aws_iam_role.r", "aws_iam_policy.p", "iam_binding")],
        )
        graph.edges[0].relation = "has_policy"
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        assert '|"has policy"|' in text
        assert "iam_binding" not in text

    def test_edges_between_the_same_two_resources_share_one_arrow(self) -> None:
        graph = graph_of(
            [resource("aws_lb", "web", "dmz"), resource("aws_instance", "app", "private")],
            [
                ("aws_lb.web", "aws_instance.app", "network_flow"),
                ("aws_lb.web", "aws_instance.app", "dependency"),
            ],
        )
        graph.edges[0].attributes = {"ports": ["8080"]}
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        # the dependency is not a flow edge, so one arrow with one label is drawn
        assert text.count("-->") == 1
        assert labels_of(text) == ["tcp/8080"]

    def test_labels_that_would_collide_become_one_joined_label(self) -> None:
        graph = graph_of(
            [resource("aws_lb", "web", "dmz"), resource("aws_instance", "app", "private")],
            [
                ("aws_lb.web", "aws_instance.app", "network_flow"),
                ("aws_lb.web", "aws_instance.app", "data_flow"),
            ],
        )
        graph.edges[0].attributes = {"ports": ["8080"]}
        graph.edges[1].attributes = {"ports": ["8080"]}
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        assert text.count("-->") == 1
        assert len(labels_of(text)) == 1
        assert set(labels_of(text)[0].split(", ")) == {"tcp/8080", "data flow"}

    def test_edges_in_both_directions_are_one_double_headed_arrow(self) -> None:
        graph = graph_of(
            [resource("aws_iam_role", "r"), resource("aws_iam_role_policy", "p")],
            [
                ("aws_iam_role.r", "aws_iam_role_policy.p", "iam_binding"),
                ("aws_iam_role_policy.p", "aws_iam_role.r", "iam_binding"),
            ],
        )
        graph.edges[0].relation = "has_policy"
        graph.edges[1].relation = "assumes"
        text = format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))
        assert_mermaid_grammar(text)
        assert text.count("<-.->") == 1
        assert re.findall(r"-\.->|<-\.->", text) == ["<-.->"]
        assert labels_of(text) == ["has policy, assumes"]


class TestDirection:
    def test_the_chart_runs_top_to_bottom_so_it_stays_narrow(self) -> None:
        assert attack_path_flowchart([path_of("a", "b")]).startswith("flowchart TB\n")
        assert format_mermaid(ThreatReport()).startswith("flowchart TB\n")


class TestAlternativeInstances:
    """FV-21: the other instance of a counted resource is drawn as an alternative route."""

    def graph_and_path(self) -> tuple[InfraGraph, ThreatReport]:
        graph = graph_of(
            [
                resource("aws_lb", "front", "dmz"),
                resource("aws_instance", "app[0]", "private"),
                resource("aws_instance", "app[1]", "private"),
                resource("aws_db_instance", "db", "data"),
            ],
            [
                ("aws_lb.front", "aws_instance.app[0]", "network_flow"),
                ("aws_lb.front", "aws_instance.app[1]", "network_flow"),
                ("aws_instance.app[0]", "aws_db_instance.db", "network_flow"),
                ("aws_instance.app[1]", "aws_db_instance.db", "network_flow"),
            ],
        )
        report = ThreatReport()
        report.attack_paths.append(
            path_of(
                "aws_lb.front",
                "aws_instance.app[0]",
                "aws_db_instance.db",
                zones=("dmz", "private", "data"),
            )
        )
        return graph, report

    def test_the_other_instance_is_dashed_red_and_so_are_its_routes(self) -> None:
        graph, report = self.graph_and_path()
        text = format_mermaid(AnalysisResult(graph=graph, report=report))
        assert_mermaid_grammar(text)
        ids = {v: k for k, v in node_labels_of(text).items()}
        assert f"class {ids['aws_instance.app#91;1#93;']} alt" in text
        assert "classDef alt stroke:#d1242f" in text
        assert re.search(
            r"linkStyle \d+,\d+ stroke:#d1242f,stroke-width:2px,stroke-dasharray", text
        )
        assert text.count("==>") == 2 and text.count("-.->") == 2

    def test_a_resource_that_is_not_an_instance_of_a_path_node_is_not_marked(self) -> None:
        graph, report = self.graph_and_path()
        text = format_mermaid(AnalysisResult(graph=graph, report=report))
        assert text.count(" alt") == 2  # the classDef and the one class line

    def test_the_embedded_chart_shows_the_hops_only(self) -> None:
        graph, report = self.graph_and_path()
        embedded = attack_path_flowchart(report.attack_paths)
        full = format_mermaid(AnalysisResult(graph=graph, report=report))
        assert "app#91;1#93;" not in embedded
        assert "app#91;1#93;" in full
        assert (
            "%% Attack path hops only. threatcode scan -f mermaid draws the whole graph."
            in embedded
        )
        assert_mermaid_grammar(embedded)


def sam_resource(address: str) -> ParsedResource:
    return ParsedResource(
        resource_type="aws_serverless_function",
        name=address.rsplit("::", 1)[-1],
        provider="aws",
        address=address,
        source_location="template.yaml",
        start_line=1,
        trust_zone="private",
    )


class TestLongAddresses:
    """RW-13: a long address keeps the part that tells resources apart."""

    TEMPLATE = "{{cookiecutter.project_name}}/template.yaml"

    def addresses(self) -> list[str]:
        return [
            f"python3.10/step-func-conn/{self.TEMPLATE}::StateMachine",
            f"python3.10/step-func-etl/{self.TEMPLATE}::StateMachine",
            f"python3.11/web-conn/{self.TEMPLATE}::HelloWorldFunction",
            f"dotnet10/s3/{self.TEMPLATE}::S3JsonLoggerFunction",
        ]

    def chart(self) -> str:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                source_path="template.yaml",
                format_type="cloudformation",
                resources=[sam_resource(a) for a in self.addresses()],
                edges=[
                    ParsedEdge(source=a, target=b, edge_type="network_flow")
                    for a, b in zip(self.addresses(), self.addresses()[1:], strict=False)
                ],
            )
        )
        return format_mermaid(AnalysisResult(graph=graph, report=ThreatReport()))

    def test_every_node_keeps_its_resource_name(self) -> None:
        labels = list(node_labels_of(self.chart()).values())
        assert len(labels) == 4
        for name in ("StateMachine", "StateMachine", "HelloWorldFunction", "S3JsonLoggerFunction"):
            assert any(label.endswith(name) for label in labels), name

    def test_labels_that_differ_in_the_input_differ_on_the_chart(self) -> None:
        labels = list(node_labels_of(self.chart()).values())
        assert len(set(labels)) == len(labels)

    def test_the_segment_all_templates_share_is_dropped(self) -> None:
        labels = list(node_labels_of(self.chart()).values())
        assert not any("cookiecutter" in label for label in labels)
        assert all("/.../" in label or "..." in label for label in labels)

    def test_the_directory_that_tells_templates_apart_survives(self) -> None:
        labels = list(node_labels_of(self.chart()).values())
        assert any("step-func-conn" in label for label in labels)
        assert any("step-func-etl" in label for label in labels)

    def test_a_label_is_never_longer_than_the_cap(self) -> None:
        text = attack_path_flowchart([path_of("internet", "x" * 500)])
        assert max(len(label) for label in node_labels_of(text).values()) <= 140

    def test_the_middle_of_a_plain_address_is_cut_not_the_end(self) -> None:
        name = (
            "aws_s3_bucket." + "a_very_long_bucket_name_for_the_data_lake_" * 2 + "on_and_on_2024"
        )
        text = attack_path_flowchart([path_of("internet", name)])
        label = node_labels_of(text)["n2"]
        assert label.startswith("aws_s3_bucket") and label.endswith("on_and_on_2024")
        assert "..." in label

    def test_mermaid_label_still_cuts_the_end_of_a_long_text(self) -> None:
        out = mermaid_label("word " * 100)
        assert len(out) <= 60 and out.endswith("...")
