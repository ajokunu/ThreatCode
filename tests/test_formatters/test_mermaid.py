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
)
from threatcode.ir.graph import InfraGraph
from threatcode.models.analysis import AnalysisResult
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

LABEL = r'"[^"<>`\[\]{}|\\\n]*"'
GRAMMAR = [
    re.compile(r"^flowchart LR$"),
    re.compile(r"^  %% \d+ nodes and \d+ edges not drawn \(size cap\)$"),
    re.compile(rf"^  subgraph z\d+\[{LABEL}\]$"),
    re.compile(rf"^    n\d+\[{LABEL}\]$"),
    re.compile(r"^  end$"),
    re.compile(rf"^  n\d+ (-->|-\.->|==>)(\|{LABEL}\|)? n\d+$"),
    re.compile(r"^  linkStyle \d+(,\d+)* stroke:#[0-9a-f]{6},stroke-width:\d+px$"),
    re.compile(r"^  classDef (entry|target|onpath) stroke:#[0-9a-f]{6},stroke-width:\dpx$"),
    re.compile(r"^  class n\d+(,n\d+)* (entry|target|onpath)$"),
    re.compile(rf"^  n1\[{LABEL}\]$"),
]


def assert_mermaid_grammar(text: str) -> None:
    """Every line is one of the statements the formatter writes; nothing else can be injected."""
    lines = text.rstrip("\n").split("\n")
    assert lines[0] == "flowchart LR"
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
        assert 'n1 ==>|"network_flow"| n2' in text
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
        assert text.startswith("flowchart LR\n")
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
