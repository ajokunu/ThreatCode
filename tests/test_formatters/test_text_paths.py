"""The attack paths of the text report: the route, why it exists and what opens each step."""

from __future__ import annotations

import re

import pytest

from tests.test_formatters.test_text import analysis_of, entries, make_threat
from threatcode.formatters import RenderOptions
from threatcode.formatters.terminal_layout import TIE
from threatcode.formatters.text import format_text
from threatcode.models.analysis import AnalysisResult
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.threat import Severity, Threat

PATH_ID = "5453d439158d"


def webapp_threats() -> list[Threat]:
    return [
        make_threat(
            1,
            Severity.LOW,
            rule_id="SG_WEB_PORT_OPEN_TO_WORLD",
            address="aws_security_group.alb",
            path_ids=[PATH_ID],
        ),
        make_threat(
            2,
            Severity.CRITICAL,
            rule_id="trivy:CVE-2022-37434",
            address="aws_instance.app[0]",
            path_ids=[PATH_ID],
        ),
        make_threat(
            3,
            Severity.MEDIUM,
            effective_severity=Severity.HIGH,
            rule_id="EC2_IMDSV1",
            address="aws_instance.app[0]",
            path_ids=[PATH_ID],
        ),
    ]


def webapp_path(**fields: object) -> AttackPath:
    hops = [
        AttackHop(
            node_id="internet",
            zone="internet",
            edge_type_to_next="network_flow",
            via={"protocol": "tcp", "ports": ["443"]},
            enabled_by=["t1"],
        ),
        AttackHop(
            node_id="aws_lb.front",
            zone="dmz",
            edge_type_to_next="network_flow",
            via={"protocol": "tcp", "ports": ["8080"]},
            enabled_by=["t1"],
        ),
        AttackHop(
            node_id="aws_instance.app[0]",
            zone="private",
            edge_type_to_next="iam_binding",
            via={"relation": "instance_profile"},
            enabled_by=["t2", "t3"],
        ),
        AttackHop(node_id="aws_s3_bucket.customer_data", zone="data"),
    ]
    defaults: dict[str, object] = {
        "id": PATH_ID,
        "entry": "internet",
        "target": "aws_s3_bucket.customer_data",
        "hops": hops,
        "severity": Severity.CRITICAL,
        "score": 9.2,
        "alternatives": 1,
        "target_kind": "data store",
    }
    return AttackPath(**{**defaults, **fields})  # type: ignore[arg-type]


def webapp(**path_fields: object) -> AnalysisResult:
    return analysis_of(*webapp_threats(), attack_paths=[webapp_path(**path_fields)])


def path_block(text: str) -> list[str]:
    """The lines of the attack paths section."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("Attack paths ("))
    end = next(i for i in range(start, len(lines)) if lines[i].startswith("Findings ("))
    return lines[start:end]


class TestAPathSaysWhyItExists:
    def test_the_header_names_the_route_and_its_number_and_severity(self) -> None:
        block = path_block(format_text(webapp(), RenderOptions(width=100)))
        assert block[0] == "Attack paths (1)"
        assert block[1] == "P1  CRITICAL  internet -> aws_s3_bucket.customer_data"

    def test_one_sentence_gives_the_target_kind_length_score_and_the_worst_enabler(self) -> None:
        block = path_block(format_text(webapp(), RenderOptions(width=200)))
        assert block[2].strip() == (
            "data store, 3 hops, score 9.2; 3 findings enable it, the worst being CRITICAL "
            "trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same "
            "resources."
        )

    def test_the_route_is_listed_node_by_node(self) -> None:
        block = path_block(format_text(webapp(), RenderOptions(width=200)))
        assert (
            "    internet > aws_lb.front > aws_instance.app[0] > aws_s3_bucket.customer_data"
            in block
        )

    def test_each_step_that_findings_open_lists_them_by_rule_id_and_effective_severity(
        self,
    ) -> None:
        block = path_block(format_text(webapp(), RenderOptions(width=200)))
        assert "    enabled by:" in block
        assert "      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD" in block
        assert (
            "      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD"
            in block
        )
        assert (
            "      aws_instance.app[0] -> aws_s3_bucket.customer_data: "
            "CRITICAL trivy:CVE-2022-37434, HIGH EC2_IMDSV1"
        ) in block

    def test_a_step_with_no_enabler_is_not_listed(self) -> None:
        threat = make_threat(1, Severity.HIGH, rule_id="ONLY")
        hops = [
            AttackHop(node_id="internet", zone="internet", edge_type_to_next="network_flow"),
            AttackHop(node_id="a", zone="dmz", edge_type_to_next="network_flow", enabled_by=["t1"]),
            AttackHop(node_id="b", zone="data"),
        ]
        path = webapp_path(hops=hops, target="b", alternatives=0)
        block = path_block(format_text(analysis_of(threat, attack_paths=[path])))
        listed = [line for line in block if " -> " in line and line.startswith("      ")]
        assert listed == ["      a -> b: HIGH ONLY"]

    def test_a_path_nothing_enables_has_no_enabled_by_section_and_no_claim_about_findings(
        self,
    ) -> None:
        hops = [AttackHop(node_id="internet", zone="internet"), AttackHop(node_id="b", zone="data")]
        path = webapp_path(hops=hops, target="b", alternatives=0)
        block = path_block(format_text(analysis_of(make_threat(1), attack_paths=[path])))
        assert not any("enabled by" in line or "enable it" in line for line in block)

    def test_only_the_worst_three_are_named_and_the_rest_counted(self) -> None:
        threats = [
            make_threat(i, Severity(sev), rule_id=f"RULE_{sev.upper()}_{i}")
            for i, sev in enumerate(["low", "high", "critical", "medium", "info"], start=1)
        ]
        hops = [
            AttackHop(
                node_id="internet",
                zone="internet",
                edge_type_to_next="network_flow",
                enabled_by=[t.id for t in threats],
            ),
            AttackHop(node_id="b", zone="data"),
        ]
        path = webapp_path(hops=hops, target="b", alternatives=0)
        block = path_block(
            format_text(analysis_of(*threats, attack_paths=[path]), RenderOptions(width=200))
        )
        line = next(line for line in block if line.startswith("      internet -> b"))
        assert line.endswith(
            "CRITICAL RULE_CRITICAL_3, HIGH RULE_HIGH_2, MEDIUM RULE_MEDIUM_4, +2 more"
        )

    def test_a_finding_the_report_does_not_list_is_counted_as_not_shown(self) -> None:
        # Hidden by --min-severity, suppressed or baselined: the path still names the step
        hops = [
            AttackHop(
                node_id="internet",
                zone="internet",
                edge_type_to_next="network_flow",
                enabled_by=["t1", "gone-1", "gone-2"],
            ),
            AttackHop(node_id="b", zone="data"),
        ]
        path = webapp_path(hops=hops, target="b", alternatives=0)
        block = path_block(
            format_text(analysis_of(make_threat(1, Severity.LOW), attack_paths=[path]))
        )
        assert "      internet -> b: LOW R1, +2 not shown" in block
        assert any("3 findings enable it" in line for line in block)

    def test_the_id_is_labelled_with_what_it_is_for(self) -> None:
        block = path_block(format_text(webapp()))
        assert f"    ignore id: {PATH_ID}" in block

    def test_the_equivalent_routes_are_counted_once(self) -> None:
        text = format_text(webapp(alternatives=2), RenderOptions(width=200))
        assert text.count("equivalent route") == 1
        assert "plus 2 equivalent routes through other instances" in text
        none = format_text(webapp(alternatives=0), RenderOptions(width=200))
        assert "equivalent route" not in none


class TestScoresPrintWithOneDecimal:
    @pytest.mark.parametrize(
        ("score", "shown"),
        [(9.0, "score 9.0"), (9.2, "score 9.2"), (7.5, "score 7.5"), (10.0, "score 10.0")],
    )
    def test_a_score_always_has_one_decimal(self, score: float, shown: str) -> None:
        block = path_block(format_text(webapp(score=score), RenderOptions(width=200)))
        assert f", {shown};" in block[2]

    def test_a_whole_score_does_not_print_next_to_a_fractional_one_in_another_form(self) -> None:
        paths = [
            webapp_path(id="a" * 12, score=9.0),
            webapp_path(id="b" * 12, score=9.2, severity=Severity.HIGH),
        ]
        text = format_text(analysis_of(*webapp_threats(), attack_paths=paths))
        scores = re.findall(r"score (\S+?);", text)
        assert sorted(scores) == ["9.0", "9.2"]
        assert not re.search(r"score \d+;", text)

    def test_a_score_is_rounded_to_the_decimal_not_cut(self) -> None:
        block = path_block(format_text(webapp(score=7.46), RenderOptions(width=200)))
        assert "score 7.5;" in block[2]

    def test_a_path_with_no_score_says_nothing_about_one(self) -> None:
        block = path_block(format_text(webapp(score=0), RenderOptions(width=200)))
        assert "score" not in block[2]


class TestASeverityStaysWithItsRule:
    def threats(self) -> list[Threat]:
        return [
            make_threat(1, Severity.CRITICAL, rule_id="MCP_SECRET_IN_CONFIG"),
            make_threat(2, Severity.HIGH, rule_id="MCP_PLAINTEXT_TRANSPORT"),
        ]

    def path(self) -> AttackPath:
        hops = [
            AttackHop(
                node_id="mcp_server.team-tools",
                zone="internet",
                edge_type_to_next="network_flow",
                enabled_by=["t1", "t2"],
            ),
            AttackHop(node_id="mcp_server.filesystem", zone="data"),
        ]
        return webapp_path(hops=hops, target="mcp_server.filesystem", alternatives=0)

    @pytest.mark.parametrize("width", [40, 50, 60, 70, 80, 90, 100])
    def test_the_severity_word_is_never_alone_at_the_end_of_a_line(self, width: int) -> None:
        analysis = analysis_of(*self.threats(), attack_paths=[self.path()])
        block = path_block(format_text(analysis, RenderOptions(width=width)))
        for line in block:
            assert not re.search(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)[,;.]?$", line.rstrip()), line

    def test_the_worst_finding_is_named_with_its_severity_on_one_line(self) -> None:
        analysis = analysis_of(*self.threats(), attack_paths=[self.path()])
        for width in (40, 60, 80, 100):
            block = path_block(format_text(analysis, RenderOptions(width=width)))
            assert any("CRITICAL MCP_SECRET_IN_CONFIG" in line for line in block), width

    def test_the_tie_never_reaches_the_screen(self) -> None:
        analysis = analysis_of(*self.threats(), attack_paths=[self.path()])
        assert TIE not in format_text(analysis, RenderOptions(width=60, color=True))


class TestWrappingAPath:
    def test_the_chain_breaks_before_an_arrow_every_time(self) -> None:
        nodes = [f"aws_some_long_resource_type.name_number_{n}" for n in range(6)]
        hops = [AttackHop(node_id=n, zone="private") for n in nodes]
        path = webapp_path(hops=hops, target=nodes[-1], alternatives=0)
        block = path_block(
            format_text(analysis_of(make_threat(1), attack_paths=[path]), RenderOptions(width=60))
        )
        why = next(i for i, line in enumerate(block) if line.strip().startswith("data store,"))
        chain = [line for line in block[why + 1 :] if "aws_some_long_resource_type" in line]
        assert len(chain) >= 3
        assert chain[0].strip().startswith(nodes[0])
        assert all(line.strip().startswith("> ") for line in chain[1:])
        assert all(not line.rstrip().endswith(">") for line in chain)

    @pytest.mark.parametrize("width", [40, 50, 60, 80])
    def test_no_line_of_the_path_section_is_wider_than_the_terminal(self, width: int) -> None:
        block = path_block(format_text(webapp(), RenderOptions(width=width)))
        assert all(len(line) <= width for line in block)

    def test_a_long_header_wraps_with_a_hanging_indent(self) -> None:
        target = "kubernetes_secret.production-platform.payment-processor-api-key-v2"
        path = webapp_path(target=target)
        block = path_block(
            format_text(analysis_of(make_threat(1), attack_paths=[path]), RenderOptions(width=50))
        )
        head = [line for line in block[1:] if line.startswith(("P1", " " * 14))]
        assert head[0].startswith("P1  CRITICAL  internet ->")
        assert all(line.startswith(" " * 14) for line in head[1:])
        assert "".join(line.strip() for line in head[1:]).endswith(target[-20:])


class TestSeveralPaths:
    def test_two_paths_to_one_target_are_told_apart_by_number_and_route(self) -> None:
        first = webapp_path(id="a" * 12, score=7.7)
        second = webapp_path(id="b" * 12, score=7.3)
        text = format_text(analysis_of(*webapp_threats(), attack_paths=[second, first]))
        assert "P1  CRITICAL  internet -> aws_s3_bucket.customer_data" in text
        assert "P2  CRITICAL  internet -> aws_s3_bucket.customer_data" in text
        # The higher score is P1 whatever order the engine returned them in
        assert text.index("ignore id: " + "a" * 12) < text.index("ignore id: " + "b" * 12)

    def test_paths_are_numbered_by_severity_then_score(self) -> None:
        low = webapp_path(id="1" * 12, severity=Severity.HIGH, score=9.9)
        high = webapp_path(id="2" * 12, severity=Severity.CRITICAL, score=1.0)
        text = format_text(analysis_of(*webapp_threats(), attack_paths=[low, high]))
        assert re.search(r"P1  CRITICAL .*\n(?:.*\n)*?.*ignore id: 2{12}", text)
        assert re.search(r"P2  HIGH .*\n(?:.*\n)*?.*ignore id: 1{12}", text)

    def test_only_ten_paths_are_listed_and_the_rest_are_pointed_to(self) -> None:
        paths = [webapp_path(id=f"{n:012d}", score=float(n)) for n in range(12)]
        text = format_text(
            analysis_of(*webapp_threats(), attack_paths=paths), RenderOptions(width=120)
        )
        assert "Attack paths (12)" in text
        assert len(re.findall(r"^P\d+ ", text, re.MULTILINE)) == 10
        assert "... and 2 more, P11 to P12 (see attack_paths in the JSON report)" in text


class TestFindingsPointBackAtTheirPaths:
    def test_a_finding_that_opens_a_path_carries_its_number(self) -> None:
        text = format_text(webapp(), RenderOptions(width=120))
        by_rule = {e.rule: e for e in entries(text)}
        assert by_rule["trivy:CVE-2022-37434"].paths == "P1"
        assert by_rule["EC2_IMDSV1"].paths == "P1"
        assert by_rule["SG_WEB_PORT_OPEN_TO_WORLD"].paths == "P1"

    def test_the_number_comes_from_the_hops_when_the_finding_does_not_name_its_paths(self) -> None:
        threats = webapp_threats()
        for threat in threats:
            threat.path_ids = []
        text = format_text(
            analysis_of(*threats, attack_paths=[webapp_path()]), RenderOptions(width=120)
        )
        assert {e.paths for e in entries(text)} == {"P1"}

    def test_many_paths_are_shown_as_a_count_not_a_long_list(self) -> None:
        paths = [webapp_path(id=f"{n:012d}", score=float(n)) for n in range(5)]
        threat = make_threat(11, Severity.HIGH)
        threat.path_ids = [p.id for p in paths]
        text = format_text(analysis_of(threat, attack_paths=paths), RenderOptions(width=120))
        assert entries(text)[0].paths == "P1,P2+3"

    def test_inside_a_severity_band_the_findings_that_open_a_path_come_first(self) -> None:
        plain = make_threat(11, Severity.HIGH, address="aws_a.first", rule_id="PLAIN")
        opens = make_threat(12, Severity.HIGH, address="aws_z.last", rule_id="OPENS")
        opens.path_ids = [PATH_ID]
        text = format_text(
            analysis_of(plain, opens, attack_paths=[webapp_path()]), RenderOptions(width=120)
        )
        assert [e.rule for e in entries(text)] == ["OPENS", "PLAIN"]

    def test_the_path_order_never_beats_severity(self) -> None:
        low = make_threat(11, Severity.LOW, address="aws_a.x", rule_id="LOW_ONE")
        low.path_ids = [PATH_ID]
        high = make_threat(12, Severity.HIGH, address="aws_z.x", rule_id="HIGH_ONE")
        text = format_text(
            analysis_of(low, high, attack_paths=[webapp_path()]), RenderOptions(width=120)
        )
        assert [e.rule for e in entries(text)] == ["HIGH_ONE", "LOW_ONE"]

    def test_the_key_explains_the_markers_only_when_they_are_used(self) -> None:
        with_paths = format_text(webapp(), RenderOptions(width=200))
        assert (
            "Key: ^ severity raised from the rule's own by context; P1, P2: the attack paths"
            in with_paths
        )
        plain = format_text(analysis_of(make_threat(1)), RenderOptions(width=200))
        assert "Key:" not in plain
