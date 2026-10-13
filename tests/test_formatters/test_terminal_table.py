"""The findings table of the terminal report: a block per finding, in columns that line up."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from tests.test_formatters.test_text import WIDTHS, analysis_of, example, make_threat
from threatcode.formatters import RenderOptions
from threatcode.formatters.terminal_table import build_rows, layout_of
from threatcode.formatters.text import format_text
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.threat import Severity, ThreatSource

HEAD = ("LOCATION", "ATT&CK", "STRIDE")
EXAMPLE_DIR = Path(__file__).resolve().parents[2] / "examples"


def section(text: str) -> list[str]:
    """The lines of the findings section: the heading to the line before the key or coverage."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("Findings ("))
    end = next(i for i in range(start, len(lines)) if lines[i].startswith(("Key:", "Coverage:")))
    while not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def blocks(text: str) -> list[list[str]]:
    """The findings: each starts at a line with a severity at the left edge."""
    found: list[list[str]] = []
    for line in section(text)[1:]:
        if re.match(r"(CRITICAL|HIGH|MEDIUM|LOW|INFO)", line):
            found.append([line])
        elif found:
            found[-1].append(line)
    return found


def header(text: str) -> list[str]:
    """The header: the lines between the heading and the first finding."""
    lines = section(text)[1:]
    first = next(i for i, line in enumerate(lines) if re.match(r"(CRITICAL|HIGH|MEDIUM|LOW)", line))
    return lines[:first]


def column_of(line: str, cell: str) -> int:
    return line.index(cell)


def threats_with_meta() -> list:
    return [
        make_threat(
            1,
            stride="information_disclosure",
            mitre_techniques=["T1530", "T1078"],
            file="tfplan.json",
            line=484,
        ),
        make_threat(2, stride="denial_of_service", file="tfplan.json", line=9),
        make_threat(
            3, stride="tampering", mitre_techniques=["T1565.002"], file="tfplan.json", line=1234
        ),
    ]


class TestTheLineUnderTheTitle:
    def test_every_finding_has_its_location_techniques_and_category_in_the_same_columns(
        self,
    ) -> None:
        text = format_text(analysis_of(*threats_with_meta()), RenderOptions(width=120))
        metas = [b[2] for b in blocks(text)]
        locations = [m.index("tfplan.json") for m in metas]
        assert len(set(locations)) == 1
        # The category starts in one column whatever the techniques before it are
        stride_columns = {m.index(word) for m, word in zip(metas, ("Info", "DoS", "Tampering"))}
        assert len(stride_columns) == 1
        # ... and so does the technique column, where there is one
        tech_columns = {metas[0].index("T1530"), metas[2].index("T1565.002")}
        assert len(tech_columns) == 1

    def test_the_header_names_the_columns_over_the_same_offsets(self) -> None:
        text = format_text(analysis_of(*threats_with_meta()), RenderOptions(width=120))
        meta_head = header(text)[-1]
        meta = blocks(text)[0][2]
        assert meta_head.split() == list(HEAD)
        assert meta_head.index("LOCATION") == meta.index("tfplan.json")
        assert meta_head.index("ATT&CK") == meta.index("T1530")
        assert meta_head.index("STRIDE") == meta.index("Info")

    def test_the_header_lists_the_finding_on_a_line_of_its_own_in_the_order_the_rows_print_it(
        self,
    ) -> None:
        text = format_text(analysis_of(*threats_with_meta()), RenderOptions(width=120))
        head = header(text)
        assert head[0].split()[:2] == ["SEVERITY", "RESOURCE"]
        assert head[1].strip() == "FINDING"
        assert head[2].split() == list(HEAD)

    def test_the_line_is_dim_and_the_title_is_not(self) -> None:
        options = RenderOptions(width=120, color=True)
        lines = format_text(analysis_of(*threats_with_meta()), options).splitlines()
        title = next(i for i, line in enumerate(lines) if "Finding number 1" in line)
        assert "\x1b[" not in lines[title]
        assert lines[title + 1].count("\x1b[2m") == 3

    def test_a_row_without_a_cell_leaves_its_place_empty_and_keeps_the_others_where_they_are(
        self,
    ) -> None:
        text = format_text(analysis_of(*threats_with_meta()), RenderOptions(width=120))
        no_technique = blocks(text)[1][2]
        assert "T1" not in no_technique
        assert no_technique.index("DoS") == blocks(text)[0][2].index("Info")

    def test_a_column_with_nothing_in_any_row_is_left_out_of_the_header_too(self) -> None:
        threats = [make_threat(i, file="", line=None) for i in (1, 2)]
        text = format_text(analysis_of(*threats), RenderOptions(width=120))
        assert header(text)[-1].split() == ["STRIDE"]
        assert all("ATT&CK" not in line and "LOCATION" not in line for line in header(text))

    def test_there_is_never_a_blank_line_inside_the_findings(self) -> None:
        text = format_text(example("k8s-platform"), RenderOptions(width=100))
        assert all(line.strip() for line in section(text))

    def test_a_location_longer_than_its_column_wraps_inside_it_and_the_rest_stays_aligned(
        self,
    ) -> None:
        deep = "modules/networking/security_groups/internal/rules/main.tf"
        threats = [
            make_threat(1, file=deep, line=120, mitre_techniques=["T1190"], stride="tampering"),
            make_threat(2, file="a.tf", line=1, mitre_techniques=["T1190"], stride="tampering"),
        ]
        text = format_text(analysis_of(*threats), RenderOptions(width=70))
        assert all(len(line) <= 70 for line in text.splitlines())
        long_block = next(b for b in blocks(text) if any("modules/" in line for line in b))
        short_block = next(b for b in blocks(text) if any("a.tf" in line for line in b))
        # The path was wrapped into the pieces of its column and no character of it is lost
        first, rest = long_block[2], long_block[3:]
        assert rest and all(line.startswith(" " * 10) for line in rest)
        shown = first.strip().split("  ")[0] + "".join(line.strip() for line in rest)
        assert shown == f"{deep}:120"
        # The techniques and the category stay in the columns of every other row
        assert first.index("T1190") == short_block[2].index("T1190")
        assert first.index("Tampering") == short_block[2].index("Tampering")

    def test_a_table_too_narrow_to_line_the_columns_up_lets_them_flow_in_the_same_order(
        self,
    ) -> None:
        text = format_text(analysis_of(*threats_with_meta()), RenderOptions(width=44))
        assert all(len(line) <= 44 for line in text.splitlines())
        assert header(text)[-1].split() == list(HEAD)
        meta = " ".join(line.strip() for line in blocks(text)[0][2:])
        assert meta.index("tfplan.json:484") < meta.index("T1530,T1078") < meta.index("Info")
        assert "Info disclosure" in meta

    def test_a_category_is_not_broken_between_its_words_when_the_columns_flow(self) -> None:
        text = format_text(analysis_of(*threats_with_meta()), RenderOptions(width=44))
        assert not re.search(r"Info\s*\n\s*disclosure", text)


class TestTheTitle:
    def test_a_long_title_wraps_with_a_hanging_indent_under_its_first_line(self) -> None:
        title = "A finding title that is much longer than the line it is printed on " * 2
        text = format_text(
            analysis_of(make_threat(1, title=title.strip())), RenderOptions(width=60)
        )
        (one,) = blocks(text)
        title_lines, meta = one[1:-1], one[-1]
        assert title_lines[0].startswith(" " * 10) and not title_lines[0].startswith(" " * 11)
        assert len(title_lines) > 1
        assert all(
            line.startswith(" " * 12) and not line.startswith(" " * 13) for line in title_lines[1:]
        )
        assert " ".join(line.strip() for line in title_lines) == title.strip()
        assert "main.tf:2" in meta

    def test_the_line_under_the_title_goes_back_to_the_indent_of_the_title(self) -> None:
        text = format_text(analysis_of(make_threat(1, title="word " * 30)), RenderOptions(width=60))
        (one,) = blocks(text)
        meta = next(line for line in one if "main.tf:2" in line)
        assert meta.startswith(" " * 10) and not meta.startswith(" " * 11)


class TestTheLayoutIsDecidedOncePerTable:
    def many(self, address: str = "aws_s3_bucket.short") -> list:
        return [
            make_threat(1, address=address, rule_id="S3_NO_ENCRYPTION"),
            make_threat(2, address="aws_s3_bucket.b", rule_id="R2"),
        ]

    def test_resource_and_rule_share_a_line_when_both_fit_whole(self) -> None:
        text = format_text(analysis_of(*self.many()), RenderOptions(width=100))
        for one in blocks(text):
            assert len(one) == 3
            assert re.search(r"aws_s3_bucket\.\w+\s{2,}\w+", one[0])

    def test_the_rule_moves_under_the_resource_when_they_do_not_fit_side_by_side(self) -> None:
        long = "module.network.aws_security_group_rule.ingress_from_load_balancer_to_app"
        text = format_text(analysis_of(*self.many(long)), RenderOptions(width=90))
        for one in blocks(text):
            assert len(one[0].split()) == 2
            assert re.fullmatch(r"\s{10}[A-Z0-9_]+", one[1])
        assert long in text

    def test_one_long_row_moves_every_row_never_just_itself(self) -> None:
        long = "module.network.aws_security_group_rule.ingress_from_load_balancer_to_app"
        text = format_text(analysis_of(*self.many(long)), RenderOptions(width=90))
        assert header(text)[1].split() == ["RULE"]
        # The short row is stacked too, so the two rows read the same way
        short = next(b for b in blocks(text) if "aws_s3_bucket.b" in b[0])
        assert short[1].strip() == "R2"

    def test_a_resource_is_never_wrapped_when_stacking_the_rule_keeps_it_whole(self) -> None:
        address = "kubernetes_service_account.platform.storefront-service-account"
        text = format_text(analysis_of(make_threat(1, address=address)), RenderOptions(width=80))
        assert address in text

    @pytest.mark.parametrize("width", WIDTHS)
    def test_every_row_of_a_table_is_laid_out_like_the_header_at_every_width(
        self, width: int
    ) -> None:
        text = format_text(example("k8s-platform"), RenderOptions(width=width))
        stacked = len(header(text)[0].split()) == 2
        for one in blocks(text):
            has_rule_beside_resource = len(one[0].split()) >= 3
            # A stacked table has the resource alone on its line; an inline one has the rule too
            assert has_rule_beside_resource != stacked, (width, one[0])


class TestAPathsCellThatDoesNotFitBesideTheRule:
    RULE = "AZURE_STORAGE_NO_NETWORK_RESTRICTION"

    def analysis(self) -> Any:
        threat = make_threat(1, address="azurerm_storage_account.main", rule_id=self.RULE)
        threat.path_ids = ["p1"]
        path = AttackPath(
            id="p1",
            entry="internet",
            target="azurerm_storage_account.main",
            hops=[
                AttackHop(node_id="internet", zone="internet", enabled_by=[threat.id]),
                AttackHop(node_id="azurerm_storage_account.main", zone="data"),
            ],
            severity=Severity.HIGH,
            target_kind="data store",
        )
        return analysis_of(threat, attack_paths=[path])

    def test_the_rule_id_is_kept_whole_and_the_paths_take_the_next_line(self) -> None:
        text = format_text(self.analysis(), RenderOptions(width=50))
        (one,) = blocks(text)
        assert one[1].strip() == self.RULE
        assert one[2].strip() == "P1"
        assert all(len(line) <= 50 for line in text.splitlines())

    def test_the_header_shows_the_same_shape(self) -> None:
        head = header(format_text(self.analysis(), RenderOptions(width=50)))
        assert [line.split() for line in head[:3]] == [
            ["SEVERITY", "RESOURCE"],
            ["RULE"],
            ["PATHS"],
        ]

    def test_with_room_enough_the_paths_stay_beside_the_rule(self) -> None:
        text = format_text(self.analysis(), RenderOptions(width=60))
        (one,) = blocks(text)
        assert one[1].split() == [self.RULE, "P1"]


class TestTheSeverityColumn:
    def test_a_mark_after_critical_widens_the_column_instead_of_pushing_the_row(self) -> None:
        raised = make_threat(1, Severity.HIGH, effective_severity=Severity.CRITICAL, address="a.x")
        plain = make_threat(2, Severity.CRITICAL, address="a.y")
        text = format_text(analysis_of(raised, plain), RenderOptions(width=120))
        rows = [b[0] for b in blocks(text)]
        assert rows[0].startswith("CRITICAL^")
        assert len({row.index("a.") for row in rows}) == 1
        assert header(text)[0].index("RESOURCE") == rows[0].index("a.")

    def test_without_a_long_marked_severity_the_column_keeps_its_usual_width(self) -> None:
        raised = make_threat(1, Severity.LOW, effective_severity=Severity.MEDIUM, address="a.x")
        text = format_text(analysis_of(raised), RenderOptions(width=120))
        assert header(text)[0].index("RESOURCE") == 10


class TestUnmatchedScannerFindings:
    def test_a_scanner_finding_with_no_resource_says_it_matched_none(self) -> None:
        orphan = make_threat(
            1, Severity.CRITICAL, source=ThreatSource.SCANNER, address="", rule_id="trivy:CVE-1-2"
        )
        text = format_text(analysis_of(orphan), RenderOptions(width=120))
        (one,) = blocks(text)
        assert "(unmatched)" in one[0] and "trivy:CVE-1-2" in one[0]
        assert " - " not in one[0]

    def test_a_rule_finding_with_no_address_keeps_the_dash(self) -> None:
        bare = make_threat(1, address="", rule_id="R1")
        (one,) = blocks(format_text(analysis_of(bare), RenderOptions(width=120)))
        assert "(unmatched)" not in one[0]
        assert re.search(r"\s-\s", one[0])

    def test_a_scanner_finding_that_has_a_resource_is_unaffected(self) -> None:
        matched = make_threat(1, source=ThreatSource.SCANNER, address="aws_instance.app[0]")
        text = format_text(analysis_of(matched), RenderOptions(width=120))
        assert "(unmatched)" not in text and "aws_instance.app[0]" in text

    def test_a_real_scan_whose_image_is_not_in_the_plan_prints_the_row_as_unmatched(
        self, tmp_path: Path
    ) -> None:
        from threatcode.pipeline import prepare_request, run_scan

        source = EXAMPLE_DIR / "aws-webapp"
        report = (source / "scanner" / "trivy-app-image.json").read_text()
        ingest = tmp_path / "trivy.json"
        ingest.write_text(
            report.replace("registry.example.com/shop/orders-api", "registry.example.com/other/zzz")
        )
        prepared = prepare_request(
            [source], min_severity="info", no_ignore=True, no_timestamp=True, ingest=[ingest]
        )
        text = format_text(run_scan(prepared.request).analysis, RenderOptions(width=120))
        orphans = [b for b in blocks(text) if "(unmatched)" in b[0]]
        assert len(orphans) == 1 and "trivy:CVE-2022-37434" in orphans[0][0]


class TestLayoutOf:
    def rows(self, *threats):
        return build_rows(list(threats), {}, None)

    def test_the_columns_are_as_wide_as_their_widest_cell_and_never_narrower_than_their_name(
        self,
    ) -> None:
        rows = self.rows(make_threat(1, address="a", rule_id="R"))
        layout = layout_of(rows, 120)
        assert layout.resource == len("RESOURCE") and layout.rule == len("RULE")
        assert layout.path == 0 and not layout.stacked

    def test_the_path_column_exists_only_when_a_finding_is_on_a_path(self) -> None:
        threat = make_threat(1)
        on_one = build_rows([threat], {threat.id: [1]}, None)
        assert layout_of(on_one, 120).path == len("PATHS")
        on_three = build_rows([threat], {threat.id: [1, 2, 3]}, None)
        assert layout_of(on_three, 120).path == len("P1,P2+1")
        assert layout_of(build_rows([threat], {}, None), 120).path == 0

    def test_stacking_keeps_the_rule_whole_when_there_is_room_for_it(self) -> None:
        rows = self.rows(make_threat(1, address="x" * 60, rule_id="A_VERY_LONG_RULE_ID"))
        layout = layout_of(rows, 80)
        assert layout.stacked and layout.rule == len("A_VERY_LONG_RULE_ID")

    def test_the_indent_follows_the_severity_column(self) -> None:
        marked = self.rows(
            make_threat(1, Severity.HIGH, effective_severity=Severity.CRITICAL, address="a")
        )
        assert layout_of(marked, 100).indent == len("CRITICAL^") + 2
        assert layout_of(self.rows(make_threat(1)), 100).indent == 10


class TestTheKey:
    def test_the_key_is_set_apart_from_the_last_finding(self) -> None:
        raised = make_threat(1, Severity.LOW, effective_severity=Severity.MEDIUM)
        lines = format_text(analysis_of(raised), RenderOptions(width=120)).splitlines()
        key = next(i for i, line in enumerate(lines) if line.startswith("Key:"))
        assert lines[key - 1] == ""
        assert lines[key - 2].strip()

    def test_no_key_and_no_stray_blank_line_when_nothing_needs_explaining(self) -> None:
        lines = format_text(analysis_of(make_threat(1)), RenderOptions(width=120)).splitlines()
        assert not any(line.startswith("Key:") for line in lines)
        findings = next(i for i, line in enumerate(lines) if line.startswith("Findings ("))
        coverage = next(i for i, line in enumerate(lines) if line.startswith("Coverage:"))
        assert lines[findings:coverage].count("") == 1


class TestEveryFieldIsMadeSafeForTheTerminal:
    HOSTILE = "evil\x1b[2J\x1b]0;TITLE\x07"

    @pytest.mark.parametrize("width", [40, 80, 120])
    def test_no_escape_or_bell_reaches_the_terminal_from_any_cell(self, width: int) -> None:
        threat = make_threat(
            1,
            address=f"aws_s3_bucket.{self.HOSTILE}",
            rule_id=f"RULE_{self.HOSTILE}",
            title=f"Title {self.HOSTILE}",
            file=f"dir/{self.HOSTILE}.tf",
            mitre_techniques=[f"T1{self.HOSTILE}"],
        )
        text = format_text(analysis_of(threat), RenderOptions(width=width, color=False))
        assert "\x1b" not in text and "\x07" not in text
        assert "\\x1b" in text

    def test_an_unmatched_scanner_finding_with_a_hostile_rule_is_made_safe_too(self) -> None:
        threat = make_threat(
            1, source=ThreatSource.SCANNER, address="", rule_id=f"trivy:{self.HOSTILE}"
        )
        text = format_text(analysis_of(threat), RenderOptions(width=100))
        assert "\x1b" not in text and "(unmatched)" in text


NAMES = st.text(alphabet="abcdefgxyz_.-:/[]0123456789", min_size=1, max_size=70)
WORDS = st.lists(st.text(alphabet="abcdefg", min_size=1, max_size=12), min_size=1, max_size=14)


class TestAnyTableAtAnyWidth:
    @given(
        st.lists(
            st.tuples(
                NAMES,
                st.text(alphabet="ABCDEFG_", min_size=2, max_size=40),
                WORDS,
                NAMES,
                st.integers(min_value=1, max_value=99999),
                st.sampled_from(list(Severity)),
            ),
            min_size=1,
            max_size=6,
        ),
        st.integers(min_value=40, max_value=200),
    )
    @settings(max_examples=120, deadline=None)
    def test_no_line_is_wider_than_the_terminal_and_every_name_is_kept_whole(
        self,
        rows: list[tuple[str, str, list[str], str, int, Severity]],
        width: int,
    ) -> None:
        threats = [
            make_threat(
                i,
                severity,
                address=f"aws_x.{address}",
                rule_id=rule,
                title=" ".join(words),
                file=file,
                line=line,
                mitre_techniques=["T1190"] if i % 2 else [],
            )
            for i, (address, rule, words, file, line, severity) in enumerate(rows, start=1)
        ]
        text = format_text(analysis_of(*threats), RenderOptions(width=width))
        assert max(len(line) for line in text.splitlines()) <= width
        flat = re.sub(r"\s+", "", text)
        for threat in threats:
            assert threat.rule_id in flat
            assert threat.resource_address in flat
            assert f"{threat.location_file}:{threat.location_start_line}" in flat
        assert len(blocks(text)) == len(threats)
        assert all(line.strip() for line in section(text))


EXAMPLES = [
    ("aws-webapp", False),
    ("aws-webapp", True),
    ("k8s-platform", False),
    ("agent-workstation", False),
]


class TestTheBundledExamplesAreTidy:
    @pytest.mark.parametrize(("name", "ingest"), EXAMPLES)
    @pytest.mark.parametrize("width", [80, 100, 120, 160])
    def test_no_line_ends_in_a_space_and_none_is_wider_than_the_terminal(
        self, name: str, ingest: bool, width: int
    ) -> None:
        text = format_text(example(name, ingest), RenderOptions(width=width))
        for line in text.splitlines():
            assert line == line.rstrip(), line
            assert len(line) <= width, line

    @pytest.mark.parametrize(("name", "ingest"), EXAMPLES)
    @pytest.mark.parametrize("width", [80, 120])
    def test_color_changes_nothing_but_the_escape_codes(
        self, name: str, ingest: bool, width: int
    ) -> None:
        plain = format_text(example(name, ingest), RenderOptions(width=width))
        colored = format_text(example(name, ingest), RenderOptions(width=width, color=True))
        assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain
        assert "\u2060" not in colored

    @pytest.mark.parametrize(("name", "ingest"), EXAMPLES)
    @pytest.mark.parametrize("width", [80, 100, 120, 160])
    def test_every_finding_has_the_three_lines_and_the_header_names_them(
        self, name: str, ingest: bool, width: int
    ) -> None:
        text = format_text(example(name, ingest), RenderOptions(width=width))
        head = header(text)
        assert head[-2].strip() == "FINDING" and head[-1].split() == list(HEAD)
        for one in blocks(text):
            also = next((i for i, line in enumerate(one) if line.lstrip().startswith("also")), None)
            meta = one[also - 1] if also else one[-1]
            assert re.search(r"\S+:\d+|T\d{4}|EoP|DoS|Tampering|Repudiation|Info|Spoofing", meta)
            assert meta.startswith(" " * 10) and not meta.startswith(" " * 11)
