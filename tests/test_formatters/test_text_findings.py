"""The findings of the text report: complete, never cut, and reconciled with their count."""

from __future__ import annotations

import re
from typing import Any

import pytest

from tests.test_formatters.test_text import (
    ENTRY_START,
    WIDTHS,
    analysis_of,
    entries,
    example,
    make_threat,
)
from threatcode.formatters import RenderOptions
from threatcode.formatters._utils import ELLIPSIS, rule_label
from threatcode.formatters.text import format_text
from threatcode.models.threat import Severity, Threat, ThreatSource

CASES = [("aws-webapp", True), ("k8s-platform", False), ("agent-workstation", False)]


def boundary(
    index: int,
    source: str,
    target: str,
    *,
    zones: tuple[str, str] = ("dmz", "private"),
    anchor: str | None = None,
    ports: tuple[str, ...] = ("8080",),
    protocols: tuple[str, ...] = ("tcp",),
    **flow: Any,
) -> Threat:
    szone, tzone = zones
    return make_threat(
        index,
        Severity.HIGH,
        source=ThreatSource.BOUNDARY,
        rule_id="",
        title=f"Trust boundary crossing: {source} ({szone}) -> {target} ({tzone})",
        address=anchor or source,
        metadata={
            "boundary_rule": "BOUNDARY_GENERIC_FLOW",
            "source_address": source,
            "target_address": target,
            "source_zone": szone,
            "target_zone": tzone,
            "flow": {"ports": list(ports), "protocols": list(protocols), **flow},
        },
    )


class TestGrouping:
    def threats(self) -> list[Threat]:
        found = [
            make_threat(i, Severity.MEDIUM, address="k.web", root_cause="container-hardening")
            for i in range(1, 5)
        ]
        found.append(make_threat(9, Severity.LOW, address="k.web"))
        return found

    def test_findings_with_one_root_cause_on_one_resource_share_an_entry(self) -> None:
        text = format_text(analysis_of(*self.threats()), RenderOptions(width=200))
        found = entries(text)
        assert len(found) == 2
        assert "(+3 related: container hardening)" in found[0].text

    def test_the_heading_says_how_many_rows_the_findings_make(self) -> None:
        text = format_text(analysis_of(*self.threats()), RenderOptions(width=200))
        assert "Findings (5, 2 rows after grouping)" in text

    def test_the_rules_of_the_folded_findings_are_listed_in_full(self) -> None:
        text = format_text(analysis_of(*self.threats()), RenderOptions(width=200))
        first = entries(text)[0]
        assert first.rule == "R1"
        assert first.body[-1] == "also R2, R3, R4"

    def test_without_grouping_the_heading_is_the_plain_count(self) -> None:
        text = format_text(analysis_of(make_threat(1), make_threat(2)), RenderOptions(width=200))
        assert "Findings (2)\n" in text and "after grouping" not in text

    def test_the_folded_rules_wrap_under_the_also_label_at_a_narrow_width(self) -> None:
        threats = [
            make_threat(
                i, Severity.MEDIUM, address="k.web", root_cause="c", rule_id=f"K8S_RULE_NUMBER_{i}"
            )
            for i in range(1, 7)
        ]
        text = format_text(analysis_of(*threats), RenderOptions(width=50))
        tail = text.split("also ")[1].split("\n\n")[0]
        assert all(f"K8S_RULE_NUMBER_{i}" in tail for i in range(2, 7))
        assert all(len(line) <= 50 for line in text.splitlines())

    def test_grouping_never_merges_findings_on_different_resources(self) -> None:
        a = make_threat(1, address="k.a", root_cause="c")
        b = make_threat(2, address="k.b", root_cause="c")
        assert len(entries(format_text(analysis_of(a, b)))) == 2


class TestSeverityMarkers:
    def test_a_raised_severity_is_marked_and_the_key_says_what_the_mark_means(self) -> None:
        raised = make_threat(1, Severity.MEDIUM, effective_severity=Severity.HIGH)
        text = format_text(analysis_of(raised), RenderOptions(width=200))
        (found,) = entries(text)
        assert (found.severity, found.marker) == ("HIGH", "^")
        assert "Key: ^ severity raised from the rule's own by context" in text

    def test_a_lowered_severity_is_marked_too(self) -> None:
        lowered = make_threat(1, Severity.HIGH, effective_severity=Severity.LOW)
        text = format_text(analysis_of(lowered), RenderOptions(width=200))
        (found,) = entries(text)
        assert (found.severity, found.marker) == ("LOW", "v")
        assert "v lowered by context" in text

    def test_an_unchanged_severity_has_no_mark_and_no_key(self) -> None:
        same = make_threat(1, Severity.HIGH, effective_severity=Severity.HIGH)
        text = format_text(analysis_of(same, make_threat(2)), RenderOptions(width=200))
        assert [e.marker for e in entries(text)] == ["", ""]
        assert "Key:" not in text

    def test_the_mark_does_not_change_the_width_of_the_severity_column(self) -> None:
        raised = make_threat(1, Severity.LOW, effective_severity=Severity.MEDIUM, address="aws_a.x")
        plain = make_threat(2, Severity.MEDIUM, address="aws_a.y")
        lines = format_text(analysis_of(raised, plain), RenderOptions(width=200)).splitlines()
        rows = [line for line in lines if ENTRY_START.match(line)]
        assert len({line.index("aws_a.") for line in rows}) == 1


class TestBoundaryFindings:
    def test_a_crossing_is_named_by_its_kind_not_by_the_word_boundary(self) -> None:
        text = format_text(analysis_of(boundary(1, "aws_lb.front", "aws_instance.app[0]")))
        (found,) = entries(text)
        assert found.rule == "BOUNDARY_GENERIC_FLOW"

    def test_two_crossings_from_one_resource_never_look_alike(self) -> None:
        threats = [
            boundary(1, "aws_lb.front", "aws_instance.app[0]"),
            boundary(2, "aws_lb.front", "aws_instance.app[1]"),
        ]
        for width in (40, 60, 80, 100, 120, 200):
            found = entries(format_text(analysis_of(*threats), RenderOptions(width=width)))
            assert len(found) == 2
            assert found[0].text != found[1].text, width
            assert "app[0]" in found[0].text and "app[1]" in found[1].text

    def test_the_title_leads_with_the_zones_and_the_other_end_and_the_port(self) -> None:
        text = format_text(
            analysis_of(boundary(1, "aws_lb.front", "aws_instance.app[0]")),
            RenderOptions(width=200),
        )
        assert "Trust boundary crossing, dmz > private: to aws_instance.app[0] (tcp/8080)" in text

    def test_a_crossing_from_the_internet_reads_from_the_internet(self) -> None:
        threat = boundary(
            1,
            "internet",
            "aws_lb.front",
            zones=("internet", "dmz"),
            anchor="aws_lb.front",
            ports=("443",),
            protocols=("https",),
        )
        text = format_text(analysis_of(threat), RenderOptions(width=200))
        assert "Trust boundary crossing, internet > dmz: from the internet (https/443)" in text

    def test_a_flow_without_a_protocol_names_the_port(self) -> None:
        threat = boundary(1, "a", "b", ports=("22",), protocols=())
        assert "(port 22)" in format_text(analysis_of(threat), RenderOptions(width=200))

    def test_a_flow_known_to_be_unencrypted_or_unauthenticated_says_so(self) -> None:
        threat = boundary(1, "a", "b", encrypted=False, authenticated=False)
        text = format_text(analysis_of(threat), RenderOptions(width=200))
        assert "(tcp/8080), unencrypted, unauthenticated" in text

    def test_a_boundary_finding_without_its_endpoints_keeps_the_engines_title(self) -> None:
        threat = make_threat(
            1, source=ThreatSource.BOUNDARY, rule_id="", title="Some crossing", metadata={}
        )
        (found,) = entries(format_text(analysis_of(threat), RenderOptions(width=200)))
        assert found.rule == "boundary" and found.text.startswith("Some crossing")

    def test_a_rule_label_prefers_the_rule_then_the_kind_then_the_source(self) -> None:
        assert rule_label(make_threat(1, rule_id="S3_X")) == "S3_X"
        assert rule_label(boundary(1, "a", "b")) == "BOUNDARY_GENERIC_FLOW"
        assert rule_label(make_threat(2, rule_id="", source=ThreatSource.LLM)) == "llm"


class TestNothingIsCut:
    def test_a_rule_id_is_printed_whole_on_one_line_at_every_usable_width(self) -> None:
        rule = "AZURE_STORAGE_NO_NETWORK_RESTRICTION"
        threat = make_threat(1, rule_id=rule)
        for width in (60, 70, 80, 100, 160, 200):
            text = format_text(analysis_of(threat), RenderOptions(width=width))
            assert any(rule in line.split() for line in text.splitlines()), width

    def test_a_long_resource_address_wraps_after_a_dot_and_keeps_every_character(self) -> None:
        address = "module.network.aws_security_group.bastion_host_ssh"
        text = format_text(analysis_of(make_threat(1, address=address)), RenderOptions(width=50))
        lines = text.splitlines()
        first = next(
            i for i, line in enumerate(lines) if "module.network.aws_security_group." in line
        )
        assert lines[first].startswith("HIGH      module.network.aws_security_group.")
        assert lines[first + 1].startswith(" " * 10 + "bastion_host_ssh")
        assert ELLIPSIS not in text and "..." not in text

    def test_a_narrow_terminal_puts_the_rule_on_its_own_line_and_wraps_the_resource(self) -> None:
        address = "kubernetes_cluster_role_binding.platform.storefront-secret-reader"
        threat = make_threat(1, address=address, rule_id="K8S_EPHEMERAL_STORAGE_UNBOUNDED")
        text = format_text(analysis_of(threat), RenderOptions(width=44))
        lines = text.splitlines()
        assert all(len(line) <= 44 for line in lines)
        first = next(i for i, line in enumerate(lines) if line.startswith("HIGH"))
        rule_line = next(
            i for i, line in enumerate(lines) if line.strip() == "K8S_EPHEMERAL_STORAGE_UNBOUNDED"
        )
        pieces = [
            lines[first][10:].strip(),
            *(line.strip() for line in lines[first + 1 : rule_line]),
        ]
        assert "".join(pieces) == address

    def test_a_finding_title_wraps_onto_further_lines_instead_of_ending_in_dots(self) -> None:
        title = "A very long finding title that goes on and on " * 3
        text = format_text(
            analysis_of(make_threat(1, title=title.strip())), RenderOptions(width=60)
        )
        body = text.split("Findings (1)")[1].split("Coverage:")[0]
        assert "..." not in body and ELLIPSIS not in body
        flat = " ".join(line.strip() for line in body.splitlines())
        assert title.strip() in flat

    def test_the_file_name_of_a_location_is_never_cut_from_the_left(self) -> None:
        file = "very/deep/directory/structure/with/main.tf"
        text = format_text(
            analysis_of(make_threat(1, file=file, line=12)), RenderOptions(width=100)
        )
        assert f"{file}:12" in text
        narrow = format_text(
            analysis_of(make_threat(1, file=file, line=12)), RenderOptions(width=40)
        )
        assert "main.tf:12" in narrow and ELLIPSIS not in narrow

    def test_the_location_does_not_wobble_with_the_number_of_digits(self) -> None:
        threats = [
            make_threat(i, line=n, file="a.tf") for i, n in enumerate((7, 255, 1234), start=1)
        ]
        found = entries(format_text(analysis_of(*threats), RenderOptions(width=120)))
        assert [re.search(r"a\.tf:\d+", e.text).group() for e in found] == [  # type: ignore[union-attr]
            "a.tf:7",
            "a.tf:255",
            "a.tf:1234",
        ]

    @pytest.mark.parametrize("width", WIDTHS)
    def test_a_hostile_width_never_breaks_the_report(self, width: int) -> None:
        threats = [
            make_threat(
                i,
                address="module.network.aws_security_group_rule.very_long_name_for_a_rule["
                + "x" * 80,
                title="A very long finding title that goes on and on " * 3,
                file="deep/dir/" * 5 + "main.tf",
                rule_id="A_RULE_ID_" + "X" * 30,
            )
            for i in range(1, 4)
        ]
        text = format_text(analysis_of(*threats), RenderOptions(width=width))
        assert all(len(line) <= max(width, 40) for line in text.splitlines())
        # Wrapped, never cut: the pieces of the rule id follow each other and hold every character
        flat = re.sub(r"\s+", "", text)
        assert "A_RULE_ID_" + "X" * 30 in flat
        assert len(entries(text)) == 3


class TestTheExamples:
    """The three bundled examples at every width: the report a user reads first."""

    @pytest.mark.parametrize(("name", "ingest"), CASES)
    @pytest.mark.parametrize("width", WIDTHS)
    def test_no_line_is_wider_than_the_terminal(self, name: str, ingest: bool, width: int) -> None:
        text = format_text(example(name, ingest), RenderOptions(width=width))
        assert max(len(line) for line in text.splitlines()) <= width

    @pytest.mark.parametrize(("name", "ingest"), CASES)
    @pytest.mark.parametrize("width", WIDTHS)
    def test_nothing_is_shortened_with_dots(self, name: str, ingest: bool, width: int) -> None:
        text = format_text(example(name, ingest), RenderOptions(width=width))
        assert ELLIPSIS not in text
        cut = [line for line in text.splitlines() if "..." in line and "... and " not in line]
        assert cut == []

    @pytest.mark.parametrize(("name", "ingest"), CASES)
    @pytest.mark.parametrize("width", [60, 80, 100, 120, 160, 200])
    def test_every_rule_id_and_every_entry_is_there_and_no_two_entries_are_alike(
        self, name: str, ingest: bool, width: int
    ) -> None:
        analysis = example(name, ingest)
        text = format_text(analysis, RenderOptions(width=width))
        for threat in analysis.report.threats:
            assert rule_label(threat) in text, (width, rule_label(threat))
        found = entries(text)
        assert len({(e.resource, e.rule, e.text) for e in found}) == len(found)

    @pytest.mark.parametrize("width", [100, 120, 160])
    def test_every_resource_address_is_printed_whole(self, width: int) -> None:
        analysis = example("k8s-platform")
        text = format_text(analysis, RenderOptions(width=width))
        for address in {t.resource_address for t in analysis.report.threats}:
            assert address in text, address

    @pytest.mark.parametrize("width", [80, 100, 120, 160])
    def test_the_rows_add_up_to_the_findings_in_the_heading(self, width: int) -> None:
        analysis = example("k8s-platform")
        text = format_text(analysis, RenderOptions(width=width))
        found = entries(text)
        folded = sum(
            len(re.split(r",\s*", e.text.split(" also ", 1)[1])) if " also " in e.text else 0
            for e in found
        )
        assert len(analysis.report.threats) == 30
        assert f"Findings (30, {len(found)} rows after grouping)" in text
        assert len(found) + folded == 30

    def test_the_folded_rules_the_old_table_hid_are_listed(self) -> None:
        text = format_text(example("k8s-platform"), RenderOptions(width=100))
        for rule in (
            "K8S_CAPABILITIES_NOT_DROPPED",
            "K8S_NO_SECURITY_CONTEXT_DEFAULTS",
            "K8S_RUN_AS_ROOT",
            "K8S_WRITABLE_ROOT_FS",
        ):
            assert rule in text

    def test_the_two_boundary_rows_on_the_load_balancer_are_distinct_at_100_columns(self) -> None:
        text = format_text(example("aws-webapp", True), RenderOptions(width=100))
        rows = [e for e in entries(text) if e.resource == "aws_lb.front" and e.severity == "HIGH"]
        assert len(rows) == 2 and rows[0].text != rows[1].text
        assert "app[0]" in rows[0].text and "app[1]" in rows[1].text
        assert {r.rule for r in rows} == {"BOUNDARY_GENERIC_FLOW"}

    def test_the_finding_that_opens_the_first_hop_points_at_the_critical_path(self) -> None:
        text = format_text(example("aws-webapp", True), RenderOptions(width=100))
        sg = next(e for e in entries(text) if e.rule == "SG_WEB_PORT_OPEN_TO_WORLD")
        assert sg.severity == "LOW" and sg.paths.startswith("P1")

    def test_inside_each_severity_band_the_findings_on_a_path_come_first(self) -> None:
        text = format_text(example("k8s-platform"), RenderOptions(width=120))
        by_band: dict[str, list[bool]] = {}
        for e in entries(text):
            by_band.setdefault(e.severity, []).append(bool(e.paths))
        for band, flags in by_band.items():
            assert flags == sorted(flags, reverse=True), band

    def test_the_ingested_cve_row_names_the_scanner_in_its_rule(self) -> None:
        text = format_text(example("aws-webapp", True), RenderOptions(width=100))
        assert {e.rule for e in entries(text) if "CVE" in e.rule} == {"trivy:CVE-2022-37434"}
