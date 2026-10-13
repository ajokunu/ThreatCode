"""The verdict line: where the scan landed, in words a reader does not have to decode."""

from __future__ import annotations

import pytest

from tests.test_formatters.test_text import analysis_of, make_threat
from threatcode.formatters import RenderOptions
from threatcode.formatters._utils import attack_path_phrase, verdict_items, verdict_line
from threatcode.formatters.markdown import format_markdown
from threatcode.formatters.text import format_text
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import Coverage, ThreatReport
from threatcode.models.threat import Severity


def path(
    kind: str = "",
    *,
    zone: str = "data",
    severity: Severity = Severity.HIGH,
    entry_zone: str = "internet",
    name: str = "p",
) -> AttackPath:
    return AttackPath(
        id=name,
        entry="internet",
        target="t",
        hops=[AttackHop(node_id="internet", zone=entry_zone), AttackHop(node_id="t", zone=zone)],
        severity=severity,
        target_kind=kind,
    )


class TestAttackPathPhrase:
    @pytest.mark.parametrize(
        ("kind", "one", "many"),
        [
            ("data store", "a data store", "data stores"),
            ("secret store", "a secret store", "secret stores"),
            ("administrator identity", "an administrator identity", "administrator identities"),
            ("cluster-admin grant", "a cluster-admin grant", "cluster-admin grants"),
            ("private data", "private data", "private data"),
        ],
    )
    def test_a_path_is_named_by_what_it_ends_at(self, kind: str, one: str, many: str) -> None:
        assert (
            attack_path_phrase([path(kind)]) == f"1 attack path from the internet to {one} (high)"
        )
        two = attack_path_phrase([path(kind, name="a"), path(kind, name="b")])
        assert two == f"2 attack paths from the internet to {many}, worst high"

    def test_the_zone_of_the_last_hop_is_not_the_target(self) -> None:
        # The agent workstation used to read "to private": a network zone, not a thing
        phrase = attack_path_phrase([path("private data", zone="private")])
        assert phrase == "1 attack path from the internet to private data (high)"

    def test_several_kinds_are_listed_most_common_first(self) -> None:
        paths = [
            path("secret store", name="a"),
            path("data store", name="b"),
            path("data store", name="c"),
        ]
        assert attack_path_phrase(paths) == (
            "3 attack paths from the internet to data stores and secret stores, worst high"
        )

    def test_the_worst_path_is_named_so_a_critical_one_is_not_hidden(self) -> None:
        paths = [path("data store", severity=s, name=s.value) for s in Severity]
        assert attack_path_phrase(paths).endswith(", worst critical")

    @pytest.mark.parametrize(
        ("zone", "noun"),
        [
            ("data", "data"),
            ("private", "private workloads"),
            ("dmz", "the DMZ"),
            ("management", "management resources"),
            ("surprise", "sensitive targets"),
            ("", "sensitive targets"),
        ],
    )
    def test_a_path_with_no_kind_falls_back_to_a_noun_for_its_zone(
        self, zone: str, noun: str
    ) -> None:
        assert attack_path_phrase([path(zone=zone)]) == (
            f"1 attack path from the internet to {noun} (high)"
        )

    def test_text_the_tables_do_not_know_is_never_echoed(self) -> None:
        phrase = attack_path_phrase(
            [path("<script>alert(1)</script>", zone="x\x1b[2J", entry_zone="# heading")]
        )
        assert phrase == "1 attack path from an exposed entry point to sensitive targets (high)"

    def test_no_paths_is_no_phrase(self) -> None:
        assert attack_path_phrase([]) == ""


def report(**fields: object) -> ThreatReport:
    coverage = fields.pop("coverage", Coverage(units_parsed=1))
    assert isinstance(coverage, Coverage)
    return ThreatReport(coverage=coverage, **fields)  # type: ignore[arg-type]


class TestVerdictLine:
    def test_findings_then_the_paths(self) -> None:
        threats = [make_threat(1, Severity.CRITICAL), make_threat(2, Severity.HIGH)]
        line = verdict_line(report(threats=threats, attack_paths=[path("data store")]))
        assert line == "1 critical, 1 high, 1 attack path from the internet to a data store (high)"

    def test_a_clean_scan_says_so(self) -> None:
        assert verdict_line(report()) == "no findings"

    def test_a_scan_that_failed_to_read_anything_is_not_clean(self) -> None:
        errors = [{"file": "main.tf", "code": "parse.failed", "message": "bad"}]
        line = verdict_line(report(coverage=Coverage(units_parsed=0, errors=errors)))
        assert line == "no result (1 input error; nothing was analysed)"

    def test_a_scan_that_read_part_of_its_input_says_incomplete(self) -> None:
        errors = [{"file": "a.tf", "code": "parse.failed", "message": "bad"}] * 2
        line = verdict_line(
            report(
                threats=[make_threat(1, Severity.HIGH)],
                coverage=Coverage(units_parsed=3, errors=errors),
            )
        )
        assert line == "incomplete (2 input errors); in the rest: 1 high"

    def test_incomplete_with_nothing_found_in_the_rest(self) -> None:
        errors = [{"file": "a.tf", "code": "parse.failed", "message": "bad"}]
        line = verdict_line(report(coverage=Coverage(units_parsed=2, errors=errors)))
        assert line == "incomplete (1 input error); in the rest: no findings"

    def test_everything_baselined_says_what_the_baseline_hid(self) -> None:
        coverage = Coverage(units_parsed=1, baselined=8, baselined_paths=2)
        assert verdict_line(report(coverage=coverage)) == (
            "no new findings (6 findings and 2 attack paths baselined)"
        )

    def test_only_attack_paths_baselined(self) -> None:
        coverage = Coverage(units_parsed=1, baselined=1, baselined_paths=1)
        assert verdict_line(report(coverage=coverage)) == (
            "no new findings (1 attack path baselined)"
        )

    def test_everything_hidden_by_min_severity_says_so(self) -> None:
        coverage = Coverage(units_parsed=1, hidden_findings=7, hidden_paths=2, min_severity="high")
        assert verdict_line(report(coverage=coverage)) == (
            "no findings at or above high (7 findings and 2 attack paths hidden by --min-severity)"
        )

    def test_the_phrases_carry_the_severity_that_colors_them(self) -> None:
        items = verdict_items(
            report(
                threats=[make_threat(1, Severity.HIGH)],
                attack_paths=[path(severity=Severity.CRITICAL)],
            )
        )
        assert [style for _text, style in items] == ["high", "critical"]


class TestVerdictInTheTextReport:
    def test_a_critical_path_is_visible_in_the_verdict_over_high_findings(self) -> None:
        text = format_text(
            analysis_of(
                make_threat(1, Severity.HIGH), attack_paths=[path(severity=Severity.CRITICAL)]
            ),
            RenderOptions(width=200),
        )
        assert "Verdict: 1 high, 1 attack path from the internet to data (critical)" in text

    def test_a_failed_scan_never_reads_as_clean(self) -> None:
        errors = [{"file": "main.tf", "code": "parse.failed", "message": "bad"}]
        text = format_text(
            analysis_of(coverage=Coverage(units_parsed=0, errors=errors)), RenderOptions(width=100)
        )
        assert "Verdict: no result (1 input error; nothing was analysed)" in text
        assert "no findings" not in text

    def test_the_verdict_wraps_at_the_terminal_width_with_a_hanging_indent(self) -> None:
        threats = [make_threat(i, s) for i, s in enumerate(Severity, start=1)]
        text = format_text(
            analysis_of(*threats, attack_paths=[path("administrator identity")]),
            RenderOptions(width=50),
        )
        lines = text.split("Verdict: ")[1].split("\n\n")[0].splitlines()
        assert len(lines) > 1
        assert all(len(line) + 9 <= 50 for line in lines[:1])
        assert all(line.startswith(" " * 9) and len(line) <= 50 for line in lines[1:])

    def test_markdown_prints_the_same_verdict(self) -> None:
        analysis = analysis_of(make_threat(1, Severity.HIGH), attack_paths=[path("data store")])
        verdict = verdict_line(analysis.report)
        assert f"- **Verdict:** {verdict}" in format_markdown(analysis.report)
