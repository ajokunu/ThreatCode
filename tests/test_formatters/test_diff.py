"""Tests for threatcode.formatters.diff."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.scan import scan_files
from threatcode.exceptions import ThreatCodeError
from threatcode.formatters.diff import compute_diff, format_diff, gating_threats, load_report
from threatcode.models.report import ThreatReport

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def threat(
    threat_id: str = "t1",
    severity: str = "high",
    title: str = "Title",
    address: str = "a.b",
    **extra: Any,
) -> dict[str, Any]:
    return {
        "id": threat_id,
        "title": title,
        "severity": severity,
        "resource_address": address,
        **extra,
    }


def write_report(path: Path, threats: list[dict[str, Any]], **extra: Any) -> str:
    data = {"schema_version": "2", "version": "0.9.1", "input_file": path.name, "threats": threats}
    data.update(extra)
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def diff_of(tmp_path: Path, before: list[dict[str, Any]], after: list[dict[str, Any]]) -> Any:
    return compute_diff(
        write_report(tmp_path / "b.json", before), write_report(tmp_path / "c.json", after)
    )


class TestLoadReport:
    def test_accepts_the_report_a_scan_writes(self, tmp_path: Path) -> None:
        result = scan_files([FIXTURES / "terraform" / "simple.tf"])
        path = tmp_path / "scan.json"
        path.write_text(json.dumps(result.report.to_dict()), encoding="utf-8")
        assert len(load_report(str(path))["threats"]) == len(result.threats)

    def test_accepts_an_older_report_that_has_version_but_no_schema_version(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "old.json"
        path.write_text(json.dumps({"version": "0.9.0", "threats": [threat()]}), encoding="utf-8")
        assert load_report(str(path))["threats"][0]["id"] == "t1"

    def test_a_missing_file_is_named(self, tmp_path: Path) -> None:
        with pytest.raises(ThreatCodeError, match="Report file not found"):
            load_report(str(tmp_path / "missing.json"))

    def test_invalid_json_is_named(self, tmp_path: Path) -> None:
        path = tmp_path / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ThreatCodeError, match="is not valid JSON"):
            load_report(str(path))

    def test_sarif_gets_its_own_message(self, tmp_path: Path) -> None:
        path = tmp_path / "scan.sarif"
        sarif = {"$schema": "https://sarif/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}
        path.write_text(json.dumps(sarif), encoding="utf-8")
        with pytest.raises(ThreatCodeError, match="is a SARIF file, not a ThreatCode report") as e:
            load_report(str(path))
        assert "scan -f json" in str(e.value)

    @pytest.mark.parametrize(
        "content",
        [{"foo": 1}, {"threats": "nope", "version": "1"}, {"version": "1"}],
    )
    def test_other_json_is_not_an_empty_baseline(self, tmp_path: Path, content: Any) -> None:
        path = tmp_path / "other.json"
        path.write_text(json.dumps(content), encoding="utf-8")
        with pytest.raises(ThreatCodeError, match="not a ThreatCode scan report"):
            load_report(str(path))

    def test_a_json_array_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "list.json"
        path.write_text("[1, 2]", encoding="utf-8")
        with pytest.raises(ThreatCodeError, match="expected a JSON object"):
            load_report(str(path))

    def test_a_report_without_a_version_marker_is_rejected(self, tmp_path: Path) -> None:
        path = tmp_path / "unmarked.json"
        path.write_text(json.dumps({"threats": []}), encoding="utf-8")
        with pytest.raises(ThreatCodeError, match="no schema_version or version"):
            load_report(str(path))

    @pytest.mark.parametrize(
        "bad",
        [
            "just a string",
            {"severity": "high"},
            {"id": "x"},
            {"id": 7, "severity": "high"},
            {"id": "x", "severity": "catastrophic"},
        ],
    )
    def test_every_threat_needs_an_id_and_a_known_severity(self, tmp_path: Path, bad: Any) -> None:
        path = tmp_path / "r.json"
        path.write_text(json.dumps({"version": "1", "threats": [threat(), bad]}), encoding="utf-8")
        with pytest.raises(ThreatCodeError, match="threat 2 must be an object with an 'id'"):
            load_report(str(path))


class TestComputeDiff:
    def test_added_threats(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [], [threat("t1", title="New")])
        assert [t["id"] for t in result["added"]] == ["t1"]
        assert result["removed"] == [] and result["changed"] == []

    def test_removed_threats(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [threat("t1")], [])
        assert [t["id"] for t in result["removed"]] == ["t1"]
        assert result["added"] == []

    def test_unchanged_count_counts_only_identical_threats(self, tmp_path: Path) -> None:
        same = threat("same")
        result = diff_of(tmp_path, [same, threat("sev", "low")], [same, threat("sev", "high")])
        assert result["unchanged_count"] == 1
        assert [c["id"] for c in result["changed"]] == ["sev"]

    def test_totals_are_the_true_list_lengths(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [threat("t1"), threat("t2")], [threat("t2"), threat("t3")])
        assert (result["baseline_total"], result["current_total"]) == (2, 2)

    def test_ids_are_compared_as_multisets(self, tmp_path: Path) -> None:
        twice = [threat("dup", title="A"), threat("dup", title="A")]
        result = diff_of(tmp_path, [threat("dup", title="A")], twice)
        assert len(result["added"]) == 1
        assert (result["baseline_total"], result["current_total"]) == (1, 2)
        assert result["unchanged_count"] == 1

        result = diff_of(tmp_path, twice, [threat("dup", title="A")])
        assert len(result["removed"]) == 1
        assert result["unchanged_count"] == 1

    def test_the_same_multiset_is_no_change(self, tmp_path: Path) -> None:
        twice = [threat("dup"), threat("dup")]
        result = diff_of(tmp_path, twice, list(twice))
        assert result["added"] == [] and result["removed"] == []
        assert result["unchanged_count"] == 2

    def test_a_severity_change_is_a_changed_threat_with_before_and_after(
        self, tmp_path: Path
    ) -> None:
        result = diff_of(tmp_path, [threat("t1", "medium")], [threat("t1", "critical")])
        (change,) = result["changed"]
        assert (change["severity_before"], change["severity_after"]) == ("medium", "critical")
        assert result["added"] == [] and result["removed"] == []
        assert result["unchanged_count"] == 0

    def test_a_title_change_is_a_changed_threat(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [threat("t1", title="Old")], [threat("t1", title="New")])
        (change,) = result["changed"]
        assert (change["title_before"], change["title_after"]) == ("Old", "New")

    def test_the_effective_severity_is_what_is_compared(self, tmp_path: Path) -> None:
        result = diff_of(
            tmp_path,
            [threat("t1", "low")],
            [threat("t1", "low", effective_severity="critical")],
        )
        (change,) = result["changed"]
        assert change["severity_after"] == "critical"

    def test_added_removed_and_changed_are_sorted_by_severity_then_title(
        self, tmp_path: Path
    ) -> None:
        added = [
            threat("a", "low", "Zed"),
            threat("b", "critical", "Beta"),
            threat("c", "critical", "Alpha"),
            threat("d", "medium", "Mid"),
        ]
        result = diff_of(tmp_path, [], added)
        assert [t["id"] for t in result["added"]] == ["c", "b", "d", "a"]

    def test_input_file_names_come_from_the_reports(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [], [])
        assert (result["baseline_file"], result["current_file"]) == ("b.json", "c.json")


class TestGating:
    def test_an_added_threat_at_or_above_the_threshold_gates(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [], [threat("a", "high"), threat("b", "low")])
        assert [t["id"] for t in gating_threats(result, "high")] == ["a"]
        assert len(gating_threats(result, "low")) == 2
        assert gating_threats(result, "critical") == []

    def test_a_worsened_threat_gates_but_an_improved_one_does_not(self, tmp_path: Path) -> None:
        result = diff_of(
            tmp_path,
            [threat("worse", "low"), threat("better", "critical")],
            [threat("worse", "high"), threat("better", "low")],
        )
        offenders = gating_threats(result, "high")
        assert [o["id"] for o in offenders] == ["worse"]

    def test_a_worsened_threat_still_below_the_threshold_does_not_gate(
        self, tmp_path: Path
    ) -> None:
        result = diff_of(tmp_path, [threat("t", "info")], [threat("t", "low")])
        assert gating_threats(result, "high") == []

    def test_resolved_threats_never_gate(self, tmp_path: Path) -> None:
        assert gating_threats(diff_of(tmp_path, [threat("t", "critical")], []), "info") == []


class TestFormatDiff:
    def test_json_format_round_trips(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [], [threat("t1")])
        assert json.loads(format_diff(result, "json")) == result

    def test_markdown_lists_each_bucket_without_em_dashes(self, tmp_path: Path) -> None:
        result = diff_of(
            tmp_path,
            [threat("gone", title="Gone"), threat("moved", "low", "Moved")],
            [threat("new", "critical", "Brand new"), threat("moved", "high", "Moved")],
        )
        text = format_diff(result, "markdown")
        assert "## New Threats (+1) - 1 critical" in text
        assert "## Resolved Threats (-1)" in text
        assert "## Changed Threats (1)" in text
        assert "low -> high" in text
        assert chr(0x2014) not in text

    def test_markdown_pluralizes(self, tmp_path: Path) -> None:
        text = format_diff(diff_of(tmp_path, [threat("a")], [threat("a"), threat("b")]), "markdown")
        assert "**Baseline:** 1 threat\n" in text
        assert "**Current:** 2 threats\n" in text

    def test_no_changes_markdown(self, tmp_path: Path) -> None:
        assert "No changes detected." in format_diff(diff_of(tmp_path, [], []), "markdown")

    def test_text_format_marks_each_bucket(self, tmp_path: Path) -> None:
        result = diff_of(
            tmp_path,
            [threat("gone", "low", "Gone"), threat("moved", "low", "Moved")],
            [threat("new", "high", "Fresh"), threat("moved", "high", "Moved")],
        )
        lines = format_diff(result, "text").splitlines()
        assert lines[0].startswith("Baseline 2 threats, current 2 threats")
        assert any(line.startswith("+ high") and "Fresh" in line for line in lines)
        assert any(line.startswith("- low") and "Gone" in line for line in lines)
        assert any(line.startswith("~ low -> high") and "Moved" in line for line in lines)

    def test_a_scan_report_diffs_against_itself_with_no_changes(self, tmp_path: Path) -> None:
        report: ThreatReport = scan_files([FIXTURES / "terraform" / "simple.tf"]).report
        path = tmp_path / "r.json"
        path.write_text(json.dumps(report.to_dict()), encoding="utf-8")
        result = compute_diff(str(path), str(path))
        assert result["added"] == result["removed"] == result["changed"] == []
        assert result["unchanged_count"] == len(report.threats) > 0


def attack_path(
    path_id: str,
    severity: str = "critical",
    entry: str = "internet",
    target: str = "aws_db_instance.main",
    score: float = 50.0,
    hops: int = 3,
) -> dict[str, Any]:
    return {
        "id": path_id,
        "entry": entry,
        "target": target,
        "severity": severity,
        "score": score,
        "hops": [{"node_id": f"n{i}"} for i in range(hops)],
    }


def diff_with_paths(
    tmp_path: Path, before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> Any:
    return compute_diff(
        write_report(tmp_path / "b.json", [], attack_paths=before),
        write_report(tmp_path / "c.json", [], attack_paths=after),
    )


class TestAttackPaths:
    def test_paths_are_added_and_removed_by_id(self, tmp_path: Path) -> None:
        result = diff_with_paths(
            tmp_path,
            [attack_path("old"), attack_path("kept")],
            [attack_path("kept"), attack_path("new", "high")],
        )
        assert [p["id"] for p in result["attack_paths_added"]] == ["new"]
        assert [p["id"] for p in result["attack_paths_removed"]] == ["old"]
        added = result["attack_paths_added"][0]
        assert added == {
            "id": "new",
            "entry": "internet",
            "target": "aws_db_instance.main",
            "severity": "high",
            "score": 50.0,
            "hops": 2,
        }

    def test_paths_are_sorted_by_severity_then_score_then_id(self, tmp_path: Path) -> None:
        result = diff_with_paths(
            tmp_path,
            [],
            [
                attack_path("c", "high", score=9),
                attack_path("a", "critical", score=1),
                attack_path("b", "high", score=9),
                attack_path("d", "high", score=20),
            ],
        )
        assert [p["id"] for p in result["attack_paths_added"]] == ["a", "d", "b", "c"]

    def test_a_report_from_before_attack_paths_has_none(self, tmp_path: Path) -> None:
        result = diff_of(tmp_path, [], [])
        assert result["attack_paths_added"] == result["attack_paths_removed"] == []

    def test_a_path_alone_is_a_change(self, tmp_path: Path) -> None:
        result = diff_with_paths(tmp_path, [], [attack_path("new")])
        text = format_diff(result, "markdown")
        assert "No changes detected." not in text
        assert "No changes detected." not in format_diff(result, "text")

    def test_paths_are_listed_before_threats_in_every_format(self, tmp_path: Path) -> None:
        result = compute_diff(
            write_report(tmp_path / "b.json", [threat("gone")], attack_paths=[attack_path("old")]),
            write_report(tmp_path / "c.json", [threat("new")], attack_paths=[attack_path("fresh")]),
        )
        markdown = format_diff(result, "markdown")
        assert markdown.index("## New Attack Paths (+1)") < markdown.index("## New Threats")
        assert markdown.index("## Closed Attack Paths (-1)") < markdown.index("## New Threats")
        assert "- **critical** `internet` to `aws_db_instance.main` (2 hops) - `fresh`" in markdown
        assert "~~`internet` to `aws_db_instance.main`~~" in markdown
        lines = format_diff(result, "text").splitlines()
        first_threat = next(i for i, ln in enumerate(lines) if "a.b" in ln)
        path_lines = [i for i, ln in enumerate(lines) if "attack path" in ln]
        assert path_lines and max(path_lines) < first_threat
        assert "+ critical attack path internet -> aws_db_instance.main (2 hops)" in lines
        assert json.loads(format_diff(result, "json"))["attack_paths_added"][0]["id"] == "fresh"

    def test_a_new_path_gates_at_or_above_its_severity(self, tmp_path: Path) -> None:
        result = diff_with_paths(tmp_path, [], [attack_path("p", "high")])
        assert [o["id"] for o in gating_threats(result, "high")] == ["p"]
        assert gating_threats(result, "critical") == []

    def test_a_closed_path_never_gates(self, tmp_path: Path) -> None:
        assert gating_threats(diff_with_paths(tmp_path, [attack_path("p")], []), "info") == []

    @pytest.mark.parametrize("bad", ["x", {"id": "p"}, [1], [{"no": "id"}], [{"id": ""}]])
    def test_malformed_attack_paths_are_rejected_with_a_message(
        self, tmp_path: Path, bad: Any
    ) -> None:
        path = write_report(tmp_path / "r.json", [], attack_paths=bad)
        with pytest.raises(ThreatCodeError, match="'attack_paths' must be a list"):
            load_report(path)


class TestMarkdownIsInert:
    def test_hostile_titles_and_addresses_stay_inline(self, tmp_path: Path) -> None:
        hostile = threat(
            "x",
            "high",
            title="\n# Fake heading\n- item @octocat <img src=x> [l](http://e) | a",
            address='res.a`b["c"]|d',
        )
        text = format_diff(diff_of(tmp_path, [], [hostile]), "markdown")
        assert not any(line.startswith(("# Fake", "- item")) for line in text.splitlines())
        assert "@octocat" not in text and "@‍octocat" in text
        assert "<img" not in text.replace("\\<img", "")
        assert "](http://e" not in text
        assert "``res.a`b" in text.replace("` `", "") or 'res.a`b["c"]|d' in text

    def test_arrows_are_not_mangled(self, tmp_path: Path) -> None:
        text = format_diff(
            diff_of(tmp_path, [], [threat("x", title="dmz -> data (x)")]), "markdown"
        )
        assert "dmz -> data (x)" in text
        assert "-\\>" not in text and "\\(" not in text

    def test_a_changed_title_is_escaped_too(self, tmp_path: Path) -> None:
        result = diff_of(
            tmp_path, [threat("t", "low", "Old *title*")], [threat("t", "high", "New <b>title</b>")]
        )
        text = format_diff(result, "markdown")
        assert "was titled Old \\*title\\*" in text
        assert "<b>" not in text.replace("\\<b>", "")

    def test_there_are_no_em_dashes_in_any_format(self, tmp_path: Path) -> None:
        result = diff_with_paths(tmp_path, [attack_path("a")], [attack_path("b")])
        for fmt in ("markdown", "text", "json"):
            assert chr(0x2014) not in format_diff(result, fmt)
