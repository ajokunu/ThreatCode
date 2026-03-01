"""Tests for threatcode.formatters.diff."""

from __future__ import annotations

import json
from pathlib import Path

from threatcode.formatters.diff import compute_diff, format_diff


def _write_report(path: Path, threats: list[dict]) -> None:
    data = {"input_file": str(path), "threats": threats}
    path.write_text(json.dumps(data))


class TestComputeDiff:
    def test_added_threats(self, tmp_path: Path) -> None:
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        t = {"id": "t1", "title": "New", "severity": "high", "resource_address": "a.b"}
        _write_report(baseline, [])
        _write_report(current, [t])
        result = compute_diff(str(baseline), str(current))
        assert len(result["added"]) == 1
        assert result["removed"] == []

    def test_removed_threats(self, tmp_path: Path) -> None:
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        t = {"id": "t1", "title": "Old", "severity": "high", "resource_address": "a.b"}
        _write_report(baseline, [t])
        _write_report(current, [])
        result = compute_diff(str(baseline), str(current))
        assert len(result["removed"]) == 1
        assert result["added"] == []

    def test_unchanged_count(self, tmp_path: Path) -> None:
        t = {"id": "t1", "title": "Same", "severity": "high", "resource_address": "a.b"}
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        _write_report(baseline, [t])
        _write_report(current, [t])
        result = compute_diff(str(baseline), str(current))
        assert result["unchanged_count"] == 1

    def test_totals(self, tmp_path: Path) -> None:
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        _write_report(baseline, [{"id": "t1"}, {"id": "t2"}])
        _write_report(current, [{"id": "t2"}, {"id": "t3"}])
        result = compute_diff(str(baseline), str(current))
        assert result["baseline_total"] == 2
        assert result["current_total"] == 2


class TestFormatDiff:
    def test_json_format(self, tmp_path: Path) -> None:
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        _write_report(baseline, [])
        _write_report(current, [])
        result = compute_diff(str(baseline), str(current))
        output = format_diff(result, "json")
        data = json.loads(output)
        assert "unchanged_count" in data

    def test_markdown_format(self, tmp_path: Path) -> None:
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        _write_report(baseline, [])
        t = {"id": "t1", "title": "New", "severity": "high", "resource_address": "a.b"}
        _write_report(current, [t])
        result = compute_diff(str(baseline), str(current))
        output = format_diff(result, "markdown")
        assert "# Threat Model Diff" in output
        assert "New Threats" in output

    def test_no_changes_markdown(self, tmp_path: Path) -> None:
        baseline = tmp_path / "b.json"
        current = tmp_path / "c.json"
        _write_report(baseline, [])
        _write_report(current, [])
        result = compute_diff(str(baseline), str(current))
        output = format_diff(result, "markdown")
        assert "No changes detected." in output
