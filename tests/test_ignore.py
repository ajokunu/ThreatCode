"""Tests for .threatcodeignore file parser."""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path

from threatcode.ignore import apply_ignore, load_ignore_ids


class TestLoadIgnoreIds:
    def test_basic_ids(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".threatcodeignore"
        ignore_file.write_text("CVE-2023-12345\nTC-DOCKER-001\n")
        ids = load_ignore_ids(search_dir=tmp_path)
        assert "CVE-2023-12345" in ids
        assert "TC-DOCKER-001" in ids

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".threatcodeignore"
        ignore_file.write_text("# This is a comment\n\nCVE-2023-1\n\n# Another\nCVE-2023-2\n")
        ids = load_ignore_ids(search_dir=tmp_path)
        assert ids == frozenset({"CVE-2023-1", "CVE-2023-2"})

    def test_expiration_future(self, tmp_path: Path) -> None:
        future = (date.today() + timedelta(days=30)).isoformat()
        ignore_file = tmp_path / ".threatcodeignore"
        ignore_file.write_text(f"CVE-2023-1  exp:{future}\n")
        ids = load_ignore_ids(search_dir=tmp_path)
        assert "CVE-2023-1" in ids

    def test_expiration_past(self, tmp_path: Path) -> None:
        past = (date.today() - timedelta(days=1)).isoformat()
        ignore_file = tmp_path / ".threatcodeignore"
        ignore_file.write_text(f"CVE-2023-1  exp:{past}\n")
        ids = load_ignore_ids(search_dir=tmp_path)
        assert "CVE-2023-1" not in ids

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        ids = load_ignore_ids(search_dir=tmp_path)
        assert ids == frozenset()

    def test_explicit_path(self, tmp_path: Path) -> None:
        custom = tmp_path / "my-ignore"
        custom.write_text("RULE-1\n")
        ids = load_ignore_ids(ignore_path=custom)
        assert "RULE-1" in ids

    def test_invalid_expiration_still_loads_id(self, tmp_path: Path) -> None:
        ignore_file = tmp_path / ".threatcodeignore"
        ignore_file.write_text("CVE-2023-1  exp:not-a-date\n")
        ids = load_ignore_ids(search_dir=tmp_path)
        # Invalid date logs warning but ID is still loaded
        assert "CVE-2023-1" in ids


class TestApplyIgnore:
    def test_filters_by_id(self) -> None:
        findings = [
            {"id": "CVE-1", "title": "a"},
            {"id": "CVE-2", "title": "b"},
            {"id": "CVE-3", "title": "c"},
        ]
        result = apply_ignore(findings, frozenset({"CVE-1", "CVE-3"}))
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2"

    def test_custom_id_key(self) -> None:
        findings = [
            {"vuln_id": "CVE-1", "title": "a"},
            {"vuln_id": "CVE-2", "title": "b"},
        ]
        result = apply_ignore(findings, frozenset({"CVE-1"}), id_key="vuln_id")
        assert len(result) == 1

    def test_empty_ignore_returns_all(self) -> None:
        findings = [{"id": "CVE-1"}]
        result = apply_ignore(findings, frozenset())
        assert len(result) == 1
