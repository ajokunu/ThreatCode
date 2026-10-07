"""Tests for threatcode.suppressions: ignore files and baselines."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from threatcode import suppressions
from threatcode.exceptions import ConfigError, ThreatCodeError
from threatcode.models.threat import Severity, Threat, ThreatSource

TODAY = date(2026, 10, 7)


def make_threat(
    rule_id: str = "S3_NO_ENCRYPTION",
    *,
    threat_id: str = "aaaaaaaaaaaa",
    fingerprint: str = "f" * 16,
    aliases: list[str] | None = None,
    source: ThreatSource = ThreatSource.RULE,
    severity: Severity = Severity.HIGH,
    address: str = "aws_s3_bucket.logs",
) -> Threat:
    return Threat(
        id=threat_id,
        title="t",
        description="d",
        stride_category="tampering",
        severity=severity,
        source=source,
        resource_type="aws_s3_bucket",
        resource_address=address,
        rule_id=rule_id,
        fingerprint=fingerprint,
        aliases=aliases or [],
    )


def parse(text: str) -> suppressions.IgnoreFile:
    return suppressions.parse(text, Path(".threatcodeignore"), TODAY)


class TestParse:
    def test_entries_comments_and_blank_lines(self) -> None:
        ignore = parse("# a comment\n\nS3_NO_ENCRYPTION\n  CVE-2023-1  \n")
        assert [e.id for e in ignore.entries] == ["S3_NO_ENCRYPTION", "CVE-2023-1"]
        assert [e.line for e in ignore.entries] == [3, 4]
        assert ignore.notices == []

    def test_an_inline_comment_is_dropped(self) -> None:
        ignore = parse("S3_NO_LOGGING exp:2027-01-01  # accepted for now\n")
        assert [e.id for e in ignore.entries] == ["S3_NO_LOGGING"]
        assert ignore.entries[0].expires == date(2027, 1, 1)

    def test_a_future_date_is_active_and_a_past_date_is_expired(self) -> None:
        ignore = parse("A exp:2026-10-07\nB exp:2026-10-06\nC exp:2099-01-01\n")
        assert [(e.id, e.expired) for e in ignore.entries] == [
            ("A", False),
            ("B", True),
            ("C", False),
        ]

    def test_a_malformed_date_counts_as_expired_and_is_warned(self) -> None:
        ignore = parse("S3_NO_ENCRYPTION exp:next-week\nOTHER exp:2026-13-45\n")
        assert all(e.expired for e in ignore.entries)
        assert len(ignore.notices) == 2
        assert "invalid expiration date 'next-week'" in ignore.notices[0]
        assert ".threatcodeignore:1" in ignore.notices[0]

    def test_a_reason_is_kept_with_its_spaces(self) -> None:
        ignore = parse('RULE reason:"covered by the bucket policy" exp:2030-01-01\n')
        assert ignore.entries[0].reason == "covered by the bucket policy"

    def test_a_scoped_entry_is_skipped_so_it_cannot_suppress_more_than_written(self) -> None:
        ignore = parse("RULE resource=aws_s3_bucket.logs\nOTHER file=main.tf\n")
        assert ignore.entries == []
        assert len(ignore.notices) == 2
        assert "not supported yet" in ignore.notices[0]

    def test_an_unknown_option_skips_the_entry(self) -> None:
        ignore = parse("RULE colour:blue\n")
        assert ignore.entries == []
        assert "unknown option 'colour:blue'" in ignore.notices[0]

    def test_an_unbalanced_quote_skips_the_line_and_keeps_reading(self) -> None:
        ignore = parse('BAD reason:"never closed\nGOOD\n')
        assert [e.id for e in ignore.entries] == ["GOOD"]
        assert "cannot read the line" in ignore.notices[0]


class TestLoad:
    def test_reads_the_file_at_the_scan_root(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").write_text("S3_NO_ENCRYPTION\n")
        ignore = suppressions.load(None, tmp_path, today=TODAY)
        assert ignore is not None
        assert ignore.path == tmp_path / ".threatcodeignore"
        assert [e.id for e in ignore.entries] == ["S3_NO_ENCRYPTION"]

    def test_no_file_at_the_root_is_not_an_error(self, tmp_path: Path) -> None:
        assert suppressions.load(None, tmp_path) is None

    def test_an_explicit_file_wins_over_the_root_file(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").write_text("AUTO\n")
        custom = tmp_path / "custom.ignore"
        custom.write_text("CUSTOM\n")
        ignore = suppressions.load(custom, tmp_path)
        assert ignore is not None
        assert [e.id for e in ignore.entries] == ["CUSTOM"]

    def test_a_missing_explicit_file_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Ignore file not found"):
            suppressions.load(tmp_path / "missing.ignore", tmp_path)

    def test_no_ignore_disables_both_the_root_file_and_an_explicit_one(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / ".threatcodeignore").write_text("AUTO\n")
        assert suppressions.load(None, tmp_path, no_ignore=True) is None
        assert suppressions.load(tmp_path / "x", tmp_path, no_ignore=True) is None

    def test_a_directory_named_as_the_ignore_file_is_not_read(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").mkdir()
        assert suppressions.load(None, tmp_path) is None

    def test_a_file_that_is_not_text_is_a_config_error(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").write_bytes(b"\xff\xfe\x00bad")
        with pytest.raises(ConfigError, match="Cannot read ignore file"):
            suppressions.load(None, tmp_path)


class TestApply:
    def test_matches_by_rule_id_threat_id_fingerprint_and_aliases(self) -> None:
        threats = [
            make_threat("RULE_A", threat_id="id0000000001", fingerprint="1" * 16),
            make_threat("RULE_B", threat_id="id0000000002", fingerprint="2" * 16),
            make_threat("RULE_C", threat_id="id0000000003", fingerprint="3" * 16),
            make_threat(
                "trivy:CVE-2023-1", threat_id="id0000000004", aliases=["CVE-2023-1", "GHSA-xxxx"]
            ),
            make_threat("RULE_E", threat_id="id0000000005", fingerprint="5" * 16),
        ]
        ignore = parse(f"RULE_A\nid0000000002\n{'3' * 16}\nGHSA-xxxx\n")
        result = suppressions.apply(threats, ignore)
        assert [t.rule_id for t in result.kept] == ["RULE_E"]
        assert len(result.suppressed) == 4

    def test_matching_ignores_case(self) -> None:
        result = suppressions.apply(
            [make_threat("S3_NO_ENCRYPTION", aliases=["CVE-2023-9"])],
            parse("s3_no_encryption\ncve-2023-9\n"),
        )
        assert result.kept == []

    def test_an_entry_that_matches_nothing_is_reported_once(self) -> None:
        result = suppressions.apply([make_threat("RULE_A")], parse("RULE_A\nGHOST\n"))
        assert [e.id for e in result.unmatched] == ["GHOST"]
        assert sum("GHOST matched no finding" in n for n in result.notices) == 1

    def test_per_entry_counts_include_every_entry_that_matches(self) -> None:
        threats = [make_threat("RULE_A", threat_id=f"id{i:010d}") for i in range(3)]
        result = suppressions.apply(threats, parse("RULE_A\nid0000000001\n"))
        assert [(e.id, n) for e, n in result.matches] == [("RULE_A", 3), ("id0000000001", 1)]
        assert result.unmatched == []

    def test_an_expired_entry_suppresses_nothing_and_is_reported(self) -> None:
        threat = make_threat("RULE_A")
        result = suppressions.apply([threat], parse("RULE_A exp:2020-01-01\n"))
        assert result.kept == [threat]
        assert result.suppressed == []
        assert [e.id for e in result.expired] == ["RULE_A"]
        assert any("expired on 2020-01-01" in n for n in result.notices)
        assert result.unmatched == []

    def test_a_malformed_date_fails_closed(self) -> None:
        threat = make_threat("RULE_A")
        result = suppressions.apply([threat], parse("RULE_A exp:oops\n"))
        assert result.kept == [threat]
        assert any("invalid expiration date" in n for n in result.notices)

    def test_without_an_ignore_file_everything_is_kept(self) -> None:
        threats = [make_threat("RULE_A")]
        result = suppressions.apply(threats, None)
        assert result.kept == threats
        assert result.suppressed == []
        assert result.notices == []

    def test_a_threat_without_aliases_or_fingerprint_does_not_match_an_empty_key(self) -> None:
        result = suppressions.apply([make_threat("R", fingerprint="")], parse("R2\n"))
        assert len(result.kept) == 1

    def test_the_order_of_kept_findings_is_preserved(self) -> None:
        threats = [make_threat(f"R{i}", threat_id=f"id{i:010d}") for i in range(5)]
        result = suppressions.apply(threats, parse("R1\nR3\n"))
        assert [t.rule_id for t in result.kept] == ["R0", "R2", "R4"]


class TestBaseline:
    def test_the_document_is_sorted_deduplicated_and_has_a_schema(self) -> None:
        threats = [
            make_threat("RULE_B", fingerprint="b" * 16, severity=Severity.LOW, address="b.b"),
            make_threat("RULE_A", fingerprint="a" * 16, severity=Severity.HIGH, address="a.a"),
            make_threat("RULE_A", fingerprint="a" * 16, severity=Severity.HIGH, address="a.a"),
        ]
        doc = suppressions.baseline_document(threats)
        assert doc["schema"] == suppressions.BASELINE_SCHEMA
        assert doc["entries"] == [
            {"fingerprint": "a" * 16, "rule_id": "RULE_A", "resource": "a.a", "severity": "high"},
            {"fingerprint": "b" * 16, "rule_id": "RULE_B", "resource": "b.b", "severity": "low"},
        ]

    def test_the_severity_recorded_is_the_effective_one(self) -> None:
        threat = make_threat("R", severity=Severity.LOW)
        threat.effective_severity = Severity.CRITICAL
        assert suppressions.baseline_document([threat])["entries"][0]["severity"] == "critical"

    def test_llm_findings_and_unfingerprinted_findings_are_left_out(self) -> None:
        threats = [
            make_threat("LLM", source=ThreatSource.LLM),
            make_threat("NOPRINT", fingerprint=""),
            make_threat("KEPT"),
        ]
        entries = suppressions.baseline_document(threats)["entries"]
        assert [e["rule_id"] for e in entries] == ["KEPT"]

    def test_write_and_load_round_trip(self, tmp_path: Path) -> None:
        threats = [make_threat("R1", fingerprint="1" * 16), make_threat("R2", fingerprint="2" * 16)]
        path = tmp_path / "out" / "baseline.json"
        written = suppressions.write_baseline(path, threats)
        assert written == path
        assert json.loads(path.read_text())["schema"] == suppressions.BASELINE_SCHEMA
        assert suppressions.load_baseline(path) == frozenset({"1" * 16, "2" * 16})

    def test_writing_to_a_directory_is_one_clear_error(self, tmp_path: Path) -> None:
        with pytest.raises(ThreatCodeError, match="cannot write .*it is a directory"):
            suppressions.write_baseline(tmp_path, [])

    def test_the_file_is_byte_stable_for_the_same_findings(self, tmp_path: Path) -> None:
        threats = [make_threat("R2", fingerprint="2" * 16), make_threat("R1", fingerprint="1" * 16)]
        suppressions.write_baseline(tmp_path / "a.json", threats)
        suppressions.write_baseline(tmp_path / "b.json", list(reversed(threats)))
        assert (tmp_path / "a.json").read_bytes() == (tmp_path / "b.json").read_bytes()

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ("not json", "Cannot read baseline"),
            ('["a"]', "is not a ThreatCode baseline"),
            ('{"entries": []}', "is not a ThreatCode baseline"),
            ('{"schema": "other/9", "entries": []}', "is not a ThreatCode baseline"),
            (f'{{"schema": "{suppressions.BASELINE_SCHEMA}", "entries": 3}}', "not a ThreatCode"),
        ],
    )
    def test_a_file_that_is_not_a_baseline_is_a_config_error(
        self, tmp_path: Path, content: str, message: str
    ) -> None:
        path = tmp_path / "b.json"
        path.write_text(content)
        with pytest.raises(ConfigError, match=message):
            suppressions.load_baseline(path)

    def test_a_missing_baseline_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Baseline file not found"):
            suppressions.load_baseline(tmp_path / "missing.json")

    def test_apply_baseline_splits_by_fingerprint_and_always_keeps_llm_findings(self) -> None:
        known = make_threat("OLD", fingerprint="1" * 16)
        new = make_threat("NEW", fingerprint="2" * 16)
        llm = make_threat("LLM", fingerprint="1" * 16, source=ThreatSource.LLM)
        kept, baselined = suppressions.apply_baseline([known, new, llm], frozenset({"1" * 16}))
        assert baselined == [known]
        assert kept == [new, llm]
