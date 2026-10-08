"""Tests for threatcode.suppressions: ignore files and baselines."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from threatcode import suppressions
from threatcode.exceptions import ConfigError, ThreatCodeError
from threatcode.models.attack_path import AttackHop, AttackPath, attack_path_id
from threatcode.models.report import Coverage
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.pipeline import (
    EXIT_FINDINGS,
    EXIT_OK,
    ScanResult,
    compute_exit_code,
    prepare_request,
    run_scan,
)

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


def make_path(*nodes: str, severity: Severity = Severity.HIGH) -> AttackPath:
    return AttackPath(
        id=attack_path_id(nodes),
        entry="internet",
        target=nodes[-1],
        hops=[AttackHop(node_id=n) for n in nodes],
        severity=severity,
    )


def parse(text: str, deprecated_ids: frozenset[str] = frozenset()) -> suppressions.IgnoreFile:
    return suppressions.parse(text, Path(".threatcodeignore"), TODAY, deprecated_ids=deprecated_ids)


def real_notices(ignore: suppressions.IgnoreFile) -> list[str]:
    """The notices that are not the missing-reason or global-entry warnings."""
    return [n for n in ignore.notices if "no reason" not in n and "global entry" not in n]


class TestParse:
    def test_entries_comments_and_blank_lines(self) -> None:
        ignore = parse("# a comment\n\nS3_NO_ENCRYPTION\n  CVE-2023-1  \n")
        assert [e.id for e in ignore.entries] == ["S3_NO_ENCRYPTION", "CVE-2023-1"]
        assert [e.line for e in ignore.entries] == [3, 4]
        assert real_notices(ignore) == []

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
        invalid = [n for n in ignore.notices if "invalid expiration date" in n]
        assert len(invalid) == 2
        assert "invalid expiration date 'next-week'" in invalid[0]
        assert ".threatcodeignore:1" in invalid[0]

    def test_a_reason_is_kept_with_its_spaces(self) -> None:
        ignore = parse('RULE reason:"covered by the bucket policy" exp:2030-01-01\n')
        assert ignore.entries[0].reason == "covered by the bucket policy"

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


class TestEntryForms:
    def test_the_full_form_is_read(self) -> None:
        ignore = parse(
            'S3_NO_ENCRYPTION resource="aws_s3_bucket.logs*" file=infra/prod/* '
            'exp:2030-01-01 reason="SSE is enforced by the account"\n'
        )
        (entry,) = ignore.entries
        assert entry.id == "S3_NO_ENCRYPTION"
        assert entry.resource == "aws_s3_bucket.logs*"
        assert entry.file == "infra/prod/*"
        assert entry.expires == date(2030, 1, 1)
        assert entry.reason == "SSE is enforced by the account"
        assert entry.scoped
        assert ignore.notices == []

    def test_options_may_come_in_any_order_and_use_either_separator(self) -> None:
        ignore = parse('RULE reason="why" file=a.tf resource=x.y exp=2030-01-01\n')
        (entry,) = ignore.entries
        assert (entry.reason, entry.file, entry.resource) == ("why", "a.tf", "x.y")
        assert entry.expires == date(2030, 1, 1)

    @pytest.mark.parametrize(
        "line",
        [
            "CVE-2023-12345",
            "GHSA-abcd-efgh-ijkl",
            "S3_NO_ENCRYPTION",
            "aaaaaaaaaaaa",
            "9f2c4a7e1b3d5c80",
        ],
    )
    def test_every_kind_of_id_is_an_entry(self, line: str) -> None:
        assert [e.id for e in parse(line + "\n").entries] == [line]

    def test_a_quoted_glob_may_hold_spaces_and_brackets(self) -> None:
        ignore = parse("RULE 'resource=aws_s3_bucket.x[\"a b\"]'\n")
        # the quoted token is one option; the key is read from its start
        assert ignore.entries[0].resource == 'aws_s3_bucket.x["a b"]'

    def test_the_file_scope_is_normalised_to_posix_without_a_dot_prefix(self) -> None:
        assert parse("RULE file=./infra/*.tf\n").entries[0].file == "infra/*.tf"

    @pytest.mark.parametrize("option", ["resource=", "file="])
    def test_an_empty_scope_skips_the_entry_rather_than_widening_it(self, option: str) -> None:
        ignore = parse(f"RULE {option}\n")
        assert ignore.entries == []
        assert "needs a glob" in ignore.notices[0]

    def test_an_option_given_twice_skips_the_entry(self) -> None:
        ignore = parse("RULE resource=a.* resource=b.*\n")
        assert ignore.entries == []
        assert "appears twice" in ignore.notices[0]

    def test_an_unknown_option_skips_the_entry_even_next_to_valid_ones(self) -> None:
        ignore = parse("RULE resource=a.b severity=high\n")
        assert ignore.entries == []
        assert "unknown option 'severity=high'" in ignore.notices[0]

    def test_a_crlf_file_and_a_byte_order_mark_read_the_same(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").write_bytes(
            b"\xef\xbb\xbfFIRST exp:2030-01-01\r\n\r\nSECOND exp:2030-01-01\r\n"
        )
        ignore = suppressions.load(None, tmp_path, today=TODAY, env={})
        assert ignore is not None
        assert [(e.id, e.line) for e in ignore.entries] == [("FIRST", 1), ("SECOND", 3)]
        assert ignore.entries[0].expires == date(2030, 1, 1)

    def test_a_form_feed_inside_a_line_does_not_shift_line_numbers(self) -> None:
        ignore = parse("# a\x0cb\nFIRST\nSECOND\n")
        assert [(e.id, e.line) for e in ignore.entries] == [("FIRST", 2), ("SECOND", 3)]


class TestWarnings:
    def test_a_missing_reason_is_warned_with_the_line(self) -> None:
        ignore = parse("RULE_A exp:2030-01-01\n")
        assert [e.id for e in ignore.entries] == ["RULE_A"]
        assert any(".threatcodeignore:1: RULE_A has no reason" in n for n in ignore.notices)

    def test_a_blank_reason_counts_as_missing(self) -> None:
        ignore = parse('RULE_A exp:2030-01-01 reason=""\n')
        assert any("has no reason" in n for n in ignore.notices)

    def test_an_entry_with_a_reason_is_not_warned_about_it(self) -> None:
        ignore = parse('RULE_A exp:2030-01-01 reason="accepted"\n')
        assert ignore.notices == []

    def test_a_global_entry_without_an_expiry_is_warned(self) -> None:
        ignore = parse('RULE_A reason="accepted"\n')
        assert len(ignore.notices) == 1
        assert "global entry" in ignore.notices[0]
        assert "no expiry" in ignore.notices[0]

    @pytest.mark.parametrize(
        "line",
        [
            'RULE_A resource=a.b reason="r"',
            'RULE_A file=main.tf reason="r"',
            f'{"a" * 16} reason="r"',
            'RULE_A exp:2030-01-01 reason="r"',
        ],
    )
    def test_scoped_fingerprint_and_dated_entries_are_not_global_warnings(self, line: str) -> None:
        assert parse(line + "\n").notices == []

    def test_a_malformed_date_is_one_warning_not_two(self) -> None:
        ignore = parse('RULE_A exp:soon reason="r"\n')
        assert len(ignore.notices) == 1
        assert "invalid expiration date" in ignore.notices[0]

    def test_a_deprecated_rule_id_warns_that_it_was_removed_or_renamed(self) -> None:
        ignore = parse(
            'OLD_RULE exp:2030-01-01 reason="r"\nLIVE_RULE exp:2030-01-01 reason="r"\n',
            deprecated_ids=frozenset({"OLD_RULE"}),
        )
        assert len(ignore.notices) == 1
        assert (
            ".threatcodeignore:1: OLD_RULE names a rule that was removed or renamed"
            in (ignore.notices[0])
        )

    def test_deprecated_ids_match_without_regard_to_case(self) -> None:
        ignore = parse('old_rule exp:2030-01-01 reason="r"\n', frozenset({"OLD_RULE"}))
        assert len(ignore.notices) == 1

    def test_load_reads_deprecated_ids_from_the_built_in_rule_files(self, tmp_path: Path) -> None:
        from threatcode.engine.rules.loader import deprecated_rule_ids

        removed = sorted(deprecated_rule_ids())
        assert removed, "the built-in rule files list no deprecated ids"
        (tmp_path / ".threatcodeignore").write_text(
            f'{removed[0]} exp:2030-01-01 reason="r"\nS3_NO_ENCRYPTION exp:2030-01-01 reason="r"\n'
        )
        ignore = suppressions.load(None, tmp_path, today=TODAY, env={})
        assert ignore is not None
        assert [n for n in ignore.notices if "removed or renamed" in n] == [
            n for n in ignore.notices if removed[0] in n
        ]
        assert sum("removed or renamed" in n for n in ignore.notices) == 1

    def test_load_reads_deprecated_ids_from_extra_rule_files(self, tmp_path: Path) -> None:
        rules = tmp_path / "mine.yml"
        rules.write_text("deprecated_ids:\n  - MY_OLD_RULE\nrules: []\n")
        (tmp_path / ".threatcodeignore").write_text('MY_OLD_RULE exp:2030-01-01 reason="r"\n')
        ignore = suppressions.load(None, tmp_path, today=TODAY, env={}, extra_rule_paths=[rules])
        assert ignore is not None
        assert any("MY_OLD_RULE names a rule that was removed" in n for n in ignore.notices)


class TestScopes:
    def test_a_resource_glob_limits_the_entry_to_matching_addresses(self) -> None:
        a = make_threat("RULE_A", threat_id="id0000000001", address="aws_s3_bucket.logs")
        b = make_threat("RULE_A", threat_id="id0000000002", address="aws_s3_bucket.data")
        result = suppressions.apply([a, b], parse("RULE_A resource=aws_s3_bucket.l*\n"))
        assert result.suppressed == [a]
        assert result.kept == [b]

    def test_a_resource_with_brackets_matches_literally(self) -> None:
        threat = make_threat("RULE_A", address='aws_instance.web["a"]')
        result = suppressions.apply([threat], parse("RULE_A 'resource=aws_instance.web[\"a\"]'\n"))
        assert result.suppressed == [threat]

    def test_resource_globs_are_case_sensitive(self) -> None:
        threat = make_threat("RULE_A", address="aws_s3_bucket.Logs")
        result = suppressions.apply([threat], parse("RULE_A resource=aws_s3_bucket.logs\n"))
        assert result.kept == [threat]

    def test_a_file_glob_limits_the_entry_to_matching_files(self) -> None:
        prod = make_threat("RULE_A", threat_id="id0000000001")
        prod.location_file = "infra/prod/main.tf"
        dev = make_threat("RULE_A", threat_id="id0000000002")
        dev.location_file = "infra/dev/main.tf"
        result = suppressions.apply([prod, dev], parse("RULE_A file=infra/dev/*\n"))
        assert result.suppressed == [dev]
        assert result.kept == [prod]

    def test_a_file_scope_never_matches_a_finding_without_a_location(self) -> None:
        threat = make_threat("RULE_A")
        assert threat.location_file == ""
        result = suppressions.apply([threat], parse("RULE_A file=*\n"))
        assert result.kept == [threat]
        assert [e.id for e in result.unmatched] == ["RULE_A"]

    def test_windows_separators_in_a_location_are_normalised(self) -> None:
        threat = make_threat("RULE_A")
        threat.location_file = "infra\\dev\\main.tf"
        result = suppressions.apply([threat], parse("RULE_A file=infra/dev/*\n"))
        assert result.suppressed == [threat]

    def test_both_scopes_must_match(self) -> None:
        threat = make_threat("RULE_A", address="aws_s3_bucket.logs")
        threat.location_file = "infra/prod/main.tf"
        both = parse("RULE_A resource=aws_s3_bucket.logs file=infra/prod/*\n")
        wrong_file = parse("RULE_A resource=aws_s3_bucket.logs file=infra/dev/*\n")
        wrong_resource = parse("RULE_A resource=aws_s3_bucket.data file=infra/prod/*\n")
        assert suppressions.apply([threat], both).suppressed == [threat]
        assert suppressions.apply([threat], wrong_file).kept == [threat]
        assert suppressions.apply([threat], wrong_resource).kept == [threat]

    def test_a_scoped_fingerprint_entry_is_still_narrowed_by_its_scope(self) -> None:
        threat = make_threat("RULE_A", fingerprint="a" * 16, address="x.y")
        result = suppressions.apply([threat], parse(f"{'a' * 16} resource=other.*\n"))
        assert result.kept == [threat]

    def test_the_same_address_in_two_files_is_told_apart(self) -> None:
        prod = make_threat("RULE_A", threat_id="id0000000001", address="aws_s3_bucket.logs")
        prod.location_file = "prod/main.tf"
        dev = make_threat("RULE_A", threat_id="id0000000002", address="aws_s3_bucket.logs")
        dev.location_file = "dev/main.tf"
        result = suppressions.apply([prod, dev], parse("RULE_A file=dev/*\n"))
        assert result.suppressed == [dev]
        assert result.kept == [prod]

    def test_counts_are_per_entry_with_scopes(self) -> None:
        threats = [
            make_threat("RULE_A", threat_id=f"id{i:010d}", address=f"x.r{i}") for i in range(4)
        ]
        result = suppressions.apply(
            threats, parse("RULE_A resource=x.r0\nRULE_A resource=x.r*\nRULE_A resource=x.none\n")
        )
        assert [(e.resource, n) for e, n in result.matches] == [
            ("x.r0", 1),
            ("x.r*", 4),
            ("x.none", 0),
        ]
        assert [e.resource for e in result.unmatched] == ["x.none"]


class TestAttackPaths:
    def test_an_entry_naming_a_path_id_suppresses_that_path_only(self) -> None:
        a = make_path("internet", "aws_lb.web", "aws_db_instance.main")
        b = make_path("internet", "aws_lb.api", "aws_db_instance.main")
        result = suppressions.apply([], parse(f"{a.id}\n"), attack_paths=[a, b])
        assert result.suppressed_paths == [a]
        assert result.kept_paths == [b]
        assert result.unmatched == []

    def test_a_path_id_matches_without_regard_to_case(self) -> None:
        path = make_path("internet", "aws_lb.web")
        result = suppressions.apply([], parse(f"{path.id.upper()}\n"), attack_paths=[path])
        assert result.suppressed_paths == [path]

    def test_a_resource_scope_matches_any_resource_on_the_route(self) -> None:
        path = make_path("internet", "aws_lb.web", "aws_db_instance.main")
        hit = suppressions.apply([], parse(f"{path.id} resource=aws_lb.*\n"), attack_paths=[path])
        miss = suppressions.apply([], parse(f"{path.id} resource=aws_s3_*\n"), attack_paths=[path])
        assert hit.suppressed_paths == [path]
        assert miss.kept_paths == [path]

    def test_a_file_scope_never_matches_a_path(self) -> None:
        path = make_path("internet", "aws_lb.web")
        result = suppressions.apply([], parse(f"{path.id} file=*\n"), attack_paths=[path])
        assert result.kept_paths == [path]

    def test_a_rule_id_does_not_suppress_a_path(self) -> None:
        path = make_path("internet", "aws_lb.web")
        result = suppressions.apply([], parse("S3_NO_ENCRYPTION\n"), attack_paths=[path])
        assert result.kept_paths == [path]

    def test_an_expired_path_entry_suppresses_nothing(self) -> None:
        path = make_path("internet", "aws_lb.web")
        result = suppressions.apply([], parse(f"{path.id} exp:2020-01-01\n"), attack_paths=[path])
        assert result.kept_paths == [path]
        assert [e.id for e in result.expired] == [path.id]

    def test_one_entry_counts_findings_and_paths_together(self) -> None:
        path = make_path("internet", "aws_lb.web")
        threat = make_threat("RULE_A", threat_id=path.id)
        result = suppressions.apply([threat], parse(f"{path.id}\n"), attack_paths=[path])
        assert [(e.id, n) for e, n in result.matches] == [(path.id, 2)]

    def test_without_an_ignore_file_the_paths_are_kept(self) -> None:
        path = make_path("internet", "aws_lb.web")
        result = suppressions.apply([], None, attack_paths=[path])
        assert result.kept_paths == [path]

    def test_the_old_call_without_paths_is_unchanged(self) -> None:
        result = suppressions.apply([make_threat("RULE_A")], parse("RULE_A\n"))
        assert result.kept_paths == []
        assert result.suppressed_paths == []


class TestReport:
    def test_applied_unmatched_and_expired_entries_are_listed(self) -> None:
        threats = [make_threat("RULE_A", threat_id=f"id{i:010d}") for i in range(2)]
        ignore = parse(
            'RULE_A exp:2030-01-01 reason="accepted"\n'
            "GHOST exp:2030-01-01\n"
            'OLD exp:2020-01-01 reason="was fine"\n'
        )
        report = suppressions.apply(threats, ignore).report()
        assert report["applied"] == [
            {
                "id": "RULE_A",
                "reason": "accepted",
                "expires": "2030-01-01",
                "ignore_file": ".threatcodeignore",
                "line": 1,
                "scope": {"resource": "", "file": ""},
                "matched": 2,
            }
        ]
        assert [(e["id"], e["matched"], e["line"]) for e in report["unmatched"]] == [
            ("GHOST", 0, 2)
        ]
        assert [(e["id"], e["expires"], e["reason"]) for e in report["expired"]] == [
            ("OLD", "2020-01-01", "was fine")
        ]
        assert all("matched" not in e for e in report["expired"])

    def test_the_scope_of_an_applied_entry_is_reported(self) -> None:
        threat = make_threat("RULE_A", address="x.y")
        report = suppressions.apply([threat], parse("RULE_A resource=x.*\n")).report()
        assert report["applied"][0]["scope"] == {"resource": "x.*", "file": ""}
        assert report["applied"][0]["expires"] is None

    def test_a_report_without_an_ignore_file_is_empty(self) -> None:
        report = suppressions.apply([make_threat("RULE_A")], None).report()
        assert report == {"applied": [], "unmatched": [], "expired": []}

    def test_the_report_is_json_serialisable(self) -> None:
        report = suppressions.apply(
            [make_threat("R")], parse("R reason=x exp:2030-01-01\n")
        ).report()
        assert json.loads(json.dumps(report)) == report


class TestCiNotice:
    def test_a_file_inside_the_tree_in_ci_gets_the_notice(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").write_text('R exp:2030-01-01 reason="r"\n')
        ignore = suppressions.load(None, tmp_path, today=TODAY, env={"CI": "true"})
        assert ignore is not None
        (notice,) = [n for n in ignore.notices if "pull request" in n]
        assert "can edit it" in notice
        assert "--ignore-file" in notice

    def test_the_notice_reaches_the_apply_result(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcodeignore").write_text('R exp:2030-01-01 reason="r"\n')
        ignore = suppressions.load(None, tmp_path, today=TODAY, env={"CI": "1"})
        result = suppressions.apply([make_threat("R")], ignore)
        assert any("pull request" in n for n in result.notices)

    def test_an_explicit_file_inside_the_tree_gets_the_notice_too(self, tmp_path: Path) -> None:
        custom = tmp_path / "config" / "ignores.txt"
        custom.parent.mkdir()
        custom.write_text('R exp:2030-01-01 reason="r"\n')
        ignore = suppressions.load(custom, tmp_path, today=TODAY, env={"CI": "true"})
        assert ignore is not None
        assert any("pull request" in n for n in ignore.notices)

    def test_a_file_outside_the_tree_gets_no_notice(self, tmp_path: Path) -> None:
        tree = tmp_path / "repo"
        tree.mkdir()
        outside = tmp_path / "protected.ignore"
        outside.write_text('R exp:2030-01-01 reason="r"\n')
        ignore = suppressions.load(outside, tree, today=TODAY, env={"CI": "true"})
        assert ignore is not None
        assert ignore.notices == []

    def test_a_sibling_directory_with_a_shared_prefix_is_not_inside(self, tmp_path: Path) -> None:
        tree = tmp_path / "repo"
        tree.mkdir()
        sibling = tmp_path / "repo-protected"
        sibling.mkdir()
        (sibling / "ignores").write_text('R exp:2030-01-01 reason="r"\n')
        assert suppressions.ci_notice(sibling / "ignores", tree, {"CI": "true"}) is None

    @pytest.mark.parametrize("value", ["", "0", "false", "False", "no"])
    def test_without_ci_there_is_no_notice(self, tmp_path: Path, value: str) -> None:
        (tmp_path / ".threatcodeignore").write_text("R\n")
        assert (
            suppressions.ci_notice(tmp_path / ".threatcodeignore", tmp_path, {"CI": value}) is None
        )
        assert suppressions.ci_notice(tmp_path / ".threatcodeignore", tmp_path, {}) is None

    def test_the_real_environment_is_read_by_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        (tmp_path / ".threatcodeignore").write_text("R\n")
        monkeypatch.setenv("CI", "true")
        assert suppressions.ci_notice(tmp_path / ".threatcodeignore", tmp_path) is not None
        monkeypatch.delenv("CI")
        assert suppressions.ci_notice(tmp_path / ".threatcodeignore", tmp_path) is None


class TestBaselineWithPaths:
    def test_the_document_lists_paths_sorted_and_deduplicated(self) -> None:
        b = make_path("internet", "b.b", severity=Severity.LOW)
        a = make_path("internet", "a.a", severity=Severity.CRITICAL)
        doc = suppressions.baseline_document([], [b, a, a])
        assert doc["attack_paths"] == sorted(
            [
                {"id": a.id, "entry": "internet", "target": "a.a", "severity": "critical"},
                {"id": b.id, "entry": "internet", "target": "b.b", "severity": "low"},
            ],
            key=lambda p: p["id"],
        )

    def test_a_document_without_paths_has_an_empty_list(self) -> None:
        assert suppressions.baseline_document([])["attack_paths"] == []

    def test_round_trip_with_findings_and_paths(self, tmp_path: Path) -> None:
        threat = make_threat("R1", fingerprint="1" * 16)
        path = make_path("internet", "aws_lb.web", "aws_db_instance.main")
        target = tmp_path / "base.json"
        suppressions.write_baseline(target, [threat], [path])
        loaded = suppressions.load_baseline(target)
        assert loaded == frozenset({"1" * 16})
        assert loaded.path_ids == frozenset({path.id})
        kept, baselined = suppressions.apply_baseline([threat], loaded)
        assert (kept, baselined) == ([], [threat])
        kept_paths, baselined_paths = suppressions.apply_baseline_paths([path], loaded)
        assert (kept_paths, baselined_paths) == ([], [path])

    def test_a_new_path_is_kept_and_an_old_one_is_baselined(self, tmp_path: Path) -> None:
        old = make_path("internet", "aws_lb.web", "aws_db_instance.main")
        new = make_path("internet", "aws_lb.api", "aws_db_instance.main")
        target = tmp_path / "base.json"
        suppressions.write_baseline(target, [], [old])
        kept, baselined = suppressions.apply_baseline_paths(
            [old, new], suppressions.load_baseline(target)
        )
        assert kept == [new]
        assert baselined == [old]

    def test_a_baseline_written_before_paths_existed_baselines_no_path(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "old.json"
        target.write_text(json.dumps({"schema": suppressions.BASELINE_SCHEMA, "entries": []}))
        loaded = suppressions.load_baseline(target)
        assert loaded.path_ids == frozenset()
        path = make_path("internet", "aws_lb.web")
        assert suppressions.apply_baseline_paths([path], loaded) == ([path], [])

    def test_a_plain_frozenset_baselines_no_path(self) -> None:
        path = make_path("internet", "aws_lb.web")
        assert suppressions.apply_baseline_paths([path], frozenset({path.id})) == ([path], [])

    def test_the_file_is_byte_stable_with_paths(self, tmp_path: Path) -> None:
        paths = [make_path("internet", "b.b"), make_path("internet", "a.a")]
        suppressions.write_baseline(tmp_path / "x.json", [], paths)
        suppressions.write_baseline(tmp_path / "y.json", [], list(reversed(paths)))
        assert (tmp_path / "x.json").read_bytes() == (tmp_path / "y.json").read_bytes()

    def test_a_baseline_whose_path_list_is_not_a_list_is_rejected(self, tmp_path: Path) -> None:
        target = tmp_path / "bad.json"
        target.write_text(
            json.dumps({"schema": suppressions.BASELINE_SCHEMA, "entries": [], "attack_paths": 3})
        )
        with pytest.raises(ConfigError, match="is not a ThreatCode baseline"):
            suppressions.load_baseline(target)

    def test_the_gate_trips_only_on_a_new_path(self) -> None:
        old = make_path("internet", "aws_lb.web", "aws_db_instance.main")
        new = make_path("internet", "aws_lb.api", "aws_db_instance.main")
        baseline = suppressions.Baseline((), [old.id])
        kept, _ = suppressions.apply_baseline_paths([old], baseline)
        assert _exit([], kept) == EXIT_OK
        kept, _ = suppressions.apply_baseline_paths([old, new], baseline)
        assert _exit([], kept) == EXIT_FINDINGS


def _exit(threats: list[Threat], paths: list[AttackPath]) -> int:
    return compute_exit_code(
        errors=[],
        strict=False,
        coverage=Coverage(),
        threats=threats,
        attack_paths=paths,
        fail_on="high",
    )


TF_EXPOSED = (
    'resource "aws_lambda_function_url" "{name}" {{\n'
    '  function_name      = "{name}"\n'
    '  authorization_type = "NONE"\n'
    "}}\n"
)


class TestThroughThePipeline:
    """The ignore file as the scan reads it: scoped entries change what the gate sees."""

    def scan(self, root: Path, ignore: str) -> ScanResult:
        (root / ".threatcodeignore").write_text(ignore)
        return run_scan(prepare_request([str(root)]).request)

    def tree(self, root: Path) -> None:
        for name in ("a", "b"):
            (root / name).mkdir()
            (root / name / "main.tf").write_text(TF_EXPOSED.format(name=name))

    def test_a_file_scope_suppresses_one_directory_and_the_gate_still_trips(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CI", raising=False)
        self.tree(tmp_path)
        result = self.scan(
            tmp_path, 'LAMBDA_URL_NO_AUTH file=a/* exp:2999-01-01 reason="a is internal"\n'
        )
        assert result.coverage.suppressed == 1
        remaining = [t for t in result.report.threats if t.rule_id == "LAMBDA_URL_NO_AUTH"]
        assert [t.location_file for t in remaining] == ["b/main.tf"]
        assert result.exit_code == EXIT_FINDINGS

    def test_suppressing_every_location_recomputes_the_gate_to_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CI", raising=False)
        self.tree(tmp_path)
        result = self.scan(
            tmp_path,
            'LAMBDA_URL_NO_AUTH file=a/* exp:2999-01-01 reason="a"\n'
            'LAMBDA_URL_NO_AUTH resource=*.b exp:2999-01-01 reason="b"\n',
        )
        assert result.coverage.suppressed == 2
        assert result.exit_code == EXIT_OK

    def test_a_resource_scope_matches_the_address_the_report_shows(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CI", raising=False)
        self.tree(tmp_path)
        result = self.scan(
            tmp_path,
            'LAMBDA_URL_NO_AUTH resource="*aws_lambda_function_url.a" exp:2999-01-01 reason="r"\n',
        )
        assert result.coverage.suppressed == 1

    def test_the_ci_notice_and_warnings_reach_the_scan_notices(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("CI", "true")
        self.tree(tmp_path)
        result = self.scan(tmp_path, "LAMBDA_URL_NO_AUTH\n")
        assert any("pull request can edit it" in n for n in result.notices)
        assert any("has no reason" in n for n in result.notices)
        assert any("global entry" in n for n in result.notices)

    def test_an_expired_scoped_entry_does_not_suppress(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("CI", raising=False)
        self.tree(tmp_path)
        result = self.scan(tmp_path, 'LAMBDA_URL_NO_AUTH file=a/* exp:2020-01-01 reason="old"\n')
        assert result.coverage.suppressed == 0
        assert any("expired on 2020-01-01" in n for n in result.notices)
        assert result.exit_code == EXIT_FINDINGS
