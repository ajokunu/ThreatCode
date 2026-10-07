"""Tests for the secret detector core: matching, redaction, line numbers, decoding and caps."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from threatcode.engine.secrets.builtin import get_builtin_rules
from threatcode.engine.secrets.config import SecretScanConfig
from threatcode.engine.secrets.scanner import (
    SecretScanner,
    decode_secret_text,
    redact,
)

FIXTURES = Path(__file__).parent.parent / "fixtures" / "secrets"
CORPUS = FIXTURES / "corpus"


def _scan(path: Path, scanner: SecretScanner | None = None) -> list[str]:
    text = path.read_text(encoding="utf-8")
    return [m.rule.id for m in (scanner or SecretScanner()).scan_text(text, path=path.name).matches]


class TestFixtureCorpus:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("dotenv.env", {"SECRET_GENERIC_PASSWORD", "SECRET_GENERIC_API_KEY"}),
            ("compose.yml", {"SECRET_GENERIC_PASSWORD"}),
            ("config.json", {"SECRET_GENERIC_PASSWORD", "SECRET_GENERIC_API_KEY"}),
            ("b.yaml", {"SECRET_GENERIC_PASSWORD"}),
            ("c.cs", {"SECRET_CONNECTION_STRING_PASSWORD"}),
            ("curl.sh", {"SECRET_AUTHORIZATION_HEADER"}),
            ("url.txt", {"SECRET_URL_CREDENTIALS"}),
            ("pkcs8_private_key.txt", {"SECRET_PRIVATE_KEY"}),
            ("encrypted_private_key.txt", {"SECRET_PRIVATE_KEY"}),
        ],
    )
    def test_each_form_is_found(self, name: str, expected: set[str]) -> None:
        assert set(_scan(CORPUS / name)) == expected

    def test_dotenv_reports_every_assignment(self) -> None:
        text = (CORPUS / "dotenv.env").read_text(encoding="utf-8")
        matches = SecretScanner().scan_text(text, path="dotenv.env").matches
        assert [(m.line, m.attribute) for m in matches] == [
            (3, "DB_PASSWORD"),
            (4, "ADMIN_PASSWORD"),
            (5, "API_KEY"),
        ]

    def test_compose_reports_both_password_forms(self) -> None:
        assert len(_scan(CORPUS / "compose.yml")) == 2

    def test_templates_references_and_names_are_clean(self) -> None:
        assert _scan(CORPUS / "clean_templates.yaml") == []

    def test_known_fixtures(self) -> None:
        scanner = SecretScanner()
        found = {*_scan(FIXTURES / "has_secrets.py", scanner)}
        assert {"SECRET_AWS_ACCESS_KEY", "SECRET_GITHUB_PAT", "SECRET_PRIVATE_KEY"} <= found
        assert _scan(FIXTURES / "clean_file.py", scanner) == []


class TestRedaction:
    def test_format(self) -> None:
        assert redact("SECRET_X", 12) == "[REDACTED SECRET_X len=12]"

    def test_preview_holds_no_character_of_the_secret(self) -> None:
        text = 'password: "Tr0ub4dor&3xKcd77"'
        (match,) = SecretScanner().scan_text(text).matches
        assert match.preview == f"[REDACTED SECRET_GENERIC_PASSWORD len={len('Tr0ub4dor&3xKcd77')}]"
        assert "Tr0u" not in match.preview and "d77" not in match.preview

    def test_match_repr_does_not_print_the_value(self) -> None:
        text = 'password: "Tr0ub4dor&3xKcd77"'
        (match,) = SecretScanner().scan_text(text).matches
        assert "Tr0ub4dor" not in repr(match)
        assert "Tr0ub4dor" not in match.masked_line

    def test_trailing_secret_characters_are_not_leaked(self) -> None:
        """The old preview showed the last four characters of the whole match, quote included."""
        text = 'DB_PASSWORD = "Tr0ub4dor&3xKcd77"'
        (match,) = SecretScanner().scan_text(text).matches
        assert "d77" not in match.preview and '"' not in match.preview

    def test_short_secrets_reveal_nothing(self) -> None:
        (match,) = SecretScanner().scan_text('password: "Ab1!Ab1!"').matches
        assert match.length == 8
        assert "Ab1" not in match.preview

    @settings(max_examples=200, deadline=None, derandomize=True)
    @given(
        secret=st.text(
            alphabet=st.sampled_from("abcdefghijklmnopqrstuvwxyz0123456789!@#%^&*"),
            min_size=8,
            max_size=40,
        ).filter(lambda s: any(c.isdigit() for c in s) and any(c.isalpha() for c in s))
    )
    def test_no_preview_contains_any_four_character_substring_of_the_secret(
        self, secret: str
    ) -> None:
        text = f"password: '{secret}'"
        outcome = SecretScanner().scan_text(text)
        for match in outcome.matches:
            preview = match.preview
            for start in range(len(secret) - 3):
                assert secret[start : start + 4] not in preview
            assert match.length == len(secret)

    def test_every_builtin_rule_previews_without_the_secret(self) -> None:
        samples = [
            "AKIA" + "Q4TRB7ZYXWVU3SPN",
            "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCYZAB1234CDE",
            "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789",
        ]
        scanner = SecretScanner()
        for sample in samples:
            for match in scanner.scan_text(f'token = "{sample}"').matches:
                for start in range(len(sample) - 3):
                    assert sample[start : start + 4] not in match.preview


class TestLineNumbers:
    def test_form_feed_does_not_shift_lines(self) -> None:
        text = 'x = 1\x0c\nplain\npassword = "Tr0ub4dor&3xKcd77"\n'
        (match,) = SecretScanner().scan_text(text).matches
        assert match.line == 3

    @pytest.mark.parametrize("separator", ["\x0b", "\x1c", "\x1d", "\x1e", "\x85", " ", " "])
    def test_other_unicode_line_separators_do_not_shift_lines(self, separator: str) -> None:
        text = f'a{separator}b\nc\npassword = "Tr0ub4dor&3xKcd77"\n'
        (match,) = SecretScanner().scan_text(text).matches
        assert match.line == 3

    def test_crlf_files_report_the_same_lines(self) -> None:
        text = 'a\r\nb\r\npassword = "Tr0ub4dor&3xKcd77"\r\n'
        (match,) = SecretScanner().scan_text(text).matches
        assert match.line == 3
        assert match.length == len("Tr0ub4dor&3xKcd77")


class TestDecoding:
    def test_utf8(self) -> None:
        assert decode_secret_text("password = 'é'".encode()) == "password = 'é'"

    def test_utf16_with_bom(self) -> None:
        raw = ("key = AKIA" + "Q4TRB7ZYXWVU3SPN\n").encode("utf-16")
        assert decode_secret_text(raw) == "key = AKIA" + "Q4TRB7ZYXWVU3SPN\n"

    @pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
    def test_utf16_without_bom(self, codec: str) -> None:
        raw = ("key = AKIA" + "Q4TRB7ZYXWVU3SPN\n").encode(codec)
        text = decode_secret_text(raw)
        assert text is not None
        assert [m.rule.id for m in SecretScanner().scan_text(text).matches] == [
            "SECRET_AWS_ACCESS_KEY"
        ]

    def test_binary_is_not_decoded(self) -> None:
        assert decode_secret_text(b"\x00\x01\x02AKIA" + b"Q4TRB7ZYXWVU3SPN\x00\x03") is None

    def test_invalid_utf8_is_replaced_not_fatal(self) -> None:
        text = decode_secret_text(b"password = '\xff\xfeZx9fQ2mLp7Tr0ub4'")
        assert text is not None and "Zx9fQ2mLp7Tr0ub4" in text


class TestCaps:
    def test_repeated_findings_are_capped_per_file_with_a_truncated_marker(self) -> None:
        text = 'password = "Tr0ub4dor&3xKcd77"\n' * 500
        outcome = SecretScanner(
            SecretScanConfig(max_findings_per_file=10, max_findings_per_rule=1000)
        ).scan_text(text)
        assert len(outcome.matches) == 10
        assert outcome.truncated is True
        assert outcome.dropped == 490

    def test_default_caps(self) -> None:
        text = 'password = "Tr0ub4dor&3xKcd77"\n' * 500
        outcome = SecretScanner().scan_text(text)
        assert len(outcome.matches) == 25
        assert outcome.truncated

    def test_the_cap_is_per_rule(self) -> None:
        text = (
            'password = "Tr0ub4dor&3xKcd77"\n' * 5 + 'api_key = "aB3dE5gH7jK9mN1pQ3sT5vX7zA"\n' * 5
        )
        outcome = SecretScanner(
            SecretScanConfig(max_findings_per_rule=3, max_findings_per_file=100)
        ).scan_text(text)
        by_rule = {m.rule.id for m in outcome.matches}
        assert by_rule == {"SECRET_GENERIC_PASSWORD", "SECRET_GENERIC_API_KEY"}
        assert len(outcome.matches) == 6 and outcome.truncated

    def test_a_clean_file_is_not_truncated(self) -> None:
        outcome = SecretScanner().scan_text('password = "Tr0ub4dor&3xKcd77"\n')
        assert len(outcome.matches) == 1 and not outcome.truncated

    def test_hostile_one_megabyte_line_finishes_quickly(self) -> None:
        import time

        text = 'password="' * 100_000
        started = time.monotonic()
        SecretScanner().scan_text(text)
        assert time.monotonic() - started < 10


class TestConfig:
    def test_disabled_rules_do_not_run(self) -> None:
        scanner = SecretScanner(SecretScanConfig(disabled_rules=["SECRET_GENERIC_PASSWORD"]))
        assert scanner.scan_text('password: "Tr0ub4dor&3xKcd77"').matches == []

    def test_extra_rule_fires_and_gets_a_secret_prefix(self) -> None:
        config = SecretScanConfig.from_mapping(
            {
                "extra_rules": [
                    {
                        "id": "INTERNAL_TOKEN",
                        "regex": r"corp_(?P<secret>[a-z0-9]{20})",
                        "keywords": ["corp_"],
                        "severity": "critical",
                    }
                ]
            }
        )
        (match,) = SecretScanner(config).scan_text("t = corp_abcdefghij0123456789").matches
        assert match.rule.id == "SECRET_INTERNAL_TOKEN"
        assert match.rule.severity == "critical"
        assert match.length == 20

    def test_from_mapping_ignores_what_it_cannot_use(self) -> None:
        config = SecretScanConfig.from_mapping(
            {
                "max_file_size": -1,
                "allow_patterns": "not a list",
                "entropy_threshold": "high",
                "extra_rules": [
                    {"id": "x", "regex": "("},
                    "nope",
                    {"id": "OK_RULE", "regex": "a" * 600},
                ],
                "surprise": 1,
            }
        )
        assert config.max_file_size == SecretScanConfig().max_file_size
        assert config.allow_patterns == []
        assert config.entropy_threshold is None
        assert config.extra_rules == []

    def test_from_mapping_reads_valid_values(self) -> None:
        config = SecretScanConfig.from_mapping(
            {
                "max_file_size": 1024,
                "allow_patterns": ["^dev-"],
                "disabled_rules": ["SECRET_JWT"],
                "entropy_threshold": 3.8,
                "max_findings_per_file": 7,
            }
        )
        assert config.max_file_size == 1024
        assert config.allow_patterns == ["^dev-"]
        assert config.disabled_rules == ["SECRET_JWT"]
        assert config.entropy_threshold == 3.8
        assert config.max_findings_per_file == 7

    def test_long_allow_pattern_is_skipped(self) -> None:
        scanner = SecretScanner(SecretScanConfig(allow_patterns=["a" * 600]))
        assert scanner._global_allow == []

    def test_invalid_allow_pattern_is_skipped(self) -> None:
        scanner = SecretScanner(SecretScanConfig(allow_patterns=["[invalid"]))
        assert scanner._global_allow == []


class TestPrefilter:
    def test_uppercase_content_reaches_lowercase_keywords(self) -> None:
        """MasterUserPassword alone in a file must not need a lower-case 'password' elsewhere."""
        text = 'MasterUserPassword: "WarehouseP@ss2026"\n'
        assert [m.rule.id for m in SecretScanner().scan_text(text).matches] == [
            "SECRET_GENERIC_PASSWORD"
        ]

    def test_export_and_lower_case_assignments_are_both_reported(self) -> None:
        text = "export DB_PASSWORD=Zx9fQ2mLp7Tr0ub4\napi_key = 'aB3dE5gH7jK9mN1pQ3sT5vX7zA'\n"
        matches = SecretScanner().scan_text(text, path="a.sh").matches
        assert [m.rule.id for m in matches] == ["SECRET_GENERIC_PASSWORD", "SECRET_GENERIC_API_KEY"]

    def test_every_keyword_is_lower_case_and_compared_to_lower_case_text(self) -> None:
        for rule in get_builtin_rules():
            assert all(kw == kw.lower() for kw in rule.keywords)

    def test_path_filter_limits_a_rule(self) -> None:
        from threatcode.engine.secrets.rules import SecretRule

        rule = SecretRule(
            "SECRET_ONLY_ENV",
            "x",
            "x",
            "low",
            re.compile(r"(?P<secret>zzz[0-9]{6})"),
            path_filter=re.compile(r"\.env$"),
        )
        scanner = SecretScanner(extra_rules=[rule])
        assert scanner.scan_text("v = zzz123456", path="a.env").matches
        assert not scanner.scan_text("v = zzz123456", path="a.txt").matches
