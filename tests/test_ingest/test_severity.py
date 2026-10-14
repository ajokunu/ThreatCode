"""The severity tables and the CVSS v3 calculator."""

from __future__ import annotations

import pytest

from threatcode.ingest.cvss import cvss3_base_score
from threatcode.ingest.model import (
    clean_text,
    severity_from_label,
    severity_from_level,
    severity_from_score,
    to_float,
)


class TestLabels:
    @pytest.mark.parametrize(
        ("label", "expected"),
        [
            ("CRITICAL", "critical"),
            ("HIGH", "high"),
            ("MEDIUM", "medium"),
            ("LOW", "low"),
            ("UNKNOWN", "info"),
            ("Critical", "critical"),
            ("High", "high"),
            ("Medium", "medium"),
            ("Low", "low"),
            ("Negligible", "info"),
            ("Unknown", "info"),
            ("MODERATE", "medium"),
            (" high ", "high"),
        ],
    )
    def test_the_tool_words_map_to_the_five_severities(self, label: str, expected: str) -> None:
        assert severity_from_label(label) == expected

    @pytest.mark.parametrize("label", [None, 3, "", "catastrophic", ["HIGH"]])
    def test_a_missing_or_unknown_word_maps_to_the_default(self, label: object) -> None:
        assert severity_from_label(label) == "info"
        assert severity_from_label(label, default="medium") == "medium"


class TestScores:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [
            (10.0, "critical"),
            (9.8, "critical"),
            (9.0, "critical"),
            (8.9, "high"),
            (7.0, "high"),
            (6.9, "medium"),
            (4.0, "medium"),
            (3.9, "low"),
            (0.1, "low"),
            (0.0, "info"),
        ],
    )
    def test_the_bands_are_9_7_and_4(self, score: float, expected: str) -> None:
        assert severity_from_score(score) == expected

    def test_no_score_maps_to_the_default(self) -> None:
        assert severity_from_score(None) == "info"
        assert severity_from_score(None, default="") == ""


class TestSarifLevels:
    @pytest.mark.parametrize(
        ("level", "expected"),
        [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")],
    )
    def test_levels(self, level: str, expected: str) -> None:
        assert severity_from_level(level) == expected

    def test_a_missing_level_is_a_warning_as_the_sarif_spec_says(self) -> None:
        assert severity_from_level(None) == "medium"
        assert severity_from_level("bogus") == "medium"


class TestHelpers:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [(7, 7.0), (7.5, 7.5), ("7.5", 7.5), (" 3 ", 3.0), (True, None), ("x", None), (None, None)],
    )
    def test_to_float(self, value: object, expected: float | None) -> None:
        assert to_float(value) == expected

    def test_clean_text_drops_control_characters_and_shortens(self) -> None:
        assert clean_text("a\x00b\x1bc\n") == "abc"
        assert clean_text("x" * 50, 10) == "xxxxxxx..."
        assert clean_text(5) == ""


class TestCvss3:
    @pytest.mark.parametrize(
        ("vector", "score"),
        [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H", 7.2),
            ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ],
    )
    def test_known_vectors(self, vector: str, score: float) -> None:
        assert cvss3_base_score(vector) == score

    @pytest.mark.parametrize(
        "vector",
        [
            "",
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            "CVSS:3.1/AV:N",
            "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ],
    )
    def test_vectors_without_a_v3_score_return_none(self, vector: str) -> None:
        assert cvss3_base_score(vector) is None
