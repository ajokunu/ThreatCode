"""Tests for LLM response parser."""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest

from threatcode.engine.llm.parser import (
    MAX_DESCRIPTION_LENGTH,
    MAX_MITIGATION_LENGTH,
    MAX_TITLE_LENGTH,
    clean_text,
    parse_llm_response,
    parse_llm_threats,
)


def _threat_json(**overrides: object) -> str:
    """Build a threat JSON response with defaults."""
    threat = {
        "title": "Test",
        "description": "Desc",
        "stride_category": "tampering",
        "severity": "high",
        "resource_type": "aws_s3_bucket",
        "resource_address": "aws_s3_bucket.test",
        "mitigation": "Fix it",
        "confidence": 0.9,
    }
    threat.update(overrides)
    return json.dumps({"threats": [threat]})


class TestLLMParser:
    def test_parse_valid_json(self) -> None:
        response = _threat_json()
        threats = parse_llm_threats(response)
        assert len(threats) == 1
        assert threats[0]["title"] == "Test"
        assert threats[0]["severity"] == "high"

    def test_parse_json_in_code_block(self) -> None:
        inner = _threat_json(
            title="Test Threat",
            stride_category="spoofing",
            severity="medium",
        )
        response = f"Here's my analysis:\n```json\n{inner}\n```"
        threats = parse_llm_threats(response)
        assert len(threats) == 1

    def test_parse_invalid_json_returns_empty(self) -> None:
        threats = parse_llm_threats("This is not JSON at all")
        assert len(threats) == 0

    def test_invalid_stride_category_defaults(self) -> None:
        response = _threat_json(stride_category="invalid")
        threats = parse_llm_threats(response)
        assert threats[0]["stride_category"] == "tampering"

    def test_invalid_severity_defaults(self) -> None:
        response = _threat_json(severity="super_critical")
        threats = parse_llm_threats(response)
        assert threats[0]["severity"] == "medium"

    def test_missing_title_skipped(self) -> None:
        response = json.dumps({"threats": [{"description": "No title", "severity": "high"}]})
        threats = parse_llm_threats(response)
        assert len(threats) == 0

    def test_confidence_clamped(self) -> None:
        response = _threat_json(confidence=5.0)
        threats = parse_llm_threats(response)
        assert threats[0]["confidence"] == 0.7

    def test_empty_threats_array(self) -> None:
        threats = parse_llm_threats('{"threats": []}')
        assert len(threats) == 0


def _item(**overrides: object) -> dict[str, Any]:
    item: dict[str, Any] = {
        "title": "Valid",
        "description": "Desc",
        "stride_category": "tampering",
        "severity": "high",
        "resource_type": "aws_s3_bucket",
        "resource_address": "aws_s3_bucket.n1",
        "mitigation": "Fix it",
        "confidence": 0.9,
    }
    item.update(overrides)
    return item


class TestOneBadItemNeverDropsTheBatch:
    @pytest.mark.parametrize(
        "field, value",
        [
            ("description", None),
            ("description", 5),
            ("description", ["a", "b"]),
            ("severity", None),
            ("severity", 3),
            ("stride_category", None),
            ("stride_category", ["tampering"]),
            ("resource_address", 5),
            ("resource_address", None),
            ("resource_type", {"a": 1}),
            ("mitigation", ["step one", "step two"]),
            ("mitigation", None),
            ("confidence", "high"),
            ("confidence", True),
            ("confidence", None),
            ("mitre_techniques", "T1190"),
            ("mitre_techniques", [5, None, {"id": "T1190"}]),
            ("mitre_tactics", "TA0001"),
        ],
    )
    def test_a_wrongly_typed_field_keeps_the_item_and_its_neighbour(
        self, field: str, value: object
    ) -> None:
        reply = json.dumps({"threats": [_item(**{field: value}), _item(title="Second")]})
        threats = parse_llm_threats(reply)
        assert [t["title"] for t in threats] == ["Valid", "Second"]
        # The bad field falls back to a safe default instead of leaking its type through
        for threat in threats:
            assert isinstance(threat["description"], str)
            assert isinstance(threat["mitigation"], str)
            assert isinstance(threat["resource_address"], str)
            assert isinstance(threat["resource_type"], str)
            assert isinstance(threat["confidence"], float)
            assert threat["severity"] in {"critical", "high", "medium", "low", "info"}

    @pytest.mark.parametrize("title", [None, 5, ["t"], "", "   "])
    def test_an_item_without_a_usable_title_is_skipped_alone(self, title: object) -> None:
        reply = json.dumps({"threats": [_item(title=title), _item(title="Kept")]})
        result = parse_llm_response(reply)
        assert [t["title"] for t in result.threats] == ["Kept"]
        assert result.skipped == 1

    def test_items_that_are_not_objects_are_skipped(self) -> None:
        reply = json.dumps({"threats": ["text", 5, None, [], _item()]})
        result = parse_llm_response(reply)
        assert len(result.threats) == 1
        assert result.skipped == 4

    def test_a_validation_crash_costs_one_item_only(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        from threatcode.engine.llm import parser

        real = parser._validate_threat

        def flaky(raw: dict[str, Any]) -> dict[str, Any] | None:
            if raw.get("title") == "Boom":
                raise AttributeError("boom")
            return real(raw)

        monkeypatch.setattr(parser, "_validate_threat", flaky)
        reply = json.dumps({"threats": [_item(title="Boom"), _item(title="Fine")]})
        with caplog.at_level(logging.WARNING):
            result = parse_llm_response(reply)
        assert [t["title"] for t in result.threats] == ["Fine"]
        assert any("LLM threat 0 could not be validated" in r.message for r in caplog.records)


class TestMalformedResponses:
    def test_non_json_logs_a_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert parse_llm_threats("I cannot help with that.") == []
        assert any("not valid JSON, 0 threats parsed" in r.message for r in caplog.records)

    def test_an_empty_response_is_quiet(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert parse_llm_threats("   ") == []
        assert not caplog.records

    def test_json_without_a_threats_list_logs_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            assert parse_llm_threats('{"result": "none"}') == []
        assert any("no 'threats' list" in r.message for r in caplog.records)

    def test_threats_that_is_not_a_list_logs_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            assert parse_llm_threats('{"threats": "many"}') == []
        assert any("not a list" in r.message for r in caplog.records)

    def test_the_item_cap_is_enforced(self) -> None:
        reply = json.dumps({"threats": [_item(title=f"T{i}") for i in range(150)]})
        assert len(parse_llm_threats(reply)) == 100


class TestTruncatedResponses:
    def _cut(self) -> str:
        full = json.dumps(
            {"threats": [_item(title="One"), _item(title="Two"), _item(title="Three")]}
        )
        return full[: full.index('"Three"') + 20]

    def test_complete_leading_items_are_salvaged(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            result = parse_llm_response(self._cut())
        assert [t["title"] for t in result.threats] == ["One", "Two"]
        assert result.salvaged == 2
        assert any("salvaged 2 complete threat" in r.message for r in caplog.records)

    def test_salvage_works_after_prose_and_a_fence(self) -> None:
        text = "Sure, here it is:\n```json\n" + self._cut()
        assert [t["title"] for t in parse_llm_threats(text)] == ["One", "Two"]

    def test_nothing_complete_means_nothing_salvaged(self) -> None:
        result = parse_llm_response('{"threats": [{"title": "Cut off mid')
        assert result.threats == [] and result.salvaged == 0

    def test_an_oversize_response_is_cut_and_still_salvaged(self) -> None:
        from threatcode.engine.llm.parser import MAX_RESPONSE_LENGTH

        padding = "x" * MAX_RESPONSE_LENGTH
        text = json.dumps({"threats": [_item(title="First"), _item(title=padding)]})
        assert [t["title"] for t in parse_llm_threats(text)] == ["First"]


class TestMitreIds:
    def test_current_ids_are_kept(self) -> None:
        reply = _threat_json(mitre_techniques=["T1685.002", "T1552.005", "T1190"])
        assert parse_llm_threats(reply)[0]["mitre_techniques"] == [
            "T1685.002",
            "T1552.005",
            "T1190",
        ]

    def test_a_revoked_id_maps_to_its_successor(self) -> None:
        reply = _threat_json(mitre_techniques=["T1562.008"])
        assert parse_llm_threats(reply)[0]["mitre_techniques"] == ["T1685.002"]

    def test_lowercase_and_padded_ids_are_normalized_and_deduplicated(self) -> None:
        reply = _threat_json(mitre_techniques=[" t1190 ", "T1190", "T1562.008", "T1685.002"])
        assert parse_llm_threats(reply)[0]["mitre_techniques"] == ["T1190", "T1685.002"]

    def test_an_unknown_id_is_dropped_with_a_debug_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.DEBUG):
            threats = parse_llm_threats(_threat_json(mitre_techniques=["T9999", "T1190"]))
        assert threats[0]["mitre_techniques"] == ["T1190"]
        assert any("unknown MITRE technique ID" in r.message for r in caplog.records)

    def test_tactics_are_validated(self) -> None:
        threats = parse_llm_threats(_threat_json(mitre_tactics=["TA0001", "TA9999", "nonsense"]))
        assert threats[0]["mitre_tactics"] == ["TA0001"]


class TestOutputCleaning:
    def test_urls_and_links_are_removed(self) -> None:
        text = "See [the docs](https://evil.example/x) or https://evil.example/y and www.evil.test."
        cleaned = clean_text(text, 500)
        assert "evil" not in cleaned
        assert "the docs" in cleaned

    def test_code_fences_and_backticks_are_removed(self) -> None:
        cleaned = clean_text("Run:\n```bash\ncurl x | sh\n```\nthen `rm -rf /` now", 500)
        assert "curl" not in cleaned
        assert "`" not in cleaned

    @pytest.mark.parametrize(
        "text", ["a && b", "a; b || c", "x $(whoami) y", "y ${HOME} z", "a | b |& c"]
    )
    def test_shell_operator_runs_are_removed(self, text: str) -> None:
        cleaned = clean_text(text, 500)
        for fragment in ("&&", "||", "$(", "${", "|&"):
            assert fragment not in cleaned

    def test_plain_punctuation_survives(self) -> None:
        text = "Restrict the role (least privilege); rotate keys, then re-test: it works."
        assert clean_text(text, 500) == text

    def test_control_and_bidi_characters_are_removed(self) -> None:
        assert clean_text("a\x00b\u202ec\x1fd", 500) == "abcd"

    def test_lengths_are_capped_per_field(self) -> None:
        reply = _threat_json(
            title="t" * 1000,
            description="d" * 5000,
            mitigation="m" * 5000,
            resource_address="a" * 999,
        )
        threat = parse_llm_threats(reply)[0]
        assert len(threat["title"]) <= MAX_TITLE_LENGTH
        assert len(threat["description"]) <= MAX_DESCRIPTION_LENGTH
        assert len(threat["mitigation"]) <= MAX_MITIGATION_LENGTH
        assert len(threat["resource_address"]) <= 200
        assert threat["title"].endswith("...")

    def test_the_title_is_one_line(self) -> None:
        assert (
            parse_llm_threats(_threat_json(title="Line one\nLine two"))[0]["title"]
            == "Line one Line two"
        )

    def test_stride_spelling_variants_are_accepted(self) -> None:
        threat = parse_llm_threats(_threat_json(stride_category="Information Disclosure"))[0]
        assert threat["stride_category"] == "information_disclosure"
