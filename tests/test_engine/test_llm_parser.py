"""Tests for LLM response parser."""

from __future__ import annotations

import json

from threatcode.engine.llm.parser import parse_llm_threats


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
