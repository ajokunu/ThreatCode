"""Tests for threatcode.parsers registry (detect_and_parse + register_parser)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from threatcode.exceptions import ParseError, UnsupportedFormatError
from threatcode.parsers import (
    _REGISTRY,
    detect_and_parse,
    register_parser,
)
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestDetectAndParse:
    def test_terraform_plan_json(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "terraform" / "simple_s3.plan.json")
        assert len(result.resources) > 0
        assert result.format_type == "terraform_plan"

    def test_cloudformation_yaml(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "cloudformation" / "insecure_stack.yml")
        assert len(result.resources) > 0

    def test_terraform_hcl(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "terraform" / "simple.tf")
        assert len(result.resources) == 2
        assert result.format_type == "terraform_hcl"

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            detect_and_parse("/nonexistent/file.json")

    def test_unsupported_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "test.xml"
        f.write_text("<root/>")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(f)

    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "big.json"
        # Create file over 50 MB limit header
        f.write_text("x" * (50 * 1024 * 1024 + 1))
        with pytest.raises(ParseError, match="MB limit"):
            detect_and_parse(f)

    def test_invalid_json_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        with pytest.raises(UnsupportedFormatError, match="Invalid JSON"):
            detect_and_parse(f)


class TestRegisterParser:
    def test_custom_parser_detected(self, tmp_path: Path) -> None:
        """Register a custom parser and verify it's used for matching files."""

        class DummyParser(BaseParser):
            def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
                return ParsedOutput(
                    resources=[ParsedResource(
                        resource_type="custom_widget",
                        address="custom_widget.test",
                        name="test",
                        provider="custom",
                    )],
                    source_path=source_path,
                    format_type="custom",
                )

        register_parser(
            name="custom_test",
            detector=lambda path, content, data: "CUSTOM_MARKER" in content,
            factory=DummyParser,
            extensions=frozenset({".json"}),
            priority=1,  # Higher priority than built-ins
        )

        try:
            f = tmp_path / "custom.json"
            f.write_text(json.dumps({"CUSTOM_MARKER": True}))
            result = detect_and_parse(f)
            assert result.format_type == "custom"
            assert result.resources[0].resource_type == "custom_widget"
        finally:
            # Remove the registered parser
            _REGISTRY[:] = [e for e in _REGISTRY if e.name != "custom_test"]
