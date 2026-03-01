"""Tests for threatcode.parsers.terraform_hcl."""

from __future__ import annotations

from pathlib import Path

import pytest
from threatcode.exceptions import ParseError
from threatcode.parsers.terraform_hcl import TerraformHCLParser

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "terraform"


class TestTerraformHCLParser:
    def test_parse_simple_tf_file(self) -> None:
        parser = TerraformHCLParser()
        result = parser.parse_file(FIXTURES_DIR / "simple.tf")
        assert len(result.resources) == 2
        assert result.format_type == "terraform_hcl"

    def test_resource_types_extracted(self) -> None:
        parser = TerraformHCLParser()
        result = parser.parse_file(FIXTURES_DIR / "simple.tf")
        types = {r.resource_type for r in result.resources}
        assert "aws_s3_bucket" in types
        assert "aws_instance" in types

    def test_address_format(self) -> None:
        parser = TerraformHCLParser()
        result = parser.parse_file(FIXTURES_DIR / "simple.tf")
        addresses = {r.address for r in result.resources}
        assert "aws_s3_bucket.test" in addresses
        assert "aws_instance.web" in addresses

    def test_provider_inferred(self) -> None:
        parser = TerraformHCLParser()
        result = parser.parse_file(FIXTURES_DIR / "simple.tf")
        for r in result.resources:
            assert r.provider == "hashicorp/aws"

    def test_parse_invalid_dict(self) -> None:
        parser = TerraformHCLParser()
        with pytest.raises(ParseError):
            parser.parse("not a dict")

    def test_parse_nonexistent_file(self) -> None:
        parser = TerraformHCLParser()
        with pytest.raises((ParseError, FileNotFoundError)):
            parser.parse_file(Path("/nonexistent/file.tf"))
