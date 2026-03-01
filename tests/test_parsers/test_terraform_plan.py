"""Tests for Terraform plan JSON parser."""

from __future__ import annotations

import pytest

from threatcode.parsers.base import ParsedOutput
from threatcode.parsers.terraform_plan import TerraformPlanParser


class TestTerraformPlanParser:
    def test_parse_simple_plan(self, simple_s3_plan_data: dict) -> None:
        parser = TerraformPlanParser()
        result = parser.parse(simple_s3_plan_data, source_path="test.json")

        assert isinstance(result, ParsedOutput)
        assert result.format_type == "terraform_plan"
        assert len(result.resources) == 7

    def test_resource_types_extracted(self, simple_s3_parsed: ParsedOutput) -> None:
        types = {r.resource_type for r in simple_s3_parsed.resources}
        assert "aws_s3_bucket" in types
        assert "aws_iam_role" in types
        assert "aws_iam_policy" in types
        assert "aws_instance" in types
        assert "aws_db_instance" in types

    def test_resource_addresses(self, simple_s3_parsed: ParsedOutput) -> None:
        addresses = {r.address for r in simple_s3_parsed.resources}
        assert "aws_s3_bucket.data" in addresses
        assert "aws_s3_bucket.public_assets" in addresses
        assert "aws_s3_bucket.logs" in addresses

    def test_properties_resolved(self, simple_s3_parsed: ParsedOutput) -> None:
        data_bucket = next(
            r for r in simple_s3_parsed.resources if r.address == "aws_s3_bucket.data"
        )
        assert data_bucket.properties["bucket"] == "my-company-data-bucket"
        assert data_bucket.properties["acl"] == "private"

    def test_dependencies_extracted(self, simple_s3_parsed: ParsedOutput) -> None:
        web = next(r for r in simple_s3_parsed.resources if r.address == "aws_instance.web")
        assert "aws_s3_bucket.data" in web.dependencies

    def test_metadata_includes_versions(self, simple_s3_parsed: ParsedOutput) -> None:
        assert simple_s3_parsed.metadata["format_version"] == "1.2"
        assert simple_s3_parsed.metadata["terraform_version"] == "1.7.0"

    def test_provider_name(self, simple_s3_parsed: ParsedOutput) -> None:
        bucket = next(r for r in simple_s3_parsed.resources if r.address == "aws_s3_bucket.data")
        assert "aws" in bucket.provider
        assert bucket.provider_short == "aws"

    def test_service_extraction(self, simple_s3_parsed: ParsedOutput) -> None:
        bucket = next(r for r in simple_s3_parsed.resources if r.address == "aws_s3_bucket.data")
        assert bucket.service == "s3"

    def test_parse_invalid_data_raises(self) -> None:
        parser = TerraformPlanParser()
        with pytest.raises(Exception):
            parser.parse("not a dict")

    def test_parse_empty_plan(self) -> None:
        parser = TerraformPlanParser()
        result = parser.parse({"planned_values": {"root_module": {}}})
        assert len(result.resources) == 0
