"""Tests for CloudFormation parser with insecure stack fixture."""

from __future__ import annotations

from pathlib import Path

from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


class TestCloudFormationParser:
    def test_parse_insecure_stack(self) -> None:
        path = FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"
        parsed = detect_and_parse(str(path))

        assert parsed.format_type == "cloudformation"
        assert len(parsed.resources) == 5

    def test_resource_type_conversion(self) -> None:
        path = FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"
        parsed = detect_and_parse(str(path))

        types = {r.resource_type for r in parsed.resources}
        assert "aws_s3_bucket" in types
        assert "aws_iam_policy" in types
        assert "aws_db_instance" in types
        assert "aws_iam_role" in types

    def test_properties_extracted(self) -> None:
        path = FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"
        parsed = detect_and_parse(str(path))

        buckets = [r for r in parsed.resources if r.resource_type == "aws_s3_bucket"]
        assert len(buckets) == 2

        public = [b for b in buckets if b.properties.get("AccessControl") == "public-read"]
        assert len(public) == 1

    def test_dependencies_extracted(self) -> None:
        path = FIXTURES_DIR / "cloudformation" / "insecure_stack.yml"
        parsed = detect_and_parse(str(path))

        db = [r for r in parsed.resources if r.resource_type == "aws_db_instance"][0]
        assert "UnencryptedBucket" in db.dependencies
