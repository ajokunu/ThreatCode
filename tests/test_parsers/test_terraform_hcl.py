"""Tests for threatcode.parsers.terraform_hcl."""

from __future__ import annotations

import codecs
from pathlib import Path

import pytest

from threatcode.exceptions import ParseError
from threatcode.parsers import detect_and_parse
from threatcode.parsers._text import decode_input
from threatcode.parsers.terraform_hcl import TerraformHCLParser

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "terraform"
SHAPES = Path(__file__).parent.parent / "fixtures" / "input_shapes"


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


class TestParseText:
    def test_parse_text_matches_parse_file(self) -> None:
        path = FIXTURES_DIR / "simple.tf"
        text = path.read_text(encoding="utf-8")
        from_text = TerraformHCLParser().parse_text(text, source_path=str(path))
        from_file = TerraformHCLParser().parse_file(path)
        assert [r.address for r in from_text.resources] == [r.address for r in from_file.resources]
        assert from_text.source_path == from_file.source_path == str(path)
        assert {r.source_location for r in from_text.resources} == {str(path)}

    def test_file_is_read_once_through_the_registry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        reads: list[str] = []

        def counting(path: Path, **kwargs: bool) -> str:
            reads.append(path.name)
            return decode_input(path, **kwargs)

        monkeypatch.setattr("threatcode.parsers.decode_input", counting)
        monkeypatch.setattr("threatcode.parsers.terraform_hcl.decode_input", counting)
        result = detect_and_parse(FIXTURES_DIR / "simple.tf")
        assert len(result.resources) == 2
        assert reads == ["simple.tf"]

    def test_file_is_read_once_through_parse_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        reads: list[str] = []

        def counting(path: Path, **kwargs: bool) -> str:
            reads.append(path.name)
            return decode_input(path, **kwargs)

        monkeypatch.setattr("threatcode.parsers.terraform_hcl.decode_input", counting)
        TerraformHCLParser().parse_file(FIXTURES_DIR / "simple.tf")
        assert reads == ["simple.tf"]

    def test_parse_text_with_json_syntax_name(self) -> None:
        text = (SHAPES / "cdk.tf.json").read_text(encoding="utf-8")
        result = TerraformHCLParser().parse_text(text, source_path="cdk.tf.json")
        addresses = {r.address for r in result.resources}
        assert addresses == {"aws_s3_bucket.assets", "aws_instance.web"}

    def test_empty_file_through_parse_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.tf"
        path.write_text("", encoding="utf-8")
        with pytest.raises(ParseError, match="file is empty"):
            TerraformHCLParser().parse_file(path)

    def test_bom_file(self, tmp_path: Path) -> None:
        path = tmp_path / "main.tf"
        path.write_bytes(codecs.BOM_UTF8 + (FIXTURES_DIR / "simple.tf").read_bytes())
        assert len(TerraformHCLParser().parse_file(path).resources) == 2

    def test_invalid_bytes_are_a_parse_error(self, tmp_path: Path) -> None:
        path = tmp_path / "main.tf"
        path.write_bytes(b'resource "a" "b" {\n  x = "\xc3\x28"\n}\n')
        with pytest.raises(ParseError, match="not valid UTF-8 text"):
            TerraformHCLParser().parse_file(path)


class TestSyntaxErrors:
    def test_message_has_file_and_no_token_dump(self) -> None:
        text = 'resource "aws_s3_bucket" "b" {\n  bucket == "x"\n}\n'
        with pytest.raises(ParseError) as exc_info:
            TerraformHCLParser().parse_text(text, source_path="/work/broken.tf")
        message = str(exc_info.value)
        assert "broken.tf" in message
        assert "/work" not in message
        assert "Token(" not in message
        assert "Expected one of" not in message
        assert "\n" not in message

    def test_message_carries_the_line_when_the_parser_reports_one(self) -> None:
        text = 'resource "aws_s3_bucket" "b" {\n  bucket == "x"\n}\n'
        with pytest.raises(ParseError) as exc_info:
            TerraformHCLParser().parse_text(text, source_path="broken.tf")
        message = str(exc_info.value)
        assert "syntax error" in message or "line" in message

    def test_original_exception_is_chained(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            TerraformHCLParser().parse_text("resource {{{\n", source_path="broken.tf")
        assert exc_info.value.__cause__ is not None


class TestJsonSyntax:
    def test_resource_object_form(self) -> None:
        data = {"resource": {"aws_s3_bucket": {"b": {"bucket": "x", "acl": "public-read"}}}}
        result = TerraformHCLParser().parse(data, source_path="main.tf.json")
        assert [r.address for r in result.resources] == ["aws_s3_bucket.b"]
        assert result.resources[0].properties["acl"] == "public-read"

    def test_resource_array_form(self) -> None:
        data = {"resource": [{"aws_s3_bucket": {"b": {"bucket": "x"}}}]}
        result = TerraformHCLParser().parse(data)
        assert [r.address for r in result.resources] == ["aws_s3_bucket.b"]

    def test_one_element_array_for_a_resource_body(self) -> None:
        data = {"resource": {"aws_instance": {"web": [{"ami": "ami-1"}]}}}
        result = TerraformHCLParser().parse(data)
        assert result.resources[0].properties == {"ami": "ami-1"}

    def test_file_with_only_other_blocks_has_no_resources(self, tmp_path: Path) -> None:
        path = tmp_path / "providers.tf.json"
        path.write_text('{"provider": {"aws": [{"region": "us-east-1"}]}}', encoding="utf-8")
        assert TerraformHCLParser().parse_file(path).resources == []

    def test_a_json_array_is_not_a_terraform_file(self, tmp_path: Path) -> None:
        path = tmp_path / "list.tf.json"
        path.write_text("[1, 2]", encoding="utf-8")
        with pytest.raises(ParseError, match="must hold an object"):
            TerraformHCLParser().parse_file(path)


class TestParseDirectory:
    def test_module_directory(self) -> None:
        result = TerraformHCLParser().parse_directory(SHAPES / "tf_module")
        assert len(result.resources) == 3
        assert result.metadata["files"] == ["main.tf", "storage.tf", "variables.tf"]

    def test_files_are_read_in_name_order(self, tmp_path: Path) -> None:
        for name, bucket in (("b.tf", "second"), ("a.tf", "first"), ("c.tf", "third")):
            (tmp_path / name).write_text(
                f'resource "aws_s3_bucket" "{bucket}" {{\n  bucket = "{bucket}"\n}}\n',
                encoding="utf-8",
            )
        result = TerraformHCLParser().parse_directory(tmp_path)
        assert [r.name for r in result.resources] == ["first", "second", "third"]

    def test_only_terraform_files_are_read(self, tmp_path: Path) -> None:
        (tmp_path / "main.tf").write_text(
            'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n', encoding="utf-8"
        )
        (tmp_path / "notes.txt").write_text("not terraform {{{", encoding="utf-8")
        (tmp_path / "values.tfvars").write_text('region = "us-east-1"\n', encoding="utf-8")
        result = TerraformHCLParser().parse_directory(tmp_path)
        assert result.metadata["files"] == ["main.tf"]
