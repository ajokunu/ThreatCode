"""Tests for threatcode.parsers.terraform_hcl."""

from __future__ import annotations

import codecs
import importlib
import itertools
import json
import sys
import textwrap
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import ParseError
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import _hcl_eval, detect_and_parse, terraform_hcl
from threatcode.parsers._text import decode_input
from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.parsers.terraform_hcl import TerraformHCLParser
from threatcode.values import is_unknown

hcl2 = importlib.import_module("hcl2")

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


# --- modules, references and evaluation ----------------------------------------------------

HCL_FIXTURES = FIXTURES_DIR / "hcl"
MODERN = hasattr(hcl2, "SerializationOptions")


def by_address(result: ParsedOutput) -> dict[str, ParsedResource]:
    return {r.address: r for r in result.resources}


def write(directory: Path, name: str, text: str) -> Path:
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")
    return path


def codes(result: ParsedOutput, code: str) -> list[Diagnostic]:
    return [d for d in result.diagnostics if d.code == code]


def parse_dir(path: Path) -> ParsedOutput:
    return TerraformHCLParser().parse_directory(path)


def parse_snippet(tmp_path: Path, text: str, name: str = "main.tf") -> ParsedOutput:
    return TerraformHCLParser().parse_file(write(tmp_path, name, text))


class TestCrossFileReferences:
    """An instance in main.tf refers to a subnet and a group declared in other files."""

    def test_the_directory_is_one_module(self) -> None:
        result = parse_dir(HCL_FIXTURES / "module_dir")
        assert set(by_address(result)) == {
            "aws_instance.web",
            "aws_s3_bucket.data",
            "aws_vpc.main",
            "aws_subnet.a",
            "aws_security_group.web",
        }

    def test_references_cross_files(self) -> None:
        web = by_address(parse_dir(HCL_FIXTURES / "module_dir"))["aws_instance.web"]
        assert web.references == {
            "subnet_id": ["aws_subnet.a.id"],
            "vpc_security_group_ids": ["aws_security_group.web.id"],
        }

    def test_depends_on_is_the_only_source_of_dependencies(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "module_dir"))
        assert resources["aws_instance.web"].dependencies == ["aws_s3_bucket.data"]
        assert resources["aws_subnet.a"].dependencies == []

    def test_a_single_file_only_finds_what_it_declares(self) -> None:
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "module_dir" / "main.tf")
        web = by_address(result)["aws_instance.web"]
        assert web.references == {}
        assert web.dependencies == ["aws_s3_bucket.data"]

    def test_the_graph_has_the_edges_of_the_whole_directory(self) -> None:
        graph = InfraGraph.from_parsed(parse_dir(HCL_FIXTURES / "module_dir"))
        edges = {(e.source, e.target, e.edge_type.value) for e in graph.edges}
        assert ("aws_instance.web", "aws_subnet.a", "containment") in edges
        assert ("aws_instance.web", "aws_security_group.web", "dependency") in edges
        assert ("aws_instance.web", "aws_s3_bucket.data", "dependency") in edges
        assert ("aws_subnet.a", "aws_vpc.main", "containment") in edges
        assert ("aws_security_group.web", "aws_vpc.main", "containment") in edges

    def test_the_directory_graph_equals_the_plan_style_graph(self) -> None:
        result = parse_dir(HCL_FIXTURES / "module_dir")
        graph = InfraGraph.from_parsed(result)
        assert all(e.source in graph.nodes and e.target in graph.nodes for e in graph.edges)
        assert graph.node_count == 5

    def test_a_reference_to_an_undeclared_resource_is_not_a_reference(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "aws_instance" "web" {
              subnet_id = aws_subnet.missing.id
            }
            """,
        )
        assert by_address(result)["aws_instance.web"].references == {}


@pytest.fixture(scope="module")
def refs() -> dict[str, ParsedResource]:
    return by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "references.tf"))


class TestReferenceShapes:
    def test_plain_and_indexed_attributes(self, refs: dict[str, ParsedResource]) -> None:
        assert refs["aws_subnet.a"].references == {"vpc_id": ["aws_vpc.main.id"]}
        assert refs["aws_route_table_association.b"].references == {
            "subnet_id": ["aws_subnet.b.id"],
            "route_table_id": ["aws_route_table.main.id"],
        }

    def test_a_nested_block_attribute_uses_the_list_path(
        self, refs: dict[str, ParsedResource]
    ) -> None:
        assert refs["aws_security_group.web"].references == {
            "vpc_id": ["aws_vpc.main.id"],
            "ingress[].security_groups": ["aws_security_group.lb.id"],
        }

    def test_a_splat(self, refs: dict[str, ParsedResource]) -> None:
        assert refs["aws_lb.front"].references["subnets"] == ["aws_subnet.b.id"]

    def test_a_for_expression_is_scanned(self, refs: dict[str, ParsedResource]) -> None:
        assert refs["aws_lb.front"].references["security_groups"] == ["aws_security_group.lb"]

    def test_a_function_call_and_a_conditional(self, refs: dict[str, ParsedResource]) -> None:
        web = refs["aws_instance.web"].references
        assert web["vpc_security_group_ids"] == ["aws_security_group.web.id"]
        assert web["iam_instance_profile"] == ["aws_iam_instance_profile.web.name"]

    def test_a_local_that_is_a_single_reference_resolves_one_level(
        self, refs: dict[str, ParsedResource]
    ) -> None:
        assert refs["aws_instance.web"].references["subnet_id"] == ["aws_subnet.b.id"]

    def test_data_references_are_kept_and_var_references_are_not(
        self, refs: dict[str, ParsedResource]
    ) -> None:
        web = refs["aws_instance.web"]
        assert web.references["ami"] == ["data.aws_ami.base.id"]
        assert "tags.Name" not in web.references

    def test_properties_hold_values_not_expression_text(
        self, refs: dict[str, ParsedResource]
    ) -> None:
        props = refs["aws_instance.web"].properties
        assert is_unknown(props["subnet_id"]) and props["subnet_id"].reference == "aws_subnet.b.id"
        assert is_unknown(props["ami"])
        assert props["tags"] == {"Name": "demo"}
        assert "${" not in json.dumps(props, default=str)

    def test_a_reference_in_an_attribute_is_unknown_never_absent(
        self, refs: dict[str, ParsedResource]
    ) -> None:
        subnet = refs["aws_subnet.b"].properties
        assert "vpc_id" in subnet and is_unknown(subnet["vpc_id"])

    def test_repeats_are_removed(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "aws_vpc" "main" {}
            resource "aws_subnet" "a" {
              tags = { x = aws_vpc.main.id, y = aws_vpc.main.id }
              cidr_block = "${aws_vpc.main.id}${aws_vpc.main.id}"
            }
            """,
        )
        refs = by_address(result)["aws_subnet.a"].references
        assert refs == {
            "tags.x": ["aws_vpc.main.id"],
            "tags.y": ["aws_vpc.main.id"],
            "cidr_block": ["aws_vpc.main.id"],
        }

    def test_the_reference_wrapping_may_be_bare_or_wrapped(self) -> None:
        # python-hcl2 wraps expressions in ${...}; a bare dictionary value must work as well
        data = {
            "resource": {
                "aws_subnet": {"a": {"vpc_id": "aws_vpc.main.id"}},
                "aws_vpc": {"main": {}},
            }
        }
        wrapped = {
            "resource": {
                "aws_subnet": {"a": {"vpc_id": "${aws_vpc.main.id}"}},
                "aws_vpc": {"main": {}},
            }
        }
        parser = TerraformHCLParser()
        assert by_address(parser.parse(wrapped))["aws_subnet.a"].references == {
            "vpc_id": ["aws_vpc.main.id"]
        }
        # a bare string is a literal in JSON syntax, never an expression
        assert by_address(parser.parse(data))["aws_subnet.a"].references == {}

    def test_python_hcl2_still_wraps_expressions(self) -> None:
        loaded = hcl2.loads('resource "a" "b" {\n  x = aws_vpc.main.id\n}\n')
        body = next(iter(next(iter(loaded["resource"][0].values())).values()))
        assert str(body["x"]).strip('"') == "${aws_vpc.main.id}"


class TestVariablesAndTfvars:
    def test_the_default_is_used_without_an_override(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf",
            """
            variable "public" {
              default = false
            }
            resource "aws_db_instance" "db" {
              publicly_accessible = var.public
            }
            """,
        )
        db = by_address(parse_dir(tmp_path))["aws_db_instance.db"]
        assert db.properties["publicly_accessible"] is False

    def test_terraform_tfvars_overrides_the_default(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "tfvars_dir"))
        assert resources["aws_db_instance.main"].properties["identifier"] == "prod-db"

    def test_an_auto_tfvars_file_overrides_terraform_tfvars_and_loads_in_name_order(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", 'variable "x" {}\nresource "a" "b" {\n  v = var.x\n}\n')
        write(tmp_path, "terraform.tfvars", 'x = "base"\n')
        write(tmp_path, "a.auto.tfvars", 'x = "a"\n')
        write(tmp_path, "b.auto.tfvars", 'x = "b"\n')
        assert by_address(parse_dir(tmp_path))["a.b"].properties["v"] == "b"

    def test_the_whole_override_chain_through_the_fixture(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "tfvars_dir"))
        assert resources["aws_db_instance.main"].properties["publicly_accessible"] is True

    def test_a_json_tfvars_file_is_read(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'variable "x" {}\nresource "a" "b" {\n  v = var.x\n}\n')
        write(tmp_path, "terraform.tfvars.json", '{"x": 7}')
        assert by_address(parse_dir(tmp_path))["a.b"].properties["v"] == 7

    def test_other_tfvars_names_are_not_read(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'variable "x" {}\nresource "a" "b" {\n  v = var.x\n}\n')
        write(tmp_path, "prod.tfvars", 'x = "prod"\n')
        result = parse_dir(tmp_path)
        assert is_unknown(by_address(result)["a.b"].properties["v"])
        assert "tfvars" not in result.metadata

    def test_tfvars_are_listed_apart_from_the_terraform_files(self) -> None:
        result = parse_dir(HCL_FIXTURES / "tfvars_dir")
        assert result.metadata["tfvars"] == ["terraform.tfvars", "zz.auto.tfvars"]
        assert result.metadata["files"] == ["main.tf", "variables.tf"]

    def test_a_broken_tfvars_file_is_a_warning_and_the_default_is_used(
        self, tmp_path: Path
    ) -> None:
        write(
            tmp_path,
            "main.tf",
            'variable "x" {\n  default = 1\n}\nresource "a" "b" {\n  v = var.x\n}\n',
        )
        write(tmp_path, "terraform.tfvars", "x = = 1\n")
        result = parse_dir(tmp_path)
        assert by_address(result)["a.b"].properties["v"] == 1
        failed = codes(result, "parse.failed")
        assert [d.level for d in failed] == ["warning"]
        assert failed[0].file.endswith("terraform.tfvars")

    def test_a_variable_with_no_value_is_unknown_and_never_absent(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'variable "key" {}\nresource "a" "b" {\n  kms = var.key\n}\n')
        value = by_address(parse_dir(tmp_path))["a.b"].properties["kms"]
        assert is_unknown(value) and value.reference == "var.key"

    def test_an_undeclared_variable_is_unknown(self, tmp_path: Path) -> None:
        value = by_address(parse_snippet(tmp_path, 'resource "a" "b" {\n  v = var.nope\n}\n'))[
            "a.b"
        ].properties["v"]
        assert is_unknown(value)

    def test_a_default_of_null_is_a_null_value(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf",
            'variable "x" {\n  default = null\n}\nresource "a" "b" {\n  v = var.x\n}\n',
        )
        assert by_address(parse_dir(tmp_path))["a.b"].properties["v"] is None

    def test_a_string_tfvars_number_drives_count(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'variable "n" {}\nresource "a" "b" {\n  count = var.n\n}\n')
        write(tmp_path, "terraform.tfvars", 'n = "3"\n')
        assert by_address(parse_dir(tmp_path))["a.b"].meta == {"count": 3}


class TestLocals:
    def test_locals_reduce_to_values(self) -> None:
        resources = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "expressions.tf"))
        main = resources["aws_db_instance.main"].properties
        assert main["identifier"] == "dev-app"
        assert main["storage_encrypted"] is False
        assert main["port"] == 5002
        assert main["username"] == "platform"

    def test_a_local_that_uses_a_merge_of_known_values(self) -> None:
        resources = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "expressions.tf"))
        assert resources["aws_s3_bucket.logs"].properties["tags"] == {
            "Owner": "platform",
            "Stage": "dev",
        }

    def test_a_self_referencing_local_is_unknown_not_a_loop(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            'locals {\n  a = local.b\n  b = local.a\n}\nresource "x" "y" {\n  v = local.a\n}\n',
        )
        assert is_unknown(by_address(result)["x.y"].properties["v"])

    def test_locals_in_two_files_are_one_namespace(self, tmp_path: Path) -> None:
        write(tmp_path, "a.tf", 'locals {\n  one = "1"\n}\n')
        write(
            tmp_path,
            "b.tf",
            'locals {\n  two = "${local.one}2"\n}\nresource "x" "y" {\n  v = local.two\n}\n',
        )
        assert by_address(parse_dir(tmp_path))["x.y"].properties["v"] == "12"

    def test_locals_do_not_cross_files_in_a_single_file_scan(self, tmp_path: Path) -> None:
        write(tmp_path, "a.tf", 'locals {\n  one = "1"\n}\n')
        write(tmp_path, "b.tf", 'resource "x" "y" {\n  v = local.one\n}\n')
        value = by_address(TerraformHCLParser().parse_file(tmp_path / "b.tf"))["x.y"].properties[
            "v"
        ]
        assert is_unknown(value)

    def test_an_unknown_local_reports_what_it_depended_on_every_time_it_is_used(
        self, tmp_path: Path
    ) -> None:
        write(
            tmp_path,
            "main.tf",
            """
            variable "missing" {}
            locals {
              name = "${var.missing}-x"
            }
            resource "x" "first" {
              a = local.name
            }
            resource "x" "second" {
              b = local.name
            }
            """,
        )
        result = parse_dir(tmp_path)
        messages = [d.message for d in codes(result, "hcl.unresolved_reference")]
        assert len(messages) == 2
        assert all("var.missing" in m for m in messages)


class TestMetaArguments:
    def test_meta_arguments_are_not_properties(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "aws_s3_bucket" "b" {
              count      = 2
              provider   = aws.west
              depends_on = [aws_s3_bucket.other]
              lifecycle {
                prevent_destroy = true
                ignore_changes  = [tags]
              }
              bucket = "x"
            }
            resource "aws_s3_bucket" "other" {}
            """,
        )
        bucket = by_address(result)["aws_s3_bucket.b"]
        assert bucket.properties == {"bucket": "x"}
        assert bucket.meta["count"] == 2
        assert bucket.meta["provider"] == "aws.west"
        assert bucket.meta["depends_on"] == ["aws_s3_bucket.other"]
        assert bucket.meta["lifecycle"] == {"prevent_destroy": True, "ignore_changes": ["tags"]}
        assert bucket.dependencies == ["aws_s3_bucket.other"]

    def test_a_literal_zero_count_drops_the_resource_with_an_info_diagnostic(
        self, tmp_path: Path
    ) -> None:
        result = parse_snippet(
            tmp_path,
            'resource "aws_security_group" "off" {\n  count = 0\n}\n'
            'resource "aws_security_group" "on" {\n  count = 1\n}\n',
        )
        assert set(by_address(result)) == {"aws_security_group.on"}
        (note,) = codes(result, "hcl.count_zero")
        assert note.level == "info"
        assert "aws_security_group.off" in note.message
        assert note.line == 1

    def test_a_non_literal_count_keeps_one_node_flagged_in_meta(self) -> None:
        result = TerraformHCLParser().parse_file(
            FIXTURES_DIR / "hcl" / "module_dir" / "main.tf",
        )
        assert result.resources  # sanity: the file parses
        # in a single file the variable is not declared, so the count is not known
        resources = by_address(
            TerraformHCLParser().parse_file(
                Path(__file__).parent.parent
                / "fixtures"
                / "real_shapes"
                / "terraform"
                / "hcl"
                / "module_app"
                / "compute.tf"
            )
        )
        app = resources["aws_instance.app"]
        assert app.meta == {"instances_unknown": True}
        assert "count" not in app.properties

    def test_a_count_that_tfvars_makes_zero_drops_the_resource(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf",
            """
            variable "on" {
              default = true
            }
            resource "a" "b" {
              count = var.on ? 1 : 0
            }
            """,
        )
        write(tmp_path, "terraform.tfvars", "on = false\n")
        result = parse_dir(tmp_path)
        assert result.resources == []
        assert len(codes(result, "hcl.count_zero")) == 1

    def test_a_count_that_only_a_default_makes_zero_keeps_the_resource(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "tfvars_dir"))
        audit = resources["aws_cloudtrail.audit"]
        assert audit.meta == {"count": 0, "count_from_default": True}

    def test_that_decision_is_explained_in_an_info_diagnostic(self) -> None:
        result = parse_dir(HCL_FIXTURES / "tfvars_dir")
        notes = [d.message for d in codes(result, "hcl.count_zero")]
        assert len(notes) == 1
        assert "aws_cloudtrail.audit" in notes[0] and "default" in notes[0]

    def test_a_count_that_a_tfvars_value_makes_positive_is_kept_as_one_node(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "tfvars_dir"))
        assert resources["aws_instance.bastion"].meta == {"count": 1}

    def test_for_each_is_recorded_and_not_a_property(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            'resource "a" "b" {\n  for_each = { x = 1, y = 2 }\n  name = each.key\n}\n',
        )
        resource = by_address(result)["a.b"]
        assert resource.meta == {"for_each": ["x", "y"]}
        assert "for_each" not in resource.properties
        assert is_unknown(resource.properties["name"])

    def test_an_unknown_for_each_keeps_one_node_flagged(self, tmp_path: Path) -> None:
        result = parse_snippet(tmp_path, 'resource "a" "b" {\n  for_each = var.things\n}\n')
        assert by_address(result)["a.b"].meta == {"instances_unknown": True}

    def test_an_empty_literal_for_each_creates_nothing(self, tmp_path: Path) -> None:
        result = parse_snippet(tmp_path, 'resource "a" "b" {\n  for_each = {}\n}\n')
        assert result.resources == []
        assert codes(result, "hcl.count_zero")

    def test_a_counted_resource_keeps_its_plain_address(self, tmp_path: Path) -> None:
        result = parse_snippet(tmp_path, 'resource "a" "b" {\n  count = 3\n}\n')
        assert list(by_address(result)) == ["a.b"]

    def test_provisioner_and_connection_blocks_stay_properties(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            'resource "a" "b" {\n  connection {\n    user = "root"\n  }\n'
            '  provisioner "local-exec" {\n    command = "echo"\n  }\n}\n',
        )
        assert set(by_address(result)["a.b"].properties) == {"connection", "provisioner"}


@pytest.fixture(scope="module")
def groups() -> dict[str, ParsedResource]:
    return by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "dynamic_blocks.tf"))


class TestDynamicBlocks:
    def test_a_dynamic_block_over_a_literal_list_becomes_the_blocks_it_generates(
        self, groups: dict[str, ParsedResource]
    ) -> None:
        listed = groups["aws_security_group.listed"].properties
        assert "dynamic" not in listed
        assert [b["from_port"] for b in listed["ingress"]] == [22, 3389]
        assert all(b["cidr_blocks"] == ["0.0.0.0/0"] for b in listed["ingress"])

    def test_an_iterator_name_and_map_keys_are_honoured(
        self, groups: dict[str, ParsedResource]
    ) -> None:
        mapped = groups["aws_security_group.mapped"].properties["ingress"]
        assert [(b["description"], b["from_port"]) for b in mapped] == [("web", 80), ("tls", 443)]

    def test_an_unknown_collection_gives_one_block_with_unknown_values(
        self, groups: dict[str, ParsedResource]
    ) -> None:
        (block,) = groups["aws_security_group.unknown"].properties["ingress"]
        assert is_unknown(block["from_port"])
        assert block["protocol"] == "tcp"

    def test_static_and_dynamic_blocks_share_one_list(
        self, groups: dict[str, ParsedResource]
    ) -> None:
        ports = [b["from_port"] for b in groups["aws_security_group.mixed"].properties["ingress"]]
        assert ports == [443, 22]

    def test_an_empty_for_each_creates_no_block(self, groups: dict[str, ParsedResource]) -> None:
        assert "ingress" not in groups["aws_security_group.empty"].properties

    def test_each_dynamic_block_is_reported(self) -> None:
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "dynamic_blocks.tf")
        notes = codes(result, "hcl.dynamic_block")
        assert len(notes) == 5
        assert all(n.level == "info" for n in notes)
        assert any("became 2 block(s)" in n.message for n in notes)
        assert any("not known" in n.message for n in notes)
        assert any("empty" in n.message for n in notes)

    def test_references_inside_dynamic_content_use_the_list_path(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "aws_security_group" "lb" {}
            resource "aws_security_group" "app" {
              dynamic "ingress" {
                for_each = [80, 443]
                content {
                  from_port       = ingress.value
                  security_groups = [aws_security_group.lb.id]
                }
              }
            }
            """,
        )
        app = by_address(result)["aws_security_group.app"]
        assert app.references == {"ingress[].security_groups": ["aws_security_group.lb.id"]}

    def test_a_large_collection_is_one_unknown_block_not_a_blowup(self, tmp_path: Path) -> None:
        ports = ", ".join(str(p) for p in range(1, 200))
        result = parse_snippet(
            tmp_path,
            f'resource "a" "b" {{\n  dynamic "rule" {{\n    for_each = [{ports}]\n'
            "    content {\n      port = rule.value\n    }\n  }\n}\n",
        )
        (block,) = by_address(result)["a.b"].properties["rule"]
        assert is_unknown(block["port"])

    def test_a_default_empty_collection_keeps_one_block(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf",
            """
            variable "rules" {
              default = []
            }
            resource "a" "b" {
              dynamic "rule" {
                for_each = var.rules
                content {
                  port = rule.value
                }
              }
            }
            """,
        )
        assert len(by_address(parse_dir(tmp_path))["a.b"].properties["rule"]) == 1

    def test_a_dynamic_block_inside_a_static_block_is_expanded(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "aws_lb" "other" {}
            resource "kubernetes_deployment" "app" {
              spec {
                template {
                  container {
                    name = "app"
                    dynamic "env" {
                      for_each = { MODE = "prod", REGION = "eu" }
                      content {
                        name  = env.key
                        value = env.value
                      }
                    }
                    dynamic "port" {
                      for_each = [8080]
                      content {
                        container_port = port.value
                        host           = aws_lb.other.dns_name
                      }
                    }
                  }
                }
              }
            }
            """,
        )
        deployment = by_address(result)["kubernetes_deployment.app"]
        container = deployment.properties["spec"][0]["template"][0]["container"][0]
        assert "dynamic" not in container
        assert container["env"] == [
            {"name": "MODE", "value": "prod"},
            {"name": "REGION", "value": "eu"},
        ]
        assert container["port"][0]["container_port"] == 8080
        assert deployment.references == {
            "spec[].template[].container[].port[].host": ["aws_lb.other.dns_name"]
        }

    def test_nested_dynamic_blocks(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "a" "b" {
              dynamic "outer" {
                for_each = ["x", "y"]
                content {
                  name = outer.value
                  dynamic "inner" {
                    for_each = [1]
                    content {
                      n = inner.value
                    }
                  }
                }
              }
            }
            """,
        )
        outer = by_address(result)["a.b"].properties["outer"]
        assert [o["name"] for o in outer] == ["x", "y"]
        assert outer[0]["inner"] == [{"n": 1}]


@pytest.fixture(scope="module")
def result() -> ParsedOutput:
    return parse_dir(HCL_FIXTURES / "local_modules")


class TestLocalModules:
    def test_module_resources_have_module_addresses(self, result: ParsedOutput) -> None:
        addresses = set(by_address(result))
        assert "module.net.aws_subnet.this" in addresses
        assert "module.net.aws_vpc.main" in addresses
        assert "module.db.aws_db_instance.this" in addresses
        assert "aws_vpc.main" in addresses

    def test_module_resources_know_their_module(self, result: ParsedOutput) -> None:
        resources = by_address(result)
        assert resources["module.net.aws_subnet.this"].module == "module.net"
        assert resources["aws_vpc.main"].module == ""
        assert resources["module.net.aws_subnet.this"].name == "this"

    def test_a_literal_input_reaches_the_module(self, result: ParsedOutput) -> None:
        db = by_address(result)["module.db.aws_db_instance.this"]
        assert db.properties["publicly_accessible"] is True

    def test_a_module_default_applies_when_no_input_is_given(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "./m"\n}\n')
        write(
            tmp_path,
            "m/main.tf",
            'variable "p" {\n  default = "d"\n}\nresource "a" "b" {\n  v = var.p\n}\n',
        )
        assert by_address(parse_dir(tmp_path))["module.m.a.b"].properties["v"] == "d"

    def test_an_input_computed_from_a_count_resolves(self, result: ParsedOutput) -> None:
        subnets = by_address(result)["module.net.aws_subnet.this"]
        assert subnets.meta == {"count": 2}

    def test_a_parent_reference_passed_as_an_input_is_a_reference_of_the_resource(
        self, tmp_path: Path
    ) -> None:
        write(
            tmp_path,
            "main.tf",
            """
            resource "aws_vpc" "main" {}
            module "m" {
              source = "./m"
              vpc_id = aws_vpc.main.id
            }
            """,
        )
        write(
            tmp_path,
            "m/main.tf",
            'variable "vpc_id" {}\nresource "aws_subnet" "s" {\n  vpc_id = var.vpc_id\n}\n',
        )
        subnet = by_address(parse_dir(tmp_path))["module.m.aws_subnet.s"]
        assert subnet.references == {"vpc_id": ["aws_vpc.main.id"]}
        assert is_unknown(subnet.properties["vpc_id"])
        assert subnet.properties["vpc_id"].reference == "aws_vpc.main.id"

    def test_a_reference_inside_a_module_is_qualified(self, result: ParsedOutput) -> None:
        group = by_address(result)["module.db.aws_db_instance.this"]
        assert group.references == {
            "db_subnet_group_name": ["module.db.aws_db_subnet_group.this.name"]
        }

    def test_a_module_output_in_the_caller_resolves_to_what_the_output_names(
        self, result: ParsedOutput
    ) -> None:
        resources = by_address(result)
        assert resources["aws_instance.app"].references == {
            "subnet_id": ["module.net.aws_subnet.this.id"]
        }
        assert resources["module.db.aws_db_subnet_group.this"].references == {
            "subnet_ids": ["module.net.aws_subnet.this.id"]
        }

    def test_a_reference_the_module_would_shadow_is_dropped_with_a_note(
        self, result: ParsedOutput
    ) -> None:
        subnet = by_address(result)["module.net.aws_subnet.this"]
        # the empty entry tells the graph the attribute was handled, so it guesses no edge
        assert subnet.references["vpc_id"] == []
        notes = [d for d in codes(result, "hcl.unresolved_reference") if "shadows" in d.message]
        assert len(notes) == 1 and "aws_vpc.main" in notes[0].message

    def test_the_graph_uses_the_module_edges(self, result: ParsedOutput) -> None:
        graph = InfraGraph.from_parsed(result)
        edges = {(e.source, e.target) for e in graph.edges}
        assert ("aws_instance.app", "module.net.aws_subnet.this") in edges
        assert ("module.db.aws_db_instance.this", "module.db.aws_db_subnet_group.this") in edges
        assert ("module.net.aws_subnet.this", "aws_vpc.main") not in edges
        assert ("module.net.aws_subnet.local", "module.net.aws_vpc.main") in edges

    def test_the_followed_modules_are_listed(self, result: ParsedOutput) -> None:
        assert result.metadata["modules"] == ["module.net", "module.db"]

    def test_a_nested_module_is_addressed_through_both(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "outer" {\n  source = "./outer"\n}\n')
        write(tmp_path, "outer/main.tf", 'module "inner" {\n  source = "./inner"\n}\n')
        write(tmp_path, "outer/inner/main.tf", 'resource "a" "b" {}\n')
        result = parse_dir(tmp_path)
        assert list(by_address(result)) == ["module.outer.module.inner.a.b"]
        assert (
            by_address(result)["module.outer.module.inner.a.b"].module
            == "module.outer.module.inner"
        )

    def test_a_module_that_calls_itself_is_skipped_not_followed_forever(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", 'module "again" {\n  source = "./m"\n}\n')
        write(tmp_path, "m/main.tf", 'resource "a" "b" {}\nmodule "loop" {\n  source = "../m"\n}\n')
        result = parse_dir(tmp_path)
        assert list(by_address(result)) == ["module.again.a.b"]
        (skipped,) = codes(result, "hcl.module_call_skipped")
        assert "calls itself" in skipped.message
        assert result.metadata["incomplete"] is True

    def test_nesting_deeper_than_the_limit_is_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.parsers.terraform_hcl.MAX_MODULE_DEPTH", 2)
        write(tmp_path, "main.tf", 'module "one" {\n  source = "./one"\n}\n')
        write(tmp_path, "one/main.tf", 'module "two" {\n  source = "./two"\n}\n')
        write(tmp_path, "one/two/main.tf", 'module "three" {\n  source = "./three"\n}\n')
        write(tmp_path, "one/two/three/main.tf", 'resource "a" "b" {}\n')
        result = parse_dir(tmp_path)
        assert result.resources == []
        assert result.metadata["incomplete"] is True
        assert any("nested" in d.message for d in codes(result, "hcl.module_call_skipped"))

    def test_the_total_number_of_module_calls_is_limited(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.parsers.terraform_hcl.MAX_MODULE_INSTANCES", 2)
        calls = "".join(f'module "m{i}" {{\n  source = "./m"\n}}\n' for i in range(4))
        write(tmp_path, "main.tf", calls)
        write(tmp_path, "m/main.tf", 'resource "a" "b" {}\n')
        result = parse_dir(tmp_path)
        assert len(result.resources) == 2
        assert result.metadata["incomplete"] is True

    def test_a_missing_module_directory_is_skipped(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "gone" {\n  source = "./nowhere"\n}\n')
        result = parse_dir(tmp_path)
        assert result.metadata["incomplete"] is True
        assert "missing" in codes(result, "hcl.module_call_skipped")[0].message

    def test_a_symlinked_module_directory_is_not_followed(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        write(outside, "main.tf", 'resource "a" "b" {}\n')
        root = tmp_path / "root"
        write(root, "main.tf", 'module "linked" {\n  source = "./link"\n}\n')
        (root / "link").symlink_to(outside, target_is_directory=True)
        result = parse_dir(root)
        assert result.resources == []
        assert result.metadata["incomplete"] is True

    def test_a_symlinked_file_inside_a_module_is_not_read(self, tmp_path: Path) -> None:
        root = tmp_path / "root"
        write(root, "main.tf", 'module "m" {\n  source = "./m"\n}\n')
        write(root, "m/real.tf", 'resource "a" "real" {}\n')
        secret = write(tmp_path / "elsewhere", "secret.tf", 'resource "a" "linked" {}\n')
        (root / "m" / "link.tf").symlink_to(secret)
        assert list(by_address(parse_dir(root))) == ["module.m.a.real"]

    def test_a_module_with_a_literal_zero_count_creates_nothing(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "./m"\n  count  = 0\n}\n')
        write(tmp_path, "m/main.tf", 'resource "a" "b" {}\n')
        result = parse_dir(tmp_path)
        assert result.resources == []
        assert "incomplete" not in result.metadata
        assert codes(result, "hcl.count_zero")

    def test_a_module_with_a_count_is_followed_once_and_flagged(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "./m"\n  count  = 2\n}\n')
        write(tmp_path, "m/main.tf", 'resource "a" "b" {}\n')
        resource = by_address(parse_dir(tmp_path))["module.m.a.b"]
        assert resource.meta == {"module_instances": "unknown"}

    def test_path_module_in_a_source_is_the_modules_own_directory(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "${path.module}/m"\n}\n')
        write(tmp_path, "m/main.tf", 'resource "a" "b" {}\n')
        assert list(by_address(parse_dir(tmp_path))) == ["module.m.a.b"]

    def test_the_same_module_called_twice_gets_two_address_sets(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf",
            'module "x" {\n  source = "./m"\n}\nmodule "y" {\n  source = "./m"\n}\n',
        )
        write(tmp_path, "m/main.tf", 'resource "a" "b" {}\n')
        assert list(by_address(parse_dir(tmp_path))) == ["module.x.a.b", "module.y.a.b"]

    def test_a_single_file_follows_its_local_modules_from_its_own_directory(self) -> None:
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "local_modules" / "main.tf")
        assert "module.net.aws_subnet.this" in by_address(result)

    def test_text_with_no_directory_cannot_follow_a_local_module(self) -> None:
        text = 'module "m" {\n  source = "./m"\n}\n'
        result = TerraformHCLParser().parse_text(text, source_path="nowhere/main.tf")
        assert result.metadata["incomplete"] is True
        assert "no directory" in codes(result, "hcl.module_call_skipped")[0].message


class TestRemoteModules:
    def test_a_remote_only_root_is_flagged_incomplete(self) -> None:
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "modules.tf")
        assert result.resources == []
        assert result.metadata["incomplete"] is True
        assert [m["module"] for m in result.metadata["skipped_modules"]] == [
            "module.s3",
            "module.vpc",
        ]

    def test_each_skipped_call_is_a_warning_that_names_the_source_and_the_remedy(self) -> None:
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "modules.tf")
        warnings = codes(result, "hcl.module_call_skipped")
        assert [w.level for w in warnings] == ["warning", "warning"]
        assert "terraform-aws-modules/s3-bucket/aws" in warnings[0].message
        assert "git::https://example.com/org/vpc.git" in warnings[1].message
        assert all("terraform show -json" in w.message for w in warnings)
        assert [w.line for w in warnings] == [3, 8]

    def test_skipped_modules_record_the_source_and_reason(self) -> None:
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "modules.tf")
        first = result.metadata["skipped_modules"][0]
        assert first["source"] == "terraform-aws-modules/s3-bucket/aws"
        assert "not a local module" in first["reason"]

    def test_a_root_without_module_calls_is_not_incomplete(self) -> None:
        result = TerraformHCLParser().parse_file(FIXTURES_DIR / "simple.tf")
        assert "incomplete" not in result.metadata
        assert "skipped_modules" not in result.metadata

    def test_a_module_with_an_unknown_source_is_skipped(self, tmp_path: Path) -> None:
        result = parse_snippet(tmp_path, 'variable "s" {}\nmodule "m" {\n  source = var.s\n}\n')
        assert result.metadata["incomplete"] is True

    def test_the_resources_around_a_remote_module_are_still_modelled(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            'resource "aws_vpc" "main" {}\nmodule "x" {\n  source = "hashicorp/consul/aws"\n}\n',
        )
        assert list(by_address(result)) == ["aws_vpc.main"]
        assert result.metadata["incomplete"] is True


class TestDataBlocks:
    def test_a_data_block_is_a_data_node(self) -> None:
        resources = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "references.tf"))
        ami = resources["data.aws_ami.base"]
        assert ami.mode == "data"
        assert ami.resource_type == "aws_ami"
        assert ami.name == "base"
        assert ami.properties == {"most_recent": True, "owners": ["amazon"]}
        assert resources["aws_vpc.main"].mode == "managed"

    def test_a_data_node_in_a_module_is_qualified(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "./m"\n}\n')
        write(tmp_path, "m/main.tf", 'data "aws_ami" "x" {}\n')
        assert list(by_address(parse_dir(tmp_path))) == ["module.m.data.aws_ami.x"]

    def test_a_data_reference_becomes_an_edge_to_the_data_node(self) -> None:
        graph = InfraGraph.from_parsed(
            TerraformHCLParser().parse_file(HCL_FIXTURES / "references.tf")
        )
        edges = {(e.source, e.target) for e in graph.edges}
        assert ("aws_instance.web", "data.aws_ami.base") in edges
        assert graph.nodes["data.aws_ami.base"].mode == "data"

    POLICY_DOC = """
        data "aws_iam_policy_document" "doc" {
          statement {
            sid       = "Read"
            actions   = ["s3:GetObject"]
            resources = ["arn:aws:s3:::b/*"]
          }
          statement {
            effect     = "Deny"
            actions    = ["s3:*", "iam:*"]
            not_resources = ["arn:aws:s3:::safe"]
            principals {
              type        = "AWS"
              identifiers = ["*"]
            }
            condition {
              test     = "Bool"
              variable = "aws:SecureTransport"
              values   = ["false"]
            }
          }
        }
        resource "aws_iam_policy" "p" {
          policy = data.aws_iam_policy_document.doc.json
        }
    """

    def test_a_policy_document_with_literal_statements_renders_to_json(
        self, tmp_path: Path
    ) -> None:
        policy = by_address(parse_snippet(tmp_path, self.POLICY_DOC))["aws_iam_policy.p"]
        document = json.loads(policy.properties["policy"])
        assert document["Version"] == "2012-10-17"
        assert document["Statement"][0] == {
            "Sid": "Read",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::b/*",
        }
        assert document["Statement"][1] == {
            "Effect": "Deny",
            "Action": ["s3:*", "iam:*"],
            "NotResource": "arn:aws:s3:::safe",
            "Principal": {"AWS": "*"},
            "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        }

    def test_the_rendered_document_is_canonical_compact_json(self, tmp_path: Path) -> None:
        policy = by_address(parse_snippet(tmp_path, self.POLICY_DOC))["aws_iam_policy.p"]
        text = policy.properties["policy"]
        assert text == json.dumps(json.loads(text), sort_keys=True, separators=(",", ":"))

    def test_a_document_that_names_a_resource_keeps_its_structure(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            resource "aws_s3_bucket" "b" {}
            data "aws_iam_policy_document" "doc" {
              statement {
                actions   = ["*"]
                resources = [aws_s3_bucket.b.arn]
              }
              statement {
                actions   = ["s3:GetObject"]
                resources = ["${aws_s3_bucket.b.arn}/*"]
              }
            }
            resource "aws_iam_policy" "p" {
              policy = data.aws_iam_policy_document.doc.json
            }
            """,
        )
        policy = by_address(result)["aws_iam_policy.p"].properties["policy"]
        assert isinstance(policy, dict)
        first, second = policy["Statement"]
        assert first["Action"] == "*"
        assert first["Resource"].reference == "aws_s3_bucket.b.arn"
        assert second["Resource"] == "(known after apply)/*"

    def test_the_policy_attribute_keeps_the_data_reference(self, tmp_path: Path) -> None:
        policy = by_address(parse_snippet(tmp_path, self.POLICY_DOC))["aws_iam_policy.p"]
        assert policy.references == {"policy": ["data.aws_iam_policy_document.doc.json"]}

    def test_the_wildcard_principal_form(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            data "aws_iam_policy_document" "doc" {
              statement {
                actions = ["s3:GetObject"]
                principals {
                  type        = "*"
                  identifiers = ["*"]
                }
              }
            }
            resource "aws_s3_bucket_policy" "p" {
              policy = data.aws_iam_policy_document.doc.json
            }
            """,
        )
        policy = json.loads(by_address(result)["aws_s3_bucket_policy.p"].properties["policy"])
        assert policy["Statement"][0]["Principal"] == "*"

    @pytest.mark.parametrize(
        "extra",
        [
            "source_policy_documents = [data.aws_iam_policy_document.other.json]",
            'override_policy_documents = ["{}"]',
            'dynamic "statement" {\n for_each = var.stmts\n content {\n actions = ["*"]\n }\n }',
        ],
    )
    def test_a_document_that_cannot_be_known_is_unknown(self, tmp_path: Path, extra: str) -> None:
        result = parse_snippet(
            tmp_path,
            f"""
            data "aws_iam_policy_document" "doc" {{
              {extra}
            }}
            resource "aws_iam_policy" "p" {{
              policy = data.aws_iam_policy_document.doc.json
            }}
            """,
        )
        assert is_unknown(by_address(result)["aws_iam_policy.p"].properties["policy"])

    def test_a_document_that_refers_to_itself_is_unknown_not_a_loop(self, tmp_path: Path) -> None:
        result = parse_snippet(
            tmp_path,
            """
            data "aws_iam_policy_document" "doc" {
              statement {
                actions   = ["*"]
                resources = [data.aws_iam_policy_document.doc.json]
              }
            }
            resource "aws_iam_policy" "p" {
              policy = data.aws_iam_policy_document.doc.json
            }
            """,
        )
        assert "aws_iam_policy.p" in by_address(result)

    def test_other_data_attributes_are_unknown(self) -> None:
        ami = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "references.tf"))[
            "aws_instance.web"
        ]
        assert is_unknown(ami.properties["ami"])


@pytest.fixture(scope="module")
def policies() -> dict[str, ParsedResource]:
    return by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "iam_policies.tf"))


class TestPolicyNormalization:
    def test_heredoc_jsonencode_and_escaped_policies_are_identical(
        self, policies: dict[str, ParsedResource]
    ) -> None:
        texts = {
            name: policies[f"aws_iam_policy.{name}"].properties["policy"]
            for name in ("heredoc", "jsonencode", "escaped", "indented_heredoc")
        }
        expected = (
            '{"Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}'
        )
        assert texts == {name: expected for name in texts}

    def test_the_existing_wildcard_rule_text_is_present(
        self, policies: dict[str, ParsedResource]
    ) -> None:
        assert '"Action":"*"' in policies["aws_iam_policy.jsonencode"].properties["policy"]

    def test_a_policy_with_a_variable_keeps_the_literal_parts(
        self, policies: dict[str, ParsedResource]
    ) -> None:
        text = policies["aws_iam_policy.with_variable"].properties["policy"]
        document = json.loads(text)
        assert document["Statement"][0]["Action"] == ["s3:GetObject"]
        assert document["Statement"][0]["Resource"] == "arn:aws:s3:::(known after apply)/*"

    def test_a_policy_with_a_resource_reference_keeps_its_structure(
        self, policies: dict[str, ParsedResource]
    ) -> None:
        policy = policies["aws_iam_policy.scoped_reference"].properties["policy"]
        assert isinstance(policy, dict)
        statement = policy["Statement"][0]
        assert statement["Action"] == ["s3:GetObject"]
        assert is_unknown(statement["Resource"])
        assert statement["Resource"].reference == "aws_s3_bucket.data.arn"

    def test_a_policy_whose_unknown_part_is_only_inside_a_template_is_text(
        self, policies: dict[str, ParsedResource]
    ) -> None:
        assert isinstance(policies["aws_iam_policy.with_variable"].properties["policy"], str)

    def test_a_policy_with_a_variable_does_not_look_like_a_wildcard(
        self, policies: dict[str, ParsedResource]
    ) -> None:
        assert '"Action":"*"' not in policies["aws_iam_policy.with_variable"].properties["policy"]

    def test_the_policy_reference_is_recorded(self, policies: dict[str, ParsedResource]) -> None:
        assert policies["aws_iam_policy.scoped_reference"].references == {
            "policy": ["aws_s3_bucket.data.arn"]
        }

    def test_ternary_expression_text_keeps_lowercase_literals(self, tmp_path: Path) -> None:
        # the Python-flavoured True and None of python-hcl2 4.x never reach a property
        result = parse_snippet(
            tmp_path,
            'resource "a" "b" {\n  x = var.p ? true : false\n  y = var.p ? null : "v"\n}\n',
        )
        props = by_address(result)["a.b"].properties
        assert is_unknown(props["x"]) and "True" not in props["x"].reference
        assert is_unknown(props["y"]) and "None" not in props["y"].reference

    def test_a_plain_string_that_is_not_json_is_unchanged(self, tmp_path: Path) -> None:
        result = parse_snippet(tmp_path, 'resource "a" "b" {\n  x = "{not json"\n}\n')
        assert by_address(result)["a.b"].properties["x"] == "{not json"


class TestUnknownValues:
    def test_unresolved_expressions_are_unknown_never_absent(self) -> None:
        main = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "expressions.tf"))[
            "aws_db_instance.main"
        ]
        assert is_unknown(main.properties["kms_key_id"])
        assert main.properties["kms_key_id"].reference == "aws_kms_key.main.arn"
        assert is_unknown(main.properties["name"])

    def test_for_expressions_functions_and_files_stay_unknown(self) -> None:
        web = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "expressions.tf"))[
            "aws_instance.web"
        ]
        assert is_unknown(web.properties["user_data"])
        assert is_unknown(web.properties["tags"]["loop"])

    def test_a_ternary_over_known_values_is_evaluated(self) -> None:
        web = by_address(TerraformHCLParser().parse_file(HCL_FIXTURES / "expressions.tf"))[
            "aws_instance.web"
        ]
        assert web.properties["instance_type"] == "t3.micro"
        assert web.properties["monitoring"] is False

    def test_the_declared_value_of_a_variable_with_a_value_is_not_unknown(self) -> None:
        assert not is_unknown(
            by_address(parse_dir(HCL_FIXTURES / "tfvars_dir"))["aws_db_instance.main"].properties[
                "identifier"
            ]
        )

    def test_no_property_holds_expression_text(self) -> None:
        for path in sorted(HCL_FIXTURES.glob("*.tf")):
            for resource in TerraformHCLParser().parse_file(path).resources:
                dumped = json.dumps(resource.properties, default=str)
                assert "${" not in dumped.replace("$${", ""), (path.name, resource.address)


class TestUnresolvedDiagnostics:
    def test_a_declared_variable_with_no_value_is_info(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf",
            'variable "db_password" {}\nresource "a" "b" {\n  password = var.db_password\n}\n',
        )
        (note,) = codes(parse_dir(tmp_path), "hcl.unresolved_reference")
        assert note.level == "info"
        assert "a.b" in note.message and "var.db_password" in note.message
        assert "'password'" in note.message
        assert note.line == 2 and note.file.endswith("main.tf")

    def test_an_undeclared_variable_in_a_directory_is_a_warning(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'resource "a" "b" {\n  x = var.never_declared\n}\n')
        (note,) = codes(parse_dir(tmp_path), "hcl.unresolved_reference")
        assert note.level == "warning"

    def test_an_undeclared_variable_in_a_single_file_is_only_info(self, tmp_path: Path) -> None:
        result = parse_snippet(tmp_path, 'resource "a" "b" {\n  x = var.maybe_elsewhere\n}\n')
        (note,) = codes(result, "hcl.unresolved_reference")
        assert note.level == "info"

    def test_one_diagnostic_per_resource_lists_every_attribute_and_name(
        self, tmp_path: Path
    ) -> None:
        write(
            tmp_path,
            "main.tf",
            """
            variable "a" {}
            variable "b" {}
            resource "x" "y" {
              first  = var.a
              second = "${var.a}-${var.b}"
              third  = var.b
              fine   = "literal"
            }
            """,
        )
        (note,) = codes(parse_dir(tmp_path), "hcl.unresolved_reference")
        assert note.message.count("var.a") == 1 and note.message.count("var.b") == 1
        for attribute in ("'first'", "'second'", "'third'"):
            assert attribute in note.message
        assert "'fine'" not in note.message

    def test_a_resource_with_every_value_known_has_no_note(self) -> None:
        assert codes(parse_dir(HCL_FIXTURES / "module_dir"), "hcl.unresolved_reference") == []

    def test_a_resource_reference_is_not_a_missing_input(self) -> None:
        # attributes of other resources are normal "known after apply" values
        result = TerraformHCLParser().parse_file(HCL_FIXTURES / "module_dir" / "net.tf")
        assert codes(result, "hcl.unresolved_reference") == []

    def test_a_module_input_that_is_missing_names_the_module(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "./m"\n}\n')
        write(tmp_path, "m/main.tf", 'variable "need" {}\nresource "a" "b" {\n  v = var.need\n}\n')
        (note,) = codes(parse_dir(tmp_path), "hcl.unresolved_reference")
        assert note.message.startswith("module.m.a.b:")


class TestSpans:
    def test_every_resource_block_has_its_lines(self) -> None:
        result = TerraformHCLParser().parse_file(FIXTURES_DIR / "simple.tf")
        spans = {r.address: (r.start_line, r.end_line) for r in result.resources}
        assert spans == {"aws_s3_bucket.test": (1, 4), "aws_instance.web": (6, 10)}

    def test_lines_are_one_based_and_inclusive_of_the_closing_brace(self, tmp_path: Path) -> None:
        text = '\n\n# comment\nresource "a" "b" {\n  x = 1\n}\n'
        (resource,) = parse_snippet(tmp_path, text).resources
        assert (resource.start_line, resource.end_line) == (4, 6)
        assert resource.start_line is not None and resource.end_line is not None
        assert text.splitlines()[resource.start_line - 1].startswith("resource")
        assert text.splitlines()[resource.end_line - 1] == "}"

    def test_data_blocks_and_module_resources_have_lines(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "local_modules"))
        assert resources["module.net.aws_subnet.this"].start_line == 14
        assert resources["aws_vpc.main"].start_line == 1

    def test_a_resource_points_at_its_own_file(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "module_dir"))
        assert resources["aws_subnet.a"].source_location.endswith("net.tf")
        assert resources["aws_instance.web"].source_location.endswith("main.tf")

    def test_module_resources_point_at_the_module_file(self) -> None:
        resources = by_address(parse_dir(HCL_FIXTURES / "local_modules"))
        location = resources["module.db.aws_db_instance.this"].source_location
        assert location.endswith("modules/db/main.tf")

    def test_the_lines_survive_a_repeated_resource_type(self, tmp_path: Path) -> None:
        text = 'resource "a" "one" {\n}\nresource "a" "two" {\n  x = 1\n}\n'
        spans = {
            r.name: (r.start_line, r.end_line) for r in parse_snippet(tmp_path, text).resources
        }
        assert spans == {"one": (1, 2), "two": (3, 5)}

    def test_json_syntax_resources_have_a_start_line(self) -> None:
        shapes = Path(__file__).parent.parent / "fixtures" / "input_shapes"
        result = TerraformHCLParser().parse_text(
            (shapes / "cdk.tf.json").read_text(encoding="utf-8"), source_path="cdk.tf.json"
        )
        lines = {r.name: r.start_line for r in result.resources}
        assert all(isinstance(line, int) and line > 0 for line in lines.values())

    def test_the_graph_nodes_carry_the_lines(self) -> None:
        graph = InfraGraph.from_parsed(TerraformHCLParser().parse_file(FIXTURES_DIR / "simple.tf"))
        node = graph.nodes["aws_instance.web"]
        assert (node.start_line, node.end_line) == (6, 10)
        assert node.source_file.endswith("simple.tf")


class TestDirectoryFailures:
    def test_one_bad_file_is_a_diagnostic_and_the_rest_still_parse(self, tmp_path: Path) -> None:
        module = tmp_path / "module"
        write(module, "main.tf", 'resource "aws_s3_bucket" "ok" {}\n')
        write(module, "zz_bad.tf", "resource {{{\n")
        result = parse_dir(module)
        assert list(by_address(result)) == ["aws_s3_bucket.ok"]
        (failure,) = codes(result, "parse.failed")
        assert failure.level == "error"
        assert failure.file.endswith("zz_bad.tf")
        assert "zz_bad.tf" in failure.message
        assert result.metadata["files"] == ["main.tf"]

    def test_several_bad_files_each_get_a_diagnostic(self, tmp_path: Path) -> None:
        write(tmp_path, "a.tf", 'resource "a" "ok" {}\n')
        write(tmp_path, "b.tf", "= = =\n")
        write(tmp_path, "c.tf", "resource {{{\n")
        failures = codes(parse_dir(tmp_path), "parse.failed")
        assert [Path(f.file).name for f in failures] == ["b.tf", "c.tf"]

    def test_every_file_bad_raises(self, tmp_path: Path) -> None:
        write(tmp_path, "a.tf", "resource {{{\n")
        write(tmp_path, "b.tf", "= = =\n")
        with pytest.raises(ParseError, match=r"a\.tf"):
            parse_dir(tmp_path)

    def test_a_single_file_scan_still_raises(self, tmp_path: Path) -> None:
        path = write(tmp_path, "bad.tf", "resource {{{\n")
        with pytest.raises(ParseError, match=r"bad\.tf"):
            TerraformHCLParser().parse_file(path)

    def test_an_undecodable_file_is_a_diagnostic(self, tmp_path: Path) -> None:
        write(tmp_path, "a.tf", 'resource "a" "ok" {}\n')
        (tmp_path / "b.tf").write_bytes(b"\xff\xfe\x00 not text")
        result = parse_dir(tmp_path)
        assert list(by_address(result)) == ["a.ok"]
        assert codes(result, "parse.failed")

    def test_a_bad_file_in_a_followed_module_is_a_diagnostic(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", 'module "m" {\n  source = "./m"\n}\nresource "a" "root" {}\n')
        write(tmp_path, "m/ok.tf", 'resource "a" "inner" {}\n')
        write(tmp_path, "m/bad.tf", "resource {{{\n")
        result = parse_dir(tmp_path)
        assert set(by_address(result)) == {"a.root", "module.m.a.inner"}
        assert [Path(f.file).name for f in codes(result, "parse.failed")] == ["bad.tf"]


class TestJsonSyntaxModules:
    def test_variables_locals_and_references_in_json_syntax(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf.json",
            json.dumps(
                {
                    "variable": {"public": {"default": False}},
                    "locals": {"name": "app"},
                    "resource": {
                        "aws_vpc": {"main": {"cidr_block": "10.0.0.0/16"}},
                        "aws_subnet": {
                            "a": {
                                "vpc_id": "${aws_vpc.main.id}",
                                "map_public_ip_on_launch": "${var.public}",
                                "tags": {"Name": "${local.name}-a"},
                            }
                        },
                    },
                }
            ),
        )
        subnet = by_address(parse_dir(tmp_path))["aws_subnet.a"]
        assert subnet.references == {"vpc_id": ["aws_vpc.main.id"]}
        assert subnet.properties["map_public_ip_on_launch"] is False
        assert subnet.properties["tags"] == {"Name": "app-a"}

    def test_json_syntax_and_hcl_files_form_one_module(self, tmp_path: Path) -> None:
        write(tmp_path, "net.tf", 'resource "aws_vpc" "main" {}\n')
        write(
            tmp_path,
            "app.tf.json",
            json.dumps({"resource": {"aws_subnet": {"a": {"vpc_id": "${aws_vpc.main.id}"}}}}),
        )
        assert by_address(parse_dir(tmp_path))["aws_subnet.a"].references == {
            "vpc_id": ["aws_vpc.main.id"]
        }

    def test_a_tofu_file_parses(self, tmp_path: Path) -> None:
        path = tmp_path / "main.tofu"
        path.write_bytes(
            (Path(__file__).parent.parent / "fixtures" / "input_shapes" / "main.tofu").read_bytes()
        )
        assert [r.address for r in TerraformHCLParser().parse_file(path).resources] == [
            "aws_s3_bucket.tofu"
        ]

    def test_json_policy_strings_are_canonical(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "main.tf.json",
            json.dumps(
                {
                    "resource": {
                        "aws_iam_policy": {
                            "p": {"policy": '{"Statement": [{"Action": "*"}], "Version": "1"}'}
                        }
                    }
                }
            ),
        )
        policy = by_address(parse_dir(tmp_path))["aws_iam_policy.p"].properties["policy"]
        assert policy == '{"Statement":[{"Action":"*"}],"Version":"1"}'


REAL_MODULES = HCL_FIXTURES / "real_modules"
FAIL_ON_4X = {"eks_node_groups.tf", "eks_managed_node_group.tf", "lambda_deploy.tf"}


class TestRealModules:
    """Files from terraform-aws-modules, copied unchanged (see the README next to them)."""

    @pytest.mark.skipif(not MODERN, reason="python-hcl2 4.x cannot parse every real module")
    @pytest.mark.parametrize("name", sorted(p.name for p in REAL_MODULES.glob("*.tf")))
    def test_every_file_parses_under_8x(self, name: str) -> None:
        result = TerraformHCLParser().parse_file(REAL_MODULES / name)
        assert result.resources, name
        assert all(r.start_line and r.end_line for r in result.resources)
        assert not [d for d in result.diagnostics if d.level == "error"]

    @pytest.mark.skipif(MODERN, reason="only python-hcl2 4.x rejects these files")
    @pytest.mark.parametrize("name", sorted(FAIL_ON_4X))
    def test_the_known_hard_files_are_a_parse_error_naming_the_file_under_4x(
        self, name: str
    ) -> None:
        with pytest.raises(ParseError, match=name):
            TerraformHCLParser().parse_file(REAL_MODULES / name)

    @pytest.mark.skipif(MODERN, reason="the easy files are checked under both in the 8.x test")
    @pytest.mark.parametrize(
        "name", sorted(p.name for p in REAL_MODULES.glob("*.tf") if p.name not in FAIL_ON_4X)
    )
    def test_the_other_files_parse_under_4x(self, name: str) -> None:
        assert TerraformHCLParser().parse_file(REAL_MODULES / name).resources

    @pytest.mark.skipif(not MODERN, reason="needs a file python-hcl2 4.x cannot parse")
    def test_the_real_modules_directory_is_one_module_under_8x(self) -> None:
        result = parse_dir(REAL_MODULES)
        assert not codes(result, "parse.failed")
        assert {"eks_node_groups.tf", "lambda_deploy.tf"} <= set(result.metadata["files"])

    @pytest.mark.skipif(not MODERN, reason="python-hcl2 4.x cannot parse every real module")
    def test_the_lambda_policies_resolve_through_the_module(self) -> None:
        result = TerraformHCLParser().parse_file(REAL_MODULES / "lambda_iam.tf")
        policies = [r for r in result.resources if r.resource_type == "aws_iam_policy"]
        assert policies
        for policy in policies:
            assert not any("${" in str(value) for value in policy.properties.values()), (
                policy.address
            )

    @pytest.mark.skipif(not MODERN, reason="python-hcl2 4.x cannot parse every real module")
    def test_real_modules_produce_no_python_literals(self) -> None:
        for path in sorted(REAL_MODULES.glob("*.tf")):
            for resource in TerraformHCLParser().parse_file(path).resources:
                dumped = json.dumps(resource.properties, default=str)
                assert "True" not in dumped and "None" not in dumped, (path.name, resource.address)


# --- limits: a hostile file must stay cheap to read ----------------------------------------


def run_within(work: Callable[[], ParsedOutput], seconds: float = 30.0) -> ParsedOutput:
    """Run ``work`` in a thread so a runaway evaluation fails the test instead of hanging it."""
    box: dict[str, Any] = {}

    def target() -> None:
        try:
            box["result"] = work()
        except BaseException as exc:  # noqa: BLE001 - handed back to the test thread below
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(seconds)
    assert not thread.is_alive(), f"the parse had not finished after {seconds} seconds"
    assert time.monotonic() - started < seconds
    if "error" in box:
        raise box["error"]
    result: ParsedOutput = box["result"]
    return result


def chain_of_locals(
    n: int,
    step: str,
    base: str = "1",
    attribute: str = "bucket",
    prefix: str = "l",
    resource: str = "b",
) -> str:
    """``<prefix>0 = base`` and ``<prefix><i> = step``, with ``PREV`` the previous local."""
    lines = ["locals {", f"  {prefix}0 = {base}"]
    for i in range(1, n + 1):
        lines.append(f"  {prefix}{i} = " + step.replace("PREV", f"local.{prefix}{i - 1}"))
    lines.append("}")
    lines.append(f'resource "aws_s3_bucket" "{resource}" {{\n  {attribute} = local.{prefix}{n}\n}}')
    return "\n".join(lines) + "\n"


TEMPLATE_DOUBLING = '"${PREV}${PREV}"'
DOUBLING_SHAPES = {
    "template": TEMPLATE_DOUBLING,
    "concat": "concat(PREV, PREV)",
    "list": "[PREV, PREV]",
    "object": "{a = PREV, b = PREV}",
    "jsonencode": "jsonencode([PREV, PREV])",
    "flatten": "flatten([PREV, PREV])",
    "merge": "merge({x = PREV}, {y = PREV})",
}
BASES = {"template": '"aaaaaaaaaa"', "concat": '["a"]'}


def doubling(shape: str, n: int, attribute: str = "bucket", **names: str) -> str:
    return chain_of_locals(n, DOUBLING_SHAPES[shape], BASES.get(shape, '"a"'), attribute, **names)


def only_resource(result: ParsedOutput) -> ParsedResource:
    (resource,) = result.resources
    return resource


class TestValueSizeLimits:
    """Short files that double a value must scan quickly and leave the value Unknown."""

    # Up to 23 the chain is within the nesting limit, so only the size limit can stop it
    @pytest.mark.parametrize("n", [19, 21, 23, 40, 400])
    @pytest.mark.parametrize("shape", ["template", "concat"])
    def test_doubling_locals_finish_fast_and_are_unknown(
        self, tmp_path: Path, shape: str, n: int
    ) -> None:
        write(tmp_path, "main.tf", doubling(shape, n))
        started = time.monotonic()
        result = run_within(lambda: parse_dir(tmp_path))
        assert time.monotonic() - started < 10
        assert is_unknown(only_resource(result).properties["bucket"])

    @pytest.mark.parametrize("shape", ["template", "concat"])
    def test_the_single_file_path_is_just_as_safe(self, tmp_path: Path, shape: str) -> None:
        path = write(tmp_path, "main.tf", doubling(shape, 23))
        result = run_within(lambda: TerraformHCLParser().parse_file(path))
        assert is_unknown(only_resource(result).properties["bucket"])

    @pytest.mark.parametrize("n", [20, 40])
    @pytest.mark.parametrize("shape", ["list", "object", "jsonencode", "flatten", "merge"])
    def test_doubling_a_shared_structure_stays_small(
        self, tmp_path: Path, shape: str, n: int
    ) -> None:
        # [x, x] shares x, so the process holds little, but anything that prints or walks the
        # value would see 2**40 elements; the value must be bounded to what it would weigh
        write(tmp_path, "main.tf", doubling(shape, n))
        result = run_within(lambda: parse_dir(tmp_path))
        value = only_resource(result).properties["bucket"]
        assert len(json.dumps(value, default=str)) < 500_000

    def test_a_string_just_under_the_limit_resolves(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", doubling("template", 12))
        result = parse_dir(tmp_path)
        assert only_resource(result).properties["bucket"] == "a" * 10 * 2**12
        assert codes(result, "hcl.evaluation_limit") == []

    def test_a_list_just_under_the_limit_resolves(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", doubling("concat", 12))
        result = parse_dir(tmp_path)
        assert only_resource(result).properties["bucket"] == ["a"] * 2**12
        assert codes(result, "hcl.evaluation_limit") == []

    def test_the_first_level_past_the_limit_is_unknown_and_the_one_before_is_not(
        self, tmp_path: Path
    ) -> None:
        # 10 characters doubled 17 times is 1,310,720, past the 1,048,576 limit; 16 times is not
        write(
            tmp_path,
            "main.tf",
            chain_of_locals(17, TEMPLATE_DOUBLING, '"aaaaaaaaaa"')
            + 'resource "aws_s3_bucket" "c" {\n  bucket = local.l16\n}\n',
        )
        resources = by_address(parse_dir(tmp_path))
        assert is_unknown(resources["aws_s3_bucket.b"].properties["bucket"])
        assert len(resources["aws_s3_bucket.c"].properties["bucket"]) == 655_360

    def test_the_limit_is_one_warning_that_says_what_it_was(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", doubling("template", 20))
        write(tmp_path, "more.tf", doubling("concat", 20, "tags", prefix="m", resource="c"))
        (note,) = codes(run_within(lambda: parse_dir(tmp_path)), "hcl.evaluation_limit")
        assert note.level == "warning"
        assert "treated as unknown" in note.message and "grew past" in note.message
        assert "levels deep" not in note.message

    def test_a_value_the_limit_hides_does_not_fire_an_absence_rule(self, tmp_path: Path) -> None:
        # an Unknown must stay unknown for the rules: it is neither absent nor a pass
        write(tmp_path, "main.tf", doubling("template", 20, "kms_key_id"))
        value = only_resource(parse_dir(tmp_path)).properties["kms_key_id"]
        assert is_unknown(value)
        assert "kms_key_id" in only_resource(parse_dir(tmp_path)).properties

    @pytest.mark.parametrize("name", ["module_dir", "local_modules"])
    def test_a_realistic_module_has_no_limit_note(self, name: str) -> None:
        assert codes(parse_dir(HCL_FIXTURES / name), "hcl.evaluation_limit") == []

    @pytest.mark.skipif(not MODERN, reason="python-hcl2 4.x cannot parse every real module")
    def test_the_real_terraform_aws_modules_hit_no_limit(self) -> None:
        # the largest real input there is: a cap that starts warning here is too tight
        assert codes(parse_dir(REAL_MODULES), "hcl.evaluation_limit") == []
        for path in sorted(REAL_MODULES.glob("*.tf")):
            result = TerraformHCLParser().parse_file(path)
            assert codes(result, "hcl.evaluation_limit") == [], path.name

    def test_references_through_doubling_locals_are_found_without_reading_them_twice(
        self, tmp_path: Path
    ) -> None:
        # 2**20 reads of the same local without a memo; with one, 20
        text = chain_of_locals(20, TEMPLATE_DOUBLING, '"${aws_vpc.main.id}"')
        write(tmp_path, "main.tf", 'resource "aws_vpc" "main" {}\n' + text)
        result = run_within(lambda: parse_dir(tmp_path))
        bucket = by_address(result)["aws_s3_bucket.b"]
        assert bucket.references["bucket"] == ["aws_vpc.main.id"]

    def test_the_work_budget_stops_many_values_just_under_the_limits(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(terraform_hcl, "MAX_EVALUATION_WORK", 3_000)
        lines = ["locals {", "  base = " + json.dumps(list(range(500))), "}"]
        for i in range(30):
            lines.append(f'resource "x" "r{i}" {{\n  v = concat(local.base, [{i}])\n}}')
        write(tmp_path, "main.tf", "\n".join(lines) + "\n")
        result = parse_dir(tmp_path)
        values = [r.properties["v"] for r in result.resources]
        assert not is_unknown(values[0]) and len(values[0]) == 501
        assert is_unknown(values[-1])
        assert codes(result, "hcl.evaluation_limit")


class TestNestingLimits:
    LIMIT = terraform_hcl.MAX_NESTED_RESOLUTIONS

    def chain_with_neighbours(self, n: int, extra: str = "") -> str:
        return (
            chain_of_locals(n, "PREV + 1")
            + 'resource "aws_s3_bucket" "head" {\n  other = local.l5\n}\n'
            + extra
        )

    @pytest.mark.parametrize("through", ["directory", "file"])
    def test_a_two_hundred_deep_chain_parses_and_the_tail_is_unknown(
        self, tmp_path: Path, through: str
    ) -> None:
        # the CLI reads a directory or a file; both used to fail with a RecursionError
        path = write(tmp_path, "main.tf", self.chain_with_neighbours(200))
        if through == "directory":
            result = run_within(lambda: parse_dir(tmp_path))
        else:
            result = run_within(lambda: TerraformHCLParser().parse_file(path))
        resources = by_address(result)
        assert is_unknown(resources["aws_s3_bucket.b"].properties["bucket"])
        assert resources["aws_s3_bucket.head"].properties["other"] == 6
        (note,) = codes(result, "hcl.evaluation_limit")
        assert str(self.LIMIT) in note.message and "levels deep" in note.message

    def test_a_chain_within_the_limit_still_resolves(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", self.chain_with_neighbours(20))
        result = parse_dir(tmp_path)
        assert by_address(result)["aws_s3_bucket.b"].properties["bucket"] == 21
        assert codes(result, "hcl.evaluation_limit") == []

    def test_the_limit_is_exact(self, tmp_path: Path) -> None:
        # l<k> needs k + 1 locals open at once
        edge = self.LIMIT - 1
        write(tmp_path, "main.tf", chain_of_locals(edge, "PREV + 1"))
        assert only_resource(parse_dir(tmp_path)).properties["bucket"] == self.LIMIT
        write(tmp_path, "main.tf", chain_of_locals(edge + 1, "PREV + 1"))
        assert is_unknown(only_resource(parse_dir(tmp_path)).properties["bucket"])

    def test_a_cut_chain_does_not_poison_a_shorter_use_of_the_same_local(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # l14 needs 15 locals open, so it is cut; l7 needs 8 and fits. The cut of l14 reaches
        # l7 while it is being worked out from there, and l7 must still come to 8 when used
        # on its own afterwards.
        monkeypatch.setattr(terraform_hcl, "MAX_NESTED_RESOLUTIONS", 8)
        text = chain_of_locals(14, "PREV + 1", attribute="first")
        text += 'resource "aws_s3_bucket" "second" {\n  middle = local.l7\n}\n'
        text += 'resource "aws_s3_bucket" "third" {\n  again = local.l14\n}\n'
        write(tmp_path, "main.tf", text)
        resources = by_address(parse_dir(tmp_path))
        assert is_unknown(resources["aws_s3_bucket.b"].properties["first"])
        assert resources["aws_s3_bucket.second"].properties["middle"] == 8
        assert is_unknown(resources["aws_s3_bucket.third"].properties["again"])

    def test_no_order_of_resources_loses_a_value_or_invents_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # What an attribute comes to may be more precise when an earlier attribute already
        # worked out part of its chain, but it is never less precise than on its own, and a
        # value it does have is always the right one.
        monkeypatch.setattr(terraform_hcl, "MAX_NESTED_RESOLUTIONS", 8)
        chain = chain_of_locals(14, "PREV + 1").split("resource")[0]
        uses = {"deep": 14, "middle": 7, "edge": 8, "low": 3}

        def values(order: tuple[str, ...]) -> dict[str, Any]:
            body = "".join(
                f'resource "aws_s3_bucket" "{name}" {{\n  v = local.l{uses[name]}\n}}\n'
                for name in order
            )
            write(tmp_path, "main.tf", chain + body)
            result = by_address(parse_dir(tmp_path))
            return {name: result[f"aws_s3_bucket.{name}"].properties["v"] for name in order}

        alone = {name: values((name,))[name] for name in uses}
        assert {name: is_unknown(value) for name, value in alone.items()} == {
            "deep": True,
            "middle": False,
            "edge": True,
            "low": False,
        }
        for order in itertools.permutations(uses):
            for name, value in values(order).items():
                assert is_unknown(value) or value == uses[name] + 1, (order, name)
                if not is_unknown(alone[name]):
                    assert value == uses[name] + 1, (order, name)

    def test_the_references_of_a_long_chain_are_cut_not_crashed(self, tmp_path: Path) -> None:
        text = chain_of_locals(120, "PREV", '"${aws_vpc.main.id}"')
        write(tmp_path, "main.tf", 'resource "aws_vpc" "main" {}\n' + text)
        result = run_within(lambda: parse_dir(tmp_path))
        assert by_address(result)["aws_s3_bucket.b"].references.get("bucket", []) == []
        assert codes(result, "hcl.evaluation_limit")

    def test_the_references_of_a_chain_within_the_limit_are_found(self, tmp_path: Path) -> None:
        text = chain_of_locals(10, "PREV", '"${aws_vpc.main.id}"')
        write(tmp_path, "main.tf", 'resource "aws_vpc" "main" {}\n' + text)
        result = parse_dir(tmp_path)
        assert by_address(result)["aws_s3_bucket.b"].references["bucket"] == ["aws_vpc.main.id"]

    def test_a_chain_that_crosses_a_module_boundary_is_bounded(self, tmp_path: Path) -> None:
        text = chain_of_locals(60, "PREV + 1").split("resource")[0]
        write(
            tmp_path,
            "main.tf",
            text
            + 'module "m" {\n  source = "./m"\n  v      = local.l60\n}\n'
            + 'resource "aws_s3_bucket" "b" {\n  bucket = module.m.o\n}\n',
        )
        write(
            tmp_path,
            "m/main.tf",
            'variable "v" {}\noutput "o" {\n  value = var.v\n}\n'
            'resource "x" "inner" {\n  v = var.v\n}\n',
        )
        result = run_within(lambda: parse_dir(tmp_path))
        resources = by_address(result)
        assert is_unknown(resources["aws_s3_bucket.b"].properties["bucket"])
        assert is_unknown(resources["module.m.x.inner"].properties["v"])

    def test_a_short_chain_through_a_module_still_resolves(self, tmp_path: Path) -> None:
        text = chain_of_locals(5, "PREV + 1").split("resource")[0]
        write(
            tmp_path,
            "main.tf",
            text
            + 'module "m" {\n  source = "./m"\n  v      = local.l5\n}\n'
            + 'resource "aws_s3_bucket" "b" {\n  bucket = module.m.o\n}\n',
        )
        write(tmp_path, "m/main.tf", 'variable "v" {}\noutput "o" {\n  value = var.v\n}\n')
        assert only_resource(parse_dir(tmp_path)).properties["bucket"] == 6

    def test_doubling_policy_documents_are_worked_out_once(self, tmp_path: Path) -> None:
        lines = [
            'data "aws_iam_policy_document" "d0" {',
            '  statement {\n    actions   = ["s3:GetObject"]\n    resources = ["*"]\n  }',
            "}",
        ]
        for i in range(1, 31):
            ref = f"data.aws_iam_policy_document.d{i - 1}.json"
            lines.append(
                f'data "aws_iam_policy_document" "d{i}" {{\n  statement {{\n'
                f'    sid       = "${{{ref}}}${{{ref}}}"\n'
                f'    actions   = ["s3:GetObject"]\n    resources = ["*"]\n  }}\n}}'
            )
        lines.append(
            'resource "aws_iam_policy" "p" {\n  policy = data.aws_iam_policy_document.d30.json\n}'
        )
        write(tmp_path, "main.tf", "\n".join(lines) + "\n")
        result = run_within(lambda: parse_dir(tmp_path))
        policy = by_address(result)["aws_iam_policy.p"].properties["policy"]
        assert len(json.dumps(policy, default=str)) < 2_000_000

    def test_a_stack_overflow_inside_a_local_is_contained(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        real = _hcl_eval.evaluate_value

        def overflowing(raw: Any, *args: Any, **kwargs: Any) -> Any:
            if raw == "${overflow_marker}":
                raise RecursionError
            return real(raw, *args, **kwargs)

        monkeypatch.setattr(terraform_hcl, "evaluate_value", overflowing)
        write(
            tmp_path,
            "main.tf",
            'locals {\n  bad = "${overflow_marker}"\n  good = "fine"\n}\n'
            'resource "x" "y" {\n  a = local.bad\n  b = local.good\n}\n',
        )
        result = parse_dir(tmp_path)
        properties = only_resource(result).properties
        assert is_unknown(properties["a"]) and properties["b"] == "fine"
        (note,) = codes(result, "hcl.evaluation_limit")
        assert "too deeply" in note.message

    def test_a_deep_caller_cannot_make_the_parse_fail(self, tmp_path: Path) -> None:
        # The scan may be entered from a deep stack. However many frames are left, a
        # RecursionError must end as an Unknown, never as a failed parse.
        write(tmp_path, "main.tf", self.chain_with_neighbours(22))
        spare = 600

        def descend(depth: int) -> ParsedOutput:
            if depth == 0:
                return parse_dir(tmp_path)
            return descend(depth - 1)

        limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(limit, 1000))
        try:
            result = descend(spare)
        finally:
            sys.setrecursionlimit(limit)
        assert by_address(result)["aws_s3_bucket.head"].properties["other"] == 6


class TestDynamicBlockLimits:
    """Dynamic blocks nested in each other must not multiply without a total per resource."""

    LIMIT = terraform_hcl.MAX_DYNAMIC_BLOCKS

    @staticmethod
    def nested_dynamic(levels: int, width: int = 30, wrap: bool = False) -> str:
        """``levels`` dynamic blocks inside each other, each over ``width`` elements."""
        items = ", ".join(str(i) for i in range(width))
        lines = ['resource "a" "b" {']
        if wrap:
            lines.append("outer {")
        for level in range(levels):
            lines += [f'dynamic "d{level}" {{', f"for_each = [{items}]", "content {"]
        lines.append(f"leaf = d{levels - 1}.value")
        lines += ["}", "}"] * levels
        if wrap:
            lines.append("}")
        lines.append("}")
        return "\n".join(lines) + "\n"

    @staticmethod
    def siblings(count: int, resource: str = "b") -> str:
        """``count`` dynamic blocks side by side, each over the most elements one may expand."""
        items = ", ".join(str(i) for i in range(terraform_hcl.MAX_DYNAMIC_EXPANSION))
        blocks = [
            f'dynamic "s{i}" {{\nfor_each = [{items}]\ncontent {{\nv = s{i}.value\n}}\n}}'
            for i in range(count)
        ]
        return f'resource "a" "{resource}" {{\n' + "\n".join(blocks) + "\n}\n"

    @classmethod
    def block_bound(cls, levels: int) -> int:
        """The most blocks ``nested_dynamic(levels)`` may hold: linear in the depth.

        At most ``LIMIT`` blocks are expanded; each body evaluated for one of them (and the
        resource itself) may then add a chain of one-block fallbacks as long as the nesting.
        """
        return cls.LIMIT + (cls.LIMIT + 1) * levels

    @staticmethod
    def dicts(value: Any) -> int:
        """How many blocks (objects) a property value holds, nested ones included."""
        if isinstance(value, dict):
            return 1 + sum(TestDynamicBlockLimits.dicts(v) for v in value.values())
        if isinstance(value, list):
            return sum(TestDynamicBlockLimits.dicts(v) for v in value)
        return 0

    @staticmethod
    def leaves(value: Any) -> list[Any]:
        """Every ``leaf`` value in the nested blocks."""
        found: list[Any] = []
        if isinstance(value, dict):
            for key, inner in value.items():
                if key == "leaf":
                    found.append(inner)
                else:
                    found.extend(TestDynamicBlockLimits.leaves(inner))
        elif isinstance(value, list):
            for inner in value:
                found.extend(TestDynamicBlockLimits.leaves(inner))
        return found

    @pytest.mark.parametrize("levels", [3, 6, 20])
    @pytest.mark.parametrize("entry", ["file", "directory"])
    def test_nested_dynamic_blocks_over_long_lists_stay_cheap(
        self, tmp_path: Path, levels: int, entry: str
    ) -> None:
        # 30 elements per level is 30**levels blocks without a total: 4 levels took 7 seconds
        # and 270 MB, and 5 levels (a file under 1 KB) did not finish
        write(tmp_path, "main.tf", self.nested_dynamic(levels))
        run = (
            (lambda: TerraformHCLParser().parse_file(tmp_path / "main.tf"))
            if entry == "file"
            else (lambda: parse_dir(tmp_path))
        )
        started = time.monotonic()
        result = run_within(run)
        assert time.monotonic() - started < 1.0
        properties = only_resource(result).properties
        # the first level is expanded in full; the total stops the multiplication below it
        assert len(properties["d0"]) == terraform_hcl.MAX_DYNAMIC_EXPANSION - 2
        assert self.dicts(properties) <= self.block_bound(levels)
        assert len(codes(result, "hcl.evaluation_limit")) == 1

    def test_the_cap_is_one_warning_that_names_the_dynamic_blocks(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", self.nested_dynamic(6))
        write(tmp_path, "more.tf", self.nested_dynamic(6).replace('"b"', '"c"'))
        (note,) = codes(run_within(lambda: parse_dir(tmp_path)), "hcl.evaluation_limit")
        assert note.level == "warning"
        assert "treated as unknown" in note.message
        assert f"more than {self.LIMIT} blocks" in note.message
        assert "grew past" not in note.message and "levels deep" not in note.message

    def test_blocks_past_the_total_are_one_block_with_unknown_iterators(
        self, tmp_path: Path
    ) -> None:
        result = parse_snippet(tmp_path, self.nested_dynamic(6))
        leaves = self.leaves(only_resource(result).properties)
        # expanded blocks keep their iterator value; the ones past the total hold an Unknown,
        # so a rule reads them as neither present nor absent
        assert any(isinstance(leaf, int) for leaf in leaves)
        unknown = [leaf for leaf in leaves if is_unknown(leaf)]
        assert unknown
        assert len(leaves) - len(unknown) <= self.LIMIT
        assert all(isinstance(leaf, int) or is_unknown(leaf) for leaf in leaves)
        messages = [d.message for d in codes(result, "hcl.dynamic_block")]
        assert any("would generate more than" in m for m in messages)
        assert any("became 30 block(s)" in m for m in messages)

    def test_the_cap_holds_for_dynamic_blocks_inside_a_static_block(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", self.nested_dynamic(6, wrap=True))
        started = time.monotonic()
        result = run_within(lambda: parse_dir(tmp_path))
        assert time.monotonic() - started < 1.0
        (outer,) = only_resource(result).properties["outer"]
        assert len(outer["d0"]) == terraform_hcl.MAX_DYNAMIC_EXPANSION - 2
        assert self.dicts(outer) <= self.block_bound(6)
        assert len(codes(result, "hcl.evaluation_limit")) == 1

    def test_a_nest_within_the_total_expands_in_full_without_a_warning(
        self, tmp_path: Path
    ) -> None:
        # 10 + 10 * 10 = 110 blocks is well within the total
        result = parse_snippet(tmp_path, self.nested_dynamic(2, width=10))
        properties = only_resource(result).properties
        leaves = self.leaves(properties)
        assert leaves == [i for _ in range(10) for i in range(10)]
        assert codes(result, "hcl.evaluation_limit") == []

    def test_the_total_is_exactly_the_limit(self, tmp_path: Path) -> None:
        full = self.LIMIT // terraform_hcl.MAX_DYNAMIC_EXPANSION
        within = only_resource(parse_snippet(tmp_path, self.siblings(full)))
        assert [len(within.properties[f"s{i}"]) for i in range(full)] == [32] * full
        assert not any(is_unknown(b["v"]) for i in range(full) for b in within.properties[f"s{i}"])
        past = parse_snippet(tmp_path, self.siblings(full + 1), name="past.tf")
        assert [len(only_resource(past).properties[f"s{i}"]) for i in range(full)] == [32] * full
        (last,) = only_resource(past).properties[f"s{full}"]
        assert is_unknown(last["v"])
        assert len(codes(past, "hcl.evaluation_limit")) == 1

    def test_the_total_below_the_limit_gives_no_warning(self, tmp_path: Path) -> None:
        full = self.LIMIT // terraform_hcl.MAX_DYNAMIC_EXPANSION
        result = parse_snippet(tmp_path, self.siblings(full))
        assert codes(result, "hcl.evaluation_limit") == []

    def test_each_resource_has_its_own_total(self, tmp_path: Path) -> None:
        full = self.LIMIT // terraform_hcl.MAX_DYNAMIC_EXPANSION
        write(tmp_path, "one.tf", self.siblings(full, "one"))
        write(tmp_path, "two.tf", self.siblings(full, "two"))
        result = parse_dir(tmp_path)
        assert len(result.resources) == 2
        for resource in result.resources:
            assert [len(resource.properties[f"s{i}"]) for i in range(full)] == [32] * full
        assert codes(result, "hcl.evaluation_limit") == []

    def test_a_collection_past_the_per_block_limit_is_not_a_total_overrun(
        self, tmp_path: Path
    ) -> None:
        # a collection that is simply too long for one block keeps its own, older behaviour
        # and does not count as having hit the total
        items = ", ".join(str(i) for i in range(terraform_hcl.MAX_DYNAMIC_EXPANSION + 1))
        result = parse_snippet(
            tmp_path,
            f'resource "a" "b" {{\ndynamic "r" {{\nfor_each = [{items}]\n'
            "content {\nv = r.value\n}\n}\n}\n",
        )
        (block,) = only_resource(result).properties["r"]
        assert is_unknown(block["v"])
        assert codes(result, "hcl.evaluation_limit") == []
