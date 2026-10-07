"""Tests for threatcode.parsers._hcl_adapter.

The adapter hides the difference between python-hcl2 4.x and 8.x, so every shape test here
runs against whichever version is installed and expects the same canonical result.
CI runs the suite against both versions (see the module docstring of the adapter).
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest

from threatcode.exceptions import ParseError
from threatcode.parsers import _hcl_adapter
from threatcode.parsers._hcl_adapter import (
    HclBlock,
    load,
    load_attributes,
    load_json_syntax,
    scan_blocks,
)

SHAPES = Path(__file__).parent.parent / "fixtures" / "input_shapes"
HCL_FIXTURES = Path(__file__).parent.parent / "fixtures" / "terraform" / "hcl"

hcl2 = importlib.import_module("hcl2")
MODERN = hasattr(hcl2, "SerializationOptions")


def only(text: str) -> HclBlock:
    document = load(text)
    assert len(document.blocks) == 1
    return document.blocks[0]


class TestCanonicalShape:
    def test_labels_have_no_quotes_and_the_body_is_plain(self) -> None:
        block = only('resource "aws_s3_bucket" "logs" {\n  bucket = "x"\n  force = true\n}\n')
        assert block.kind == "resource"
        assert block.labels == ("aws_s3_bucket", "logs")
        assert block.body == {"bucket": "x", "force": True}

    def test_the_same_canonical_result_for_a_rich_resource(self) -> None:
        text = (
            'resource "aws_instance" "web" {\n'
            '  ami = "ami-1"\n'
            "  count = var.n\n"
            "  subnet_id = aws_subnet.a[count.index].id\n"
            '  ids = [aws_security_group.web.id, "sg-1"]\n'
            '  tags = { Name = "web", "quoted-key" = "v" }\n'
            "  flag = true\n"
            "  none = null\n"
            "  size = 2\n"
            "  ratio = 1.5\n"
            "  ebs_block_device {\n    encrypted = false\n  }\n"
            "  ebs_block_device {\n    encrypted = true\n  }\n"
            "}\n"
        )
        assert only(text).body == {
            "ami": "ami-1",
            "count": "${var.n}",
            "subnet_id": "${aws_subnet.a[count.index].id}",
            "ids": ["${aws_security_group.web.id}", "sg-1"],
            "tags": {"Name": "web", "quoted-key": "v"},
            "flag": True,
            "none": None,
            "size": 2,
            "ratio": 1.5,
            "ebs_block_device": [{"encrypted": False}, {"encrypted": True}],
        }

    def test_an_interpolation_stays_an_expression_and_a_template_keeps_its_text(self) -> None:
        body = only('resource "a" "b" {\n  x = "${var.a}"\n  y = "pre-${var.a}-post"\n}\n').body
        assert body == {"x": "${var.a}", "y": "pre-${var.a}-post"}

    def test_quoted_strings_keep_their_backslash_escapes(self) -> None:
        body = only('resource "a" "b" {\n  x = "say \\"hi\\" \\\\ ok"\n}\n').body
        assert body["x"] == 'say \\"hi\\" \\\\ ok'

    def test_heredocs_are_their_text_without_markers_or_trailing_newline(self) -> None:
        text = (
            'resource "a" "b" {\n'
            "  plain = <<EOT\nline1\n  line2 ${var.x}\nEOT\n"
            "  indented = <<-EOT\n    top\n      nested\n    EOT\n"
            "}\n"
        )
        body = only(text).body
        assert body["plain"] == "line1\n  line2 ${var.x}"
        assert body["indented"] == "top\n  nested"

    @pytest.mark.skipif(not MODERN, reason="python-hcl2 4.x keeps the indent of a <<- heredoc")
    def test_a_heredoc_with_blank_lines_keeps_them(self) -> None:
        text = 'resource "a" "b" {\n  x = <<-EOT\n    one\n\n    two\n  EOT\n}\n'
        assert only(text).body["x"] == "one\n\ntwo"

    def test_a_dynamic_block_keeps_its_label_as_a_key(self) -> None:
        text = (
            'resource "aws_security_group" "web" {\n'
            '  dynamic "ingress" {\n'
            "    for_each = [22, 3389]\n"
            "    content {\n      from_port = ingress.value\n    }\n"
            "  }\n"
            "}\n"
        )
        dynamic = only(text).body["dynamic"]
        assert dynamic == [
            {"ingress": {"for_each": [22, 3389], "content": [{"from_port": "${ingress.value}"}]}}
        ]

    def test_block_markers_are_dropped(self) -> None:
        body = only('resource "a" "b" {\n  inner {\n    x = 1\n  }\n}\n').body
        assert body == {"inner": [{"x": 1}]}
        assert "__is_block__" not in json.dumps(body)

    def test_blocks_of_every_read_kind(self) -> None:
        text = (
            'variable "v" {\n  default = 1\n}\n'
            "locals {\n  a = 1\n}\n"
            "locals {\n  b = 2\n}\n"
            'data "aws_ami" "base" {\n  most_recent = true\n}\n'
            'module "m" {\n  source = "./m"\n}\n'
            'output "o" {\n  value = 1\n}\n'
            'provider "aws" {\n  region = "us-east-1"\n}\n'
            'terraform {\n  required_version = ">= 1.5"\n}\n'
        )
        found = [(b.kind, b.labels) for b in load(text).blocks]
        assert sorted(found) == sorted(
            [
                ("variable", ("v",)),
                ("locals", ()),
                ("locals", ()),
                ("data", ("aws_ami", "base")),
                ("module", ("m",)),
                ("output", ("o",)),
                ("provider", ("aws",)),
                ("terraform", ()),
            ]
        )

    def test_other_block_kinds_are_not_blocks(self) -> None:
        text = (
            "moved {\n  from = a.b\n  to = a.c\n}\n"
            'check "c" {\n  assert {\n    condition = true\n    error_message = "x"\n  }\n}\n'
        )
        assert load(text).blocks == []


class TestSpans:
    def test_lines_of_every_block(self) -> None:
        text = (
            'resource "a" "one" {\n'  # 1
            "  x = 1\n"  # 2
            "}\n"  # 3
            "\n"  # 4
            'resource "a" "two" {\n'  # 5
            "  inner {\n"  # 6
            "    y = 2\n"  # 7
            "  }\n"  # 8
            "}\n"  # 9
        )
        spans = {b.labels[1]: (b.start_line, b.end_line) for b in load(text).blocks}
        assert spans == {"one": (1, 3), "two": (5, 9)}

    def test_braces_in_comments_strings_and_heredocs_do_not_end_a_block(self) -> None:
        text = (
            'resource "a" "tricky" {\n'  # 1
            "  # a comment with a brace } and an apostrophe don't\n"  # 2
            "  // another } here\n"  # 3
            "  /* and a block comment }\n"  # 4
            "     spanning lines { */\n"  # 5
            '  s = "closing } inside"\n'  # 6
            '  t = "interpolated ${merge({a = "}"}, {})} end"\n'  # 7
            '  u = "escaped $${ is not an interpolation"\n'  # 8
            "  h = <<EOT\n"  # 9
            "} not the end {\n"  # 10
            "EOT\n"  # 11
            "}\n"  # 12
            'resource "a" "after" {\n'  # 13
            "}\n"  # 14
        )
        spans = {s.labels[1]: (s.start_line, s.end_line) for s in scan_blocks(text)}
        assert spans == {"tricky": (1, 12), "after": (13, 14)}

    def test_the_same_blocks_parse_when_the_text_is_valid_hcl(self) -> None:
        text = (
            'resource "a" "tricky" {\n'  # 1
            "  # a comment with a brace } and an apostrophe don't\n"  # 2
            '  s = "closing } inside"\n'  # 3
            "  h = <<EOT\n"  # 4
            "} not the end {\n"  # 5
            "EOT\n"  # 6
            "}\n"  # 7
            'resource "a" "after" {\n'  # 8
            "}\n"  # 9
        )
        spans = {b.labels[1]: (b.start_line, b.end_line) for b in load(text).blocks}
        assert spans == {"tricky": (1, 7), "after": (8, 9)}

    def test_a_repeated_label_pairs_with_its_own_occurrence(self) -> None:
        text = (
            "locals {\n  a = 1\n}\n"  # 1-3
            "locals {\n  b = 2\n}\n"  # 4-6
            'variable "x" {\n}\n'  # 7-8
        )
        found = {(b.kind, tuple(b.body)): (b.start_line, b.end_line) for b in load(text).blocks}
        assert found == {
            ("locals", ("a",)): (1, 3),
            ("locals", ("b",)): (4, 6),
            ("variable", ()): (7, 8),
        }

    def test_scan_blocks_reports_file_order(self) -> None:
        text = 'variable "v" {\n}\nresource "a" "b" {\n}\nlocals {\n}\n'
        assert [(s.kind, s.labels, s.start_line, s.end_line) for s in scan_blocks(text)] == [
            ("variable", ("v",), 1, 2),
            ("resource", ("a", "b"), 3, 4),
            ("locals", (), 5, 6),
        ]

    def test_scan_blocks_survives_an_unterminated_block(self) -> None:
        spans = scan_blocks('resource "a" "b" {\n  x = 1\n')
        assert [(s.kind, s.start_line) for s in spans] == [("resource", 1)]

    def test_scan_blocks_skips_a_top_level_attribute(self) -> None:
        spans = scan_blocks('name = "x"\nresource "a" "b" {\n}\n')
        assert [(s.kind, s.labels) for s in spans] == [("resource", ("a", "b"))]

    def test_scan_blocks_reads_identifier_labels(self) -> None:
        spans = scan_blocks("resource aws_s3_bucket logs {\n}\n")
        assert [(s.kind, s.labels) for s in spans] == [("resource", ("aws_s3_bucket", "logs"))]

    @pytest.mark.skipif(MODERN, reason="python-hcl2 8.x reports no line numbers")
    @pytest.mark.parametrize(
        "path",
        [
            HCL_FIXTURES / "references.tf",
            HCL_FIXTURES / "dynamic_blocks.tf",
            HCL_FIXTURES / "iam_policies.tf",
            HCL_FIXTURES / "expressions.tf",
            Path(__file__).parent.parent / "fixtures" / "realistic" / "05_hybrid_vpn_datacenter.tf",
        ],
    )
    def test_the_scan_agrees_with_python_hcl2_4_meta_lines(self, path: Path) -> None:
        text = path.read_text(encoding="utf-8")
        reported = hcl2.loads(text, with_meta=True)
        expected: dict[tuple[str, tuple[str, ...]], list[tuple[int, int]]] = {}
        for kind, entries in reported.items():
            for entry in entries:
                if kind in ("resource", "data"):
                    for rtype, names in entry.items():
                        for name, body in names.items():
                            resource_key = (kind, (rtype, name))
                            expected.setdefault(resource_key, []).append(
                                (body["__start_line__"], body["__end_line__"])
                            )
                elif kind in ("module", "variable", "output", "provider"):
                    for label, body in entry.items():
                        key = (kind, (label,))
                        expected.setdefault(key, []).append(
                            (body["__start_line__"], body["__end_line__"])
                        )
        scanned: dict[tuple[str, tuple[str, ...]], list[tuple[int, int]]] = {}
        for span in scan_blocks(text):
            if (span.kind, span.labels) in expected:
                scanned.setdefault((span.kind, span.labels), []).append(
                    (span.start_line, span.end_line)
                )
        assert scanned == expected


class TestJsonSyntax:
    def test_resource_object_form(self) -> None:
        data = {"resource": {"aws_s3_bucket": {"b": {"bucket": "x"}}}}
        block = load_json_syntax(data).blocks[0]
        assert (block.kind, block.labels, block.body) == (
            "resource",
            ("aws_s3_bucket", "b"),
            {"bucket": "x"},
        )

    def test_resource_list_form_and_list_bodies(self) -> None:
        data = {"resource": [{"aws_instance": {"web": [{"ami": "a"}], "app": {"ami": "b"}}}]}
        blocks = load_json_syntax(data).blocks
        assert sorted((b.labels[1], b.body["ami"]) for b in blocks) == [("app", "b"), ("web", "a")]

    def test_other_blocks(self) -> None:
        data = {
            "variable": {"v": {"default": 1}},
            "locals": {"a": 1},
            "module": {"m": {"source": "./m"}},
            "data": {"aws_ami": {"base": {"most_recent": True}}},
            "output": {"o": {"value": 2}},
            "terraform": {"required_version": ">= 1"},
        }
        kinds = sorted((b.kind, b.labels) for b in load_json_syntax(data).blocks)
        assert kinds == [
            ("data", ("aws_ami", "base")),
            ("locals", ()),
            ("module", ("m",)),
            ("output", ("o",)),
            ("terraform", ()),
            ("variable", ("v",)),
        ]

    def test_start_lines_come_from_the_text(self) -> None:
        text = (SHAPES / "cdk.tf.json").read_text(encoding="utf-8")
        blocks = load_json_syntax(json.loads(text), text).blocks
        lines = {b.labels[1]: b.start_line for b in blocks if b.kind == "resource"}
        source_lines = text.splitlines()
        assets, web = lines["assets"], lines["web"]
        assert assets is not None and web is not None
        assert source_lines[assets - 1].strip().startswith('"assets"')
        assert source_lines[web - 1].strip().startswith('"web"')
        assert all(b.end_line is None for b in blocks)

    def test_without_text_there_are_no_lines(self) -> None:
        block = load_json_syntax({"resource": {"a": {"b": {}}}}).blocks[0]
        assert block.start_line is None

    def test_non_object_entries_are_ignored(self) -> None:
        assert load_json_syntax({"resource": {"aws_s3_bucket": "not an object"}}).blocks == []
        assert load_json_syntax({"resource": ["x", 1]}).blocks == []


class TestAttributes:
    def test_a_tfvars_file(self) -> None:
        values = load_attributes(
            'environment = "prod"\ncount = 3\nflag = true\nlist = ["a", "b"]\n'
            'tags = {\n  Owner = "me"\n}\n'
        )
        assert values == {
            "environment": "prod",
            "count": 3,
            "flag": True,
            "list": ["a", "b"],
            "tags": {"Owner": "me"},
        }

    def test_a_syntax_error_raises(self) -> None:
        with pytest.raises(ParseError, match="x.tfvars"):
            load_attributes("a = = 1\n", "x.tfvars")


class TestErrors:
    def test_a_syntax_error_names_the_file_and_is_one_line(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            load('resource "a" "b" {\n  x == 1\n}\n', "broken.tf")
        message = str(exc_info.value)
        assert "broken.tf" in message
        assert "\n" not in message
        assert "Token(" not in message

    def test_the_original_exception_is_chained(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            load("resource {{{\n", "broken.tf")
        assert exc_info.value.__cause__ is not None

    def test_a_missing_python_hcl2_is_a_clear_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def missing() -> object:
            raise ImportError("no hcl2")

        monkeypatch.setattr(_hcl_adapter, "_hcl2", missing)
        with pytest.raises(ParseError, match="python-hcl2 required"):
            load('resource "a" "b" {\n}\n')

    @pytest.mark.parametrize("levels", [250, 600, 2000])
    def test_nesting_past_the_limit_is_a_parse_error_naming_the_file(self, levels: int) -> None:
        # python-hcl2 4.x and 8.x fail in different places; both must end as this one error
        deep = "[" * levels + "]" * levels
        with pytest.raises(ParseError, match=r"^deep\.tf: nested too deeply to read$"):
            load(f'resource "a" "b" {{\n  x = {deep}\n}}\n', "deep.tf")
        with pytest.raises(ParseError, match=r"^deep\.tf: nested too deeply to read$"):
            load_attributes(f"x = {deep}\n", "deep.tf")

    def test_json_syntax_nested_past_the_limit_is_a_parse_error(self) -> None:
        deep: object = 1
        for _ in range(250):
            deep = [deep]
        data = {"resource": {"a": {"b": {"x": deep}}}}
        with pytest.raises(ParseError, match=r"^deep\.tf\.json: nested too deeply to read$"):
            load_json_syntax(data, None, "deep.tf.json")

    def test_nesting_inside_the_limit_is_read(self) -> None:
        deep = "[" * 100 + "1" + "]" * 100
        block = only(f'resource "a" "b" {{\n  x = {deep}\n}}\n')
        value = block.body["x"]
        for _ in range(100):
            (value,) = value
        assert value == 1
        assert load_attributes(f"x = {deep}\n")["x"] is not None


class TestDescribeError:
    def test_token_dumps_are_replaced(self) -> None:
        message = _hcl_adapter.describe_error(Exception("Token('A', 'x') Expected one of"), "f.tf")
        assert message == "Invalid HCL in f.tf: syntax error"

    def test_line_and_column_are_reported(self) -> None:
        class PositionedError(Exception):
            line = 4
            column = 9

        assert (
            _hcl_adapter.describe_error(PositionedError("x"), "f.tf")
            == "Invalid HCL in f.tf, line 4, column 9: syntax error"
        )

    def test_an_empty_message_names_the_exception(self) -> None:
        assert (
            _hcl_adapter.describe_error(ValueError(), "f.tf") == "Invalid HCL in f.tf: ValueError"
        )
