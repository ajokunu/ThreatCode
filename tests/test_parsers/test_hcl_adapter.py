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
from hypothesis import given, settings
from hypothesis import strategies as st

from threatcode.exceptions import ParseError
from threatcode.parsers import _hcl_adapter
from threatcode.parsers._hcl_adapter import (
    HclBlock,
    load,
    load_attributes,
    load_json_syntax,
    normalize_layout,
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


# --- layout normalization and the retry -------------------------------------------------------


def one_line(text: str) -> str:
    return " ".join(text.split())


class TestNormalizeLayout:
    """The rewrites that make valid HCL readable to python-hcl2 4.x and 8.x."""

    def test_an_operator_expression_in_an_object_element_is_wrapped(self) -> None:
        text = 'locals {\n  a = {\n    i = var.n == 0 ? 0 : 1\n    n = "x"\n  }\n}\n'
        assert normalize_layout(text) == (
            'locals {\n  a = {\n    i = (var.n == 0 ? 0 : 1)\n    n = "x"\n  }\n}\n'
        )

    @pytest.mark.parametrize(
        "value",
        [
            "var.n == 1",
            "var.n != 1",
            "var.a && var.b",
            "var.a || var.b",
            "var.n > 1",
            "var.n + 1",
            "var.n * 2",
            "var.n / 2",
            "var.n % 2",
            "var.n - 1",
            "!var.a ? 1 : 2",
            "var.n <= 1",
        ],
    )
    def test_every_operator_expression_is_wrapped(self, value: str) -> None:
        text = f"locals {{\n  a = {{\n    k = {value}\n    m = 1\n  }}\n}}\n"
        result = normalize_layout(text)
        assert result is not None
        assert f"k = ({value})\n" in result

    @pytest.mark.parametrize(
        "value",
        [
            '"x"',
            "var.a",
            "1",
            "-1",
            "[1, 2]",
            "{ a = 1 }",
            "f(var.a + 1)",
            "var.a.*.b",
            "true",
            "var.a[0].b",
            "<<EOT\nx\nEOT",
        ],
    )
    def test_an_element_without_a_top_level_operator_is_left_alone(self, value: str) -> None:
        text = f"locals {{\n  a = {{\n    k = {value}\n    m = 1\n  }}\n}}\n"
        assert normalize_layout(text) == text

    def test_the_comment_after_a_wrapped_value_stays_outside_the_parentheses(self) -> None:
        text = "locals {\n  a = {\n    i = var.n + 1 # note\n    m = 1\n  }\n}\n"
        assert normalize_layout(text) == (
            "locals {\n  a = {\n    i = (var.n + 1) # note\n    m = 1\n  }\n}\n"
        )

    def test_comma_separated_elements_are_each_judged(self) -> None:
        text = "locals { a = { i = var.n + 1, j = var.q, k = var.a && var.b } }\n"
        assert normalize_layout(text) == (
            "locals { a = { i = (var.n + 1), j = var.q, k = (var.a && var.b) } }\n"
        )

    def test_a_nested_object_is_judged_on_its_own(self) -> None:
        text = (
            "locals {\n  a = {\n    o = {\n      i = var.n + 1\n      j = 2\n    }\n"
            "    k = 1\n  }\n}\n"
        )
        assert normalize_layout(text) == text.replace("var.n + 1", "(var.n + 1)")

    def test_a_block_body_is_not_an_object(self) -> None:
        text = 'resource "a" "b" {\n  x = var.n + 1\n  y = 2\n}\n'
        assert normalize_layout(text) == text

    def test_line_breaks_inside_parentheses_become_spaces(self) -> None:
        text = "locals {\n  p = (\n    var.a\n    ? 1\n    : 2\n  )\n}\n"
        assert normalize_layout(text) == "locals {\n  p = (     var.a     ? 1     : 2   )\n}\n"

    def test_line_breaks_inside_brackets_and_calls_become_spaces(self) -> None:
        text = "locals {\n  a = [\n    1,\n    2\n  ]\n  b = f(\n    x,\n    y\n  )\n}\n"
        assert (
            normalize_layout(text)
            == "locals {\n  a = [     1,     2   ]\n  b = f(     x,     y   )\n}\n"
        )

    def test_a_traversal_that_continues_on_the_next_line_joins(self) -> None:
        text = "locals {\n  a = try(\n    var.b\n    .c\n    .d,\n    1\n  )\n}\n"
        assert ".c" in one_line(normalize_layout(text) or "")
        assert "\n    .c" not in (normalize_layout(text) or "")

    def test_line_breaks_inside_a_for_object_join(self) -> None:
        text = "locals {\n  a = {\n    for k, v in var.m :\n    k => v\n  }\n}\n"
        assert (
            normalize_layout(text)
            == "locals {\n  a = {     for k, v in var.m :     k => v   }\n}\n"
        )

    def test_line_breaks_between_the_elements_of_an_object_stay(self) -> None:
        text = "locals {\n  a = {\n    b = 1\n    c = 2\n  }\n}\n"
        assert normalize_layout(text) == text

    def test_an_object_inside_parentheses_keeps_its_own_line_breaks(self) -> None:
        text = "locals {\n  a = (\n    {\n      b = 1\n      c = 2\n    }\n  )\n}\n"
        result = normalize_layout(text)
        assert result == "locals {\n  a = (     {\n      b = 1\n      c = 2\n    }   )\n}\n"

    def test_a_comment_inside_parentheses_is_blanked_so_it_cannot_swallow_the_next_line(
        self,
    ) -> None:
        text = "locals {\n  a = (\n    1 # one\n    + 2 // two\n    /* three */\n  )\n}\n"
        result = normalize_layout(text)
        assert result is not None
        assert "#" not in result and "//" not in result and "/*" not in result
        assert "\n" not in result.split("a = (")[1].split(")")[0]

    def test_a_comment_outside_brackets_is_not_touched(self) -> None:
        text = "# one\nlocals {\n  // two\n  a = 1 /* three */\n}\n"
        assert normalize_layout(text) == text

    def test_a_heredoc_inside_parentheses_keeps_its_line_breaks(self) -> None:
        text = "locals {\n  a = f(\n    <<EOT\nline one\nline two\nEOT\n  )\n}\n"
        result = normalize_layout(text)
        assert result is not None
        assert "<<EOT\nline one\nline two\nEOT\n" in result

    def test_brackets_and_operators_inside_strings_are_never_looked_into(self) -> None:
        text = (
            'locals {\n  a = {\n    s = "( [ { ? : == ${f(1 +\n 2)}"\n    t = "x"\n  }\n'
            '  b = ")"\n}\n'
        )
        assert normalize_layout(text) == text

    def test_a_group_inside_an_interpolation_is_not_marked(self) -> None:
        text = 'locals {\n  a = "${(1 + 2) * 3}"\n}\n'
        assert normalize_layout(text, flatten=False, mark=True) == text

    def test_crlf_becomes_lf(self) -> None:
        text = "/**\r\n * header\r\n */\r\nlocals {\r\n  a = 1\r\n}\r\n"
        assert normalize_layout(text) == "/**\n * header\n */\nlocals {\n  a = 1\n}\n"

    def test_text_that_needs_nothing_comes_back_unchanged(self) -> None:
        text = 'resource "a" "b" {\n  tags = {\n    Name = "x"\n  }\n  ids = [1, 2]\n}\n'
        assert normalize_layout(text) == text
        assert normalize_layout(text, flatten=False, mark=True) == text

    @pytest.mark.parametrize(
        "text",
        [
            "locals {\n  a = (1\n",
            "locals {\n  a = 1\n}}\n",
            "locals {\n  a = (1]\n}\n",
            'locals {\n  a = "unterminated\n}\n',
            "locals {\n  a = [\n}\n",
            ")",
        ],
    )
    def test_brackets_that_do_not_match_give_nothing_to_rewrite(self, text: str) -> None:
        assert normalize_layout(text) is None

    def test_nesting_past_the_frame_limit_gives_nothing_to_rewrite(self) -> None:
        assert normalize_layout("a = " + "(" * 300 + "1" + ")" * 300 + "\n") is None

    def test_a_long_flat_text_is_handled(self) -> None:
        text = "locals {\n" + "".join(f"  v{i} = {{ a = {i} + 1 }}\n" for i in range(2000)) + "}\n"
        result = normalize_layout(text)
        assert result is not None
        assert result.count("(") == 2000


class TestGroupMarks:
    """python-hcl2 4.x drops the parentheses of a group; the adapter carries them through."""

    def test_a_group_is_marked_and_a_call_is_not(self) -> None:
        result = normalize_layout("x = (a || b) && f(c)\n", flatten=False, mark=True)
        assert result == "x =  __tcg(a || b) && f(c)\n"

    @pytest.mark.parametrize(
        "text",
        [
            "x = a ? (b) : c",
            "x = !(a)",
            "x = -(a)",
            "x = [(a)]",
            "x = {k = (a)}",
            "x = f((a))",
            "x = a == (b)",
            "y = [for i in z : i if (i > 1)]",
            "y = [for i in (z) : i]",
        ],
    )
    def test_every_other_position_is_a_group(self, text: str) -> None:
        result = normalize_layout(text + "\n", flatten=False, mark=True)
        assert result is not None
        assert "__tcg(" in result

    @pytest.mark.parametrize(
        "text",
        ["x = f(a)", "x = a.b(c)", "x = provider::aws::arn_parse(a)", "x = f (a)", "x = f(g(a))"],
    )
    def test_a_call_is_not_a_group(self, text: str) -> None:
        assert normalize_layout(text + "\n", flatten=False, mark=True) == text + "\n"

    def test_the_parenthesized_key_of_an_object_element_is_not_marked(self) -> None:
        text = "x = { (var.k) = (a || b) }\n"
        assert normalize_layout(text, flatten=False, mark=True) == (
            "x = { (var.k) =  __tcg(a || b) }\n"
        )

    def test_a_text_that_already_uses_the_marker_is_left_unmarked(self) -> None:
        text = "x = (a)\ny = __tcg(b)\n"
        assert normalize_layout(text, flatten=False, mark=True) == text

    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("a && (b || c)", "${a && (b || c)}"),
            ("(a || b) && c", "${(a || b) && c}"),
            ("(a + b) * c", "${(a + b) * c}"),
            ("!(a && b)", "${!(a && b)}"),
            ("a ? (b || c) : d", "${a ? (b || c) : d}"),
            ("f((a || b) && c)", "${f((a || b) && c)}"),
        ],
    )
    def test_a_grouped_expression_keeps_its_parentheses_under_both_majors(
        self, expression: str, expected: str
    ) -> None:
        block = only(f'resource "a" "b" {{\n  v = {expression}\n}}\n')
        assert block.body["v"] == expected
        assert "__tcg" not in json.dumps(block.body)

    def test_a_group_in_a_nested_block_and_a_list_keeps_its_parentheses(self) -> None:
        block = only(
            'resource "a" "b" {\n  inner {\n    v = [(x || y) && z, 1]\n  }\n'
            "  w = { k = (p + q) * r }\n}\n"
        )
        assert block.body["inner"][0]["v"][0] == "${(x || y) && z}"
        assert block.body["w"]["k"] == "${(p + q) * r}"

    def test_a_group_inside_a_quoted_template_is_left_as_written(self) -> None:
        block = only('resource "a" "b" {\n  v = "${(1 + 2) * 3}-x"\n}\n')
        assert "(1 + 2) * 3" in block.body["v"]


LAYOUT_SHAPES = {
    "an operator in an object element": (
        'locals {\n  cfg = {\n    index = var.n == 0 ? 0 : 1\n    name = "x"\n  }\n}\n'
    ),
    "a conditional that breaks before the question mark": (
        'locals {\n  p = (\n    var.a == null\n    ? null\n    : (\n      startswith(var.a, "o")\n'
        '      ? "o"\n      : "f"\n    )\n  )\n}\n'
    ),
    "a function argument that breaks before the question mark": (
        'locals {\n  z = merge(\n    { a = 1 },\n    contains(keys(x), "p")\n'
        "    ? { b = 1 }\n    : {}\n  )\n}\n"
    ),
    "an or that begins its line": (
        "locals {\n  p = (\n    var.a == null\n    || var.b == 1\n  )\n}\n"
    ),
    "an object element holding an object branch": (
        "locals {\n  x = {\n    use = try(v.a, null) == null ? null : {\n      id = v.a\n    }\n"
        "    other = 1\n  }\n}\n"
    ),
    "a list of objects with operator values": (
        "locals {\n  z = [\n    {\n      a = var.x == 1 ? 1 : 2\n      c = 3\n    }\n  ]\n}\n"
    ),
    "a traversal that continues on the next line": (
        "locals {\n  a = try(\n    var.b\n    .c\n    .d,\n    1\n  )\n}\n"
    ),
    "a for object whose conditional breaks its line": (
        "locals {\n  u = {\n    for k, v in var.m : k =>\n    v == 1\n"
        "    ? { n = k }\n    : { n = v }\n  }\n}\n"
    ),
    "windows line endings": "/**\r\n * header\r\n */\r\nlocals {\r\n  a = 1\r\n}\r\n",
}


class TestGrammarGapsAreRetried:
    """Valid HCL that python-hcl2 rejects as written is read, and means what it says."""

    @pytest.mark.parametrize("shape", sorted(LAYOUT_SHAPES))
    def test_the_shape_reads(self, shape: str) -> None:
        block = only(LAYOUT_SHAPES[shape])
        assert block.kind == "locals"
        assert block.body

    def test_the_values_are_the_ones_the_text_says(self) -> None:
        block = only(LAYOUT_SHAPES["an operator in an object element"])
        cfg = block.body["cfg"]
        assert cfg["name"] == "x"
        assert "var.n == 0" in cfg["index"]
        assert cfg["index"].startswith("${") and cfg["index"].endswith("}")

    def test_the_second_block_keeps_the_lines_of_the_original_text(self) -> None:
        text = (
            "locals {\n  p = (\n    var.a\n    ? 1\n    : 2\n  )\n}\n\n"
            'resource "a" "b" {\n  x = 1\n}\n'
        )
        document = load(text)
        resource = next(b for b in document.blocks if b.kind == "resource")
        assert (resource.start_line, resource.end_line) == (9, 11)
        local = next(b for b in document.blocks if b.kind == "locals")
        assert (local.start_line, local.end_line) == (1, 7)

    def test_crlf_text_keeps_its_lines_too(self) -> None:
        text = "/**\r\n * header\r\n */\r\nlocals {\r\n  a = 1\r\n}\r\n"
        (block,) = load(text).blocks
        assert (block.start_line, block.end_line) == (4, 6)

    def test_text_that_fails_every_way_reports_the_error_of_the_original_text(self) -> None:
        # as written it fails at the line that starts with `.c` (line 4); with the layout
        # normalized the group is one line and it fails later, which would name another line
        text = "locals {\n  a = try(\n    var.b\n    .c,\n    1\n  )\n  b = = 3\n}\n"
        with pytest.raises(ParseError, match=r"line 4") as exc_info:
            load(text, "broken.tf")
        assert "broken.tf" in str(exc_info.value)

    def test_a_failure_under_4x_says_how_to_upgrade_and_under_8x_does_not(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            load("locals {\n  b = = 3\n}\n", "broken.tf")
        assert ("pip install -U" in str(exc_info.value)) is (not MODERN)

    def test_the_retry_is_not_made_for_text_past_the_size_limit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(_hcl_adapter, "_MAX_NORMALIZED_CHARS", 10)
        # fine as written under 8.x, rejected as written under 4.x
        text = "locals {\n  a = {\n    i = var.n == 0 ? 0 : 1\n    j = 1\n  }\n}\n"
        if MODERN:
            assert load(text).blocks
        else:
            with pytest.raises(ParseError):
                load(text)

    def test_a_layout_pass_that_raises_is_not_a_new_failure(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(text: str, **_: object) -> str:
            raise RuntimeError("boom")

        monkeypatch.setattr(_hcl_adapter, "normalize_layout", explode)
        with pytest.raises(ParseError, match="broken.tf"):
            load("locals {\n  a = = 1\n}\n", "broken.tf")


class TestParseCache:
    """The same text is parsed once; the data a caller gets is its own."""

    @pytest.fixture(autouse=True)
    def clean_cache(self) -> None:
        _hcl_adapter._PARSE_CACHE.clear()

    @staticmethod
    def counting(monkeypatch: pytest.MonkeyPatch) -> list[str]:
        calls: list[str] = []
        real = _hcl_adapter._hcl2_loads

        def counted(text: str) -> dict[str, object]:
            calls.append(text)
            return real(text)

        monkeypatch.setattr(_hcl_adapter, "_hcl2_loads", counted)
        return calls

    def test_the_same_text_is_parsed_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = self.counting(monkeypatch)
        text = 'resource "a" "b" {\n  x = 1\n}\n'
        first, second = load(text), load(text, "other.tf")
        assert len(calls) == 1
        assert first.blocks[0].body == second.blocks[0].body

    def test_another_text_is_parsed_again(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = self.counting(monkeypatch)
        load('resource "a" "b" {\n  x = 1\n}\n')
        load('resource "a" "b" {\n  x = 2\n}\n')
        assert len(calls) == 2

    def test_changing_a_returned_body_does_not_change_the_next_load(self) -> None:
        text = 'resource "a" "b" {\n  x = [1, 2]\n  tags = { k = "v" }\n  n { m = 1 }\n}\n'
        first = load(text).blocks[0]
        first.body["x"].append(99)
        first.body["tags"]["k"] = "changed"
        first.body["n"][0]["m"] = 100
        again = load(text).blocks[0]
        assert again.body["x"] == [1, 2]
        assert again.body["tags"]["k"] == "v"
        assert again.body["n"][0]["m"] == 1

    def test_load_attributes_shares_the_cache_and_copies_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = self.counting(monkeypatch)
        text = 'region = "us-east-1"\nids = [1, 2]\n'
        first = load_attributes(text)
        first["ids"].append(3)
        assert load_attributes(text)["ids"] == [1, 2]
        assert len(calls) == 1

    def test_a_failure_is_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        calls = self.counting(monkeypatch)
        for _ in range(2):
            with pytest.raises(ParseError):
                load("resource {{{\n", "broken.tf")
        assert len(calls) >= 2

    def test_a_different_loader_does_not_hit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        text = 'resource "a" "b" {\n  x = 1\n}\n'
        load(text)
        calls = self.counting(monkeypatch)
        load(text)
        assert len(calls) == 1

    def test_the_oldest_text_is_evicted_past_the_cap(self) -> None:
        cache = _hcl_adapter._ParseCache(max_chars=10)
        loads = object()
        keys = [(name, loads) for name in ("aaaa", "bbbb", "cccc")]
        for key in keys:
            cache.put(key, {"v": key[0]}, 4)  # type: ignore[arg-type]
        assert cache.get(keys[0]) is None  # type: ignore[arg-type]
        assert cache.get(keys[1]) == {"v": "bbbb"}  # type: ignore[arg-type]
        assert cache.get(keys[2]) == {"v": "cccc"}  # type: ignore[arg-type]

    def test_reading_an_entry_keeps_it_from_being_the_oldest(self) -> None:
        cache = _hcl_adapter._ParseCache(max_chars=10)
        loads = object()
        keys = [(name, loads) for name in ("aaaa", "bbbb", "cccc")]
        cache.put(keys[0], {"v": 1}, 4)  # type: ignore[arg-type]
        cache.put(keys[1], {"v": 2}, 4)  # type: ignore[arg-type]
        assert cache.get(keys[0]) == {"v": 1}  # type: ignore[arg-type]
        cache.put(keys[2], {"v": 3}, 4)  # type: ignore[arg-type]
        assert cache.get(keys[1]) is None  # type: ignore[arg-type]
        assert cache.get(keys[0]) == {"v": 1}  # type: ignore[arg-type]

    def test_a_text_larger_than_the_whole_cache_is_not_kept(self) -> None:
        cache = _hcl_adapter._ParseCache(max_chars=10)
        key = ("x" * 11, object())
        cache.put(key, {"v": 1}, 11)  # type: ignore[arg-type]
        assert cache.get(key) is None  # type: ignore[arg-type]
        assert cache._chars == 0


class TestNormalizeLayoutProperties:
    """Whatever the text, the rewrite neither raises nor invents or loses anything."""

    ALPHABET = st.sampled_from(
        list('{}()[]"#/<\n\r= ?:,.+-*!&|ab1_$%\\') + ["==", "=>", "<<EOT\n", "${", "/*", "*/"]
    )
    texts = st.lists(ALPHABET, max_size=60).map("".join)

    @settings(max_examples=400, deadline=None)
    @given(texts)
    def test_it_never_raises(self, text: str) -> None:
        for flatten, mark in ((True, False), (False, True), (True, True), (False, False)):
            result = normalize_layout(text, flatten=flatten, mark=mark)
            assert result is None or isinstance(result, str)

    @settings(max_examples=400, deadline=None)
    @given(texts)
    def test_without_flattening_or_marking_nothing_changes(self, text: str) -> None:
        assert normalize_layout(text, flatten=False, mark=False) in (None, text)

    @settings(max_examples=400, deadline=None)
    @given(texts)
    def test_marks_are_the_only_change_and_come_out_again(self, text: str) -> None:
        result = normalize_layout(text, flatten=False, mark=True)
        if result is not None:
            assert result.replace(" __tcg(", "(") == text

    @settings(max_examples=400, deadline=None)
    @given(texts)
    def test_flattening_twice_is_flattening_once(self, text: str) -> None:
        once = normalize_layout(text)
        if once is not None:
            assert normalize_layout(once) == once

    @settings(max_examples=400, deadline=None)
    @given(texts)
    def test_flattening_never_adds_a_line(self, text: str) -> None:
        result = normalize_layout(text)
        if result is not None:
            assert result.count("\n") <= text.replace("\r\n", "\n").count("\n")
