"""Tests for threatcode.parsers._hcl_values."""

from __future__ import annotations

import json
from typing import Any

import pytest

from threatcode.parsers._hcl_values import (
    as_json_text,
    canonical_json,
    decode_escapes,
    find_interpolations,
    normalize_text,
    normalize_value,
    unpythonize_expression,
    unpythonize_template,
)
from threatcode.values import UNKNOWN_TEXT, Unknown, is_unknown

ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}
ADMIN_JSON = '{"Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}'


class TestCanonicalJson:
    def test_keys_are_sorted_and_separators_are_compact(self) -> None:
        assert canonical_json(ADMIN) == ADMIN_JSON

    def test_non_ascii_text_is_kept(self) -> None:
        assert canonical_json({"a": "café"}) == '{"a":"café"}'

    def test_an_unknown_is_written_as_its_placeholder(self) -> None:
        assert canonical_json({"a": Unknown("x.y")}) == f'{{"a":"{UNKNOWN_TEXT}"}}'

    def test_list_order_is_kept(self) -> None:
        assert canonical_json([3, 1, 2]) == "[3,1,2]"


class TestDecodeEscapes:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ('a\\"b', 'a"b'),
            ("a\\\\b", "a\\b"),
            ("line\\nbreak", "line\nbreak"),
            ("tab\\there", "tab\there"),
            ("\\u00e9", "é"),
            ("\\U0001F600", "\U0001f600"),
            ("a\\/b", "a/b"),
            ("it\\'s", "it's"),
            ("\\x41", "A"),
        ],
    )
    def test_known_escapes(self, text: str, expected: str) -> None:
        assert decode_escapes(text) == expected

    @pytest.mark.parametrize("text", ["\\q", "trailing\\", "\\u12", "\\uZZZZ", "\\x4"])
    def test_unknown_or_malformed_escapes_are_kept(self, text: str) -> None:
        assert decode_escapes(text) == text

    def test_text_without_a_backslash_is_returned_as_is(self) -> None:
        sentinel = "plain text"
        assert decode_escapes(sentinel) is sentinel

    def test_an_out_of_range_code_point_is_kept(self) -> None:
        assert decode_escapes("\\UFFFFFFFF") == "\\UFFFFFFFF"


class TestNormalizeText:
    def test_json_is_canonicalized(self) -> None:
        assert normalize_text(json.dumps(ADMIN, indent=2)) == ADMIN_JSON

    def test_escaped_literal_json_is_decoded_and_canonicalized(self) -> None:
        escaped = '{\\"Version\\": \\"2012-10-17\\", \\"Statement\\": []}'
        assert normalize_text(escaped) == '{"Statement":[],"Version":"2012-10-17"}'

    def test_a_heredoc_policy_with_escapes_inside_json_strings_is_not_decoded_twice(self) -> None:
        text = '{"Pattern": "a\\"b"}'
        assert normalize_text(text) == '{"Pattern":"a\\"b"}'

    def test_three_spellings_of_one_policy_are_identical(self) -> None:
        heredoc = (
            '{\n  "Version": "2012-10-17",\n'
            '  "Statement": [{"Effect": "Allow",\n "Action": "*", "Resource": "*"}]\n}'
        )
        escaped = json.dumps(json.dumps(ADMIN))[1:-1]
        encoded = normalize_value(
            "${jsonencode({'Version': '2012-10-17', "
            "'Statement': [{'Effect': 'Allow', 'Action': '*', 'Resource': '*'}]})}"
        )
        assert normalize_text(heredoc) == normalize_text(escaped) == encoded == ADMIN_JSON

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "plain",
            "{not json",
            "{'single': 'quotes'}",
            '"just a string"',
            "42",
            "[unterminated",
            "{ a = 1 }",
        ],
    )
    def test_anything_that_is_not_a_json_container_is_unchanged(self, text: str) -> None:
        assert normalize_text(text) == text

    def test_a_json_scalar_is_unchanged(self) -> None:
        assert normalize_text("true") == "true"

    def test_a_huge_document_is_left_alone(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("threatcode.parsers._hcl_values.MAX_JSON_TEXT", 10)
        text = '{"a":      1,  "b": 2}'
        assert normalize_text(text) == text

    def test_as_json_text_reports_none_for_text(self) -> None:
        assert as_json_text("hello") is None
        assert as_json_text("[1, 2]") == "[1,2]"


class TestInterpolations:
    def test_spans_of_each_interpolation(self) -> None:
        text = "a ${x} b ${y.z} c"
        assert [text[s:e] for s, e in find_interpolations(text)] == ["${x}", "${y.z}"]

    def test_a_nested_interpolation_belongs_to_the_outer_span(self) -> None:
        text = 'x ${f("a ${g(1)} b")} y'
        assert [text[s:e] for s, e in find_interpolations(text)] == ['${f("a ${g(1)} b")}']

    def test_a_brace_inside_a_quoted_string_does_not_close_the_span(self) -> None:
        text = 'x ${f("}")} y'
        assert [text[s:e] for s, e in find_interpolations(text)] == ['${f("}")}']

    def test_an_escaped_dollar_is_not_an_interpolation(self) -> None:
        assert find_interpolations("literal $${not} here") == []

    def test_an_unterminated_interpolation_runs_to_the_end(self) -> None:
        text = "x ${unterminated"
        assert [text[s:e] for s, e in find_interpolations(text)] == ["${unterminated"]


class TestUnpythonize:
    def test_python_literals_become_hcl_literals(self) -> None:
        assert unpythonize_expression("var.a ? True : False") == "var.a ? true : false"
        assert unpythonize_expression("var.a == None") == "var.a == null"

    def test_the_inside_of_a_string_is_never_touched(self) -> None:
        assert unpythonize_expression("\"True\" == 'None'") == "\"True\" == 'None'"
        assert unpythonize_expression('f("False and True")') == 'f("False and True")'

    def test_a_longer_identifier_is_not_a_literal(self) -> None:
        assert unpythonize_expression("TrueValue + NoneSuch + var.True") == (
            "TrueValue + NoneSuch + var.True"
        )

    def test_a_template_changes_only_its_interpolations(self) -> None:
        text = 'None of ${var.a ? True : "True"} is True'
        assert unpythonize_template(text) == 'None of ${var.a ? true : "True"} is True'

    def test_text_without_python_literals_is_returned_as_is(self) -> None:
        sentinel = "${var.a ? 1 : 2}"
        assert unpythonize_template(sentinel) is sentinel

    def test_python_repr_objects_keep_their_quotes(self) -> None:
        text = "${jsonencode({'a': True, 'b': None, 'c': 'True'})}"
        assert unpythonize_template(text) == "${jsonencode({'a': true, 'b': null, 'c': 'True'})}"

    def test_an_unterminated_interpolation_is_handled(self) -> None:
        assert unpythonize_template("${a ? True") == "${a ? true"


def unknown_reference(value: Any) -> str:
    assert is_unknown(value), value
    return value.reference


class TestNormalizeValue:
    def test_literal_values_pass_through(self) -> None:
        assert normalize_value(3) == 3
        assert normalize_value(True) is True
        assert normalize_value(None) is None
        assert normalize_value("plain") == "plain"

    def test_jsonencode_of_a_literal_object_is_canonical_json_text(self) -> None:
        value = normalize_value("${jsonencode({'Version': '2012-10-17', 'Statement': []})}")
        assert value == '{"Statement":[],"Version":"2012-10-17"}'

    def test_jsonencode_in_hcl_8_syntax_gives_the_same_text(self) -> None:
        value = normalize_value('${jsonencode({Version = "2012-10-17", Statement = []})}')
        assert value == '{"Statement":[],"Version":"2012-10-17"}'

    def test_jsonencode_keeps_a_resource_reference_as_an_unknown_leaf(self) -> None:
        value = normalize_value(
            "${jsonencode({'Statement': [{'Resource': '${aws_s3_bucket.b.arn}'}]})}"
        )
        assert isinstance(value, dict)
        leaf = value["Statement"][0]["Resource"]
        assert unknown_reference(leaf) == "aws_s3_bucket.b.arn"

    def test_jsonencode_keeps_the_literal_text_around_an_unresolved_part(self) -> None:
        value = normalize_value("${jsonencode({'Resource': 'arn:aws:s3:::${var.bucket}/*'})}")
        assert json.loads(value) == {"Resource": f"arn:aws:s3:::{UNKNOWN_TEXT}/*"}

    def test_a_variable_with_no_context_is_unknown_not_text(self) -> None:
        value = normalize_value("${var.encrypted}")
        assert unknown_reference(value) == "var.encrypted"
        assert value != "${var.encrypted}"

    def test_an_unknown_has_the_placeholder_text(self) -> None:
        assert normalize_value("${aws_kms_key.k.arn}") == UNKNOWN_TEXT

    def test_a_resource_reference_names_what_it_refers_to(self) -> None:
        assert unknown_reference(normalize_value("${aws_kms_key.k.arn}")) == "aws_kms_key.k.arn"

    def test_a_literal_expression_is_evaluated(self) -> None:
        assert normalize_value("${1 + 2}") == 3
        assert normalize_value('${true ? "a" : "b"}') == "a"

    def test_python_literals_in_a_ternary_are_restored(self) -> None:
        assert normalize_value("${true ? True : False}") is True
        assert normalize_value("${false ? True : None}") is None

    def test_containers_are_normalized_element_by_element(self) -> None:
        value = normalize_value(
            {"a": ["${1 + 1}", "${var.x}"], "policy": '{\\"a\\": 1}', "n": {"b": "${false}"}}
        )
        assert value["a"][0] == 2
        assert unknown_reference(value["a"][1]) == "var.x"
        assert value["policy"] == '{"a":1}'
        assert value["n"] == {"b": False}

    def test_a_template_is_joined_when_every_part_is_known(self) -> None:
        assert normalize_value("a-${1 + 1}-${true}") == "a-2-true"

    def test_a_template_with_an_unknown_part_is_unknown(self) -> None:
        assert is_unknown(normalize_value("a-${var.x}-b"))

    def test_a_json_template_with_an_unknown_part_keeps_its_literal_text(self) -> None:
        text = '{"Action": "*", "Resource": "arn:${var.partition}:s3:::b/*"}'
        value = normalize_value(text)
        assert json.loads(value) == {
            "Action": "*",
            "Resource": f"arn:{UNKNOWN_TEXT}:s3:::b/*",
        }

    def test_an_escaped_interpolation_is_literal_text(self) -> None:
        assert normalize_value("echo $${HOME}") == "echo ${HOME}"

    def test_a_template_directive_is_unknown(self) -> None:
        assert is_unknown(normalize_value("%{ if true }yes%{ endif }-${1}"))
