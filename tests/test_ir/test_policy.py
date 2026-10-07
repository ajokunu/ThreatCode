"""Policy documents in every spelling they reach the scan in."""

from __future__ import annotations

import json
from typing import Any

import pytest

from threatcode.ir.policy import (
    MAX_POLICY_CHARS,
    Statement,
    normalize_policy,
    principal_is_wildcard,
    statements_to_dicts,
)
from threatcode.values import Unknown, is_unknown

ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
}


def _one(value: Any) -> Statement:
    result = normalize_policy(value)
    assert not is_unknown(result), f"expected statements, got {result!r}"
    assert len(result) == 1
    return result[0]


class TestShapes:
    def test_mapping(self) -> None:
        statement = _one(ADMIN)
        assert statement == Statement(effect="Allow", actions=("*",), resources=("*",))

    def test_compact_json_string(self) -> None:
        assert _one(json.dumps(ADMIN)).actions == ("*",)

    def test_pretty_printed_json_string(self) -> None:
        assert _one(json.dumps(ADMIN, indent=4)).resources == ("*",)

    def test_heredoc_with_trailing_newline(self) -> None:
        assert _one(json.dumps(ADMIN, indent=2) + "\n").actions == ("*",)

    def test_hcl_escaped_quotes(self) -> None:
        # python-hcl2 keeps the backslashes of a quoted string
        escaped = json.dumps(ADMIN).replace('"', '\\"')
        assert _one(escaped).actions == ("*",)

    def test_hcl_doubled_backslashes(self) -> None:
        once = json.dumps(ADMIN).replace('"', '\\"')
        twice = once.replace("\\", "\\\\")
        assert _one(twice).actions == ("*",)

    def test_json_string_that_is_itself_json_encoded(self) -> None:
        assert _one(json.dumps(json.dumps(ADMIN))).actions == ("*",)

    def test_python_repr_inside_jsonencode(self) -> None:
        wrapped = "${jsonencode(" + repr(ADMIN) + ")}"
        statement = _one(wrapped)
        assert statement.effect == "Allow"
        assert statement.actions == ("*",)

    def test_python_repr_with_booleans_and_none(self) -> None:
        wrapped = (
            "${jsonencode({'Statement': "
            "[{'Effect': 'Allow', 'Action': 's3:*', 'Resource': '*', 'Sid': None}]})}"
        )
        assert _one(wrapped).actions == ("s3:*",)

    def test_a_list_of_statements_without_the_document(self) -> None:
        result = normalize_policy([{"Effect": "Deny", "Action": "*", "Resource": "*"}])
        assert not is_unknown(result)
        assert result[0].effect == "Deny"

    def test_cloudformation_dict_with_a_single_statement_object(self) -> None:
        document = {"Statement": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}}
        assert _one(document).actions == ("s3:GetObject",)

    def test_empty_statement_list_is_a_policy_that_allows_nothing(self) -> None:
        assert normalize_policy({"Statement": []}) == []


class TestFields:
    def test_action_as_string_and_as_list(self) -> None:
        assert _one(
            {"Statement": [{"Effect": "Allow", "Action": "iam:*", "Resource": "*"}]}
        ).actions == ("iam:*",)
        listed = {"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}
        assert _one(listed).actions == ("*",)
        assert _one(listed).resources == ("*",)

    def test_deny_is_kept_as_deny(self) -> None:
        assert (
            _one({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}).effect
            == "Deny"
        )

    def test_effect_is_case_insensitive_and_canonical(self) -> None:
        assert (
            _one({"Statement": [{"Effect": "allow", "Action": "*", "Resource": "*"}]}).effect
            == "Allow"
        )

    def test_not_action_and_not_resource(self) -> None:
        statement = _one(
            {"Statement": [{"Effect": "Allow", "NotAction": ["iam:*"], "NotResource": "arn:x"}]}
        )
        assert statement.not_actions == ("iam:*",)
        assert statement.not_resources == ("arn:x",)
        assert statement.actions == ()

    @pytest.mark.parametrize(
        ("principal", "expected"),
        [
            ("*", ("*",)),
            ({"AWS": "*"}, ("*",)),
            ({"AWS": ["arn:aws:iam::1:root", "*"]}, ("arn:aws:iam::1:root", "*")),
            ({"Service": "lambda.amazonaws.com"}, ("lambda.amazonaws.com",)),
            (
                {"AWS": "arn:a", "Service": ["ecs.amazonaws.com"]},
                ("arn:a", "ecs.amazonaws.com"),
            ),
        ],
    )
    def test_principal_forms_are_flattened(self, principal: Any, expected: tuple[str, ...]) -> None:
        statement = _one(
            {"Statement": [{"Effect": "Allow", "Principal": principal, "Action": "s3:Get*"}]}
        )
        assert statement.principals == expected

    def test_wildcard_principal_helper(self) -> None:
        statement = _one(
            {"Statement": [{"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "*"}]}
        )
        assert principal_is_wildcard(statement.to_dict())
        scoped = _one({"Statement": [{"Effect": "Allow", "Principal": "arn:a", "Action": "*"}]})
        assert not principal_is_wildcard(scoped.to_dict())

    def test_condition_keys_across_operators(self) -> None:
        statement = _one(
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": "*",
                        "Action": "s3:GetObject",
                        "Condition": {
                            "StringEquals": {"aws:PrincipalOrgID": "o-1"},
                            "IpAddress": {
                                "aws:SourceIp": "10.0.0.0/8",
                                "aws:PrincipalOrgID": "o-1",
                            },
                        },
                    }
                ]
            }
        )
        assert statement.has_condition
        assert statement.condition_keys == ("aws:PrincipalOrgID", "aws:SourceIp")

    def test_no_condition(self) -> None:
        statement = _one(ADMIN)
        assert not statement.has_condition
        assert statement.condition_keys == ()

    def test_a_lone_interpolation_is_unknown_and_a_partial_one_is_kept(self) -> None:
        wrapped = (
            "${jsonencode({'Statement': [{'Effect': 'Allow', 'Action': '${var.actions}', "
            "'Resource': ['${aws_s3_bucket.b.arn}', '${aws_s3_bucket.b.arn}/*']}]})}"
        )
        statement = _one(wrapped)
        assert is_unknown(statement.actions[0])
        assert statement.actions[0].reference == "var.actions"
        assert is_unknown(statement.resources[0])
        assert statement.resources[1] == "${aws_s3_bucket.b.arn}/*"

    def test_to_dict_is_plain_data(self) -> None:
        data = _one(ADMIN).to_dict()
        assert data["actions"] == ["*"]
        assert isinstance(data["resources"], list)
        json.dumps(data)
        assert statements_to_dicts([_one(ADMIN)]) == [data]


class TestInvalidInput:
    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "   ",
            "not json",
            "{broken",
            42,
            ["not a statement"],
            {"Version": "2012-10-17"},
            {"Statement": "*"},
            {"Statement": [{"Action": "*", "Resource": "*"}]},
            {"Statement": [{"Effect": "Maybe", "Action": "*"}]},
            {"Statement": [{"Effect": "Allow", "Action": "*"}, "x"]},
            "${data.aws_iam_policy_document.p.json}",
            "${jsonencode(local.doc)}",
            "${jsonencode(merge({'a': 1}, local.b))}",
        ],
    )
    def test_unreadable_input_is_unknown_not_an_empty_list(self, value: Any) -> None:
        assert is_unknown(normalize_policy(value))

    def test_an_unknown_passes_through_with_its_reference(self) -> None:
        unknown = Unknown("aws_iam_policy_document.p.json")
        result = normalize_policy(unknown)
        assert is_unknown(result)
        assert result.reference == "aws_iam_policy_document.p.json"

    def test_a_data_source_reference_keeps_the_expression(self) -> None:
        result = normalize_policy("${data.aws_iam_policy_document.p.json}")
        assert is_unknown(result)
        assert result.reference == "data.aws_iam_policy_document.p.json"

    def test_malformed_input_never_raises(self) -> None:
        for value in [
            "{" * 50000,
            "[" * 50000,
            "${jsonencode(" + "(" * 5000 + ")}",
            b"bytes",
            object(),
        ]:
            assert is_unknown(normalize_policy(value))

    def test_oversized_text_is_not_parsed(self) -> None:
        assert is_unknown(normalize_policy(" " * (MAX_POLICY_CHARS + 1) + json.dumps(ADMIN)))

    def test_python_repr_is_never_evaluated(self) -> None:
        # literal_eval accepts literals only; a call is not one
        hostile = "${jsonencode({'Statement': __import__('os').getcwd()})}"
        assert is_unknown(normalize_policy(hostile))
