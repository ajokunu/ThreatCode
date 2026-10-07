"""Tests for threatcode.parsers._yaml: CloudFormation short-form tags and the line index."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.exceptions import ParseError
from threatcode.parsers._yaml import CfnSafeLoader, load_yaml_documents

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _value(text: str) -> Any:
    """Load ``value: <text>`` and return the value."""
    docs = load_yaml_documents(f"value: {text}\n")
    assert len(docs) == 1
    return docs[0]["value"]


INTRINSIC_CASES: list[tuple[str, Any]] = [
    # Ref and Condition use the bare key, everything else is Fn::<Name>
    ("!Ref Bucket", {"Ref": "Bucket"}),
    ('!Ref "AWS::Region"', {"Ref": "AWS::Region"}),
    ("!Condition IsProd", {"Condition": "IsProd"}),
    # Sub in its string form and its list form
    ('!Sub "${AWS::StackName}-data"', {"Fn::Sub": "${AWS::StackName}-data"}),
    ('!Sub ["${A}-x", {A: b}]', {"Fn::Sub": ["${A}-x", {"A": "b"}]}),
    # GetAtt: dotted scalar and list form normalise identically, split on the first dot
    ("!GetAtt Role.Arn", {"Fn::GetAtt": ["Role", "Arn"]}),
    ("!GetAtt [Role, Arn]", {"Fn::GetAtt": ["Role", "Arn"]}),
    ("!GetAtt A.B.C", {"Fn::GetAtt": ["A", "B.C"]}),
    ("!GetAtt Db.Endpoint.Address", {"Fn::GetAtt": ["Db", "Endpoint.Address"]}),
    # Condition functions
    ("!If [IsProd, !Ref A, !Ref B]", {"Fn::If": ["IsProd", {"Ref": "A"}, {"Ref": "B"}]}),
    ("!Equals [!Ref Env, prod]", {"Fn::Equals": [{"Ref": "Env"}, "prod"]}),
    ("!Not [!Condition IsProd]", {"Fn::Not": [{"Condition": "IsProd"}]}),
    ("!Or [!Condition A, !Condition B]", {"Fn::Or": [{"Condition": "A"}, {"Condition": "B"}]}),
    ("!And [!Condition A, !Condition B]", {"Fn::And": [{"Condition": "A"}, {"Condition": "B"}]}),
    # String and list functions
    ('!Join ["-", [a, b]]', {"Fn::Join": ["-", ["a", "b"]]}),
    ('!Select [0, !GetAZs ""]', {"Fn::Select": [0, {"Fn::GetAZs": ""}]}),
    ('!Split [",", "a,b"]', {"Fn::Split": [",", "a,b"]}),
    (
        '!FindInMap [Map, !Ref "AWS::Region", Key]',
        {"Fn::FindInMap": ["Map", {"Ref": "AWS::Region"}, "Key"]},
    ),
    ("!ImportValue SharedVpcId", {"Fn::ImportValue": "SharedVpcId"}),
    ('!Base64 "hello"', {"Fn::Base64": "hello"}),
    (
        "!Cidr [!GetAtt Vpc.CidrBlock, 6, 8]",
        {"Fn::Cidr": [{"Fn::GetAtt": ["Vpc", "CidrBlock"]}, 6, 8]},
    ),
    ('!GetAZs ""', {"Fn::GetAZs": ""}),
    (
        '!Transform {Name: AWS::Include, Parameters: {Location: "s3://b/k"}}',
        {"Fn::Transform": {"Name": "AWS::Include", "Parameters": {"Location": "s3://b/k"}}},
    ),
    # Unknown tags, including vendor tags, never raise and never lose the value
    ("!Frobnicate x", {"Fn::Frobnicate": "x"}),
    ("!Frobnicate [a, b]", {"Fn::Frobnicate": ["a", "b"]}),
    ("!Frobnicate {a: b}", {"Fn::Frobnicate": {"a": "b"}}),
    ("!Rain::Module ./module.yaml", {"Fn::Rain::Module": "./module.yaml"}),
]


class TestIntrinsics:
    @pytest.mark.parametrize(("text", "expected"), INTRINSIC_CASES)
    def test_short_form_becomes_long_form(self, text: str, expected: Any) -> None:
        assert _value(text) == expected

    def test_long_form_is_left_alone(self) -> None:
        docs = load_yaml_documents("value:\n  Fn::GetAtt: [Role, Arn]\n")
        assert docs[0]["value"] == {"Fn::GetAtt": ["Role", "Arn"]}

    def test_short_and_long_form_give_the_same_template(self) -> None:
        head = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        short = head + "      N: !GetAtt R2.Arn\n"
        long = head + "      N:\n        Fn::GetAtt: [R2, Arn]\n"
        assert load_yaml_documents(short) == load_yaml_documents(long)

    def test_nested_short_forms_compose(self) -> None:
        value = _value('!Join ["", [!Ref A, "-", !GetAtt B.Arn]]')
        assert value == {"Fn::Join": ["", [{"Ref": "A"}, "-", {"Fn::GetAtt": ["B", "Arn"]}]]}

    def test_long_form_wrapping_a_short_form(self) -> None:
        docs = load_yaml_documents('value:\n  Fn::Base64: !Sub "x ${Y}"\n')
        assert docs[0]["value"] == {"Fn::Base64": {"Fn::Sub": "x ${Y}"}}

    def test_block_style_tagged_sequence(self) -> None:
        text = "value: !Join\n  - ','\n  - - a\n    - !Ref B\n"
        assert load_yaml_documents(text)[0]["value"] == {"Fn::Join": [",", ["a", {"Ref": "B"}]]}

    def test_every_fixture_tag_family_loads(self) -> None:
        text = (FIXTURES / "input_shapes" / "cfn_short_form.yml").read_text(encoding="utf-8")
        docs = load_yaml_documents(text, source="cfn_short_form.yml")
        assert len(docs) == 1
        template = docs[0]
        props = template["Resources"]["Bucket"]["Properties"]
        assert props["BucketName"] == {"Fn::Sub": "${AWS::StackName}-data"}
        assert props["AccessControl"] == {"Fn::If": ["IsProd", "Private", "PublicRead"]}
        assert template["Conditions"]["NotProd"] == {"Fn::Not": [{"Condition": "IsProd"}]}
        outputs = template["Outputs"]
        assert outputs["BucketArn"]["Value"] == {"Fn::GetAtt": ["Bucket", "Arn"]}
        assert outputs["BucketDomain"]["Value"] == {"Fn::GetAtt": ["Bucket", "DomainName"]}


class TestSafety:
    @pytest.mark.parametrize(
        "text",
        [
            'value: !!python/object/apply:os.system ["echo pwned"]',
            "value: !!python/object:subprocess.Popen {args: [id]}",
            "value: !!python/name:os.system",
            'value: !!python/object/new:os.system ["id"]',
        ],
    )
    def test_python_object_tags_stay_rejected(self, text: str) -> None:
        with pytest.raises(ParseError, match=r"python/"):
            load_yaml_documents(text + "\n", source="evil.yaml")

    def test_loader_is_a_safe_loader(self) -> None:
        safe_bases = (yaml.SafeLoader, getattr(yaml, "CSafeLoader", yaml.SafeLoader))
        assert issubclass(CfnSafeLoader, safe_bases)
        assert not issubclass(CfnSafeLoader, yaml.UnsafeLoader)
        assert not issubclass(CfnSafeLoader, yaml.FullLoader)

    def test_registering_tags_does_not_leak_into_the_stock_safe_loader(self) -> None:
        # The short-form constructor lives on the subclass, so yaml.safe_load is unchanged.
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load("value: !Ref Bucket\n")

    def test_timestamps_stay_text(self) -> None:
        docs = load_yaml_documents("version: 2012-10-17\nquoted: '2010-09-09'\n")
        assert docs[0] == {"version": "2012-10-17", "quoted": "2010-09-09"}

    def test_deep_nesting_is_a_parse_error_not_a_crash(self) -> None:
        text = "value: " + "[" * 5000 + "]" * 5000 + "\n"
        try:
            load_yaml_documents(text, source="deep.yaml")
        except ParseError as exc:
            assert "deep.yaml" in str(exc)


class TestDocuments:
    def test_multiple_documents(self) -> None:
        assert load_yaml_documents("a: 1\n---\nb: 2\n") == [{"a": 1}, {"b": 2}]

    def test_empty_documents_are_dropped(self) -> None:
        assert load_yaml_documents("---\na: 1\n---\n---\nb: 2\n---\n") == [{"a": 1}, {"b": 2}]

    def test_no_documents(self) -> None:
        assert load_yaml_documents("# only a comment\n") == []

    def test_scalar_document(self) -> None:
        assert load_yaml_documents("just text\n") == ["just text"]


class TestErrors:
    def test_error_names_file_line_and_problem(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            load_yaml_documents("key: value\n  bad: indent\n", source="stack.yaml")
        message = str(exc_info.value)
        assert "stack.yaml" in message
        assert "line 2" in message
        assert "\n" not in message

    def test_unknown_python_tag_message_names_the_tag(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            load_yaml_documents("v: !!python/object/apply:os.system [id]\n", source="x.yaml")
        assert "python/object/apply:os.system" in str(exc_info.value)

    def test_unterminated_flow_sequence(self) -> None:
        with pytest.raises(ParseError, match=r"Invalid YAML in broken\.yml"):
            load_yaml_documents("items: [1, 2\nother: 3\n", source="broken.yml")


TEMPLATE = (
    "Resources:\n"
    "  Bucket:\n"
    "    Type: AWS::S3::Bucket\n"
    "    Properties:\n"
    "      Tags:\n"
    "        - Key: a\n"
    "        - Key: b\n"
)


class TestLineIndex:
    def test_default_return_is_only_the_documents(self) -> None:
        assert isinstance(load_yaml_documents(TEMPLATE), list)

    def test_keys_and_sequence_items_get_start_lines(self) -> None:
        docs, indexes = load_yaml_documents(TEMPLATE, with_lines=True)
        assert len(docs) == len(indexes) == 1
        index = indexes[0]
        assert index[""] == 1
        assert index["/Resources"] == 1
        assert index["/Resources/Bucket"] == 2
        assert index["/Resources/Bucket/Type"] == 3
        assert index["/Resources/Bucket/Properties"] == 4
        assert index["/Resources/Bucket/Properties/Tags"] == 5
        assert index["/Resources/Bucket/Properties/Tags/0"] == 6
        assert index["/Resources/Bucket/Properties/Tags/0/Key"] == 6
        assert index["/Resources/Bucket/Properties/Tags/1"] == 7

    def test_one_index_per_document(self) -> None:
        docs, indexes = load_yaml_documents("a: 1\n---\n\n---\nb: 2\nc: 3\n", with_lines=True)
        assert docs == [{"a": 1}, {"b": 2, "c": 3}]
        assert indexes[0]["/a"] == 1
        assert indexes[1]["/b"] == 5
        assert indexes[1]["/c"] == 6

    def test_pointer_escaping(self) -> None:
        _docs, indexes = load_yaml_documents('"a/b": 1\n"~x": 2\n', with_lines=True)
        assert indexes[0]["/a~1b"] == 1
        assert indexes[0]["/~0x"] == 2

    def test_short_form_collections_are_indexed_under_their_long_form_key(self) -> None:
        text = "Prop: !Join\n  - ','\n  - [a, b]\nOther: !Ref X\n"
        docs, indexes = load_yaml_documents(text, with_lines=True)
        assert docs[0]["Prop"] == {"Fn::Join": [",", ["a", "b"]]}
        index = indexes[0]
        assert index["/Prop"] == 1
        assert index["/Prop/Fn::Join/0"] == 2
        assert index["/Prop/Fn::Join/1"] == 3
        assert index["/Other"] == 4

    def test_aliases_keep_the_first_line(self) -> None:
        text = "base: &b\n  x: 1\ncopy: *b\n"
        _docs, indexes = load_yaml_documents(text, with_lines=True)
        assert indexes[0]["/base/x"] == 2
        assert indexes[0]["/copy"] == 3

    def test_billion_laughs_alias_walk_terminates(self) -> None:
        text = "a: &a [x, x, x, x, x, x, x, x, x]\n"
        previous = "a"
        for name in ("b", "c", "d", "e", "f"):
            items = ", ".join([f"*{previous}"] * 9)
            text += f"{name}: &{name} [{items}]\n"
            previous = name
        _docs, indexes = load_yaml_documents(text, with_lines=True)
        assert indexes[0]["/f"] == 6
