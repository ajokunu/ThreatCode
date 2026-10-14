"""Tests for threatcode.parsers registry (detect_and_parse + register_parser)."""

from __future__ import annotations

import codecs
import json
import os
import re
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import pytest

from threatcode.constants import is_dockerfile_name
from threatcode.exceptions import ParseError, UnsupportedFormatError
from threatcode.parsers import (
    _REGISTRY,
    DuplicateParserError,
    ParseFileParser,
    ParserPriority,
    detect_and_parse,
    looks_like_infrastructure,
    register_parser,
)
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource
from threatcode.parsers.terraform_hcl import TerraformHCLParser

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
SHAPES = FIXTURES_DIR / "input_shapes"
SIMPLE_PLAN = FIXTURES_DIR / "terraform" / "simple_s3.plan.json"
SIMPLE_TF = FIXTURES_DIR / "terraform" / "simple.tf"
K8S_DEPLOYMENT = FIXTURES_DIR / "kubernetes" / "insecure_deployment.yml"
MCP_FIXED = FIXTURES_DIR / "mcp" / "fixed" / ".mcp.json"

BUILTIN_PARSERS = [
    "helm",
    "terraform_plan",
    "mcp_config",
    "cloudformation",
    "kubernetes",
    "dockerfile",
    "terraform_hcl",
]

RESOURCES_ONLY = (
    "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: demo\n"
)
SAM_TEMPLATE = (
    "Transform: AWS::Serverless-2016-10-31\n"
    "Resources:\n"
    "  Fn:\n"
    "    Type: AWS::Serverless::Function\n"
    "    Properties:\n"
    "      Handler: app.handler\n"
    "      Runtime: python3.12\n"
    "      CodeUri: .\n"
)


class DummyParser(BaseParser):
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        return ParsedOutput(
            resources=[
                ParsedResource(
                    resource_type="custom_widget",
                    address="custom_widget.test",
                    name="test",
                    provider="custom",
                )
            ],
            source_path=source_path,
            format_type="custom",
        )


class AttributeErrorParser(BaseParser):
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        raise AttributeError("boom")


class TypeErrorParser(BaseParser):
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        raise TypeError("wrong type")


class ParseErrorParser(BaseParser):
    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        raise ParseError("custom failure")


@contextmanager
def registered(name: str, **kwargs: Any) -> Iterator[None]:
    """Register a parser for the length of a block, then remove it."""
    register_parser(name, **kwargs)
    try:
        yield
    finally:
        _REGISTRY[:] = [e for e in _REGISTRY if e.name != name]


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _write_bytes(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _change(address: str, action: str, mode: str = "managed") -> dict[str, Any]:
    """A resource_changes entry of a Terraform plan."""
    return {"address": address, "mode": mode, "change": {"actions": [action]}}


class TestDetectAndParse:
    def test_terraform_plan_json(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "terraform" / "simple_s3.plan.json")
        assert len(result.resources) > 0
        assert result.format_type == "terraform_plan"

    def test_cloudformation_yaml(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "cloudformation" / "insecure_stack.yml")
        assert len(result.resources) > 0

    def test_terraform_hcl(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "terraform" / "simple.tf")
        assert len(result.resources) == 2
        assert result.format_type == "terraform_hcl"

    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            detect_and_parse("/nonexistent/file.json")

    def test_unsupported_extension(self, tmp_path: Path) -> None:
        f = tmp_path / "test.xml"
        f.write_text("<root/>")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(f)

    def test_unsupported_message_lists_inputs_on_short_lines(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "test.xml", "<root/>")
        with pytest.raises(UnsupportedFormatError) as exc_info:
            detect_and_parse(f)
        lines = str(exc_info.value).splitlines()
        assert lines[0] == "Cannot detect format for test.xml."
        assert "Supported inputs:" in lines
        assert len(lines) >= 8
        assert max(len(line) for line in lines) <= 90
        listed = "\n".join(lines)
        for name in ("Terraform", "CloudFormation", "Kubernetes", "Helm", "Dockerfile", "MCP"):
            assert name in listed

    def test_oversized_file_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "big.json"
        # Create file over 50 MB limit header
        f.write_text("x" * (50 * 1024 * 1024 + 1))
        with pytest.raises(ParseError, match="MB limit"):
            detect_and_parse(f)

    def test_invalid_json_rejected(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.json"
        f.write_text("{not valid json")
        with pytest.raises(UnsupportedFormatError, match="Invalid JSON"):
            detect_and_parse(f)

    def test_invalid_json_names_the_file_and_line(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "bad.json", '{\n  "a": 1,\n  oops\n}\n')
        with pytest.raises(UnsupportedFormatError, match=r"Invalid JSON in bad\.json, line 3"):
            detect_and_parse(f)

    def test_invalid_yaml_names_the_file_and_line(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "bad.yaml", "key: value\n  bad: indent\n")
        with pytest.raises(UnsupportedFormatError, match=r"Invalid YAML in bad\.yaml, line 2"):
            detect_and_parse(f)

    @pytest.mark.parametrize("name", ["empty.yaml", "empty.json", "empty.tf", "Dockerfile"])
    @pytest.mark.parametrize("content", ["", "  \n\t\n"])
    def test_empty_file_is_reported(self, tmp_path: Path, name: str, content: str) -> None:
        f = _write(tmp_path, name, content)
        with pytest.raises(ParseError, match="file is empty") as exc_info:
            detect_and_parse(f)
        assert name in str(exc_info.value)
        assert not isinstance(exc_info.value, UnsupportedFormatError)

    def test_binary_file_is_not_valid_text(self, tmp_path: Path) -> None:
        f = _write_bytes(tmp_path, "blob.json", b"\x89PNG\r\n\x1a\n\x00\x00")
        with pytest.raises(ParseError, match="not valid UTF-8 text"):
            detect_and_parse(f)


class TestRegisterParser:
    def test_custom_parser_detected(self, tmp_path: Path) -> None:
        """Register a custom parser and verify it's used for matching files."""
        with registered(
            "custom_test",
            detector=lambda path, content, data: "CUSTOM_MARKER" in content,
            factory=DummyParser,
            extensions=frozenset({".json"}),
            priority=1,  # Higher priority than built-ins
        ):
            f = tmp_path / "custom.json"
            f.write_text(json.dumps({"CUSTOM_MARKER": True}))
            result = detect_and_parse(f)
        assert result.format_type == "custom"
        assert result.resources[0].resource_type == "custom_widget"

    def test_duplicate_name_is_rejected(self) -> None:
        before = list(_REGISTRY)
        with pytest.raises(DuplicateParserError, match="terraform_plan"):
            register_parser("terraform_plan", lambda path, content, data: False, DummyParser)
        assert _REGISTRY == before

    def test_duplicate_name_error_is_a_value_error(self) -> None:
        with pytest.raises(ValueError, match="already registered"):
            register_parser("helm", lambda path, content, data: False, DummyParser)

    def test_builtin_priority_ordering_is_unchanged(self) -> None:
        assert [e.name for e in _REGISTRY if e.name in BUILTIN_PARSERS] == BUILTIN_PARSERS

    def test_builtin_priorities_are_the_named_values(self) -> None:
        priorities = {e.name: e.priority for e in _REGISTRY}
        assert priorities["helm"] == ParserPriority.HELM == 8
        assert priorities["terraform_plan"] == ParserPriority.TERRAFORM_PLAN == 10
        assert priorities["mcp_config"] == ParserPriority.MCP_CONFIG == 15
        assert priorities["cloudformation"] == ParserPriority.CLOUDFORMATION == 20
        assert priorities["kubernetes"] == ParserPriority.KUBERNETES == 22
        assert priorities["dockerfile"] == ParserPriority.DOCKERFILE == 25
        assert priorities["terraform_hcl"] == ParserPriority.TERRAFORM_HCL == 30

    def test_extensions_are_compared_case_insensitively(self) -> None:
        with registered(
            "upper_ext",
            detector=lambda path, content, data: False,
            factory=DummyParser,
            extensions={".JSON", ".Yaml"},
        ):
            entry = next(e for e in _REGISTRY if e.name == "upper_ext")
            assert entry.extensions == frozenset({".json", ".yaml"})
            assert entry.priority == ParserPriority.DEFAULT

    def test_parse_file_protocol(self) -> None:
        assert isinstance(TerraformHCLParser(), ParseFileParser)
        assert not isinstance(DummyParser(), ParseFileParser)


class TestTypedFailures:
    def test_attribute_error_in_a_parser_names_parser_and_file(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "thing.json", json.dumps({"MARK": 1}))
        with registered(
            "boom_parser",
            detector=lambda path, content, data: "MARK" in content,
            factory=AttributeErrorParser,
            extensions=frozenset({".json"}),
            priority=1,
        ):
            with pytest.raises(ParseError) as exc_info:
                detect_and_parse(f)
        error = exc_info.value
        assert not isinstance(error, UnsupportedFormatError)
        assert "boom_parser parser failed on thing.json" in str(error)
        assert "AttributeError: boom" in str(error)
        assert isinstance(error.__cause__, AttributeError)

    def test_type_error_is_not_reported_as_cannot_detect(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "thing.json", json.dumps({"MARK": 1}))
        with registered(
            "wrong_type",
            detector=lambda path, content, data: True,
            factory=TypeErrorParser,
            extensions=frozenset({".json"}),
            priority=1,
        ):
            with pytest.raises(ParseError) as exc_info:
                detect_and_parse(f)
        assert "Cannot detect format" not in str(exc_info.value)
        assert "TypeError: wrong type" in str(exc_info.value)

    def test_a_parse_error_from_a_parser_is_not_wrapped(self, tmp_path: Path) -> None:
        f = _write(tmp_path, "thing.json", json.dumps({"MARK": 1}))
        with registered(
            "polite",
            detector=lambda path, content, data: True,
            factory=ParseErrorParser,
            extensions=frozenset({".json"}),
            priority=1,
        ):
            with pytest.raises(ParseError) as exc_info:
                detect_and_parse(f)
        assert str(exc_info.value) == "custom failure"
        assert exc_info.value.__cause__ is None

    def test_a_failing_factory_is_wrapped_too(self, tmp_path: Path) -> None:
        def factory() -> BaseParser:
            raise RuntimeError("cannot construct")

        f = _write(tmp_path, "thing.json", json.dumps({"MARK": 1}))
        with registered(
            "broken_factory",
            detector=lambda path, content, data: True,
            factory=factory,
            extensions=frozenset({".json"}),
            priority=1,
        ):
            with pytest.raises(ParseError, match="broken_factory parser failed on thing.json"):
                detect_and_parse(f)

    def test_detector_exception_falls_through_to_later_parsers(self) -> None:
        def bad_detector(path: Path, content: str, data: Any) -> bool:
            raise RuntimeError("detector broke")

        with registered(
            "bad_detector",
            detector=bad_detector,
            factory=DummyParser,
            extensions=frozenset({".json"}),
            priority=1,
        ):
            result = detect_and_parse(SIMPLE_PLAN)
        assert result.format_type == "terraform_plan"

    def test_detector_that_declines_never_builds_the_parser(self) -> None:
        built: list[str] = []

        def factory() -> BaseParser:
            built.append("built")
            return DummyParser()

        with registered(
            "declines",
            detector=lambda path, content, data: False,
            factory=factory,
            extensions=frozenset({".json"}),
            priority=1,
        ):
            result = detect_and_parse(SIMPLE_PLAN)
        assert built == []
        assert result.format_type == "terraform_plan"


class TestMultiDocumentYaml:
    """Kubernetes manifests with several --- separated documents must parse, not error."""

    def test_multi_document_manifest_detected(self) -> None:
        result = detect_and_parse(FIXTURES_DIR / "kubernetes" / "multi_resource.yml")
        assert result.format_type == "kubernetes"
        types = {r.resource_type for r in result.resources}
        assert {"kubernetes_cluster_role", "kubernetes_deployment"} <= types

    def test_trailing_separator_is_single_document(self, tmp_path: Path) -> None:
        manifest = tmp_path / "pod.yaml"
        manifest.write_text("---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n---\n")
        result = detect_and_parse(manifest)
        assert [r.resource_type for r in result.resources] == ["kubernetes_pod"]

    def test_mixed_documents_are_claimed_when_any_is_kubernetes(self) -> None:
        result = detect_and_parse(SHAPES / "k8s_mixed.yml")
        assert result.format_type == "kubernetes"
        assert [r.resource_type for r in result.resources] == ["kubernetes_pod"]

    def test_documents_without_a_kubernetes_object_are_not_claimed(self, tmp_path: Path) -> None:
        mixed = _write(tmp_path, "mixed.yaml", "foo: bar\n---\nbaz: 1\n")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(mixed)


class TestTerraformJson:
    def test_state_json_is_rejected_with_the_right_command(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            detect_and_parse(SHAPES / "terraform_state.json")
        message = str(exc_info.value)
        assert "This is Terraform state, not a plan" in message
        assert "terraform plan -out tfplan && terraform show -json tfplan" in message
        assert not isinstance(exc_info.value, UnsupportedFormatError)

    def test_state_message_matches_the_documented_wording(self) -> None:
        with pytest.raises(ParseError) as exc_info:
            detect_and_parse(SHAPES / "terraform_state.json")
        assert re.fullmatch(
            r"This is Terraform state, not a plan\. "
            r"Run: terraform plan -out tfplan && terraform show -json tfplan",
            str(exc_info.value),
        )

    def test_destroy_only_plan_is_rejected(self) -> None:
        with pytest.raises(ParseError, match="this plan destroys every resource"):
            detect_and_parse(SHAPES / "terraform_destroy.plan.json")

    def test_destroy_plan_with_data_source_reads_is_still_destroy_only(
        self, tmp_path: Path
    ) -> None:
        plan = json.loads((SHAPES / "terraform_destroy.plan.json").read_text(encoding="utf-8"))
        plan["resource_changes"].append(_change("data.aws_caller_identity.me", "read", "data"))
        path = _write(tmp_path, "destroy.plan.json", json.dumps(plan))
        with pytest.raises(ParseError, match="destroys every resource"):
            detect_and_parse(path)

    def test_bare_format_version_is_not_claimed(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "bare.json", json.dumps({"format_version": "1.0"}))
        with pytest.raises(UnsupportedFormatError, match="Cannot detect format"):
            detect_and_parse(path)

    def test_format_version_with_unrelated_keys_is_not_claimed(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "x.json", json.dumps({"format_version": "3", "name": "x"}))
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(path)

    def test_plan_that_replaces_a_resource_is_not_destroy_only(self, tmp_path: Path) -> None:
        new_bucket = {
            "address": "aws_s3_bucket.new",
            "mode": "managed",
            "type": "aws_s3_bucket",
            "name": "new",
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "values": {"bucket": "new-assets"},
        }
        plan = {
            "format_version": "1.2",
            "planned_values": {"root_module": {"resources": [new_bucket]}},
            "resource_changes": [
                _change("aws_s3_bucket.old", "delete"),
                _change("aws_s3_bucket.new", "create"),
            ],
        }
        result = detect_and_parse(_write(tmp_path, "replace.plan.json", json.dumps(plan)))
        assert result.format_type == "terraform_plan"
        assert [r.address for r in result.resources] == ["aws_s3_bucket.new"]

    def test_plan_with_resources_in_a_child_module_is_not_destroy_only(
        self, tmp_path: Path
    ) -> None:
        child_bucket = {
            "address": "module.app.aws_s3_bucket.b",
            "type": "aws_s3_bucket",
            "name": "b",
            "values": {"bucket": "b"},
        }
        child = {"address": "module.app", "resources": [child_bucket]}
        plan = {
            "format_version": "1.2",
            "planned_values": {"root_module": {"child_modules": [child]}},
            "resource_changes": [_change("aws_s3_bucket.old", "delete")],
        }
        result = detect_and_parse(_write(tmp_path, "child.plan.json", json.dumps(plan)))
        assert result.format_type == "terraform_plan"
        assert len(result.resources) == 1

    @pytest.mark.parametrize(
        "plan",
        [
            {"format_version": "1.2", "planned_values": {"root_module": {}}},
            {"format_version": "1.2", "planned_values": {}, "resource_changes": []},
            {
                "format_version": "1.2",
                "planned_values": {"root_module": {}},
                "resource_changes": [_change("aws_s3_bucket.b", "no-op")],
            },
        ],
    )
    def test_empty_plan_still_parses(self, tmp_path: Path, plan: dict[str, Any]) -> None:
        result = detect_and_parse(_write(tmp_path, "empty.plan.json", json.dumps(plan)))
        assert result.format_type == "terraform_plan"
        assert result.resources == []

    def test_existing_plan_fixtures_are_unchanged(self) -> None:
        for name in ("simple_s3", "multi_service_insecure", "multi_service_secure"):
            result = detect_and_parse(FIXTURES_DIR / "terraform" / f"{name}.plan.json")
            assert result.format_type == "terraform_plan"
            assert result.resources


class TestCloudFormationDetection:
    def test_resources_only_template(self, tmp_path: Path) -> None:
        result = detect_and_parse(_write(tmp_path, "stack.yaml", RESOURCES_ONLY))
        assert result.format_type == "cloudformation"
        assert [r.resource_type for r in result.resources] == ["aws_s3_bucket"]

    def test_sam_template_without_a_version(self, tmp_path: Path) -> None:
        result = detect_and_parse(_write(tmp_path, "template.yaml", SAM_TEMPLATE))
        assert result.format_type == "cloudformation"
        # the function and the execution role SAM creates for it
        assert [r.name for r in result.resources] == ["Fn", "FnRole"]

    @pytest.mark.parametrize("resource_type", ["Custom::Thing", "Alexa::ASK::Skill"])
    def test_custom_and_alexa_types_are_claimed(self, tmp_path: Path, resource_type: str) -> None:
        text = f"Resources:\n  Thing:\n    Type: {resource_type}\n"
        result = detect_and_parse(_write(tmp_path, "stack.yml", text))
        assert result.format_type == "cloudformation"

    @pytest.mark.parametrize("name", ["stack.template", "stack.cfn"])
    def test_template_and_cfn_extensions_with_yaml(self, tmp_path: Path, name: str) -> None:
        result = detect_and_parse(_write(tmp_path, name, RESOURCES_ONLY))
        assert result.format_type == "cloudformation"
        assert len(result.resources) == 1

    def test_template_extension_with_a_json_body(self, tmp_path: Path) -> None:
        body = json.dumps({"Resources": {"Bucket": {"Type": "AWS::S3::Bucket"}}})
        result = detect_and_parse(_write(tmp_path, "stack.template", body))
        assert result.format_type == "cloudformation"
        assert len(result.resources) == 1

    def test_template_extension_with_an_invalid_body_is_unsupported(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "stack.template", "{not json")
        with pytest.raises(UnsupportedFormatError, match="Invalid JSON in stack.template"):
            detect_and_parse(path)

    def test_resources_with_foreign_types_are_not_claimed(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "stack.yaml", "Resources:\n  A:\n    Type: Foo::Bar\n")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(path)

    def test_older_heuristic_still_claims_resources_next_to_another_section(
        self, tmp_path: Path
    ) -> None:
        text = "Description: x\nResources:\n  A:\n    Type: Foo::Bar\n"
        result = detect_and_parse(_write(tmp_path, "stack.yaml", text))
        assert result.format_type == "cloudformation"

    def test_typed_resources_win_over_a_kubernetes_shaped_header(self, tmp_path: Path) -> None:
        text = "apiVersion: v1\nkind: Foo\nResources:\n  A:\n    Type: AWS::S3::Bucket\n"
        result = detect_and_parse(_write(tmp_path, "mixed.yaml", text))
        assert result.format_type == "cloudformation"

    def test_short_form_fixture(self) -> None:
        result = detect_and_parse(SHAPES / "cfn_short_form.yml")
        assert result.format_type == "cloudformation"
        assert {r.name for r in result.resources} == {"Bucket", "Instance", "Subnets"}
        bucket = next(r for r in result.resources if r.name == "Bucket")
        props = bucket.properties
        # the short forms are expanded to the long form and kept as written under _cfn
        assert props["_cfn"]["BucketName"] == {"Fn::Sub": "${AWS::StackName}-data"}
        assert props["_cfn"]["AccessControl"] == {"Fn::If": ["IsProd", "Private", "PublicRead"]}
        assert result.metadata["template_version"] == "2010-09-09"

    def test_short_form_output_is_json_serializable(self) -> None:
        result = detect_and_parse(SHAPES / "cfn_short_form.yml")
        json.dumps([r.properties for r in result.resources])
        json.dumps(result.metadata)

    def test_short_form_template_equals_its_long_form_twin(self, tmp_path: Path) -> None:
        head = "Resources:\n  R:\n    Type: AWS::S3::Bucket\n    Properties:\n"
        short = head + "      BucketName: !Sub '${AWS::StackName}-x'\n"
        short += "      Arn: !GetAtt Other.Arn\n"
        long = head + "      BucketName:\n        Fn::Sub: '${AWS::StackName}-x'\n"
        long += "      Arn:\n        Fn::GetAtt: [Other, Arn]\n"
        short_result = detect_and_parse(_write(tmp_path, "short.yaml", short))
        long_result = detect_and_parse(_write(tmp_path, "long.yaml", long))
        assert short_result.resources[0].properties == long_result.resources[0].properties


class TestKubernetesDetection:
    # A List is claimed as Kubernetes input here. Expanding its items into one resource each
    # belongs to the Kubernetes parser (WI-K7), so these tests only pin the detection.
    def test_list_object_in_yaml(self) -> None:
        assert detect_and_parse(SHAPES / "k8s_list.yml").format_type == "kubernetes"

    def test_list_object_in_json(self) -> None:
        assert detect_and_parse(SHAPES / "k8s_list.json").format_type == "kubernetes"

    def test_list_kind_without_api_version(self, tmp_path: Path) -> None:
        text = (
            "kind: PodList\n"
            "items:\n"
            "  - apiVersion: v1\n"
            "    kind: Pod\n"
            "    metadata:\n"
            "      name: a\n"
        )
        result = detect_and_parse(_write(tmp_path, "pods.yaml", text))
        assert result.format_type == "kubernetes"

    def test_json_manifest(self, tmp_path: Path) -> None:
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "image": "nginx:1.25"}]},
        }
        result = detect_and_parse(_write(tmp_path, "pod.json", json.dumps(pod)))
        assert result.format_type == "kubernetes"
        assert [r.resource_type for r in result.resources] == ["kubernetes_pod"]

    def test_a_kind_that_only_ends_in_list_is_not_claimed(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "todo.yaml", "kind: ShoppingList\nowner: me\n")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(path)

    def test_plain_yaml_without_api_version_and_kind_is_not_claimed(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "config.yaml", "settings:\n  retries: 3\n")
        with pytest.raises(UnsupportedFormatError, match="apiVersion and kind"):
            detect_and_parse(path)


DOCKERFILE_NAMES = [
    "Dockerfile",
    "dockerfile",
    "DOCKERFILE",
    "Containerfile",
    "containerfile",
    "CONTAINERFILE",
    "Dockerfile.dev",
    "dockerfile.prod",
    "Dockerfile-dev",
    "Dockerfile_api",
    "app.dockerfile",
    "API.Dockerfile",
    "app.containerfile",
    "Containerfile.build",
]
NOT_DOCKERFILE_NAMES = [
    "Dockerfiles",
    "mydockerfile",
    "docker-compose.yml",
    "README.md",
    "main.tf",
]
DOCKERFILE_VARIANTS = [
    "Containerfile",
    "Dockerfile-dev",
    "Dockerfile_api",
    "app.containerfile",
    "Dockerfile.dev",
]


class TestDockerfileNames:
    @pytest.mark.parametrize("name", DOCKERFILE_NAMES)
    def test_dockerfile_names(self, name: str) -> None:
        assert is_dockerfile_name(name)

    @pytest.mark.parametrize("name", NOT_DOCKERFILE_NAMES)
    def test_other_names(self, name: str) -> None:
        assert not is_dockerfile_name(name)

    @pytest.mark.parametrize("name", DOCKERFILE_VARIANTS)
    def test_variants_are_parsed_as_dockerfiles(self, tmp_path: Path, name: str) -> None:
        path = _write(tmp_path, name, "FROM alpine:3.19\nUSER app\n")
        result = detect_and_parse(path)
        assert result.format_type == "dockerfile"
        assert "dockerfile_from" in {r.resource_type for r in result.resources}


class TestHclInputs:
    def test_tofu_file(self) -> None:
        result = detect_and_parse(SHAPES / "main.tofu")
        assert result.format_type == "terraform_hcl"
        assert [r.address for r in result.resources] == ["aws_s3_bucket.tofu"]

    def test_tf_json_file(self) -> None:
        result = detect_and_parse(SHAPES / "cdk.tf.json")
        assert result.format_type == "terraform_hcl"
        addresses = {r.address for r in result.resources}
        assert addresses == {"aws_s3_bucket.assets", "aws_instance.web"}
        bucket = next(r for r in result.resources if r.name == "assets")
        assert bucket.properties["acl"] == "public-read"
        assert bucket.provider == "hashicorp/aws"

    def test_invalid_hcl_names_the_file_without_a_token_dump(self, tmp_path: Path) -> None:
        text = 'resource "aws_s3_bucket" "b" {\n  bucket == "x"\n}\n'
        with pytest.raises(ParseError) as exc_info:
            detect_and_parse(_write(tmp_path, "broken.tf", text))
        message = str(exc_info.value)
        assert "broken.tf" in message
        assert "Token(" not in message
        assert "Expected one of" not in message
        assert "\n" not in message

    def test_a_terraform_parse_error_is_not_unsupported(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "broken.tf", "resource {{{\n")
        with pytest.raises(ParseError) as exc_info:
            detect_and_parse(path)
        assert not isinstance(exc_info.value, UnsupportedFormatError)

    def test_invalid_tf_json(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "broken.tf.json", "{not json")
        with pytest.raises(UnsupportedFormatError, match="Invalid JSON in broken.tf.json"):
            detect_and_parse(path)


class TestTerraformDirectory:
    def test_directory_is_one_module(self) -> None:
        module = SHAPES / "tf_module"
        result = detect_and_parse(module)
        assert result.format_type == "terraform_hcl"
        assert result.source_path == module.as_posix()
        assert [r.address for r in result.resources] == [
            "aws_s3_bucket.logs",
            "aws_instance.web",
            "aws_s3_bucket.public",
        ]
        assert result.metadata["files"] == ["main.tf", "storage.tf", "variables.tf"]

    def test_resources_point_at_their_own_file(self) -> None:
        result = detect_and_parse(SHAPES / "tf_module")
        by_address = {r.address: r.source_location for r in result.resources}
        assert by_address["aws_s3_bucket.logs"].endswith("main.tf")
        assert by_address["aws_s3_bucket.public"].endswith("storage.tf")

    def test_empty_files_in_a_module_are_skipped(self, tmp_path: Path) -> None:
        module = tmp_path / "module"
        shutil.copytree(SHAPES / "tf_module", module)
        (module / "outputs.tf").write_text("", encoding="utf-8")
        (module / "locals.tf").write_text("\n  \n", encoding="utf-8")
        result = detect_and_parse(module)
        assert len(result.resources) == 3
        assert result.metadata["files"] == ["main.tf", "storage.tf", "variables.tf"]

    def test_json_syntax_and_tofu_files_join_the_module(self, tmp_path: Path) -> None:
        module = tmp_path / "module"
        module.mkdir()
        shutil.copy(SHAPES / "cdk.tf.json", module / "cdk.tf.json")
        shutil.copy(SHAPES / "main.tofu", module / "main.tofu")
        result = detect_and_parse(module)
        assert len(result.resources) == 3

    def test_a_broken_file_names_itself(self, tmp_path: Path) -> None:
        module = tmp_path / "module"
        shutil.copytree(SHAPES / "tf_module", module)
        (module / "zz_bad.tf").write_text("resource {{{\n", encoding="utf-8")
        # a broken file is an error diagnostic that names it; the rest of the module is
        # still read, so the scan reports the file instead of aborting
        result = detect_and_parse(module)
        failed = [d for d in result.diagnostics if d.code == "parse.failed"]
        assert len(failed) == 1
        assert failed[0].level == "error"
        assert "zz_bad.tf" in failed[0].message
        assert len(result.resources) == 3
        assert "zz_bad.tf" not in result.metadata["files"]

    def test_directory_without_terraform_files_is_unsupported(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# nothing here\n", encoding="utf-8")
        (tmp_path / "app.yaml").write_text("a: 1\n", encoding="utf-8")
        with pytest.raises(UnsupportedFormatError, match="no Terraform files"):
            detect_and_parse(tmp_path)

    def test_empty_directory_is_unsupported(self, tmp_path: Path) -> None:
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(tmp_path)

    def test_nested_directories_are_not_read(self, tmp_path: Path) -> None:
        nested = tmp_path / "nested"
        nested.mkdir()
        shutil.copy(SIMPLE_TF, nested / "main.tf")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(tmp_path)

    def test_symlinked_files_are_skipped(self, tmp_path: Path) -> None:
        target = tmp_path / "outside" / "real.tf"
        target.parent.mkdir()
        shutil.copy(SIMPLE_TF, target)
        module = tmp_path / "module"
        module.mkdir()
        try:
            os.symlink(target, module / "link.tf")
        except (OSError, NotImplementedError):
            pytest.skip("symlinks are not available here")
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(module)

    def test_parse_directory_without_terraform_files(self, tmp_path: Path) -> None:
        with pytest.raises(ParseError, match="No Terraform files"):
            TerraformHCLParser().parse_directory(tmp_path)


class TestEncodings:
    def test_utf8_bom_terraform(self, tmp_path: Path) -> None:
        data = codecs.BOM_UTF8 + SIMPLE_TF.read_bytes()
        result = detect_and_parse(_write_bytes(tmp_path, "main.tf", data))
        assert len(result.resources) == 2

    def test_utf8_bom_plan_json(self, tmp_path: Path) -> None:
        data = codecs.BOM_UTF8 + SIMPLE_PLAN.read_bytes()
        result = detect_and_parse(_write_bytes(tmp_path, "plan.json", data))
        assert result.format_type == "terraform_plan"
        assert result.resources

    @pytest.mark.parametrize(
        ("bom", "codec"),
        [
            (codecs.BOM_UTF16_LE, "utf-16-le"),
            (codecs.BOM_UTF16_BE, "utf-16-be"),
            (codecs.BOM_UTF32_LE, "utf-32-le"),
        ],
    )
    def test_wide_encoded_plan_json(self, tmp_path: Path, bom: bytes, codec: str) -> None:
        text = SIMPLE_PLAN.read_text(encoding="utf-8")
        result = detect_and_parse(_write_bytes(tmp_path, "plan.json", bom + text.encode(codec)))
        assert result.format_type == "terraform_plan"
        assert result.resources

    def test_powershell_style_utf16_plan(self, tmp_path: Path) -> None:
        text = SIMPLE_PLAN.read_text(encoding="utf-8")
        result = detect_and_parse(_write_bytes(tmp_path, "plan.json", text.encode("utf-16")))
        assert result.format_type == "terraform_plan"

    def test_utf8_bom_kubernetes_yaml(self, tmp_path: Path) -> None:
        data = codecs.BOM_UTF8 + K8S_DEPLOYMENT.read_bytes()
        result = detect_and_parse(_write_bytes(tmp_path, "deploy.yaml", data))
        assert result.format_type == "kubernetes"

    def test_utf8_bom_dockerfile(self, tmp_path: Path) -> None:
        data = codecs.BOM_UTF8 + b"FROM alpine:3.19\nUSER app\n"
        result = detect_and_parse(_write_bytes(tmp_path, "Dockerfile", data))
        assert "dockerfile_from" in {r.resource_type for r in result.resources}

    def test_utf8_bom_mcp_config(self, tmp_path: Path) -> None:
        data = codecs.BOM_UTF8 + MCP_FIXED.read_bytes()
        result = detect_and_parse(_write_bytes(tmp_path, ".mcp.json", data))
        assert result.format_type == "mcp_config"
        assert result.resources

    @pytest.mark.parametrize(
        ("bom", "codec"),
        [(codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")],
    )
    def test_utf16_mcp_config(self, tmp_path: Path, bom: bytes, codec: str) -> None:
        text = MCP_FIXED.read_text(encoding="utf-8")
        result = detect_and_parse(_write_bytes(tmp_path, ".mcp.json", bom + text.encode(codec)))
        assert result.format_type == "mcp_config"
        assert result.resources


class TestCaseInsensitiveSuffixes:
    def test_upper_case_terraform(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "MAIN.TF", SIMPLE_TF.read_text(encoding="utf-8"))
        assert len(detect_and_parse(path).resources) == 2

    def test_upper_case_plan_json(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "PLAN.JSON", SIMPLE_PLAN.read_text(encoding="utf-8"))
        assert detect_and_parse(path).format_type == "terraform_plan"

    @pytest.mark.parametrize("name", ["STACK.YAML", "Stack.Yml", "stack.TEMPLATE"])
    def test_upper_case_cloudformation(self, tmp_path: Path, name: str) -> None:
        result = detect_and_parse(_write(tmp_path, name, RESOURCES_ONLY))
        assert result.format_type == "cloudformation"

    def test_upper_case_kubernetes(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "DEPLOY.YML", K8S_DEPLOYMENT.read_text(encoding="utf-8"))
        assert detect_and_parse(path).format_type == "kubernetes"

    def test_upper_case_tf_json(self, tmp_path: Path) -> None:
        text = (SHAPES / "cdk.tf.json").read_text(encoding="utf-8")
        path = _write(tmp_path, "CDK.TF.JSON", text)
        assert len(detect_and_parse(path).resources) == 2


class TestLooksLikeInfrastructure:
    """The start of an unparseable file says whether it was meant to be infrastructure (TUX-04)."""

    PLAN_HEAD = '{"format_version": "1.2", "terraform_version": "1.9.0", "planned_values": {"root'
    CFN_JSON_HEAD = '{"AWSTemplateFormatVersion": "2010-09-09", "Resources": {"B": {"Type": "AW'
    CFN_NO_VERSION_JSON = '{"Resources": {"B": {"Type": "AWS::S3::Bucket", "Properties": {'
    K8S_JSON_HEAD = '{"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"na'

    @pytest.mark.parametrize(
        ("name", "text"),
        [
            ("plan.json", PLAN_HEAD),
            ("show.json", PLAN_HEAD),
            ("t.json", CFN_JSON_HEAD),
            ("t.json", CFN_NO_VERSION_JSON),
            ("d.json", K8S_JSON_HEAD),
            ("t.yaml", "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B: [\n"),
            ("t.yaml", "Description: x\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    x: [\n"),
            ("t.yml", "---\napiVersion: v1\nkind: Pod\nmetadata:\n  name: [\n"),
            ("t.template", "\ufeffAWSTemplateFormatVersion: x\nbad: [\n"),
        ],
    )
    def test_a_prefix_that_reads_like_infrastructure_is_claimed(
        self, tmp_path: Path, name: str, text: str
    ) -> None:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        assert looks_like_infrastructure(path)

    @pytest.mark.parametrize(
        ("name", "text"),
        [
            ("tsconfig.json", '{"compilerOptions": {"target": "es5"}'),
            ("package.json", '{"name": "x", "version": "1.0.0", "scripts": {'),
            ("plan.json", '{"tier": "pro", "seats": 5'),
            ("ci.yml", "stages: [build\n"),
            ("x.json", '{"format_version": "1"'),
            ("x.json", '{"apiVersion": "v1"'),
            ("x.yaml", "apiVersion: v1\nname: not a manifest\n"),
            ("x.yaml", "kind: Thing\n"),
            ("x.yaml", "Resources:\n  - one\n  - two: [\n"),
        ],
    )
    def test_other_files_are_not(self, tmp_path: Path, name: str, text: str) -> None:
        path = tmp_path / name
        path.write_text(text, encoding="utf-8")
        assert not looks_like_infrastructure(path)

    def test_a_template_for_another_tool_is_not_claimed(self, tmp_path: Path) -> None:
        for text in (
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Values.name }}\n",
            "apiVersion: v1\nkind: ConfigMap\n{% if x %}\ndata: {}\n{% endif %}\n",
        ):
            path = tmp_path / "t.yaml"
            path.write_text(text, encoding="utf-8")
            assert not looks_like_infrastructure(path)

    def test_a_missing_or_binary_file_is_not_claimed(self, tmp_path: Path) -> None:
        assert not looks_like_infrastructure(tmp_path / "absent.json")
        blob = tmp_path / "blob.json"
        blob.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01" * 100)
        assert not looks_like_infrastructure(blob)

    def test_only_the_start_of_a_huge_file_is_read_and_the_check_stays_linear(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "hostile.json"
        path.write_text('{"Resources": ' + '"apiVersion": ' * 20000 + '"kind"', encoding="utf-8")
        assert looks_like_infrastructure(path) is False
        late = tmp_path / "late.yaml"
        late.write_text("x: 1\n" * 40000 + "apiVersion: v1\nkind: Pod\n", encoding="utf-8")
        assert not looks_like_infrastructure(late)


class TestTheLoadedTextIsPassedOn:
    """A parser that finds its line numbers in the text gets the text the registry decoded."""

    @staticmethod
    def count_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
        from threatcode.parsers import cloudformation, kubernetes
        from threatcode.parsers._text import decode_input

        reads: list[str] = []

        def counting(path: Path, **kwargs: bool) -> str:
            reads.append(path.name)
            return decode_input(path, **kwargs)

        for module in (cloudformation, kubernetes):
            monkeypatch.setattr(module, "decode_input", counting)
        monkeypatch.setattr("threatcode.parsers.decode_input", counting)
        return reads

    def test_a_cloudformation_template_is_read_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "stack.yaml"
        path.write_text(RESOURCES_ONLY, encoding="utf-8")
        reads = self.count_reads(monkeypatch)
        result = detect_and_parse(path)
        assert reads == ["stack.yaml"]
        assert result.resources[0].start_line == 2

    def test_a_json_cloudformation_template_is_read_once_and_keeps_its_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "stack.json"
        path.write_text(
            '{\n  "Resources": {\n    "B": {\n      "Type": "AWS::S3::Bucket"\n    }\n  }\n}\n',
            encoding="utf-8",
        )
        reads = self.count_reads(monkeypatch)
        result = detect_and_parse(path)
        assert reads == ["stack.json"]
        assert (result.resources[0].start_line, result.resources[0].end_line) == (3, 5)

    def test_a_kubernetes_manifest_is_read_once_and_keeps_its_lines(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "pod.yaml"
        path.write_text(
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\n---\n"
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: b\n",
            encoding="utf-8",
        )
        reads = self.count_reads(monkeypatch)
        result = detect_and_parse(path)
        assert reads == ["pod.yaml"]
        assert [r.start_line for r in result.resources] == [1, 6]

    def test_a_kubernetes_json_list_is_read_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        path = tmp_path / "pod.json"
        path.write_text(
            '{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "a"}}\n', encoding="utf-8"
        )
        reads = self.count_reads(monkeypatch)
        result = detect_and_parse(path)
        assert reads == ["pod.json"]
        assert result.resources[0].start_line == 1

    def test_a_parser_that_does_not_take_text_still_gets_what_it_did(self) -> None:
        from threatcode.parsers import _takes_text
        from threatcode.parsers.cloudformation import CloudFormationParser
        from threatcode.parsers.dockerfile import DockerfileParser
        from threatcode.parsers.kubernetes import KubernetesParser

        assert _takes_text(CloudFormationParser)
        assert _takes_text(KubernetesParser)
        assert not _takes_text(DockerfileParser)
