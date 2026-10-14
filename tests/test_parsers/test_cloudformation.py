"""Tests for the CloudFormation parser: types, properties, references, lines and diagnostics."""

from __future__ import annotations

import datetime
import importlib.util
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from threatcode.exceptions import ParseError
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import NodeCategory, categorize_resource
from threatcode.parsers import detect_and_parse
from threatcode.parsers._cfn_types import (
    CFN_TO_TERRAFORM,
    UNSUPPORTED_IN_CFN,
    cfn_types_for,
    provider_of,
    resolve_type,
    terraform_types,
)
from threatcode.parsers.base import ParsedOutput
from threatcode.parsers.cloudformation import CloudFormationParser
from threatcode.values import is_unknown

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
CFN = FIXTURES_DIR / "cloudformation"
SHAPES = FIXTURES_DIR / "real_shapes" / "cloudformation"
SCRIPT = Path(__file__).parent.parent.parent / "scripts" / "gen_cfn_type_coverage.py"

# The types the parser mapped before the explicit table, and what it named them
ORIGINAL_MAPPING = {
    "AWS::S3::Bucket": "aws_s3_bucket",
    "AWS::EC2::Instance": "aws_instance",
    "AWS::EC2::SecurityGroup": "aws_security_group",
    "AWS::EC2::VPC": "aws_vpc",
    "AWS::EC2::Subnet": "aws_subnet",
    "AWS::EC2::InternetGateway": "aws_internet_gateway",
    "AWS::RDS::DBInstance": "aws_db_instance",
    "AWS::Lambda::Function": "aws_lambda_function",
    "AWS::IAM::Role": "aws_iam_role",
    "AWS::IAM::Policy": "aws_iam_policy",
    "AWS::IAM::User": "aws_iam_user",
    "AWS::DynamoDB::Table": "aws_dynamodb_table",
    "AWS::SQS::Queue": "aws_sqs_queue",
    "AWS::SNS::Topic": "aws_sns_topic",
    "AWS::ECS::Service": "aws_ecs_service",
    "AWS::ECS::TaskDefinition": "aws_ecs_task_definition",
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
    "AWS::CloudFront::Distribution": "aws_cloudfront_distribution",
}


def parse_text(text: str, name: str = "template.yaml") -> ParsedOutput:
    return CloudFormationParser().parse_text(text, name)


def doc(*lines: str) -> str:
    """Template text from its lines."""
    return "\n".join(lines) + "\n"


def by_name(output: ParsedOutput) -> dict[str, Any]:
    return {r.name: r for r in output.resources}


def codes(output: ParsedOutput) -> list[str]:
    return [d.code for d in output.diagnostics]


class TestCloudFormationParser:
    def test_parse_insecure_stack(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        assert parsed.format_type == "cloudformation"
        assert len(parsed.resources) == 5

    def test_resource_type_conversion(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        types = {r.resource_type for r in parsed.resources}
        assert types == {"aws_s3_bucket", "aws_iam_policy", "aws_db_instance", "aws_iam_role"}

    def test_properties_are_translated_and_the_raw_ones_kept(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        buckets = [r for r in parsed.resources if r.resource_type == "aws_s3_bucket"]
        assert len(buckets) == 2
        public = [b for b in buckets if b.properties.get("acl") == "public-read"]
        assert len(public) == 1
        assert public[0].properties["_cfn"]["AccessControl"] == "public-read"
        assert "AccessControl" not in public[0].properties

    def test_value_attributes_use_the_names_the_rules_read(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        db = by_name(parsed)["PublicDatabase"]
        assert db.properties["publicly_accessible"] is True
        assert db.properties["storage_encrypted"] is False
        assert db.properties["backup_retention_period"] == 0

    def test_dependencies_extracted(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        db = [r for r in parsed.resources if r.resource_type == "aws_db_instance"][0]
        assert "UnencryptedBucket" in db.dependencies

    def test_address_and_name_are_the_logical_id_and_the_provider_is_aws(self) -> None:
        for resource in detect_and_parse(CFN / "insecure_stack.yml").resources:
            assert resource.address == resource.name
            assert resource.provider == "aws"
            assert resource.mode == "managed" and resource.evidence == "config"

    def test_source_location_is_the_file(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        assert {r.source_location for r in parsed.resources} == {
            (CFN / "insecure_stack.yml").as_posix()
        }

    def test_meta_records_the_cloudformation_type(self) -> None:
        parsed = detect_and_parse(CFN / "insecure_stack.yml")
        assert by_name(parsed)["PublicBucket"].meta["cfn_type"] == "AWS::S3::Bucket"

    def test_a_template_with_nothing_to_report_has_no_diagnostics(self) -> None:
        assert detect_and_parse(CFN / "insecure_stack.yml").diagnostics == []


class TestTypeTable:
    def test_the_eighteen_originally_mapped_types_map_identically(self) -> None:
        for cfn_type, terraform in ORIGINAL_MAPPING.items():
            assert resolve_type(cfn_type).resource_type == terraform, cfn_type

    def test_the_types_that_were_guessed_wrongly_now_map_to_the_names_rules_know(self) -> None:
        wrong_before = {
            "AWS::EC2::NatGateway": "aws_nat_gateway",
            "AWS::ElasticLoadBalancingV2::TargetGroup": "aws_lb_target_group",
            "AWS::ElasticLoadBalancingV2::Listener": "aws_lb_listener",
            "AWS::Logs::LogGroup": "aws_cloudwatch_log_group",
            "AWS::CloudTrail::Trail": "aws_cloudtrail",
            "AWS::EC2::EIP": "aws_eip",
            "AWS::EC2::Route": "aws_route",
            "AWS::EC2::RouteTable": "aws_route_table",
            "AWS::EC2::VPCEndpoint": "aws_vpc_endpoint",
            "AWS::IAM::ManagedPolicy": "aws_iam_policy",
            "AWS::RDS::DBCluster": "aws_rds_cluster",
            "AWS::OpenSearchService::Domain": "aws_opensearch_domain",
            "AWS::EKS::Nodegroup": "aws_eks_node_group",
            "AWS::S3::BucketPolicy": "aws_s3_bucket_policy",
            "AWS::StepFunctions::StateMachine": "aws_sfn_state_machine",
        }
        for cfn_type, terraform in wrong_before.items():
            assert resolve_type(cfn_type).resource_type == terraform, cfn_type

    def test_every_type_the_design_lists_is_mapped(self) -> None:
        design = [
            "S3::Bucket", "S3::BucketPolicy", "EC2::Instance", "EC2::SecurityGroup",
            "EC2::SecurityGroupIngress", "EC2::SecurityGroupEgress", "EC2::EIP",
            "EC2::NatGateway", "EC2::InternetGateway", "EC2::VPC", "EC2::Subnet",
            "EC2::RouteTable", "EC2::Route", "EC2::SubnetRouteTableAssociation",
            "EC2::LaunchTemplate", "EC2::Volume", "EC2::VPCEndpoint", "EC2::FlowLog",
            "RDS::DBInstance", "RDS::DBCluster", "RDS::DBSubnetGroup",
            "ElasticLoadBalancingV2::LoadBalancer", "ElasticLoadBalancingV2::Listener",
            "ElasticLoadBalancingV2::TargetGroup", "Logs::LogGroup", "CloudTrail::Trail",
            "IAM::Role", "IAM::Policy", "IAM::ManagedPolicy", "IAM::User", "IAM::InstanceProfile",
            "KMS::Key", "SecretsManager::Secret", "SecretsManager::RotationSchedule",
            "SNS::Topic", "SNS::Subscription", "SNS::TopicPolicy", "SQS::Queue", "SQS::QueuePolicy",
            "Lambda::Function", "Lambda::Permission", "Lambda::Url", "ApiGateway::RestApi",
            "ApiGateway::Method", "ApiGatewayV2::Api", "ApiGatewayV2::Route", "DynamoDB::Table",
            "ElastiCache::ReplicationGroup", "ElastiCache::CacheCluster",
            "OpenSearchService::Domain", "Elasticsearch::Domain", "EKS::Cluster", "EKS::Nodegroup",
            "ECS::Cluster", "ECS::TaskDefinition", "ECS::Service", "ECR::Repository",
            "CloudFront::Distribution", "WAFv2::WebACL", "WAFv2::LoggingConfiguration",
            "GuardDuty::Detector", "Config::ConfigurationRecorder", "Config::DeliveryChannel",
            "SSM::Parameter", "Redshift::Cluster", "SageMaker::NotebookInstance",
            "Kinesis::Stream", "Cognito::UserPool", "AutoScaling::AutoScalingGroup",
        ]  # fmt: skip
        missing = [t for t in design if f"AWS::{t}" not in CFN_TO_TERRAFORM]
        assert not missing

    def test_the_table_is_well_formed(self) -> None:
        for cfn_type, terraform in CFN_TO_TERRAFORM.items():
            parts = cfn_type.split("::")
            assert len(parts) == 3 and parts[0] == "AWS", cfn_type
            assert terraform.startswith("aws_") and terraform == terraform.lower(), terraform

    def test_distinct_cloudformation_types_share_a_terraform_type_only_on_purpose(self) -> None:
        shared = {tf: cfn_types_for(tf) for tf in terraform_types() if len(cfn_types_for(tf)) > 1}
        assert shared == {
            "aws_security_group_rule": [
                "AWS::EC2::SecurityGroupEgress",
                "AWS::EC2::SecurityGroupIngress",
            ],
            "aws_iam_policy": ["AWS::IAM::ManagedPolicy", "AWS::IAM::Policy"],
        }

    def test_an_unmapped_type_keeps_its_cloudformation_name(self) -> None:
        resolved = resolve_type("AWS::Foo::Bar")
        assert (resolved.resource_type, resolved.provider, resolved.mapped) == (
            "AWS::Foo::Bar",
            "aws",
            False,
        )

    @pytest.mark.parametrize(
        ("cfn_type", "provider"),
        [
            ("AWS::S3::Bucket", "aws"),
            ("Custom::Thing", "custom"),
            ("AWS::CloudFormation::CustomResource", "custom"),
            ("Datadog::Monitors::Monitor", "datadog"),
            ("Alexa::ASK::Skill", "alexa"),
        ],
    )
    def test_providers(self, cfn_type: str, provider: str) -> None:
        assert provider_of(cfn_type) == provider
        assert resolve_type(cfn_type).provider == provider

    def test_a_vpn_gateway_attachment_is_not_an_internet_gateway_attachment(self) -> None:
        internet = resolve_type("AWS::EC2::VPCGatewayAttachment", {"InternetGatewayId": "i"})
        vpn = resolve_type("AWS::EC2::VPCGatewayAttachment", {"VpnGatewayId": "v"})
        both = resolve_type(
            "AWS::EC2::VPCGatewayAttachment", {"VpnGatewayId": "v", "InternetGatewayId": "i"}
        )
        assert internet.resource_type == "aws_internet_gateway_attachment"
        assert vpn.resource_type == "aws_vpn_gateway_attachment"
        assert both.resource_type == "aws_internet_gateway_attachment"
        assert "AWS::EC2::VPCGatewayAttachment" in cfn_types_for("aws_vpn_gateway_attachment")

    def test_the_table_is_read_only(self) -> None:
        with pytest.raises(TypeError):
            CFN_TO_TERRAFORM["AWS::Foo::Bar"] = "aws_foo"  # type: ignore[index]
        with pytest.raises(TypeError):
            UNSUPPORTED_IN_CFN["aws_foo"] = "x"  # type: ignore[index]

    @pytest.mark.parametrize(
        "cfn_type",
        [
            "AWS::S3::Bucket",
            "AWS::EC2::Instance",
            "AWS::EC2::VPC",
            "AWS::EC2::Subnet",
            "AWS::EC2::SecurityGroup",
            "AWS::RDS::DBInstance",
            "AWS::DynamoDB::Table",
            "AWS::Lambda::Function",
            "AWS::IAM::Role",
            "AWS::SQS::Queue",
            "AWS::SNS::Topic",
            "AWS::ElasticLoadBalancingV2::LoadBalancer",
            "AWS::CloudFront::Distribution",
            "AWS::ECS::Service",
            "AWS::ElastiCache::ReplicationGroup",
            "AWS::EC2::NatGateway",
            "AWS::EC2::InternetGateway",
        ],
    )
    def test_the_core_types_get_a_category_from_the_catalog(self, cfn_type: str) -> None:
        category = categorize_resource(resolve_type(cfn_type).resource_type)
        assert category is not NodeCategory.UNKNOWN

    def test_the_coverage_script_finds_no_gap(self) -> None:
        spec = importlib.util.spec_from_file_location("gen_cfn_type_coverage", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules["gen_cfn_type_coverage"] = module
        spec.loader.exec_module(module)
        assert module.check() == []
        assert module.main(["--check"]) == 0

    def test_every_unsupported_type_is_in_use_and_unmapped(self) -> None:
        assert set(UNSUPPORTED_IN_CFN) == {
            "aws_config_configuration_recorder_status",
            "aws_default_security_group",
            "aws_iam_group_policy",
            "aws_iam_group_policy_attachment",
            "aws_iam_policy_attachment",
            "aws_iam_role_policy",
            "aws_iam_role_policy_attachment",
            "aws_iam_user_policy",
            "aws_iam_user_policy_attachment",
            "aws_rds_cluster_instance",
            "aws_s3_account_public_access_block",
            "aws_s3_bucket_public_access_block",
        }
        assert not set(UNSUPPORTED_IN_CFN) & terraform_types()
        assert all(reason.strip() for reason in UNSUPPORTED_IN_CFN.values())


class TestValidation:
    def test_type_as_a_mapping_is_skipped_with_a_diagnostic(self) -> None:
        output = parse_text(
            "Resources:\n"
            "  Mod:\n"
            "    Type:\n"
            "      Source: ./module.yaml\n"
            "  Bucket:\n"
            "    Type: AWS::S3::Bucket\n"
        )
        assert [r.name for r in output.resources] == ["Bucket"]
        skipped = [d for d in output.diagnostics if d.code == "cfn.skipped_resource"]
        assert len(skipped) == 1
        assert skipped[0].level == "warning"
        assert "Mod" in skipped[0].message and "Type must be a string" in skipped[0].message
        assert skipped[0].line == 2
        assert "Rain" not in skipped[0].message
        assert "incomplete" not in output.metadata

    def test_a_rain_module_says_what_it_is_and_what_to_run(self) -> None:
        output = parse_text(
            "Resources:\n"
            "  Storage:\n"
            "    Type: !Rain::Module ../../RainModules/bucket.yml\n"
            "    Properties:\n"
            "      Name: data\n"
            "  Bucket:\n"
            "    Type: AWS::S3::Bucket\n"
        )
        assert [r.name for r in output.resources] == ["Bucket"]
        (skipped,) = [d for d in output.diagnostics if d.code == "cfn.skipped_resource"]
        assert skipped.level == "warning"
        assert skipped.line == 2
        assert skipped.message == (
            "Resource 'Storage' was skipped: Rain module not expanded "
            "(Type is !Rain::Module ../../RainModules/bucket.yml; run rain pkg to expand it), "
            "so the resources it creates are not analysed"
        )
        assert "Type must be a string" not in skipped.message
        assert "dict" not in skipped.message

    def test_a_rain_module_makes_the_template_incomplete(self) -> None:
        output = parse_text(
            "Resources:\n  M:\n    Type: !Rain::Module ./m.yaml\n  B:\n    Type: AWS::S3::Bucket\n"
        )
        assert output.metadata["incomplete"] is True

    def test_a_template_without_a_rain_module_is_not_marked_incomplete(self) -> None:
        output = parse_text("Resources:\n  B:\n    Type: AWS::S3::Bucket\n")
        assert "incomplete" not in output.metadata

    def test_a_non_mapping_entry_is_skipped_not_dropped_silently(self) -> None:
        output = parse_text(
            "Resources:\n  Loop:\n    - one\n  Text: hello\n  Bucket:\n    Type: AWS::S3::Bucket\n"
        )
        skipped = [d for d in output.diagnostics if d.code == "cfn.skipped_resource"]
        assert len(skipped) == 2
        assert {r.name for r in output.resources} == {"Bucket"}

    def test_a_missing_or_blank_type_is_skipped(self) -> None:
        output = parse_text(
            "Resources:\n  NoType:\n    Properties: {}\n  Blank:\n    Type: ' '\n"
            "  Bucket:\n    Type: AWS::S3::Bucket\n"
        )
        assert len([d for d in output.diagnostics if d.code == "cfn.skipped_resource"]) == 2

    def test_properties_that_are_not_a_mapping_are_skipped(self) -> None:
        output = parse_text(
            "Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties: [1, 2]\n"
            "  B:\n    Type: AWS::S3::Bucket\n"
        )
        assert [r.name for r in output.resources] == ["B"]
        message = next(d.message for d in output.diagnostics if d.code == "cfn.skipped_resource")
        assert "Properties must be a mapping" in message

    def test_null_properties_are_an_empty_mapping(self) -> None:
        output = parse_text("Resources:\n  A:\n    Type: AWS::S3::Bucket\n    Properties:\n")
        assert output.resources[0].properties == {"_cfn": {}}
        assert output.diagnostics == []

    def test_resources_as_a_list_is_an_error_that_says_so(self) -> None:
        with pytest.raises(ParseError, match="Resources must be a mapping.*not a list"):
            parse_text("Resources:\n  - Type: AWS::S3::Bucket\n")

    @pytest.mark.parametrize(
        "body", ["Description: x\nResources: {}\n", "Description: x\nResources:\n"]
    )
    def test_an_empty_or_missing_resources_block_is_an_error(self, body: str) -> None:
        with pytest.raises(ParseError, match="no Resources block"):
            parse_text(body)

    def test_a_template_that_is_not_a_mapping_is_an_error(self) -> None:
        with pytest.raises(ParseError, match="must be an object"):
            CloudFormationParser().parse(["a"])
        with pytest.raises(ParseError, match="must be an object"):
            CloudFormationParser().parse("text")

    def test_when_every_entry_is_skipped_the_template_reports_zero_resources(self) -> None:
        output = parse_text("Resources:\n  A: text\n  B: [1]\n")
        assert output.resources == []
        zero = [d for d in output.diagnostics if d.code == "parse.zero_resources"]
        assert len(zero) == 1 and zero[0].level == "warning"
        assert "2 resource entries" in zero[0].message

    def test_a_template_that_is_not_one_document_is_an_error(self) -> None:
        with pytest.raises(ParseError, match="2 YAML documents"):
            parse_text(
                doc(
                    "Resources:",
                    "  A:",
                    "    Type: AWS::S3::Bucket",
                    "---",
                    "Resources:",
                    "  B:",
                    "    Type: AWS::S3::Bucket",
                )
            )

    def test_invalid_json_is_an_error(self) -> None:
        with pytest.raises(ParseError, match="Invalid JSON"):
            parse_text('{"Resources": ', "bad.json")


class TestDiagnostics:
    def test_an_unmapped_type_is_reported_once_with_its_resources(self) -> None:
        text = (
            "Resources:\n"
            "  A:\n    Type: AWS::Foo::Bar\n"
            "  B:\n    Type: AWS::Foo::Bar\n"
            "  C:\n    Type: AWS::Baz::Qux\n"
            "  Bucket:\n    Type: AWS::S3::Bucket\n"
        )
        output = parse_text(text)
        unmapped = [d for d in output.diagnostics if d.code == "cfn.unmapped_type"]
        assert len(unmapped) == 2
        assert all(d.level == "info" for d in unmapped)
        foo = next(d for d in unmapped if "AWS::Foo::Bar" in d.message)
        assert "2 resources: A, B" in foo.message
        assert {r.resource_type for r in output.resources} == {
            "AWS::Foo::Bar",
            "AWS::Baz::Qux",
            "aws_s3_bucket",
        }

    def test_a_custom_resource_has_provider_custom_and_is_reported_as_unmapped(self) -> None:
        output = parse_text(
            "Resources:\n  X:\n    Type: Custom::Thing\n    Properties:\n      Key: v\n"
        )
        resource = output.resources[0]
        assert (resource.resource_type, resource.provider) == ("Custom::Thing", "custom")
        assert resource.properties["Key"] == "v"
        assert codes(output) == ["cfn.unmapped_type"]

    def test_a_nested_stack_keeps_a_node_and_a_warning(self) -> None:
        output = detect_and_parse(SHAPES / "nested_parent.yaml")
        network = by_name(output)["Network"]
        assert network.resource_type == "aws_cloudformation_stack"
        nested = [d for d in output.diagnostics if d.code == "cfn.nested_stack"]
        assert len(nested) == 1 and nested[0].level == "warning"
        assert "Network" in nested[0].message and "nested_child.yaml" in nested[0].message
        assert nested[0].line == network.start_line
        assert output.metadata["incomplete"] is True

    def test_unresolved_intrinsics_are_counted_in_one_diagnostic(self) -> None:
        output = detect_and_parse(SHAPES / "web_stack.yaml")
        found = [d for d in output.diagnostics if d.code == "cfn.unresolved_intrinsic"]
        assert len(found) == 1 and found[0].level == "info"
        count = output.metadata["unresolved_intrinsics"]
        assert count > 20 and str(count) in found[0].message

    def test_a_template_with_no_unresolved_intrinsics_says_nothing_about_them(self) -> None:
        output = parse_text(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: b\n"
        )
        assert "unresolved_intrinsics" not in output.metadata
        assert output.diagnostics == []

    def test_a_template_macro_is_reported(self) -> None:
        text = "Transform: AWS::Include\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"
        output = parse_text(text)
        message = next(
            d.message for d in output.diagnostics if d.code == "cfn.unresolved_intrinsic"
        )
        assert "AWS::Include" in message and "not expanded" in message
        assert output.metadata["transform"] == ["AWS::Include"]

    def test_the_sam_transform_is_not_reported_as_a_macro(self) -> None:
        text = (
            "Transform: AWS::Serverless-2016-10-31\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"
        )
        assert parse_text(text).diagnostics == []

    def test_a_transform_list_with_sam_and_a_macro_reports_only_the_macro(self) -> None:
        text = (
            "Transform: [AWS::Serverless-2016-10-31, AWS::LanguageExtensions]\n"
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
        )
        message = next(d.message for d in parse_text(text).diagnostics)
        assert "AWS::LanguageExtensions" in message and "Serverless" not in message

    def test_diagnostics_carry_the_file_and_the_resource_line(self) -> None:
        output = detect_and_parse(CFN / "sam_function.yaml")
        note = next(d for d in output.diagnostics if d.code == "cfn.sam_policy_template")
        assert note.file == (CFN / "sam_function.yaml").as_posix() and note.line == 27


class TestHeadersAndDates:
    def test_an_unquoted_format_version_date_is_stored_as_text(self, tmp_path: Path) -> None:
        path = tmp_path / "t.yaml"
        path.write_text(
            doc(
                "AWSTemplateFormatVersion: 2010-09-09",
                "Description: d",
                "Resources:",
                "  B:",
                "    Type: AWS::S3::Bucket",
            ),
            encoding="utf-8",
        )
        output = detect_and_parse(path)
        assert output.metadata["template_version"] == "2010-09-09"
        json.dumps(output.metadata)

    def test_a_date_handed_in_by_another_loader_is_stored_as_text(self) -> None:
        template = {
            "AWSTemplateFormatVersion": datetime.date(2010, 9, 9),
            "Description": "d",
            "Resources": {
                "P": {
                    "Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {
                        "PolicyDocument": {
                            "Version": datetime.date(2012, 10, 17),
                            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
                        }
                    },
                }
            },
        }
        output = CloudFormationParser().parse(template)
        assert output.metadata["template_version"] == "2010-09-09"
        translated = {k: v for k, v in output.resources[0].properties.items() if k != "_cfn"}
        assert '"Version":"2012-10-17"' in translated["policy"]
        json.dumps(output.metadata)
        json.dumps(translated)

    def test_the_description_and_version_default_to_empty_text(self) -> None:
        output = parse_text("Resources:\n  B:\n    Type: AWS::S3::Bucket\n")
        assert output.metadata["template_version"] == "" and output.metadata["description"] == ""

    def test_a_description_that_is_not_text_is_empty(self) -> None:
        output = CloudFormationParser().parse(
            {"Description": ["a"], "Resources": {"B": {"Type": "AWS::S3::Bucket"}}}
        )
        assert output.metadata["description"] == ""


class TestInputForms:
    def test_a_resources_only_template_is_read(self) -> None:
        output = detect_and_parse(CFN / "minimal.yaml")
        assert [(r.name, r.resource_type) for r in output.resources] == [
            ("Bucket", "aws_s3_bucket")
        ]

    def test_a_template_extension_with_yaml_and_with_json(self, tmp_path: Path) -> None:
        yaml_path = tmp_path / "stack.template"
        yaml_path.write_text((CFN / "minimal.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        json_path = tmp_path / "stack.cfn"
        json_path.write_text(
            json.dumps({"Resources": {"B": {"Type": "AWS::S3::Bucket"}}}), encoding="utf-8"
        )
        for path in (yaml_path, json_path):
            assert detect_and_parse(path).format_type == "cloudformation"

    def test_a_sam_template_without_a_format_version_is_read(self) -> None:
        output = detect_and_parse(CFN / "sam_function.yaml")
        assert output.format_type == "cloudformation"
        assert "AdminFunction" in by_name(output)

    def test_parse_text_reads_yaml_with_short_form_tags_and_json(self) -> None:
        yaml_text = doc(
            "Resources:",
            "  B:",
            "    Type: AWS::S3::Bucket",
            "    Properties:",
            "      BucketName: !Ref Name",
        )
        json_text = json.dumps(
            {
                "Resources": {
                    "B": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": {"Ref": "Name"}}}
                }
            }
        )
        short, long = parse_text(yaml_text), parse_text(json_text, "t.json")
        assert short.resources[0].properties["bucket"].reference == "Name"
        assert long.resources[0].properties["bucket"].reference == "Name"

    def test_parse_file(self) -> None:
        output = CloudFormationParser().parse_file(CFN / "minimal.yaml")
        assert output.source_path == (CFN / "minimal.yaml").as_posix()

    def test_a_json_template_is_read_like_its_yaml_twin(self) -> None:
        yaml_output = detect_and_parse(CFN / "graph_stack.yml")
        json_output = detect_and_parse(CFN / "graph_stack.json")
        signature = lambda o: [  # noqa: E731
            (r.name, r.resource_type, sorted(r.references), r.dependencies) for r in o.resources
        ]
        assert signature(yaml_output) == signature(json_output)


class TestImportsAndMeta:
    TEXT = (
        "Parameters:\n  Env:\n    Type: String\n    Default: prod\n"
        "Conditions:\n  IsProd: !Equals [!Ref Env, prod]\n  IsDev: !Equals [!Ref Env, dev]\n"
        "Resources:\n"
        "  Bucket:\n"
        "    Type: AWS::S3::Bucket\n"
        "    Condition: IsProd\n"
        "    DeletionPolicy: Retain\n"
        "    UpdateReplacePolicy: Delete\n"
        "    Properties:\n"
        "      BucketName: !ImportValue shared-bucket-name\n"
        "  Dev:\n"
        "    Type: AWS::SQS::Queue\n"
        "    Condition: IsDev\n"
        "  Other:\n"
        "    Type: AWS::SQS::Queue\n"
        "    Condition: Mystery\n"
    )

    def test_import_values_are_recorded_and_make_no_reference(self) -> None:
        output = parse_text(self.TEXT)
        bucket = by_name(output)["Bucket"]
        assert bucket.meta["import_values"] == ["shared-bucket-name"]
        assert bucket.references == {} and bucket.dependencies == []
        assert output.metadata["imports"] == ["shared-bucket-name"]

    def test_the_condition_and_whether_it_holds_are_recorded(self) -> None:
        resources = by_name(parse_text(self.TEXT))
        assert resources["Bucket"].meta["condition"] == "IsProd"
        assert resources["Bucket"].meta["condition_holds"] is True
        assert resources["Dev"].meta["condition_holds"] is False
        assert resources["Other"].meta["condition_holds"] is None

    def test_a_resource_whose_condition_is_false_is_still_modelled(self) -> None:
        assert "Dev" in by_name(parse_text(self.TEXT))

    def test_deletion_policies_are_recorded(self) -> None:
        meta = by_name(parse_text(self.TEXT))["Bucket"].meta
        assert (meta["deletion_policy"], meta["update_replace_policy"]) == ("Retain", "Delete")

    def test_depends_on_accepts_a_string_a_list_and_ignores_junk(self) -> None:
        text = (
            "Resources:\n"
            "  A:\n    Type: AWS::S3::Bucket\n"
            "  B:\n    Type: AWS::S3::Bucket\n    DependsOn: A\n"
            "  C:\n    Type: AWS::S3::Bucket\n    DependsOn: [A, B, 7]\n"
            "  D:\n    Type: AWS::S3::Bucket\n    DependsOn: {x: 1}\n"
        )
        resources = by_name(parse_text(text))
        assert resources["B"].dependencies == ["A"]
        assert resources["C"].dependencies == ["A", "B"]
        assert resources["D"].dependencies == []


class TestReferences:
    def test_references_are_keyed_by_the_attribute_a_rule_reads(self) -> None:
        output = detect_and_parse(SHAPES / "web_stack.yaml")
        resources = by_name(output)
        assert resources["PublicSubnet"].references["vpc_id"] == ["Vpc"]
        assert resources["AppInstance"].references["subnet_id"] == ["PrivateSubnet"]
        assert resources["AppInstance"].references["vpc_security_group_ids"] == ["AppSecurityGroup"]
        assert resources["AppInstance"].references["iam_instance_profile"] == ["AppInstanceProfile"]
        assert resources["AppInstanceProfile"].references["role"] == ["AppRole"]
        assert resources["Database"].references["db_subnet_group_name"] == ["DbSubnetGroup"]
        assert resources["Database"].references["vpc_security_group_ids"] == [
            "DatabaseSecurityGroup"
        ]
        assert resources["LoadBalancer"].references["subnets"] == ["PublicSubnet", "PrivateSubnetB"]
        assert resources["DbSubnetGroup"].references["subnet_ids"] == [
            "PrivateSubnet",
            "PrivateSubnetB",
        ]

    def test_a_reference_inside_a_block_list_is_keyed_with_the_list_marker(self) -> None:
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        assert resources["AppSecurityGroup"].references["ingress[].security_groups"] == [
            "LoadBalancerSecurityGroup"
        ]
        assert resources["DatabaseSecurityGroup"].references["ingress[].security_groups"] == [
            "AppSecurityGroup"
        ]

    def test_a_reference_in_a_policy_document_is_keyed_by_the_policy(self) -> None:
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        assert resources["AppRole"].references["inline_policy[].policy"] == ["UploadsBucket"]

    def test_sub_variables_count_as_references(self) -> None:
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        assert "UploadsBucket" in resources["AppRole"].dependencies

    def test_parameters_pseudo_parameters_and_unknown_names_are_not_references(self) -> None:
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        assert resources["Vpc"].references == {} and resources["Vpc"].dependencies == []
        names = {n for r in resources.values() for n in r.dependencies}
        assert not names & {"Environment", "VpcCidr", "AppInstanceType", "DbPassword"}

    def test_dependencies_list_depends_on_first_then_references_without_repeats(self) -> None:
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        route = resources["PublicRoute"]
        assert route.dependencies[0] == "GatewayAttachment"
        assert len(route.dependencies) == len(set(route.dependencies))

    def test_a_target_a_typed_edge_covers_is_not_also_a_dependency(self) -> None:
        # vpc_id becomes a containment edge to the VPC; a second plain dependency edge between
        # the same pair would double every boundary threat on it
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        assert "Vpc" not in resources["PrivateSubnet"].dependencies
        assert resources["PrivateSubnet"].references["vpc_id"] == ["Vpc"]

    def test_a_target_the_typed_rule_rejects_stays_a_dependency(self) -> None:
        # subnet_id only attaches to subnets; a nested stack that supplies the id has no typed edge
        resources = by_name(detect_and_parse(SHAPES / "nested_parent.yaml"))
        instance = resources["AppInstance"]
        assert instance.references["subnet_id"] == ["Network"]
        assert instance.dependencies == ["Network"]

    def test_an_attribute_the_graph_does_not_type_stays_a_dependency(self) -> None:
        resources = by_name(detect_and_parse(SHAPES / "web_stack.yaml"))
        assert resources["Listener"].dependencies == ["LoadBalancer", "TargetGroup"]

    def test_the_graph_draws_typed_and_untyped_edges(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(CFN / "graph_stack.yml"))
        edges = {(e.source, e.target, e.edge_type.value) for e in graph.edges}
        assert ("PublicSubnet", "Vpc", "containment") in edges
        assert ("WebInstance", "PublicSubnet", "containment") in edges
        assert ("WebInstance", "WebSecurityGroup", "dependency") in edges
        assert ("ApiFunction", "ApiRole", "iam_binding") in edges
        assert ("ApiFunction", "PrivateSubnet", "containment") in edges
        assert ("Database", "DatabaseSubnets", "dependency") in edges
        assert ("DatabaseSecurityGroup", "WebSecurityGroup", "dependency") in edges
        assert ("Distribution", "LoadBalancer", "dependency") in edges
        assert ("ApiFunction", "OrdersTable", "dependency") in edges
        assert ("ApiRole", "OrdersTable", "dependency") in edges

    def test_the_long_and_short_forms_draw_the_same_graph(self) -> None:
        def edges(path: Path) -> set[tuple[str, str, str]]:
            graph = InfraGraph.from_parsed(detect_and_parse(path))
            return {(e.source, e.target, e.edge_type.value) for e in graph.edges}

        assert edges(CFN / "graph_stack.yml") == edges(CFN / "graph_stack.json")
        assert edges(SHAPES / "web_stack.yaml") == edges(SHAPES / "web_stack.json")

    def test_a_reference_to_an_id_that_is_not_modelled_adds_no_edge(self) -> None:
        text = doc(
            "Resources:",
            "  A:",
            "    Type: AWS::EC2::Subnet",
            "    Properties:",
            "      VpcId: !Ref Missing",
        )
        graph = InfraGraph.from_parsed(parse_text(text))
        assert graph.edges == []

    def test_the_cycle_a_b_a_does_not_hang_or_fail(self) -> None:
        text = (
            "Resources:\n"
            "  A:\n    Type: AWS::SQS::Queue\n    Properties:\n      QueueName: !Ref B\n"
            "  B:\n    Type: AWS::SQS::Queue\n    Properties:\n      QueueName: !Ref A\n"
        )
        graph = InfraGraph.from_parsed(parse_text(text))
        assert {(e.source, e.target) for e in graph.edges} == {("A", "B"), ("B", "A")}


class TestLines:
    def test_yaml_resources_have_their_first_and_last_line(self) -> None:
        output = detect_and_parse(CFN / "minimal.yaml")
        bucket = output.resources[0]
        assert (bucket.start_line, bucket.end_line) == (2, 5)

    def test_a_resource_ends_before_the_blank_line_and_comment_that_precede_the_next(self) -> None:
        text = (
            "Resources:\n"           # 1
            "  A:\n"                 # 2
            "    Type: AWS::S3::Bucket\n"  # 3
            "    Properties:\n"      # 4
            "      BucketName: a\n"  # 5
            "\n"                     # 6
            "  # the second bucket\n"  # 7
            "  B:\n"                 # 8
            "    Type: AWS::S3::Bucket\n"  # 9
            "\n"                     # 10
            "Outputs:\n"             # 11
            "  X:\n"                 # 12
            "    Value: v\n"         # 13
        )  # fmt: skip
        resources = by_name(parse_text(text))
        assert (resources["A"].start_line, resources["A"].end_line) == (2, 5)
        assert (resources["B"].start_line, resources["B"].end_line) == (8, 9)

    def test_the_last_resource_of_a_file_ends_on_its_last_line(self) -> None:
        text = doc(
            "Resources:",
            "  A:",
            "    Type: AWS::S3::Bucket",
            "  B:",
            "    Type: AWS::S3::Bucket",
            "    Properties:",
            "      BucketName: b",
        )
        assert by_name(parse_text(text))["B"].end_line == 7

    def test_short_form_tags_do_not_disturb_the_lines(self) -> None:
        output = detect_and_parse(SHAPES / "web_stack.yaml")
        vpc = by_name(output)["Vpc"]
        text = (SHAPES / "web_stack.yaml").read_text(encoding="utf-8").splitlines()
        assert text[vpc.start_line - 1].strip() == "Vpc:"
        assert text[vpc.end_line - 1].strip() != ""

    def test_json_resources_have_the_line_of_their_key_and_their_closing_bracket(self) -> None:
        output = detect_and_parse(SHAPES / "web_stack.json")
        text = (SHAPES / "web_stack.json").read_text(encoding="utf-8").splitlines()
        for resource in output.resources:
            assert resource.start_line is not None and resource.end_line is not None
            assert text[resource.start_line - 1].lstrip().startswith(f'"{resource.name}"')
            assert text[resource.end_line - 1].strip() in ("}", "},")
            assert resource.end_line >= resource.start_line

    def test_a_one_line_json_template_still_has_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "t.json"
        path.write_text(
            '{"Resources":{"A":{"Type":"AWS::S3::Bucket"},"B":{"Type":"AWS::SQS::Queue"}}}',
            encoding="utf-8",
        )
        assert [(r.start_line, r.end_line) for r in detect_and_parse(path).resources] == [
            (1, 1),
            (1, 1),
        ]

    def test_generated_resources_use_their_origins_lines(self) -> None:
        output = detect_and_parse(CFN / "sam_function.yaml")
        resources = by_name(output)
        assert resources["AdminFunctionRole"].start_line == resources["AdminFunction"].start_line
        assert resources["AdminFunctionRole"].end_line == resources["AdminFunction"].end_line

    def test_a_template_parsed_from_a_dict_has_no_lines(self) -> None:
        output = CloudFormationParser().parse({"Resources": {"A": {"Type": "AWS::S3::Bucket"}}})
        assert (output.resources[0].start_line, output.resources[0].end_line) == (None, None)

    def test_a_source_path_that_does_not_exist_gives_no_lines_and_no_error(self) -> None:
        output = CloudFormationParser().parse(
            {"Resources": {"A": {"Type": "AWS::S3::Bucket"}}}, "/no/such/template.yaml"
        )
        assert output.resources[0].start_line is None

    def test_lines_flow_to_the_graph_nodes(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(CFN / "minimal.yaml"))
        node = graph.nodes["Bucket"]
        assert (node.start_line, node.end_line) == (2, 5)
        assert node.source_file.endswith("minimal.yaml")


class TestHostileTemplates:
    def test_an_alias_bomb_in_the_properties_is_refused_quickly(self, tmp_path: Path) -> None:
        lines = [
            "Resources:",
            "  B:",
            "    Type: AWS::SSM::Parameter",
            "    Properties:",
            "      Value:",
        ]
        lines.append("        l0: &l0 [" + ",".join(['"lol"'] * 9) + "]")
        for level in range(1, 10):
            lines.append(f"        l{level}: &l{level} [" + ",".join([f"*l{level - 1}"] * 9) + "]")
        path = tmp_path / "bomb.yaml"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        started = time.monotonic()
        with pytest.raises(ParseError, match="aliases are expanded"):
            detect_and_parse(path)
        assert time.monotonic() - started < 30

    def test_an_anchor_that_contains_itself_does_not_hang(self, tmp_path: Path) -> None:
        path = tmp_path / "loop.yaml"
        path.write_text(
            "Resources:\n  B:\n    Type: AWS::SSM::Parameter\n    Properties:\n"
            "      Value: &a\n        - *a\n        - x\n",
            encoding="utf-8",
        )
        output = detect_and_parse(path)
        assert output.resources[0].name == "B"

    def test_a_long_chain_of_conditions_is_not_a_crash(self) -> None:
        conditions = {f"C{i}": {"Condition": f"C{i + 1}"} for i in range(500)}
        template = {
            "Conditions": conditions,
            "Resources": {
                "P": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Value": {"Fn::If": ["C0", "a", "b"]}},
                }
            },
        }
        output = CloudFormationParser().parse(template)
        assert is_unknown(output.resources[0].properties["value"])

    def test_many_resources_parse(self) -> None:
        resources = {
            f"Bucket{i}": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": f"b{i}"}}
            for i in range(2_000)
        }
        output = CloudFormationParser().parse({"Resources": resources})
        assert len(output.resources) == 2_000


class TestLanguageExtensions:
    def test_a_for_each_loop_is_reported_not_silently_dropped(self) -> None:
        text = doc(
            "Transform: AWS::LanguageExtensions",
            "Resources:",
            "  Fn::ForEach::Queues:",
            "    - Name",
            "    - [A, B]",
            "    - 'Queue${Name}':",
            "        Type: AWS::SQS::Queue",
            "  Bucket:",
            "    Type: AWS::S3::Bucket",
        )
        output = parse_text(text)
        assert [r.name for r in output.resources] == ["Bucket"]
        skipped = [d for d in output.diagnostics if d.code == "cfn.skipped_resource"]
        assert len(skipped) == 1
        assert "Fn::ForEach" in skipped[0].message and "not expanded" in skipped[0].message


hypothesis = pytest.importorskip("hypothesis")

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

_INTRINSICS = [
    "Ref",
    "Fn::GetAtt",
    "Fn::Sub",
    "Fn::Join",
    "Fn::If",
    "Fn::Select",
    "Fn::Split",
    "Fn::FindInMap",
    "Fn::Base64",
    "Fn::ImportValue",
    "Fn::Equals",
    "Fn::Not",
    "Condition",
]
_leaves = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(10**6), max_value=10**6),
    st.floats(allow_nan=False, allow_infinity=False),
    st.text(max_size=12),
    st.sampled_from(["true", "false", "0", "AWS::NoValue", "Bucket", "Other", "${Bucket.Arn}"]),
)
_values = st.recursive(
    _leaves,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(st.text(max_size=8), children, max_size=4),
        st.builds(lambda key, arg: {key: arg}, st.sampled_from(_INTRINSICS), children),
    ),
    max_leaves=14,
)
_TYPES = [
    "AWS::S3::Bucket",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Instance",
    "AWS::IAM::Role",
    "AWS::Lambda::Function",
    "AWS::ECS::TaskDefinition",
    "AWS::ElasticLoadBalancingV2::LoadBalancer",
    "AWS::CloudFront::Distribution",
    "AWS::DynamoDB::Table",
    "AWS::Serverless::Function",
    "AWS::Foo::Bar",
    "Custom::Thing",
]


class TestPropertyBased:
    @settings(max_examples=150, derandomize=True, deadline=None)
    @given(
        cfn_type=st.sampled_from(_TYPES),
        properties=st.dictionaries(st.text(max_size=10), _values, max_size=6),
        extra=st.dictionaries(st.text(max_size=6), _values, max_size=3),
    )
    def test_arbitrary_properties_never_crash_and_always_serialize(
        self, cfn_type: str, properties: dict[str, Any], extra: dict[str, Any]
    ) -> None:
        template = {
            "Parameters": {"P": {"Type": "String", "Default": "x"}},
            "Conditions": extra,
            "Resources": {
                "Subject": {"Type": cfn_type, "Properties": properties},
                "Bucket": {"Type": "AWS::S3::Bucket"},
                "Other": {"Type": "AWS::SQS::Queue", "DependsOn": ["Bucket", 3]},
            },
        }
        output = CloudFormationParser().parse(template)
        names = {r.name for r in output.resources}
        assert {"Subject", "Bucket", "Other"} <= names
        for resource in output.resources:
            translated = {k: v for k, v in resource.properties.items() if k != "_cfn"}
            json.dumps(translated)
            assert set(resource.dependencies) <= names
            for targets in resource.references.values():
                assert set(targets) <= names
        InfraGraph.from_parsed(output)
