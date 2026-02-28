"""AWS CloudFormation template parser."""

from __future__ import annotations

from typing import Any

from threatcode.exceptions import ParseError
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource


class CloudFormationParser(BaseParser):
    """Parse CloudFormation YAML/JSON templates."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if not isinstance(data, dict):
            raise ParseError("CloudFormation template must be an object")

        resources_block = data.get("Resources", {})
        if not resources_block:
            raise ParseError("CloudFormation template has no Resources block")

        resources: list[ParsedResource] = []
        for logical_id, definition in resources_block.items():
            if not isinstance(definition, dict):
                continue

            cfn_type = definition.get("Type", "")
            properties = definition.get("Properties", {}) or {}
            depends_on = definition.get("DependsOn", [])
            if isinstance(depends_on, str):
                depends_on = [depends_on]

            resources.append(
                ParsedResource(
                    resource_type=_cfn_to_terraform_type(cfn_type),
                    address=logical_id,
                    name=logical_id,
                    provider="aws",
                    properties=properties,
                    dependencies=depends_on,
                    source_location=source_path,
                )
            )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="cloudformation",
            metadata={
                "template_version": data.get("AWSTemplateFormatVersion", ""),
                "description": data.get("Description", ""),
            },
        )


def _cfn_to_terraform_type(cfn_type: str) -> str:
    """Convert CFN resource type to approximate Terraform type for rule matching.

    AWS::S3::Bucket -> aws_s3_bucket
    AWS::EC2::Instance -> aws_instance
    """
    if not cfn_type.startswith("AWS::"):
        return cfn_type.lower().replace("::", "_")

    parts = cfn_type.split("::")
    if len(parts) < 3:
        return cfn_type.lower().replace("::", "_")

    service = parts[1].lower()
    resource = parts[2]

    # Special mappings
    known: dict[str, str] = {
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

    if cfn_type in known:
        return known[cfn_type]

    # Generic conversion
    resource_snake = _camel_to_snake(resource)
    return f"aws_{service}_{resource_snake}"


def _camel_to_snake(name: str) -> str:
    import re

    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()
