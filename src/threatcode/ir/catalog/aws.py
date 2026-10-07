"""AWS resource categories and trust zones."""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "aws_instance": NodeCategory.COMPUTE,
    "aws_launch_template": NodeCategory.COMPUTE,
    "aws_autoscaling_group": NodeCategory.COMPUTE,
    "aws_ecs": NodeCategory.CONTAINER,
    "aws_eks": NodeCategory.CONTAINER,
    "aws_lambda": NodeCategory.SERVERLESS,
    "aws_s3": NodeCategory.STORAGE,
    "aws_ebs": NodeCategory.STORAGE,
    "aws_dynamodb": NodeCategory.DATABASE,
    "aws_rds": NodeCategory.DATABASE,
    "aws_db": NodeCategory.DATABASE,
    "aws_elasticache": NodeCategory.DATABASE,
    "aws_vpc": NodeCategory.NETWORK,
    "aws_subnet": NodeCategory.NETWORK,
    "aws_security_group": NodeCategory.NETWORK,
    "aws_lb": NodeCategory.NETWORK,
    "aws_alb": NodeCategory.NETWORK,
    "aws_nlb": NodeCategory.NETWORK,
    "aws_route": NodeCategory.NETWORK,
    "aws_internet_gateway": NodeCategory.NETWORK,
    "aws_nat_gateway": NodeCategory.NETWORK,
    "aws_eip": NodeCategory.NETWORK,
    "aws_iam": NodeCategory.IAM,
    "aws_cloudfront": NodeCategory.CDN,
    "aws_route53": NodeCategory.DNS,
    "aws_cloudwatch": NodeCategory.MONITORING,
    "aws_sns": NodeCategory.MESSAGING,
    "aws_sqs": NodeCategory.MESSAGING,
}

ZONES: dict[str, TrustZone] = {
    "aws_internet_gateway": TrustZone.INTERNET,
    "aws_cloudfront": TrustZone.DMZ,
    "aws_lb": TrustZone.DMZ,
    "aws_alb": TrustZone.DMZ,
    "aws_nlb": TrustZone.DMZ,
    "aws_lambda": TrustZone.PRIVATE,
    "aws_ecs": TrustZone.PRIVATE,
    "aws_instance": TrustZone.PRIVATE,
    "aws_rds": TrustZone.DATA,
    "aws_dynamodb": TrustZone.DATA,
    "aws_s3": TrustZone.DATA,
    "aws_elasticache": TrustZone.DATA,
    "aws_iam": TrustZone.MANAGEMENT,
    "aws_cloudwatch": TrustZone.MANAGEMENT,
}
