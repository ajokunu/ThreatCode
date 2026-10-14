"""AWS resource categories and trust zones.

`CATEGORIES` and `ZONES` are prefix tables: a type matches the longest entry it starts with, and an
exact entry therefore beats a shorter prefix.
A type without a `ZONES` entry gets the default zone of its category (see `threatcode.ir.catalog`),
so the data stores, secret stores and monitoring services below need no zone entry of their own.

Network helpers that sit under a data store prefix (a DB subnet group, a parameter group) are exact
entries: they are NETWORK and PRIVATE whatever the data store they configure is.
"""

from __future__ import annotations

from typing import Any

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    # Compute
    "aws_instance": NodeCategory.COMPUTE,
    "aws_spot_instance_request": NodeCategory.COMPUTE,
    "aws_launch_template": NodeCategory.COMPUTE,
    "aws_launch_configuration": NodeCategory.COMPUTE,
    "aws_autoscaling": NodeCategory.COMPUTE,
    "aws_sagemaker": NodeCategory.COMPUTE,
    "aws_glue": NodeCategory.COMPUTE,
    # Containers
    "aws_ecs": NodeCategory.CONTAINER,
    "aws_eks": NodeCategory.CONTAINER,
    "aws_ecr": NodeCategory.CONTAINER,
    # Serverless
    "aws_lambda": NodeCategory.SERVERLESS,
    "aws_sfn": NodeCategory.SERVERLESS,
    # Managed API front doors
    "aws_api_gateway": NodeCategory.API,
    "aws_apigatewayv2": NodeCategory.API,
    "aws_lambda_function_url": NodeCategory.API,
    # Object, block and file storage
    "aws_s3": NodeCategory.STORAGE,
    "aws_ebs": NodeCategory.STORAGE,
    "aws_efs": NodeCategory.STORAGE,
    "aws_fsx": NodeCategory.STORAGE,
    "aws_volume_attachment": NodeCategory.STORAGE,
    "aws_backup_vault": NodeCategory.STORAGE,
    # Databases, caches, search and streams that hold data
    "aws_dynamodb": NodeCategory.DATABASE,
    "aws_rds": NodeCategory.DATABASE,
    "aws_db": NodeCategory.DATABASE,
    "aws_elasticache": NodeCategory.DATABASE,
    "aws_redshift": NodeCategory.DATABASE,
    "aws_docdb": NodeCategory.DATABASE,
    "aws_neptune": NodeCategory.DATABASE,
    "aws_memorydb": NodeCategory.DATABASE,
    "aws_dax": NodeCategory.DATABASE,
    "aws_qldb": NodeCategory.DATABASE,
    "aws_keyspaces": NodeCategory.DATABASE,
    "aws_timestreamwrite": NodeCategory.DATABASE,
    "aws_opensearch": NodeCategory.DATABASE,
    "aws_elasticsearch": NodeCategory.DATABASE,
    "aws_msk": NodeCategory.DATABASE,
    "aws_kinesis": NodeCategory.DATABASE,
    "aws_glue_catalog": NodeCategory.DATABASE,
    # Secret and key material
    "aws_kms": NodeCategory.SECRET,
    "aws_secretsmanager": NodeCategory.SECRET,
    "aws_ssm_parameter": NodeCategory.SECRET,
    "aws_acm_certificate": NodeCategory.SECRET,
    "aws_api_gateway_api_key": NodeCategory.SECRET,
    # Networks
    "aws_vpc": NodeCategory.NETWORK,
    "aws_subnet": NodeCategory.NETWORK,
    "aws_security_group": NodeCategory.NETWORK,
    "aws_default_security_group": NodeCategory.NETWORK,
    "aws_network_acl": NodeCategory.NETWORK,
    "aws_default_network_acl": NodeCategory.NETWORK,
    "aws_network_interface": NodeCategory.NETWORK,
    "aws_lb": NodeCategory.NETWORK,
    "aws_alb": NodeCategory.NETWORK,
    "aws_nlb": NodeCategory.NETWORK,
    "aws_elb": NodeCategory.NETWORK,
    "aws_route": NodeCategory.NETWORK,
    "aws_main_route_table_association": NodeCategory.NETWORK,
    "aws_internet_gateway": NodeCategory.NETWORK,
    "aws_egress_only_internet_gateway": NodeCategory.NETWORK,
    "aws_nat_gateway": NodeCategory.NETWORK,
    "aws_eip": NodeCategory.NETWORK,
    "aws_vpn": NodeCategory.NETWORK,
    "aws_customer_gateway": NodeCategory.NETWORK,
    "aws_ec2_transit_gateway": NodeCategory.NETWORK,
    "aws_dx": NodeCategory.NETWORK,
    "aws_wafv2": NodeCategory.NETWORK,
    "aws_waf": NodeCategory.NETWORK,
    # Network helpers under a data store prefix: exact entries beat the data store prefix
    "aws_db_subnet_group": NodeCategory.NETWORK,
    "aws_db_parameter_group": NodeCategory.NETWORK,
    "aws_db_option_group": NodeCategory.NETWORK,
    "aws_db_security_group": NodeCategory.NETWORK,
    "aws_rds_cluster_parameter_group": NodeCategory.NETWORK,
    "aws_elasticache_subnet_group": NodeCategory.NETWORK,
    "aws_elasticache_parameter_group": NodeCategory.NETWORK,
    "aws_redshift_subnet_group": NodeCategory.NETWORK,
    "aws_redshift_parameter_group": NodeCategory.NETWORK,
    "aws_docdb_subnet_group": NodeCategory.NETWORK,
    "aws_docdb_cluster_parameter_group": NodeCategory.NETWORK,
    "aws_neptune_subnet_group": NodeCategory.NETWORK,
    "aws_neptune_parameter_group": NodeCategory.NETWORK,
    "aws_neptune_cluster_parameter_group": NodeCategory.NETWORK,
    "aws_memorydb_subnet_group": NodeCategory.NETWORK,
    "aws_memorydb_parameter_group": NodeCategory.NETWORK,
    "aws_dax_subnet_group": NodeCategory.NETWORK,
    "aws_dax_parameter_group": NodeCategory.NETWORK,
    # Identity
    "aws_iam": NodeCategory.IAM,
    "aws_cognito": NodeCategory.IAM,
    # Edge, DNS and messaging
    "aws_cloudfront": NodeCategory.CDN,
    "aws_route53": NodeCategory.DNS,
    "aws_sns": NodeCategory.MESSAGING,
    "aws_sqs": NodeCategory.MESSAGING,
    "aws_mq": NodeCategory.MESSAGING,
    "aws_ses": NodeCategory.MESSAGING,
    # Monitoring, auditing and posture services
    "aws_cloudwatch": NodeCategory.MONITORING,
    "aws_cloudtrail": NodeCategory.MONITORING,
    "aws_config": NodeCategory.MONITORING,
    "aws_guardduty": NodeCategory.MONITORING,
    "aws_securityhub": NodeCategory.MONITORING,
    "aws_accessanalyzer": NodeCategory.MONITORING,
    "aws_macie2": NodeCategory.MONITORING,
    "aws_inspector2": NodeCategory.MONITORING,
    "aws_flow_log": NodeCategory.MONITORING,
    # Systems Manager is operations tooling; its parameters are the SECRET entry above
    "aws_ssm": NodeCategory.MONITORING,
}

ZONES: dict[str, TrustZone] = {
    "aws_internet_gateway": TrustZone.INTERNET,
    # Internet facing by design; zone_override moves an internal load balancer or a private API
    "aws_cloudfront": TrustZone.DMZ,
    "aws_lb": TrustZone.DMZ,
    "aws_alb": TrustZone.DMZ,
    "aws_nlb": TrustZone.DMZ,
    "aws_elb": TrustZone.DMZ,
    "aws_nat_gateway": TrustZone.DMZ,
    "aws_wafv2": TrustZone.DMZ,
    "aws_waf": TrustZone.DMZ,
    "aws_cognito": TrustZone.DMZ,
    "aws_api_gateway": TrustZone.DMZ,
    "aws_apigatewayv2": TrustZone.DMZ,
    "aws_api_gateway_api_key": TrustZone.DATA,
    # Workloads
    "aws_lambda": TrustZone.PRIVATE,
    "aws_ecs": TrustZone.PRIVATE,
    "aws_instance": TrustZone.PRIVATE,
    # Data stores keep their entries; the rest are DATA through their category
    "aws_rds": TrustZone.DATA,
    "aws_dynamodb": TrustZone.DATA,
    "aws_s3": TrustZone.DATA,
    "aws_elasticache": TrustZone.DATA,
    "aws_iam": TrustZone.MANAGEMENT,
    "aws_cloudwatch": TrustZone.MANAGEMENT,
    # Helpers of a data store are plain network configuration
    "aws_db_subnet_group": TrustZone.PRIVATE,
    "aws_db_parameter_group": TrustZone.PRIVATE,
    "aws_db_option_group": TrustZone.PRIVATE,
    "aws_db_security_group": TrustZone.PRIVATE,
    "aws_rds_cluster_parameter_group": TrustZone.PRIVATE,
    "aws_elasticache_subnet_group": TrustZone.PRIVATE,
    "aws_elasticache_parameter_group": TrustZone.PRIVATE,
    "aws_redshift_subnet_group": TrustZone.PRIVATE,
    "aws_redshift_parameter_group": TrustZone.PRIVATE,
    "aws_docdb_subnet_group": TrustZone.PRIVATE,
    "aws_docdb_cluster_parameter_group": TrustZone.PRIVATE,
    "aws_neptune_subnet_group": TrustZone.PRIVATE,
    "aws_neptune_parameter_group": TrustZone.PRIVATE,
    "aws_neptune_cluster_parameter_group": TrustZone.PRIVATE,
    "aws_memorydb_subnet_group": TrustZone.PRIVATE,
    "aws_memorydb_parameter_group": TrustZone.PRIVATE,
    "aws_dax_subnet_group": TrustZone.PRIVATE,
    "aws_dax_parameter_group": TrustZone.PRIVATE,
}

_LOAD_BALANCER_TYPES = frozenset({"aws_lb", "aws_alb", "aws_nlb", "aws_elb"})


def _is_true(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _contains(value: Any, wanted: str) -> bool:
    """Whether a string or a (nested) list of strings holds `wanted`, ignoring case."""
    if isinstance(value, str):
        return value.strip().upper() == wanted
    if isinstance(value, (list, tuple)):
        return any(_contains(item, wanted) for item in value)
    return False


def _endpoint_types(properties: dict[str, Any]) -> Any:
    """The `types` of an API Gateway `endpoint_configuration` block, in any spelling."""
    config = properties.get("endpoint_configuration")
    items = config if isinstance(config, list) else [config]
    found: list[Any] = []
    for item in items:
        if isinstance(item, dict) and "types" in item:
            found.append(item["types"])
    return found


def zone_override(resource_type: str, properties: dict[str, Any]) -> TrustZone | None:
    """The zone a property decides, else None.

    A load balancer with `internal` true is private, and any other keeps the DMZ of its type.
    An `internal` that is not known keeps the type default as well, because an unresolved value
    never selects a zone.
    An API Gateway REST API whose only endpoint type is PRIVATE is private.
    A Lambda function URL that requires no authorization faces the internet, and one that requires
    IAM does not.
    """
    if resource_type in _LOAD_BALANCER_TYPES and _is_true(properties.get("internal")):
        return TrustZone.PRIVATE
    if resource_type == "aws_api_gateway_rest_api":
        types = _endpoint_types(properties)
        if (
            types
            and _contains(types, "PRIVATE")
            and not _contains(types, "EDGE")
            and not _contains(types, "REGIONAL")
        ):
            return TrustZone.PRIVATE
    if resource_type == "aws_lambda_function_url":
        auth = properties.get("authorization_type")
        if isinstance(auth, str) and auth.strip().upper() == "NONE":
            return TrustZone.DMZ
    return None
