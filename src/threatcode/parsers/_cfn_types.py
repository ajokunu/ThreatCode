"""The CloudFormation resource type table.

The rules, the category table and the trust zone table are written for Terraform resource
type names (`aws_s3_bucket`), so the CloudFormation parser names every resource after the
Terraform type that models the same service object.
The mapping is an explicit table: a type that is not in it keeps its CloudFormation name
(`AWS::Foo::Bar`) instead of a Terraform-looking guess that no rule or catalog entry
would ever match, and the parser reports it with a `cfn.unmapped_type` diagnostic.

`UNSUPPORTED_IN_CFN` lists the Terraform types that the built-in rules name and that
CloudFormation cannot express at all, each with the reason.
`scripts/gen_cfn_type_coverage.py --check` fails when a built-in rule resource type is
neither reachable from a CloudFormation type nor listed there.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

# CloudFormation type -> Terraform type. Grouped by service, in the order of the AWS docs.
_CFN_TO_TERRAFORM: dict[str, str] = {
    # S3
    "AWS::S3::Bucket": "aws_s3_bucket",
    "AWS::S3::BucketPolicy": "aws_s3_bucket_policy",
    "AWS::S3::AccessPoint": "aws_s3_access_point",
    # EC2 and VPC
    "AWS::EC2::Instance": "aws_instance",
    "AWS::EC2::SecurityGroup": "aws_security_group",
    "AWS::EC2::SecurityGroupIngress": "aws_security_group_rule",
    "AWS::EC2::SecurityGroupEgress": "aws_security_group_rule",
    "AWS::EC2::EIP": "aws_eip",
    "AWS::EC2::EIPAssociation": "aws_eip_association",
    "AWS::EC2::NatGateway": "aws_nat_gateway",
    "AWS::EC2::InternetGateway": "aws_internet_gateway",
    "AWS::EC2::VPCGatewayAttachment": "aws_internet_gateway_attachment",
    "AWS::EC2::VPC": "aws_vpc",
    "AWS::EC2::Subnet": "aws_subnet",
    "AWS::EC2::RouteTable": "aws_route_table",
    "AWS::EC2::Route": "aws_route",
    "AWS::EC2::SubnetRouteTableAssociation": "aws_route_table_association",
    "AWS::EC2::LaunchTemplate": "aws_launch_template",
    "AWS::EC2::Volume": "aws_ebs_volume",
    "AWS::EC2::VolumeAttachment": "aws_volume_attachment",
    "AWS::EC2::VPCEndpoint": "aws_vpc_endpoint",
    "AWS::EC2::FlowLog": "aws_flow_log",
    "AWS::EC2::NetworkAcl": "aws_network_acl",
    "AWS::EC2::NetworkAclEntry": "aws_network_acl_rule",
    "AWS::EC2::SubnetNetworkAclAssociation": "aws_network_acl_association",
    "AWS::EC2::NetworkInterface": "aws_network_interface",
    "AWS::EC2::KeyPair": "aws_key_pair",
    "AWS::EC2::VPNGateway": "aws_vpn_gateway",
    "AWS::EC2::VPNConnection": "aws_vpn_connection",
    "AWS::EC2::CustomerGateway": "aws_customer_gateway",
    "AWS::EC2::TransitGateway": "aws_ec2_transit_gateway",
    # RDS
    "AWS::RDS::DBInstance": "aws_db_instance",
    "AWS::RDS::DBCluster": "aws_rds_cluster",
    "AWS::RDS::DBSubnetGroup": "aws_db_subnet_group",
    "AWS::RDS::DBParameterGroup": "aws_db_parameter_group",
    "AWS::RDS::DBClusterParameterGroup": "aws_rds_cluster_parameter_group",
    "AWS::RDS::OptionGroup": "aws_db_option_group",
    "AWS::RDS::DBProxy": "aws_db_proxy",
    # Load balancing
    "AWS::ElasticLoadBalancingV2::LoadBalancer": "aws_lb",
    "AWS::ElasticLoadBalancingV2::Listener": "aws_lb_listener",
    "AWS::ElasticLoadBalancingV2::ListenerRule": "aws_lb_listener_rule",
    "AWS::ElasticLoadBalancingV2::TargetGroup": "aws_lb_target_group",
    "AWS::ElasticLoadBalancing::LoadBalancer": "aws_elb",
    # Logging and monitoring
    "AWS::Logs::LogGroup": "aws_cloudwatch_log_group",
    "AWS::Logs::MetricFilter": "aws_cloudwatch_log_metric_filter",
    "AWS::Logs::SubscriptionFilter": "aws_cloudwatch_log_subscription_filter",
    "AWS::CloudWatch::Alarm": "aws_cloudwatch_metric_alarm",
    "AWS::Events::Rule": "aws_cloudwatch_event_rule",
    "AWS::CloudTrail::Trail": "aws_cloudtrail",
    "AWS::Config::ConfigurationRecorder": "aws_config_configuration_recorder",
    "AWS::Config::DeliveryChannel": "aws_config_delivery_channel",
    "AWS::Config::ConfigurationAggregator": "aws_config_configuration_aggregator",
    "AWS::Config::ConfigRule": "aws_config_config_rule",
    "AWS::GuardDuty::Detector": "aws_guardduty_detector",
    # Identity
    "AWS::IAM::Role": "aws_iam_role",
    "AWS::IAM::Policy": "aws_iam_policy",
    "AWS::IAM::ManagedPolicy": "aws_iam_policy",
    "AWS::IAM::User": "aws_iam_user",
    "AWS::IAM::Group": "aws_iam_group",
    "AWS::IAM::InstanceProfile": "aws_iam_instance_profile",
    "AWS::IAM::AccessKey": "aws_iam_access_key",
    "AWS::IAM::UserToGroupAddition": "aws_iam_user_group_membership",
    "AWS::IAM::OIDCProvider": "aws_iam_openid_connect_provider",
    "AWS::IAM::SAMLProvider": "aws_iam_saml_provider",
    "AWS::Cognito::UserPool": "aws_cognito_user_pool",
    "AWS::Cognito::UserPoolClient": "aws_cognito_user_pool_client",
    "AWS::Cognito::IdentityPool": "aws_cognito_identity_pool",
    # Keys and secrets
    "AWS::KMS::Key": "aws_kms_key",
    "AWS::KMS::Alias": "aws_kms_alias",
    "AWS::SecretsManager::Secret": "aws_secretsmanager_secret",
    "AWS::SecretsManager::RotationSchedule": "aws_secretsmanager_secret_rotation",
    "AWS::SecretsManager::ResourcePolicy": "aws_secretsmanager_secret_policy",
    "AWS::SSM::Parameter": "aws_ssm_parameter",
    "AWS::ACM::Certificate": "aws_acm_certificate",
    # Messaging
    "AWS::SNS::Topic": "aws_sns_topic",
    "AWS::SNS::Subscription": "aws_sns_topic_subscription",
    "AWS::SNS::TopicPolicy": "aws_sns_topic_policy",
    "AWS::SQS::Queue": "aws_sqs_queue",
    "AWS::SQS::QueuePolicy": "aws_sqs_queue_policy",
    "AWS::Kinesis::Stream": "aws_kinesis_stream",
    "AWS::KinesisFirehose::DeliveryStream": "aws_kinesis_firehose_delivery_stream",
    "AWS::MSK::Cluster": "aws_msk_cluster",
    # Compute and containers
    "AWS::Lambda::Function": "aws_lambda_function",
    "AWS::Lambda::Permission": "aws_lambda_permission",
    "AWS::Lambda::Url": "aws_lambda_function_url",
    "AWS::Lambda::EventSourceMapping": "aws_lambda_event_source_mapping",
    "AWS::Lambda::LayerVersion": "aws_lambda_layer_version",
    "AWS::Lambda::Alias": "aws_lambda_alias",
    "AWS::Lambda::EventInvokeConfig": "aws_lambda_function_event_invoke_config",
    "AWS::AutoScaling::AutoScalingGroup": "aws_autoscaling_group",
    "AWS::AutoScaling::LaunchConfiguration": "aws_launch_configuration",
    "AWS::AutoScaling::ScalingPolicy": "aws_autoscaling_policy",
    "AWS::ECS::Cluster": "aws_ecs_cluster",
    "AWS::ECS::TaskDefinition": "aws_ecs_task_definition",
    "AWS::ECS::Service": "aws_ecs_service",
    "AWS::ECR::Repository": "aws_ecr_repository",
    "AWS::EKS::Cluster": "aws_eks_cluster",
    "AWS::EKS::Nodegroup": "aws_eks_node_group",
    "AWS::EKS::FargateProfile": "aws_eks_fargate_profile",
    "AWS::EKS::Addon": "aws_eks_addon",
    "AWS::StepFunctions::StateMachine": "aws_sfn_state_machine",
    "AWS::SageMaker::NotebookInstance": "aws_sagemaker_notebook_instance",
    # APIs and edge
    "AWS::ApiGateway::RestApi": "aws_api_gateway_rest_api",
    "AWS::ApiGateway::Method": "aws_api_gateway_method",
    "AWS::ApiGateway::Resource": "aws_api_gateway_resource",
    "AWS::ApiGateway::Stage": "aws_api_gateway_stage",
    "AWS::ApiGateway::Deployment": "aws_api_gateway_deployment",
    "AWS::ApiGateway::Authorizer": "aws_api_gateway_authorizer",
    "AWS::ApiGateway::UsagePlan": "aws_api_gateway_usage_plan",
    "AWS::ApiGateway::ApiKey": "aws_api_gateway_api_key",
    "AWS::ApiGateway::DomainName": "aws_api_gateway_domain_name",
    "AWS::ApiGatewayV2::Api": "aws_apigatewayv2_api",
    "AWS::ApiGatewayV2::Route": "aws_apigatewayv2_route",
    "AWS::ApiGatewayV2::Stage": "aws_apigatewayv2_stage",
    "AWS::ApiGatewayV2::Integration": "aws_apigatewayv2_integration",
    "AWS::ApiGatewayV2::Authorizer": "aws_apigatewayv2_authorizer",
    "AWS::CloudFront::Distribution": "aws_cloudfront_distribution",
    "AWS::CloudFront::OriginAccessControl": "aws_cloudfront_origin_access_control",
    "AWS::WAFv2::WebACL": "aws_wafv2_web_acl",
    "AWS::WAFv2::LoggingConfiguration": "aws_wafv2_web_acl_logging_configuration",
    "AWS::WAFv2::RuleGroup": "aws_wafv2_rule_group",
    "AWS::WAFv2::WebACLAssociation": "aws_wafv2_web_acl_association",
    "AWS::WAFv2::IPSet": "aws_wafv2_ip_set",
    "AWS::Route53::HostedZone": "aws_route53_zone",
    "AWS::Route53::RecordSet": "aws_route53_record",
    # Data stores
    "AWS::DynamoDB::Table": "aws_dynamodb_table",
    "AWS::ElastiCache::ReplicationGroup": "aws_elasticache_replication_group",
    "AWS::ElastiCache::CacheCluster": "aws_elasticache_cluster",
    "AWS::ElastiCache::SubnetGroup": "aws_elasticache_subnet_group",
    "AWS::OpenSearchService::Domain": "aws_opensearch_domain",
    "AWS::Elasticsearch::Domain": "aws_elasticsearch_domain",
    "AWS::Redshift::Cluster": "aws_redshift_cluster",
    "AWS::Redshift::ClusterSubnetGroup": "aws_redshift_subnet_group",
    "AWS::EFS::FileSystem": "aws_efs_file_system",
    "AWS::EFS::MountTarget": "aws_efs_mount_target",
    "AWS::DocDB::DBCluster": "aws_docdb_cluster",
    "AWS::DocDB::DBInstance": "aws_docdb_cluster_instance",
    "AWS::Neptune::DBCluster": "aws_neptune_cluster",
    "AWS::Glue::Database": "aws_glue_catalog_database",
    "AWS::Glue::Crawler": "aws_glue_crawler",
    "AWS::Glue::Job": "aws_glue_job",
    # Nesting
    "AWS::CloudFormation::Stack": "aws_cloudformation_stack",
}

CFN_TO_TERRAFORM: Mapping[str, str] = MappingProxyType(_CFN_TO_TERRAFORM)

# A type whose Terraform name depends on one of its properties: CloudFormation type ->
# (property that selects the variant, property that marks the default, variant type).
_VARIANTS: dict[str, tuple[str, str, str]] = {
    "AWS::EC2::VPCGatewayAttachment": (
        "VpnGatewayId",
        "InternetGatewayId",
        "aws_vpn_gateway_attachment",
    ),
}

# Terraform types that built-in rules name and that CloudFormation cannot express.
# The reason is shown in the support matrix.
UNSUPPORTED_IN_CFN: Mapping[str, str] = MappingProxyType(
    {
        "aws_default_security_group": (
            "CloudFormation cannot adopt the default security group of a VPC"
        ),
        "aws_s3_bucket_acl": (
            "CloudFormation sets the ACL through AccessControl on AWS::S3::Bucket, "
            "which becomes the acl attribute of aws_s3_bucket"
        ),
    }
)

_CUSTOM_RESOURCE = "AWS::CloudFormation::CustomResource"


@dataclass(frozen=True)
class ResolvedType:
    """What the parser names a resource of one CloudFormation type."""

    resource_type: str
    provider: str
    # False when the table has no entry, so the resource keeps its CloudFormation name
    mapped: bool


def provider_of(cfn_type: str) -> str:
    """The provider a CloudFormation type belongs to: `aws`, `custom`, or its namespace."""
    namespace = cfn_type.split("::", 1)[0]
    if cfn_type == _CUSTOM_RESOURCE or namespace == "Custom":
        return "custom"
    return namespace.lower() or "aws"


def resolve_type(cfn_type: str, properties: Mapping[str, object] | None = None) -> ResolvedType:
    """Name the Terraform type for a CloudFormation type, or keep the CloudFormation name.

    `properties` are the raw template properties; only the few types whose Terraform name
    depends on a property read them.
    """
    provider = provider_of(cfn_type)
    target = _CFN_TO_TERRAFORM.get(cfn_type)
    if target is None:
        return ResolvedType(cfn_type, provider, mapped=False)
    variant = _VARIANTS.get(cfn_type)
    if variant is not None and properties is not None:
        selector, default, variant_type = variant
        if selector in properties and default not in properties:
            target = variant_type
    return ResolvedType(target, provider, mapped=True)


def terraform_types() -> frozenset[str]:
    """Every Terraform type some CloudFormation type can be named."""
    return frozenset(_CFN_TO_TERRAFORM.values()) | frozenset(
        variant[2] for variant in _VARIANTS.values()
    )


def cfn_types_for(terraform_type: str) -> list[str]:
    """The CloudFormation types that map to a Terraform type, sorted."""
    found = [cfn for cfn, tf in _CFN_TO_TERRAFORM.items() if tf == terraform_type]
    found.extend(cfn for cfn, variant in _VARIANTS.items() if variant[2] == terraform_type)
    return sorted(found)
