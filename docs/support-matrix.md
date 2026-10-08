# Support matrix

What each kind of input supports, which rules evaluate it, and where the limits are.
The tables on this page are generated from the code, and `tests/test_docs.py` scans a fixture for every row, so a row that says an input is evaluated is backed by a scan that produced a finding.

## Inputs

<!-- gen:inputs -->
| Input | Files | Evaluated by | Attack paths | Limits |
| --- | --- | --- | --- | --- |
| Terraform plan JSON | `terraform show -json tfplan` output | AWS, Azure, GCP (188 rules) | AWS | Values known only after apply are unknown and never produce a finding. State JSON and destroy-only plans are rejected with the command that fixes them. |
| Terraform and OpenTofu source | `.tf`, `.tofu`, `.tf.json`, or a directory of them | AWS, Azure, GCP (188 rules) | AWS | A directory is one module. Variables, locals, count, for_each and local modules are followed; remote modules are not analysed and are reported as a coverage gap. python-hcl2 4.3 and 8.x are both supported. |
| CloudFormation and SAM | YAML or JSON templates, `.template`, `.cfn` | AWS (99 rules) | AWS | 142 resource types are mapped to the types the rules read. Nested stacks are not followed, intrinsics that need the deployed stack are unknown, and a transform other than SAM is not expanded. |
| Kubernetes manifests | YAML or JSON, multi-document files, `List` documents, `kubectl get -o yaml` | Kubernetes (39 rules) | Kubernetes | A NetworkPolicy covers a workload only within the same scan input. Kinds without a rule are parsed into a node and not evaluated. |
| Helm charts | a directory with `Chart.yaml` | Kubernetes (39 rules) | Kubernetes | Rendered with the `helm` binary when it is installed, else with a built-in renderer that reports every fallback as a coverage gap. `THREATCODE_HELM=off` forces the built-in renderer and `required` fails without helm. |
| Dockerfiles | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile` | Dockerfile (19 rules) | none (the image is judged where it runs) | Multi-stage builds, heredocs, `ONBUILD` and lowercase instructions are read. The image summary describes the final stage. A Dockerfile is not an attack path entry on its own. |
| MCP client and agent configs | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json`, `~/.claude.json`, `mcp_config.json`, Gemini CLI `settings.json` | MCP (10 rules) | MCP | OpenCode and Zed use other top-level keys and are not read. Servers are never started or contacted. A server that is not in the capability table adds nothing to the agent's capabilities and is reported as `mcp.unknown_capability`. |
<!-- /gen:inputs -->

Anything else is not read.
A directory scan counts files it does not recognize under "not infrastructure" in the coverage block, and a single file that nothing recognizes is an input error and exit 2.
Terraform state JSON (`terraform show -json` without a plan file) and a plan that only destroys resources are rejected with a message that names the right command.
Docker Compose files and Azure ARM or Bicep templates are not supported.
A Kustomize `kustomization.yaml` becomes one node and is not evaluated, because overlays are not built.

## Rules and topology by provider

<!-- gen:providers -->
| Provider | Rules | Resource types with a rule | Topology |
| --- | --- | --- | --- |
| AWS | 99 | 59 | yes: exposure, reachability edges and attack paths |
| Azure | 49 | 24 | no: rule findings only, no topology and no attack paths yet |
| GCP | 40 | 58 | no: rule findings only, no topology and no attack paths yet |
| Kubernetes | 39 | 15 | yes: exposure, reachability edges and attack paths |
| Dockerfile | 19 | 6 | per image: judged where the image runs |
| MCP | 10 | 2 | yes: exposure, reachability edges and attack paths |
<!-- /gen:providers -->

**Attack paths are modeled for AWS, Kubernetes and MCP agent configs.**
Azure and GCP resources are parsed, categorized and checked by rules, so they produce findings with severities and ATT&CK mappings.
They have no exposure analysis and no reachability edges yet, so a scan of an Azure or GCP stack reports no attack path.
That is "not modeled", not "no path exists".

## Terraform

- **Plan JSON** needs `format_version` together with `planned_values` or `resource_changes`.
  Values known only after apply are listed in `after_unknown` and read as unknown, which a rule never treats as "not configured".
  `count`, `for_each` and module instances keep the relationships the configuration states, module inputs and outputs are resolved through any number of levels, and data sources are context nodes that rules do not evaluate.
- **Source** is read with python-hcl2 4.3 to 8.x.
  A directory is one module: variables take their value from `terraform.tfvars` and `*.auto.tfvars`, then their default, then the module call's input; locals, string interpolation, arithmetic, conditionals and a few pure functions are evaluated; `dynamic` blocks over known collections are expanded; and local modules (`./` and `../`) are followed up to 8 levels.
  A registry, git or other remote module is **not** downloaded: it is a coverage gap that names the source, and a root that only calls remote modules cannot scan to a clean pass.
  Scan `terraform show -json` output when you need modules resolved.
- Provider defaults that a plan materialises are filled in for HCL and CloudFormation only (for example an EKS cluster's public endpoint), never for a plan.
  An attribute the provider defaults to a secure value is not reported as missing.

## CloudFormation and SAM

Templates in YAML (including short-form intrinsics like `!Ref` and `!Sub`) or JSON are detected by `AWSTemplateFormatVersion`, by a `Transform`, or by `Resources` whose types start with `AWS::`, `Custom::` or `Alexa::`.
Each resource's PascalCase properties are translated to the names the rules read, `Ref`, `Fn::GetAtt` and `Fn::Sub` become edges, and policy documents become the same JSON text a plan produces, so one rule serves both formats.

`AWS::Serverless-2016-10-31` is expanded: a function gets its implicit role, events add the API, permission and subscription they imply, and `Globals` are merged.
Nested stacks keep a node and are reported as a gap, intrinsics that need the deployed stack (`Fn::ImportValue`, `AWS::Region`, `Fn::GetAtt` of a resource attribute) are unknown, and a transform other than SAM is reported as not expanded.

### CloudFormation type table

The 142<!-- count:cfn_types --> mapped types, and the built-in rules that fire on each:

<!-- gen:cloudformation -->
| CloudFormation type | Modeled as | Rules |
| --- | --- | --- |
| `AWS::ACM::Certificate` | `aws_acm_certificate` | parsed, no rule yet |
| `AWS::ApiGateway::ApiKey` | `aws_api_gateway_api_key` | parsed, no rule yet |
| `AWS::ApiGateway::Authorizer` | `aws_api_gateway_authorizer` | parsed, no rule yet |
| `AWS::ApiGateway::Deployment` | `aws_api_gateway_deployment` | parsed, no rule yet |
| `AWS::ApiGateway::DomainName` | `aws_api_gateway_domain_name` | parsed, no rule yet |
| `AWS::ApiGateway::Method` | `aws_api_gateway_method` | `APIGW_METHOD_NO_AUTH` |
| `AWS::ApiGateway::Resource` | `aws_api_gateway_resource` | parsed, no rule yet |
| `AWS::ApiGateway::RestApi` | `aws_api_gateway_rest_api` | `APIGW_PUBLIC_POLICY` |
| `AWS::ApiGateway::Stage` | `aws_api_gateway_stage` | `APIGW_NO_ACCESS_LOGS` |
| `AWS::ApiGateway::UsagePlan` | `aws_api_gateway_usage_plan` | parsed, no rule yet |
| `AWS::ApiGatewayV2::Api` | `aws_apigatewayv2_api` | parsed, no rule yet |
| `AWS::ApiGatewayV2::Authorizer` | `aws_apigatewayv2_authorizer` | parsed, no rule yet |
| `AWS::ApiGatewayV2::Integration` | `aws_apigatewayv2_integration` | parsed, no rule yet |
| `AWS::ApiGatewayV2::Route` | `aws_apigatewayv2_route` | `APIGW_ROUTE_NO_AUTH` |
| `AWS::ApiGatewayV2::Stage` | `aws_apigatewayv2_stage` | `APIGW_NO_ACCESS_LOGS` |
| `AWS::AutoScaling::AutoScalingGroup` | `aws_autoscaling_group` | parsed, no rule yet |
| `AWS::AutoScaling::LaunchConfiguration` | `aws_launch_configuration` | `EC2_IMDSV1` |
| `AWS::AutoScaling::ScalingPolicy` | `aws_autoscaling_policy` | parsed, no rule yet |
| `AWS::CloudFormation::Stack` | `aws_cloudformation_stack` | parsed, no rule yet |
| `AWS::CloudFront::Distribution` | `aws_cloudfront_distribution` | `CLOUDFRONT_NO_GEO_RESTRICTION`, `CLOUDFRONT_NO_HTTPS`, `CLOUDFRONT_NO_LOGGING`, `CLOUDFRONT_NO_WAF` |
| `AWS::CloudFront::OriginAccessControl` | `aws_cloudfront_origin_access_control` | parsed, no rule yet |
| `AWS::CloudTrail::Trail` | `aws_cloudtrail` | `CLOUDTRAIL_NOT_ENABLED`, `CLOUDTRAIL_NOT_MULTI_REGION`, `CLOUDTRAIL_NO_ENCRYPTION`, `CLOUDTRAIL_NO_LOG_VALIDATION` |
| `AWS::CloudWatch::Alarm` | `aws_cloudwatch_metric_alarm` | parsed, no rule yet |
| `AWS::Cognito::IdentityPool` | `aws_cognito_identity_pool` | parsed, no rule yet |
| `AWS::Cognito::UserPool` | `aws_cognito_user_pool` | parsed, no rule yet |
| `AWS::Cognito::UserPoolClient` | `aws_cognito_user_pool_client` | parsed, no rule yet |
| `AWS::Config::ConfigRule` | `aws_config_config_rule` | parsed, no rule yet |
| `AWS::Config::ConfigurationAggregator` | `aws_config_configuration_aggregator` | parsed, no rule yet |
| `AWS::Config::ConfigurationRecorder` | `aws_config_configuration_recorder` | `CONFIG_NOT_ALL_RESOURCES` |
| `AWS::Config::DeliveryChannel` | `aws_config_delivery_channel` | parsed, no rule yet |
| `AWS::DocDB::DBCluster` | `aws_docdb_cluster` | parsed, no rule yet |
| `AWS::DocDB::DBInstance` | `aws_docdb_cluster_instance` | parsed, no rule yet |
| `AWS::DynamoDB::Table` | `aws_dynamodb_table` | `DYNAMODB_NO_ENCRYPTION`, `DYNAMODB_NO_PITR` |
| `AWS::EC2::CustomerGateway` | `aws_customer_gateway` | parsed, no rule yet |
| `AWS::EC2::EIP` | `aws_eip` | parsed, no rule yet |
| `AWS::EC2::EIPAssociation` | `aws_eip_association` | parsed, no rule yet |
| `AWS::EC2::FlowLog` | `aws_flow_log` | parsed, no rule yet |
| `AWS::EC2::Instance` | `aws_instance` | `EC2_IMDSV1`, `EC2_PUBLIC_IP`, `EC2_UNENCRYPTED_EBS` |
| `AWS::EC2::InternetGateway` | `aws_internet_gateway` | parsed, no rule yet |
| `AWS::EC2::KeyPair` | `aws_key_pair` | parsed, no rule yet |
| `AWS::EC2::LaunchTemplate` | `aws_launch_template` | `EC2_IMDSV1` |
| `AWS::EC2::NatGateway` | `aws_nat_gateway` | parsed, no rule yet |
| `AWS::EC2::NetworkAcl` | `aws_network_acl` | parsed, no rule yet |
| `AWS::EC2::NetworkAclEntry` | `aws_network_acl_rule` | parsed, no rule yet |
| `AWS::EC2::NetworkInterface` | `aws_network_interface` | parsed, no rule yet |
| `AWS::EC2::Route` | `aws_route` | parsed, no rule yet |
| `AWS::EC2::RouteTable` | `aws_route_table` | parsed, no rule yet |
| `AWS::EC2::SecurityGroup` | `aws_security_group` | `SG_TEMPORARY_OPEN`, `SG_UNRESTRICTED_INGRESS`, `SG_WEB_PORT_OPEN_TO_WORLD` |
| `AWS::EC2::SecurityGroupEgress` | `aws_security_group_rule` | parsed, no rule yet |
| `AWS::EC2::SecurityGroupIngress` | `aws_security_group_rule` | parsed, no rule yet |
| `AWS::EC2::Subnet` | `aws_subnet` | parsed, no rule yet |
| `AWS::EC2::SubnetNetworkAclAssociation` | `aws_network_acl_association` | parsed, no rule yet |
| `AWS::EC2::SubnetRouteTableAssociation` | `aws_route_table_association` | parsed, no rule yet |
| `AWS::EC2::TransitGateway` | `aws_ec2_transit_gateway` | parsed, no rule yet |
| `AWS::EC2::VPC` | `aws_vpc` | `VPC_NO_FLOW_LOGS` |
| `AWS::EC2::VPCEndpoint` | `aws_vpc_endpoint` | parsed, no rule yet |
| `AWS::EC2::VPCGatewayAttachment` | `aws_internet_gateway_attachment` | parsed, no rule yet |
| `AWS::EC2::VPNConnection` | `aws_vpn_connection` | parsed, no rule yet |
| `AWS::EC2::VPNGateway` | `aws_vpn_gateway` | parsed, no rule yet |
| `AWS::EC2::Volume` | `aws_ebs_volume` | parsed, no rule yet |
| `AWS::EC2::VolumeAttachment` | `aws_volume_attachment` | parsed, no rule yet |
| `AWS::ECR::Repository` | `aws_ecr_repository` | `ECR_MUTABLE_TAGS`, `ECR_NO_SCAN_ON_PUSH`, `ECR_PUBLIC_POLICY` |
| `AWS::ECS::Cluster` | `aws_ecs_cluster` | parsed, no rule yet |
| `AWS::ECS::Service` | `aws_ecs_service` | `ECS_EXEC_ENABLED` |
| `AWS::ECS::TaskDefinition` | `aws_ecs_task_definition` | `ECS_HOST_NETWORKING`, `ECS_NO_LOGGING`, `ECS_NO_READONLY_FS`, `ECS_PRIVILEGED_CONTAINER` |
| `AWS::EFS::FileSystem` | `aws_efs_file_system` | parsed, no rule yet |
| `AWS::EFS::MountTarget` | `aws_efs_mount_target` | parsed, no rule yet |
| `AWS::EKS::Addon` | `aws_eks_addon` | parsed, no rule yet |
| `AWS::EKS::Cluster` | `aws_eks_cluster` | `EKS_NO_ENCRYPTION`, `EKS_NO_IRSA`, `EKS_NO_LOGGING`, `EKS_OUTDATED_VERSION`, `EKS_PUBLIC_ACCESS_ANY_CIDR`, `EKS_PUBLIC_ENDPOINT` |
| `AWS::EKS::FargateProfile` | `aws_eks_fargate_profile` | parsed, no rule yet |
| `AWS::EKS::Nodegroup` | `aws_eks_node_group` | `EKS_SSH_ACCESS_NODES` |
| `AWS::ElastiCache::CacheCluster` | `aws_elasticache_cluster` | parsed, no rule yet |
| `AWS::ElastiCache::ReplicationGroup` | `aws_elasticache_replication_group` | `ELASTICACHE_NO_AUTH`, `ELASTICACHE_NO_ENCRYPTION_REST`, `ELASTICACHE_NO_ENCRYPTION_TRANSIT` |
| `AWS::ElastiCache::SubnetGroup` | `aws_elasticache_subnet_group` | parsed, no rule yet |
| `AWS::ElasticLoadBalancing::LoadBalancer` | `aws_elb` | parsed, no rule yet |
| `AWS::ElasticLoadBalancingV2::Listener` | `aws_lb_listener` | `ELB_NO_HTTPS`, `ELB_OUTDATED_TLS` |
| `AWS::ElasticLoadBalancingV2::ListenerRule` | `aws_lb_listener_rule` | parsed, no rule yet |
| `AWS::ElasticLoadBalancingV2::LoadBalancer` | `aws_lb` | `ELB_NO_ACCESS_LOGS` |
| `AWS::ElasticLoadBalancingV2::TargetGroup` | `aws_lb_target_group` | parsed, no rule yet |
| `AWS::Elasticsearch::Domain` | `aws_elasticsearch_domain` | `ES_NO_ENCRYPTION`, `ES_NO_NODE_TO_NODE_ENCRYPTION`, `ES_PUBLIC_DOMAIN` |
| `AWS::Events::Rule` | `aws_cloudwatch_event_rule` | parsed, no rule yet |
| `AWS::Glue::Crawler` | `aws_glue_crawler` | parsed, no rule yet |
| `AWS::Glue::Database` | `aws_glue_catalog_database` | parsed, no rule yet |
| `AWS::Glue::Job` | `aws_glue_job` | parsed, no rule yet |
| `AWS::GuardDuty::Detector` | `aws_guardduty_detector` | `GUARDDUTY_NOT_ENABLED`, `GUARDDUTY_NO_EKS_PROTECTION`, `GUARDDUTY_NO_MALWARE_SCAN`, `GUARDDUTY_NO_S3_PROTECTION` |
| `AWS::IAM::AccessKey` | `aws_iam_access_key` | parsed, no rule yet |
| `AWS::IAM::Group` | `aws_iam_group` | `IAM_ADMIN_POLICY_ATTACHED`, `IAM_PASSROLE_WILDCARD`, `IAM_SERVICE_WILDCARD`, `IAM_WILDCARD_ACTION` |
| `AWS::IAM::InstanceProfile` | `aws_iam_instance_profile` | parsed, no rule yet |
| `AWS::IAM::ManagedPolicy` | `aws_iam_policy` | `IAM_PASSROLE_WILDCARD`, `IAM_SERVICE_WILDCARD`, `IAM_WILDCARD_ACTION` |
| `AWS::IAM::OIDCProvider` | `aws_iam_openid_connect_provider` | parsed, no rule yet |
| `AWS::IAM::Policy` | `aws_iam_policy` | `IAM_PASSROLE_WILDCARD`, `IAM_SERVICE_WILDCARD`, `IAM_WILDCARD_ACTION` |
| `AWS::IAM::Role` | `aws_iam_role` | `IAM_ADMIN_POLICY_ATTACHED`, `IAM_OVERPERMISSIVE_ROLE`, `IAM_PASSROLE_WILDCARD`, `IAM_SERVICE_WILDCARD`, `IAM_WILDCARD_ACTION` |
| `AWS::IAM::SAMLProvider` | `aws_iam_saml_provider` | parsed, no rule yet |
| `AWS::IAM::User` | `aws_iam_user` | `IAM_ADMIN_POLICY_ATTACHED`, `IAM_PASSROLE_WILDCARD`, `IAM_SERVICE_WILDCARD`, `IAM_WILDCARD_ACTION` |
| `AWS::IAM::UserToGroupAddition` | `aws_iam_user_group_membership` | parsed, no rule yet |
| `AWS::KMS::Alias` | `aws_kms_alias` | parsed, no rule yet |
| `AWS::KMS::Key` | `aws_kms_key` | `KMS_KEY_EXPOSED`, `KMS_KEY_ROTATION_DISABLED` |
| `AWS::Kinesis::Stream` | `aws_kinesis_stream` | parsed, no rule yet |
| `AWS::KinesisFirehose::DeliveryStream` | `aws_kinesis_firehose_delivery_stream` | parsed, no rule yet |
| `AWS::Lambda::Alias` | `aws_lambda_alias` | parsed, no rule yet |
| `AWS::Lambda::EventInvokeConfig` | `aws_lambda_function_event_invoke_config` | parsed, no rule yet |
| `AWS::Lambda::EventSourceMapping` | `aws_lambda_event_source_mapping` | parsed, no rule yet |
| `AWS::Lambda::Function` | `aws_lambda_function` | `LAMBDA_NO_VPC`, `LAMBDA_OVERPERMISSIVE_ROLE` |
| `AWS::Lambda::LayerVersion` | `aws_lambda_layer_version` | parsed, no rule yet |
| `AWS::Lambda::Permission` | `aws_lambda_permission` | parsed, no rule yet |
| `AWS::Lambda::Url` | `aws_lambda_function_url` | `LAMBDA_URL_NO_AUTH` |
| `AWS::Logs::LogGroup` | `aws_cloudwatch_log_group` | parsed, no rule yet |
| `AWS::Logs::MetricFilter` | `aws_cloudwatch_log_metric_filter` | parsed, no rule yet |
| `AWS::Logs::SubscriptionFilter` | `aws_cloudwatch_log_subscription_filter` | parsed, no rule yet |
| `AWS::MSK::Cluster` | `aws_msk_cluster` | parsed, no rule yet |
| `AWS::Neptune::DBCluster` | `aws_neptune_cluster` | parsed, no rule yet |
| `AWS::OpenSearchService::Domain` | `aws_opensearch_domain` | `ES_NO_ENCRYPTION`, `ES_NO_NODE_TO_NODE_ENCRYPTION`, `ES_PUBLIC_DOMAIN` |
| `AWS::RDS::DBCluster` | `aws_rds_cluster` | `RDS_NO_BACKUP`, `RDS_NO_DELETION_PROTECTION`, `RDS_NO_ENCRYPTION`, `RDS_NO_IAM_AUTH` |
| `AWS::RDS::DBClusterParameterGroup` | `aws_rds_cluster_parameter_group` | parsed, no rule yet |
| `AWS::RDS::DBInstance` | `aws_db_instance` | `RDS_NO_BACKUP`, `RDS_NO_ENCRYPTION`, `RDS_PUBLIC_ACCESS` |
| `AWS::RDS::DBParameterGroup` | `aws_db_parameter_group` | parsed, no rule yet |
| `AWS::RDS::DBProxy` | `aws_db_proxy` | parsed, no rule yet |
| `AWS::RDS::DBSubnetGroup` | `aws_db_subnet_group` | parsed, no rule yet |
| `AWS::RDS::OptionGroup` | `aws_db_option_group` | parsed, no rule yet |
| `AWS::Redshift::Cluster` | `aws_redshift_cluster` | `REDSHIFT_NO_ENCRYPTION`, `REDSHIFT_NO_LOGGING`, `REDSHIFT_PUBLIC_ACCESS` |
| `AWS::Redshift::ClusterSubnetGroup` | `aws_redshift_subnet_group` | parsed, no rule yet |
| `AWS::Route53::HostedZone` | `aws_route53_zone` | parsed, no rule yet |
| `AWS::Route53::RecordSet` | `aws_route53_record` | parsed, no rule yet |
| `AWS::S3::AccessPoint` | `aws_s3_access_point` | parsed, no rule yet |
| `AWS::S3::Bucket` | `aws_s3_bucket` | `S3_NO_ENCRYPTION`, `S3_NO_LOGGING`, `S3_NO_VERSIONING`, `S3_PUBLIC_ACCESS` |
| `AWS::S3::BucketPolicy` | `aws_s3_bucket_policy` | parsed, no rule yet |
| `AWS::SNS::Subscription` | `aws_sns_topic_subscription` | `SNS_NO_HTTPS` |
| `AWS::SNS::Topic` | `aws_sns_topic` | `SNS_NO_ENCRYPTION`, `SNS_WORLD_SUBSCRIBABLE` |
| `AWS::SNS::TopicPolicy` | `aws_sns_topic_policy` | `SNS_WORLD_SUBSCRIBABLE` |
| `AWS::SQS::Queue` | `aws_sqs_queue` | `SQS_NO_ENCRYPTION`, `SQS_WILDCARD_POLICY` |
| `AWS::SQS::QueuePolicy` | `aws_sqs_queue_policy` | `SQS_WILDCARD_POLICY` |
| `AWS::SSM::Parameter` | `aws_ssm_parameter` | `SSM_NO_ALLOWED_PATTERN`, `SSM_NO_DESCRIPTION`, `SSM_UNENCRYPTED_PARAMETER` |
| `AWS::SageMaker::NotebookInstance` | `aws_sagemaker_notebook_instance` | `SAGEMAKER_NOTEBOOK_DIRECT_INTERNET`, `SAGEMAKER_NOTEBOOK_NO_KMS`, `SAGEMAKER_NOTEBOOK_ROOT_ACCESS` |
| `AWS::SecretsManager::ResourcePolicy` | `aws_secretsmanager_secret_policy` | parsed, no rule yet |
| `AWS::SecretsManager::RotationSchedule` | `aws_secretsmanager_secret_rotation` | `SM_LONG_ROTATION` |
| `AWS::SecretsManager::Secret` | `aws_secretsmanager_secret` | `SM_NO_KMS_KEY`, `SM_NO_ROTATION` |
| `AWS::StepFunctions::StateMachine` | `aws_sfn_state_machine` | parsed, no rule yet |
| `AWS::WAFv2::IPSet` | `aws_wafv2_ip_set` | parsed, no rule yet |
| `AWS::WAFv2::LoggingConfiguration` | `aws_wafv2_web_acl_logging_configuration` | parsed, no rule yet |
| `AWS::WAFv2::RuleGroup` | `aws_wafv2_rule_group` | `WAFV2_RATE_LIMIT_HIGH`, `WAF_EMPTY_RULES` |
| `AWS::WAFv2::WebACL` | `aws_wafv2_web_acl` | `WAFV2_NO_GEO_BLOCKING`, `WAFV2_NO_IP_REPUTATION`, `WAFV2_NO_SQL_INJECTION_RULE`, `WAFV2_NO_XSS_RULE`, `WAFV2_RATE_LIMIT_HIGH`, `WAF_EMPTY_RULES`, `WAF_NO_DEFAULT_BLOCK`, `WAF_NO_LOGGING`, `WAF_NO_MANAGED_RULES`, `WAF_NO_RATE_LIMITING` |
| `AWS::WAFv2::WebACLAssociation` | `aws_wafv2_web_acl_association` | parsed, no rule yet |

Rule resource types that CloudFormation cannot express are not reachable from a template:

| Terraform type | Why a template cannot carry it |
| --- | --- |
| `aws_config_configuration_recorder_status` | CloudFormation has no resource that starts or stops a configuration recorder |
| `aws_default_security_group` | CloudFormation cannot adopt the default security group of a VPC |
| `aws_iam_group_policy` | CloudFormation writes an inline policy of a group as AWS::IAM::Policy, which becomes aws_iam_policy |
| `aws_iam_group_policy_attachment` | CloudFormation attaches managed policies through ManagedPolicyArns on AWS::IAM::Group |
| `aws_iam_policy_attachment` | CloudFormation has no exclusive policy attachment resource; policies are attached through ManagedPolicyArns or the Roles, Users and Groups of AWS::IAM::Policy |
| `aws_iam_role_policy` | CloudFormation writes an inline policy of a role as AWS::IAM::Policy, which becomes aws_iam_policy |
| `aws_iam_role_policy_attachment` | CloudFormation attaches managed policies through ManagedPolicyArns on AWS::IAM::Role |
| `aws_iam_user_policy` | CloudFormation writes an inline policy of a user as AWS::IAM::Policy, which becomes aws_iam_policy |
| `aws_iam_user_policy_attachment` | CloudFormation attaches managed policies through ManagedPolicyArns on AWS::IAM::User |
| `aws_rds_cluster_instance` | CloudFormation creates a cluster member as AWS::RDS::DBInstance with DBClusterIdentifier, which becomes aws_db_instance |
| `aws_s3_account_public_access_block` | CloudFormation has no resource for the account-level S3 public access block |
| `aws_s3_bucket_public_access_block` | CloudFormation sets the public access block through PublicAccessBlockConfiguration on AWS::S3::Bucket, which becomes the public_access_block fact of aws_s3_bucket |
<!-- /gen:cloudformation -->

## Kubernetes

Manifests are YAML or JSON.
A multi-document file, a `List` or `<Kind>List` document and `kubectl get -o yaml` or `-o json` output are all read; a document that is not a Kubernetes object is skipped with a warning.
Every pod-bearing kind is read into one property shape, so a rule written once applies to a Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job and CronJob.
Security settings are the effective ones: a container value wins over the pod value, and a workload is unsafe when any applicable container is.

<!-- gen:kubernetes -->
| Kind | Resource type | Status | Rules that apply |
| --- | --- | --- | --- |
| `Pod` | `kubernetes_pod` | parsed and evaluated | 22 |
| `Deployment` | `kubernetes_deployment` | parsed and evaluated | 22 |
| `DaemonSet` | `kubernetes_daemon_set` | parsed and evaluated | 22 |
| `StatefulSet` | `kubernetes_stateful_set` | parsed and evaluated | 22 |
| `ReplicaSet` | `kubernetes_replica_set` | parsed and evaluated | 22 |
| `Job` | `kubernetes_job` | parsed and evaluated | 22 |
| `CronJob` | `kubernetes_cron_job` | parsed and evaluated | 22 |
| `Service` | `kubernetes_service` | parsed and evaluated | 1 |
| `Ingress` | `kubernetes_ingress` | parsed and evaluated | 1 |
| `ConfigMap` | `kubernetes_config_map` | parsed, not evaluated | 0 |
| `Secret` | `kubernetes_secret` | parsed, not evaluated | 0 |
| `NetworkPolicy` | `kubernetes_network_policy` | parsed, not evaluated | 0 |
| `ServiceAccount` | `kubernetes_service_account` | parsed and evaluated | 1 |
| `Role` | `kubernetes_role` | parsed and evaluated | 6 |
| `ClusterRole` | `kubernetes_cluster_role` | parsed and evaluated | 6 |
| `RoleBinding` | `kubernetes_role_binding` | parsed and evaluated | 2 |
| `ClusterRoleBinding` | `kubernetes_cluster_role_binding` | parsed and evaluated | 3 |
| `Namespace` | `kubernetes_namespace` | parsed and evaluated | 1 |
| `PersistentVolumeClaim` | `kubernetes_pvc` | parsed, not evaluated | 0 |
<!-- /gen:kubernetes -->

Kinds that are not in the table (for example `HorizontalPodAutoscaler` or a custom resource) become a node of type `kubernetes_<snake_case_kind>` and are not evaluated.
A NetworkPolicy covers a workload only when both are in the same scan input, which is why the coverage rules are low severity and say so.
Cluster-scoped kinds (`Namespace`, `ClusterRole`, `ClusterRoleBinding` and the other built-in cluster-scoped kinds) are addressed `<type>.<name>` with no namespace.

## Helm

A chart (a directory with `Chart.yaml`) is one unit that owns its `templates/`, `charts/` and values files, and its templates are never scanned as raw manifests.
It is rendered with `helm template` when the binary is installed, and otherwise with a built-in renderer that evaluates `.Values`, `.Chart`, `.Release`, control flow, variables, `include` and `template`, and the Sprig functions charts use.
Every fallback is reported as a `helm.fallback_render` coverage gap with the reason, and a template that was skipped or only approximated adds a warning.
`THREATCODE_HELM=off` always uses the built-in renderer and `required` makes a missing or failing `helm` an error.
A value the chart does not give prints as a `placeholder-` token, so two resources named from different values never collide and an image that is a placeholder is not reported as untagged.

## Dockerfiles

`Dockerfile`, `Dockerfile.*`, `Dockerfile-*`, `*.dockerfile`, `*.containerfile` and `Containerfile` are read in any letter case.
The lexer follows BuildKit: comments inside a continuation, heredocs, the `# escape=` directive and physical line numbers.
Every `FROM` opens a stage, and the image summary (user, health check, ports, base image) describes the **final** stage.
`ONBUILD` instructions are unwrapped and ignored by the summary, `EXPOSE` ranges are kept as ranges, and a tag taken from a variable with no default is unknown, never "latest".
A Dockerfile has no zone of its own: a declared port is not internet exposure, so a Dockerfile alone starts no attack path.

## MCP client and agent configs

Servers are read from the config, never started or contacted.

| Client | File | Shape |
|--------|------|-------|
| Claude Code | `.mcp.json` (project), `~/.claude.json` (user and per project) | `mcpServers` |
| Claude Desktop | `claude_desktop_config.json` | `mcpServers` |
| Cursor | `.cursor/mcp.json` | `mcpServers` |
| VS Code | `.vscode/mcp.json`, comments allowed | `servers` |
| VS Code and Copilot portable format | `.mcp.json`, `~/.copilot/mcp-config.json` | `mcpServers` |
| Windsurf and Devin | `mcp_config.json` | `mcpServers`, remote servers use `serverUrl` |
| Gemini CLI | `settings.json` | `mcpServers`, remote servers use `httpUrl` |

OpenCode (`mcp`) and Zed (`context_servers`) use other top-level keys and are not read.

The parser works out the command a client really runs before any check reads it.
It unwraps `cmd /c`, `powershell -Command`, `bash -c`, `env`, `sudo`, `nice`, `nohup`, `exec`, `command`, `timeout` and `wsl`, resolves `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx`, `uv tool run`, `pipx run`, `docker run` and `podman run`, and treats `mcp-remote`, `supergateway` and `mcp-proxy` bridges as remote servers.
Each config scope gets one synthetic `mcp_agent` node that holds the union of what its enabled servers can do, and the lethal trifecta rule (private data, untrusted content, a way to exfiltrate) fires on that node.
A server that is not in the reviewed capability table adds nothing to the agent and is reported as `mcp.unknown_capability`.

## Secrets

The secret detectors (34<!-- count:secret_detectors --> of them) run over the files the scan models, and each finding attaches to the resource that holds the secret:

- Terraform `.tf`, `.tf.json` and the `*.tfvars` beside a module, and plan JSON;
- CloudFormation templates;
- Kubernetes manifests, where base64 `Secret` data is decoded and judged;
- Helm `values*.yaml` and the raw templates;
- Dockerfile `ENV` and `ARG` and MCP configs, through their own rules.

A secret outside every resource (a variable default, a `*.tfvars` entry) has an empty address.
Previews never contain secret characters.
The high-entropy detector is off by default.
For a whole-repository secret scan, run Gitleaks and pass its SARIF to `--ingest`.

## Scanner results

`--ingest` reads the results of other tools.
The format is detected from the content, not the file name.

<!-- gen:ingest -->
| Format | Produced by | Detected from content |
| --- | --- | --- |
| Trivy JSON | `trivy image -f json`, `trivy fs -f json`, `trivy config -f json` | yes |
| Grype JSON | `grype IMAGE -o json` | yes |
| OSV-Scanner JSON | `osv-scanner --format json` | yes |
| SARIF 2.1.0 | Checkov, Gitleaks, Trivy and any other SARIF producer | yes |
<!-- /gen:ingest -->

A finding is placed on the graph by the first key that matches: the container image reference a workload holds (Kubernetes, ECS task definitions, Lambda `image_uri`, `user_data` commands, the base image of each Dockerfile stage), then the file and line of a resource, then the directory of a lockfile.
Image references are compared by registry, repository, tag and digest with Docker Hub names normalized.
A finding no key can place is kept with an empty address and counted in an `ingest.unattached` diagnostic.
The same advisory reported by two tools on the same package of the same node is one finding.
