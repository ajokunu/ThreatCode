"""End-to-end scan tests for CloudFormation templates.

A template is parsed, translated to the attributes the rules read, built into a graph and
scanned, the way ``threatcode scan`` does it.
The tests assert both directions: a resource that sets what a rule looks for gets no
finding, and a resource that sets something dangerous gets one.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pytest

from tests.helpers.scan import ScanResult, scan_files, scan_text
from threatcode.models.threat import ThreatSource

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"
CFN = FIXTURES_DIR / "cloudformation"
REALISTIC = FIXTURES_DIR / "realistic"
PARITY = FIXTURES_DIR.parent / "test_rules" / "parity"


def rules_by_resource(result: ScanResult) -> dict[str, set[str]]:
    found: dict[str, set[str]] = defaultdict(set)
    for threat in result.threats:
        if threat.source == ThreatSource.RULE:
            found[threat.resource_address].add(threat.rule_id)
    return found


def scan(path: Path) -> dict[str, set[str]]:
    return rules_by_resource(scan_files([path]))


class TestInsecureStack:
    def test_value_rules_fire_on_the_attributes_the_template_sets(self) -> None:
        found = scan(CFN / "insecure_stack.yml")
        assert "S3_PUBLIC_ACCESS" in found["PublicBucket"]
        assert "RDS_PUBLIC_ACCESS" in found["PublicDatabase"]
        assert "IAM_WILDCARD_ACTION" in found["WildcardPolicy"]
        assert "IAM_OVERPERMISSIVE_ROLE" in found["OverpermissiveRole"]

    def test_the_private_bucket_is_not_public(self) -> None:
        assert "S3_PUBLIC_ACCESS" not in scan(CFN / "insecure_stack.yml")["UnencryptedBucket"]

    def test_absence_rules_fire_where_the_attribute_is_really_missing(self) -> None:
        found = scan(CFN / "insecure_stack.yml")
        for bucket in ("PublicBucket", "UnencryptedBucket"):
            assert {"S3_NO_ENCRYPTION", "S3_NO_VERSIONING", "S3_NO_LOGGING"} <= found[bucket]
        # BackupRetentionPeriod 0 and StorageEncrypted false are values, not absences
        assert {"RDS_NO_BACKUP", "RDS_NO_ENCRYPTION"} <= found["PublicDatabase"]

    def test_findings_sit_on_the_resources_that_declare_the_type(self) -> None:
        result = scan_files([CFN / "insecure_stack.yml"])
        found = rules_by_resource(result)
        s3 = {a for a, ids in found.items() if any(i.startswith("S3_") for i in ids)}
        rds = {a for a, ids in found.items() if any(i.startswith("RDS_") for i in ids)}
        assert {result.graph.nodes[a].resource_type for a in s3} == {"aws_s3_bucket"}
        assert {result.graph.nodes[a].resource_type for a in rds} == {"aws_db_instance"}


class TestSecureStack:
    """Every attribute the absence rules look for is set, so none of them fires."""

    FAMILIES = ("S3_", "RDS_", "SQS_", "LAMBDA_", "CLOUDTRAIL_", "KMS_")

    def test_no_absence_finding_in_the_data_and_logging_families(self) -> None:
        found = scan(CFN / "secure_stack.yml")
        noisy = {
            (address, rule)
            for address, rules in found.items()
            for rule in rules
            if rule.startswith(self.FAMILIES)
        }
        assert not noisy

    def test_the_bucket_database_queue_function_and_trail_are_all_modelled(self) -> None:
        result = scan_files([CFN / "secure_stack.yml"])
        types = {n.id: n.resource_type for n in result.graph.nodes.values()}
        assert types["DataBucket"] == "aws_s3_bucket"
        assert types["Database"] == "aws_db_instance"
        assert types["OrdersQueue"] == "aws_sqs_queue"
        assert types["ProcessorFunction"] == "aws_lambda_function"
        assert types["AuditTrail"] == "aws_cloudtrail"
        assert types["DataKey"] == "aws_kms_key"

    def test_the_findings_that_remain_are_not_about_a_configured_resource(self) -> None:
        # the VPC flow-log rule reads a tag that no CloudFormation property sets
        assert scan(CFN / "secure_stack.yml") == {"Vpc": {"VPC_NO_FLOW_LOGS"}}


class TestHardenedStack:
    def test_a_stack_hardened_throughout_reports_no_rule_finding(self) -> None:
        assert scan(CFN / "hardened_stack.yml") == {}

    def test_it_models_every_first_wave_type(self) -> None:
        result = scan_files([CFN / "hardened_stack.yml"])
        assert {n.resource_type for n in result.graph.nodes.values()} == {
            "aws_kms_key",
            "aws_s3_bucket",
            "aws_db_instance",
            "aws_sqs_queue",
            "aws_dynamodb_table",
            "aws_iam_role",
            "aws_lambda_function",
            "aws_security_group",
            "aws_instance",
            "aws_cloudtrail",
        }


INSECURE_COUNTERPARTS = [
    pytest.param(
        "AWS::S3::Bucket",
        {"AccessControl": "PublicReadWrite"},
        "S3_PUBLIC_ACCESS",
        id="s3-public-read-write",
    ),
    pytest.param(
        "AWS::S3::Bucket",
        {"AccessControl": "AuthenticatedRead"},
        "S3_PUBLIC_ACCESS",
        id="s3-authenticated-read",
    ),
    pytest.param(
        "AWS::S3::Bucket",
        {"VersioningConfiguration": {"Status": "Suspended"}},
        "S3_NO_VERSIONING",
        id="s3-versioning-suspended",
    ),
    pytest.param(
        "AWS::RDS::DBInstance",
        {"PubliclyAccessible": "true"},
        "RDS_PUBLIC_ACCESS",
        id="rds-public-written-as-text",
    ),
    pytest.param(
        "AWS::RDS::DBInstance",
        {"StorageEncrypted": "false"},
        "RDS_NO_ENCRYPTION",
        id="rds-unencrypted-written-as-text",
    ),
    pytest.param(
        "AWS::RDS::DBInstance",
        {"BackupRetentionPeriod": "0"},
        "RDS_NO_BACKUP",
        id="rds-no-backups",
    ),
    pytest.param(
        "AWS::EC2::Instance",
        {"NetworkInterfaces": [{"DeviceIndex": "0", "AssociatePublicIpAddress": "true"}]},
        "EC2_PUBLIC_IP",
        id="ec2-public-ip-on-the-interface",
    ),
    pytest.param(
        "AWS::EC2::Instance",
        {"BlockDeviceMappings": [{"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": False}}]},
        "EC2_UNENCRYPTED_EBS",
        id="ec2-unencrypted-root-volume",
    ),
    pytest.param(
        "AWS::ElastiCache::ReplicationGroup",
        {"ReplicationGroupDescription": "d", "AtRestEncryptionEnabled": "false"},
        "ELASTICACHE_NO_ENCRYPTION_REST",
        id="elasticache-unencrypted",
    ),
    pytest.param(
        "AWS::CloudTrail::Trail",
        {"IsLogging": True, "IsMultiRegionTrail": "false", "S3BucketName": "b"},
        "CLOUDTRAIL_NOT_MULTI_REGION",
        id="cloudtrail-single-region",
    ),
    pytest.param(
        "AWS::CloudTrail::Trail",
        {"IsLogging": True, "EnableLogFileValidation": False, "S3BucketName": "b"},
        "CLOUDTRAIL_NO_LOG_VALIDATION",
        id="cloudtrail-no-validation",
    ),
    pytest.param(
        "AWS::KMS::Key",
        {"EnableKeyRotation": "false"},
        "KMS_KEY_ROTATION_DISABLED",
        id="kms-no-rotation",
    ),
    pytest.param(
        "AWS::Lambda::Function",
        {"Role": "arn:aws:iam::1:role/admin-role"},
        "LAMBDA_OVERPERMISSIVE_ROLE",
        id="lambda-admin-role-literal",
    ),
    pytest.param(
        "AWS::ECS::TaskDefinition",
        {"ContainerDefinitions": [{"Name": "a", "Image": "x", "Privileged": True}]},
        "ECS_PRIVILEGED_CONTAINER",
        id="ecs-privileged-container",
    ),
    pytest.param(
        "AWS::ECS::TaskDefinition",
        {"NetworkMode": "host"},
        "ECS_HOST_NETWORKING",
        id="ecs-host-network",
    ),
    pytest.param(
        "AWS::ECS::Service",
        {"EnableExecuteCommand": "true"},
        "ECS_EXEC_ENABLED",
        id="ecs-exec",
    ),
    pytest.param(
        "AWS::SSM::Parameter",
        {"Type": "String", "Value": "x"},
        "SSM_UNENCRYPTED_PARAMETER",
        id="ssm-plain-string",
    ),
    pytest.param(
        "AWS::GuardDuty::Detector",
        {"Enable": "false"},
        "GUARDDUTY_NOT_ENABLED",
        id="guardduty-disabled",
    ),
    pytest.param(
        "AWS::ElasticLoadBalancingV2::Listener",
        {"Protocol": "HTTP", "Port": 80},
        "ELB_NO_HTTPS",
        id="listener-http",
    ),
    pytest.param(
        "AWS::CloudFront::Distribution",
        {
            "DistributionConfig": {
                "Enabled": True,
                "DefaultCacheBehavior": {
                    "TargetOriginId": "o",
                    "ViewerProtocolPolicy": "allow-all",
                },
            }
        },
        "CLOUDFRONT_NO_HTTPS",
        id="cloudfront-allow-all",
    ),
]


class TestInsecureCounterparts:
    """One insecure counterpart per translated type: the rule fires on what the template says."""

    @pytest.mark.parametrize(("cfn_type", "properties", "rule"), INSECURE_COUNTERPARTS)
    def test_the_rule_fires(self, cfn_type: str, properties: dict[str, object], rule: str) -> None:
        import json

        template = {"Resources": {"Subject": {"Type": cfn_type, "Properties": properties}}}
        result = scan_text(json.dumps(template), "template.json")
        assert rule in result.rule_ids_for("Subject")


class TestUnresolvedValuesNeverFireARule:
    """An intrinsic the template cannot decide is not an absent property."""

    def scan_properties(
        self, cfn_type: str, properties: dict[str, object], **sections: object
    ) -> set[str]:
        import json

        template = {
            "Resources": {"Subject": {"Type": cfn_type, "Properties": properties}},
            **sections,
        }
        return scan_text(json.dumps(template), "template.json").rule_ids_for("Subject")

    def test_a_reference_in_a_configured_attribute_is_not_missing(self) -> None:
        fired = self.scan_properties(
            "AWS::SQS::Queue",
            {"KmsMasterKeyId": {"Ref": "Key"}, "RedrivePolicy": {"Ref": "Policy"}},
        )
        assert not fired & {"SQS_NO_ENCRYPTION", "SQS_NO_DLQ"}

    def test_a_getatt_is_not_missing(self) -> None:
        fired = self.scan_properties(
            "AWS::Lambda::Function",
            {
                "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                "VpcConfig": {"SubnetIds": [{"Ref": "S"}]},
                "DeadLetterConfig": {"TargetArn": {"Fn::GetAtt": ["Q", "Arn"]}},
            },
        )
        assert not fired

    def test_an_unknown_boolean_neither_passes_nor_fails(self) -> None:
        fired = self.scan_properties(
            "AWS::RDS::DBInstance",
            {
                "PubliclyAccessible": {"Ref": "Public"},
                "StorageEncrypted": {"Ref": "Encrypted"},
                "BackupRetentionPeriod": {"Ref": "Days"},
            },
            Parameters={
                "Public": {"Type": "String"},
                "Encrypted": {"Type": "String"},
                "Days": {"Type": "Number"},
            },
        )
        assert not fired & {"RDS_PUBLIC_ACCESS", "RDS_NO_ENCRYPTION", "RDS_NO_BACKUP"}

    def test_an_undecidable_if_neither_passes_nor_fails(self) -> None:
        fired = self.scan_properties(
            "AWS::RDS::DBInstance",
            {"StorageEncrypted": {"Fn::If": ["Mystery", True, False]}},
            Conditions={"Mystery": {"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}},
        )
        assert "RDS_NO_ENCRYPTION" not in fired

    def test_a_decidable_if_takes_its_branch(self) -> None:
        conditions = {"IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}}
        parameters = {"Env": {"Type": "String", "Default": "prod"}}
        secure = self.scan_properties(
            "AWS::RDS::DBInstance",
            {"StorageEncrypted": {"Fn::If": ["IsProd", True, False]}},
            Conditions=conditions,
            Parameters=parameters,
        )
        insecure = self.scan_properties(
            "AWS::RDS::DBInstance",
            {"StorageEncrypted": {"Fn::If": ["IsProd", False, True]}},
            Conditions=conditions,
            Parameters=parameters,
        )
        assert "RDS_NO_ENCRYPTION" not in secure
        assert "RDS_NO_ENCRYPTION" in insecure

    def test_a_parameter_default_decides_a_value_rule(self) -> None:
        fired = self.scan_properties(
            "AWS::S3::Bucket",
            {"AccessControl": {"Ref": "Acl"}},
            Parameters={"Acl": {"Type": "String", "Default": "PublicRead"}},
        )
        assert "S3_PUBLIC_ACCESS" in fired

    def test_a_property_removed_with_no_value_is_missing(self) -> None:
        fired = self.scan_properties("AWS::SQS::Queue", {"KmsMasterKeyId": {"Ref": "AWS::NoValue"}})
        assert "SQS_NO_ENCRYPTION" in fired

    def test_an_unresolved_policy_document_is_not_read_as_a_wildcard_or_as_safe(self) -> None:
        fired = self.scan_properties("AWS::IAM::Policy", {"PolicyDocument": {"Ref": "Document"}})
        assert "IAM_WILDCARD_ACTION" not in fired


class TestRealisticStacks:
    def test_the_data_pipeline_public_bucket_is_found(self) -> None:
        found = scan(REALISTIC / "03_aws_data_pipeline.yaml")
        assert "S3_PUBLIC_ACCESS" in found["AthenaResultsBucket"]

    def test_the_data_pipeline_configured_bucket_has_no_absence_finding(self) -> None:
        found = scan(REALISTIC / "03_aws_data_pipeline.yaml")
        assert not found["RawDataBucket"] & {"S3_NO_ENCRYPTION", "S3_NO_VERSIONING"}
        assert "S3_NO_ENCRYPTION" in found["ProcessedDataBucket"]

    def test_the_healthcare_stack_configured_resources_are_clean(self) -> None:
        found = scan(REALISTIC / "09_aws_healthcare_hipaa.yaml")
        assert not found["PatientRecordsBucket"] & {
            "S3_NO_ENCRYPTION",
            "S3_NO_VERSIONING",
            "S3_NO_LOGGING",
            "S3_PUBLIC_ACCESS",
        }
        assert "LAMBDA_NO_VPC" not in found["RecordsApiFunction"]
        assert "LAMBDA_NO_VPC" in found["ReportGeneratorFunction"]
        assert "S3_NO_ENCRYPTION" in found["TempUploadsBucket"]

    def test_the_serverless_stack_public_bucket_is_found(self) -> None:
        assert (
            "S3_PUBLIC_ACCESS"
            in scan(REALISTIC / "06_aws_serverless_api.yaml")["PartnerDocsBucket"]
        )


class TestBucketPoliciesAreNotBuckets:
    def test_serverless_stack_bucket_policy_gets_no_bucket_findings(self) -> None:
        found = scan(REALISTIC / "06_aws_serverless_api.yaml")
        assert "PartnerDocsBucketPolicy" not in found
        assert any(i.startswith("S3_") for ids in found.values() for i in ids)

    def test_healthcare_stack_bucket_policy_gets_no_bucket_findings(self) -> None:
        assert "CloudTrailBucketPolicy" not in scan(REALISTIC / "09_aws_healthcare_hipaa.yaml")


class TestCloudTrailTemplateTypes:
    def test_a_trail_is_the_type_the_cloudtrail_rules_are_written_for(self) -> None:
        result = scan_files([REALISTIC / "09_aws_healthcare_hipaa.yaml"])
        assert result.graph.nodes["HIPAACloudTrail"].resource_type == "aws_cloudtrail"

    def test_a_trail_with_a_key_and_a_bucket_is_not_reported_as_unencrypted(self) -> None:
        # the trail sets KMSKeyId and S3BucketName, as references to the key and the bucket
        flagged = scan(REALISTIC / "09_aws_healthcare_hipaa.yaml").get("HIPAACloudTrail", set())
        assert "CLOUDTRAIL_NO_ENCRYPTION" not in flagged
        assert "CLOUDTRAIL_NO_S3_ACCESS_LOGGING" not in flagged

    def test_a_trail_without_a_key_is_reported(self) -> None:
        template = (
            '{"Resources": {"T": {"Type": "AWS::CloudTrail::Trail", "Properties": '
            '{"IsLogging": true, "S3BucketName": "b"}}}}'
        )
        assert "CLOUDTRAIL_NO_ENCRYPTION" in scan_text(template, "t.json").rule_ids_for("T")


@pytest.mark.parametrize(
    ("config", "rules"),
    [
        ("public_bucket", {"S3_PUBLIC_ACCESS"}),
        ("public_database", {"RDS_PUBLIC_ACCESS", "RDS_NO_ENCRYPTION"}),
        ("open_instance", {"EC2_PUBLIC_IP"}),
        ("wildcard_policy", {"IAM_WILDCARD_ACTION"}),
    ],
)
def test_the_template_trips_the_same_rules_as_the_plan(config: str, rules: set[str]) -> None:
    """The same configuration as a template and as a Terraform plan reports the same rules."""

    def fired(suffix: str) -> set[str]:
        return scan_files([PARITY / f"{config}{suffix}"]).rule_ids & rules

    assert fired(".cfn.yaml") == fired(".plan.json") == rules
