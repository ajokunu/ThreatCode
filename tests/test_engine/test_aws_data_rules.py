"""Tests for the AWS data, identity and logging rules.

Covers the fifteen rule files s3, iam, kms, rds, dynamodb, sqs, sns, secrets_manager, ssm,
elasticache, elasticsearch, cloudtrail, config, guardduty and redshift, and the module
``threatcode.ir.enrichment.aws_data`` that computes the facts they read.
Every scenario is real syntax (Terraform HCL, plan JSON or a CloudFormation template) run through
the parser, the graph and the engine, so a rule is tested together with the enrichment it depends
on.
The bad and good example of every rule also live in ``tests/test_rules/cases/aws__*``.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Mapping
from typing import Any

import pytest

from tests.helpers.scan import ScanResult, scan_text
from tests.test_rules.harness import load_rules_by_group
from threatcode.engine.mitre import TECHNIQUE_DB, is_revoked, tactics_for_techniques
from threatcode.engine.rules.loader import Rule, deprecated_rule_ids, load_builtin_rules
from threatcode.engine.rules.matcher import matches_rule
from threatcode.ir import enrich as enrich_module
from threatcode.ir.enrichment import aws_data
from threatcode.values import Unknown, is_unknown

GROUPS = (
    "aws__s3",
    "aws__iam",
    "aws__kms",
    "aws__rds",
    "aws__dynamodb",
    "aws__sqs",
    "aws__sns",
    "aws__secrets_manager",
    "aws__ssm",
    "aws__elasticache",
    "aws__elasticsearch",
    "aws__cloudtrail",
    "aws__config",
    "aws__guardduty",
    "aws__redshift",
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class Raw(str):
    """An HCL expression written as is, such as ``var.name``."""


def _value(value: Any) -> str:
    if isinstance(value, Raw):
        return str(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list):
        return "[" + ", ".join(_value(item) for item in value) + "]"
    return str(value)


def block(name: str, body: str = "", /, depth: int = 1, **attributes: Any) -> str:
    """A nested HCL block; ``body`` holds blocks nested one level deeper (``depth`` + 1)."""
    pad = "  " * depth
    lines = "".join(f"{pad}  {key} = {_value(value)}\n" for key, value in attributes.items())
    return f"{pad}{name} {{\n{lines}{body}{pad}}}\n"


def res(rtype: str, name: str, body: str = "", /, **attributes: Any) -> str:
    """One HCL resource: ``attributes`` as lines and ``body`` as nested blocks."""
    lines = "".join(f"  {key} = {_value(value)}\n" for key, value in attributes.items())
    return f'resource "{rtype}" "{name}" {{\n{lines}{body}}}\n'


def policy(*statements: Mapping[str, Any]) -> str:
    """A compact policy document, as a plan JSON holds it."""
    document = {"Version": "2012-10-17", "Statement": list(statements)}
    return json.dumps(document, separators=(",", ":"))


def encoded(*statements: Mapping[str, Any]) -> Raw:
    """The same document as an HCL ``jsonencode(...)`` call."""
    document = {"Version": "2012-10-17", "Statement": list(statements)}
    return Raw(f"jsonencode({json.dumps(document)})")


def hcl(*sources: str) -> ScanResult:
    return scan_text("\n".join(textwrap.dedent(s) for s in sources), "main.tf")


def cfn(source: str) -> ScanResult:
    return scan_text(textwrap.dedent(source), "template.yaml")


def plan(
    *resources: tuple[str, str, Mapping[str, Any]],
    refs: Mapping[str, Mapping[str, list[str]]] | None = None,
) -> ScanResult:
    """Scan a plan JSON of (type, name, values) entries.

    ``refs`` maps ``"type.name"`` to ``{attribute: [reference, ...]}`` for attributes that are
    known only after apply, which a real plan lists under ``after_unknown`` and
    ``configuration.expressions``.
    """
    refs = refs or {}
    planned: list[dict[str, Any]] = []
    changes: list[dict[str, Any]] = []
    configured: list[dict[str, Any]] = []
    for rtype, name, values in resources:
        address = f"{rtype}.{name}"
        unknown: dict[str, bool] = {"id": True} | dict.fromkeys(refs.get(address, {}), True)
        body = {k: v for k, v in values.items() if k not in unknown}
        head = {"address": address, "mode": "managed", "type": rtype, "name": name}
        planned.append({**head, "values": body})
        change = {"actions": ["create"], "before": None, "after": body, "after_unknown": unknown}
        changes.append({**head, "change": change})
        expressions: dict[str, Any] = {k: {"constant_value": v} for k, v in body.items()}
        for attribute, targets in refs.get(address, {}).items():
            expressions[attribute] = {"references": targets}
        configured.append({**head, "expressions": expressions})
    document = {
        "format_version": "1.2",
        "terraform_version": "1.9.5",
        "planned_values": {"root_module": {"resources": planned}},
        "resource_changes": changes,
        "configuration": {"root_module": {"resources": configured}},
    }
    return scan_text(json.dumps(document), "tfplan.json")


def derived(result: ScanResult, address: str) -> dict[str, Any]:
    found = result.graph.nodes[address].properties.get("derived")
    assert isinstance(found, dict), f"{address} has no derived facts"
    return found


def fired(result: ScanResult, address: str) -> set[str]:
    return result.rule_ids_for(address)


def link(rtype: str, name: str, attribute: str = "id") -> list[str]:
    return [f"{rtype}.{name}.{attribute}", f"{rtype}.{name}"]


ALL_ON_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}
ROLE = res(
    "aws_iam_role",
    "app",
    name="app",
    assume_role_policy=encoded(
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ),
)


# ---------------------------------------------------------------------------
# The rule files
# ---------------------------------------------------------------------------


def _rules() -> dict[str, Rule]:
    by_group = load_rules_by_group()
    return {rule.id: rule for group in GROUPS for rule in by_group[group]}


class TestRuleFiles:
    def test_every_group_loads_and_every_rule_belongs_to_one(self) -> None:
        by_group = load_rules_by_group()
        for group in GROUPS:
            assert by_group[group], group
        ids = [rule.id for group in GROUPS for rule in by_group[group]]
        assert len(ids) == len(set(ids))

    def test_the_rule_ids_the_design_names_exist(self) -> None:
        assert {
            "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
            "IAM_SERVICE_WILDCARD",
            "IAM_PASSROLE_WILDCARD",
            "IAM_ADMIN_POLICY_ATTACHED",
            "REDSHIFT_PUBLIC_ACCESS",
            "REDSHIFT_NO_ENCRYPTION",
            "REDSHIFT_NO_LOGGING",
            "RDS_NO_DELETION_PROTECTION",
            "RDS_NO_IAM_AUTH",
        } <= set(_rules())

    DELETED = {
        "aws__iam": {"IAM_NO_MFA"},
        "aws__kms": {"KMS_WILDCARD_POLICY", "KMS_NO_DELETION_PROTECTION"},
        "aws__sqs": {"SQS_NO_DLQ"},
        "aws__dynamodb": {"DYNAMODB_NO_AUTOSCALING"},
        "aws__ssm": {"SSM_STANDARD_TIER_SECRET"},
        "aws__cloudtrail": {"CLOUDTRAIL_NO_S3_ACCESS_LOGGING"},
        "aws__config": {"CONFIG_NO_DELIVERY_CHANNEL", "CONFIG_NO_AGGREGATION"},
        "aws__secrets_manager": {"SM_NO_RESOURCE_POLICY"},
    }

    def test_deleted_rules_are_recorded_as_deprecated_and_no_longer_defined(self) -> None:
        deprecated = deprecated_rule_ids()
        defined = {rule.id for rule in load_builtin_rules()}
        for group, ids in self.DELETED.items():
            assert ids <= deprecated, group
            assert not ids & defined, group

    def test_every_rule_declares_a_confidence_that_matches_its_severity(self) -> None:
        for rule in _rules().values():
            if rule.confidence == "absence":
                assert rule.severity in ("medium", "low", "info"), rule.id
            if rule.confidence == "heuristic":
                assert rule.severity != "critical", rule.id
            if rule.severity == "critical":
                assert rule.confidence == "definitive", rule.id

    def test_the_search_domain_public_endpoint_is_a_heuristic_capped_at_high(self) -> None:
        rule = _rules()["ES_PUBLIC_DOMAIN"]
        assert (rule.confidence, rule.severity) == ("heuristic", "high")

    def test_cmk_preference_rules_are_low_and_say_customer_managed(self) -> None:
        for rule_id in (
            "S3_NO_ENCRYPTION",
            "DYNAMODB_NO_ENCRYPTION",
            "SQS_NO_ENCRYPTION",
            "SNS_NO_ENCRYPTION",
            "SM_NO_KMS_KEY",
            "CLOUDTRAIL_NO_ENCRYPTION",
        ):
            rule = _rules()[rule_id]
            assert rule.severity == "low", rule_id
            assert "customer-managed" in rule.title, rule_id

    def test_s3_encryption_keeps_its_id_for_suppressions(self) -> None:
        rule = _rules()["S3_NO_ENCRYPTION"]
        assert rule.title == "S3 bucket not encrypted with a customer-managed KMS key"

    def test_techniques_exist_and_none_is_revoked(self) -> None:
        for rule in _rules().values():
            for technique in (rule.metadata.get("mitre") or {}).get("techniques", []):
                assert technique in TECHNIQUE_DB, (rule.id, technique)
                assert not is_revoked(technique), (rule.id, technique)

    def test_tactics_are_derived_from_the_techniques(self) -> None:
        for rule in _rules().values():
            mitre = rule.metadata.get("mitre") or {}
            techniques = list(mitre.get("techniques", []))
            derived_tactics = tactics_for_techniques(techniques)
            assert list(mitre.get("tactics", derived_tactics)) == derived_tactics, rule.id

    LOGGING_AND_DETECTION = (
        "S3_NO_LOGGING",
        "SSM_NO_DESCRIPTION",
        "CLOUDTRAIL_NOT_ENABLED",
        "CLOUDTRAIL_NOT_MULTI_REGION",
        "CLOUDTRAIL_NO_LOG_VALIDATION",
        "CONFIG_NOT_ENABLED",
        "CONFIG_NOT_ALL_RESOURCES",
        "GUARDDUTY_NOT_ENABLED",
        "GUARDDUTY_NO_S3_PROTECTION",
        "GUARDDUTY_NO_EKS_PROTECTION",
        "GUARDDUTY_NO_MALWARE_SCAN",
        "REDSHIFT_NO_LOGGING",
    )

    @pytest.mark.parametrize("rule_id", LOGGING_AND_DETECTION)
    def test_missing_logging_and_detection_is_repudiation_with_no_technique(
        self, rule_id: str
    ) -> None:
        rule = _rules()[rule_id]
        assert rule.stride_category == "repudiation"
        assert not (rule.metadata.get("mitre") or {}).get("techniques")

    @pytest.mark.parametrize(
        "rule_id",
        ["S3_NO_VERSIONING", "RDS_NO_BACKUP", "RDS_NO_DELETION_PROTECTION", "DYNAMODB_NO_PITR"],
    )
    def test_recoverability_controls_use_denial_of_service(self, rule_id: str) -> None:
        assert _rules()[rule_id].stride_category == "denial_of_service"

    def test_no_rule_reads_a_derived_fact_that_the_enrichment_does_not_write(self) -> None:
        known = {
            "versioning_enabled",
            "sse_algorithm",
            "logging_enabled",
            "public_access_block",
            "acl",
            "rotation_enabled",
            "allows_any_principal",
            "allows_all_actions",
            "allows_service_wildcard",
            "allows_passrole_wildcard",
            "admin_policy_attached",
            "secret_name",
            "publicly_accessible",
        }
        for rule in _rules().values():
            text = json.dumps(rule.condition)
            for part in text.split("derived.")[1:]:
                name = part.split('"')[0].split(".")[0]
                assert name in known, (rule.id, name)


# ---------------------------------------------------------------------------
# S3 on companion resources
# ---------------------------------------------------------------------------

BUCKET_ID = Raw("aws_s3_bucket.data.id")
ALL_BLOCKED = {
    "block_public_acls": True,
    "block_public_policy": True,
    "ignore_public_acls": True,
    "restrict_public_buckets": True,
}
ABSENCE = {"S3_NO_VERSIONING", "S3_NO_LOGGING", "S3_NO_ENCRYPTION"}
COMPANION_TYPES = (
    "aws_s3_bucket_versioning",
    "aws_s3_bucket_server_side_encryption_configuration",
    "aws_s3_bucket_logging",
    "aws_s3_bucket_public_access_block",
)


def v4_bucket(*, sse: str = "aws:kms", versioning: str = "Enabled", drop: str = "") -> str:
    """A bucket with the four v4 companion resources; ``drop`` names one to leave out."""
    default = block(
        "apply_server_side_encryption_by_default",
        depth=2,
        sse_algorithm=sse,
        kms_master_key_id="alias/data",
    )
    parts = {
        "bucket": res("aws_s3_bucket", "data", bucket="data"),
        "aws_s3_bucket_versioning": res(
            "aws_s3_bucket_versioning",
            "data",
            block("versioning_configuration", status=versioning),
            bucket=BUCKET_ID,
        ),
        "aws_s3_bucket_server_side_encryption_configuration": res(
            "aws_s3_bucket_server_side_encryption_configuration",
            "data",
            block("rule", default),
            bucket=BUCKET_ID,
        ),
        "aws_s3_bucket_logging": res(
            "aws_s3_bucket_logging",
            "data",
            bucket=BUCKET_ID,
            target_bucket="central-logs",
            target_prefix="data/",
        ),
        "aws_s3_bucket_public_access_block": res(
            "aws_s3_bucket_public_access_block", "data", bucket=BUCKET_ID, **ALL_BLOCKED
        ),
    }
    return "\n".join(text for key, text in parts.items() if key != drop)


V4_BUCKET_CFN = """
    AWSTemplateFormatVersion: "2010-09-09"
    Resources:
      Data:
        Type: AWS::S3::Bucket
        Properties:
          BucketName: data
          VersioningConfiguration:
            Status: Enabled
          BucketEncryption:
            ServerSideEncryptionConfiguration:
              - ServerSideEncryptionByDefault:
                  SSEAlgorithm: aws:kms
                  KMSMasterKeyID: alias/data
          LoggingConfiguration:
            DestinationBucketName: central-logs
          PublicAccessBlockConfiguration:
            BlockPublicAcls: true
            BlockPublicPolicy: true
            IgnorePublicAcls: true
            RestrictPublicBuckets: true
"""


def v4_bucket_plan() -> ScanResult:
    sse = [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]
    return plan(
        ("aws_s3_bucket", "data", {"bucket": "data"}),
        ("aws_s3_bucket_versioning", "data", {"versioning_configuration": [{"status": "Enabled"}]}),
        ("aws_s3_bucket_server_side_encryption_configuration", "data", {"rule": sse}),
        ("aws_s3_bucket_logging", "data", {"target_bucket": "central-logs"}),
        ("aws_s3_bucket_public_access_block", "data", ALL_BLOCKED),
        refs={
            f"{kind}.data": {"bucket": link("aws_s3_bucket", "data")} for kind in COMPANION_TYPES
        },
    )


class TestS3ProviderV4Bucket:
    def test_hcl_with_every_companion_reports_nothing(self) -> None:
        result = hcl(v4_bucket())
        assert fired(result, "aws_s3_bucket.data") == set()

    def test_plan_json_with_every_companion_reports_none_of_the_absence_rules(self) -> None:
        result = v4_bucket_plan()
        assert not fired(result, "aws_s3_bucket.data") & ABSENCE
        facts = derived(result, "aws_s3_bucket.data")
        assert facts["versioning_enabled"] is True
        assert facts["logging_enabled"] is True

    def test_cloudformation_with_every_setting_reports_nothing(self) -> None:
        assert fired(cfn(V4_BUCKET_CFN), "Data") == set()

    def test_companions_carry_no_findings_themselves(self) -> None:
        result = hcl(v4_bucket())
        assert result.rule_ids == set()

    def test_the_same_bucket_without_companions_reports_all_three(self) -> None:
        bare_hcl = hcl(res("aws_s3_bucket", "data", bucket="data"))
        assert ABSENCE <= fired(bare_hcl, "aws_s3_bucket.data")
        bare_cfn = cfn("Resources:\n  Data:\n    Type: AWS::S3::Bucket\n")
        assert ABSENCE <= fired(bare_cfn, "Data")

    @pytest.mark.parametrize(
        ("missing", "rule"),
        [
            ("aws_s3_bucket_versioning", "S3_NO_VERSIONING"),
            ("aws_s3_bucket_logging", "S3_NO_LOGGING"),
            ("aws_s3_bucket_server_side_encryption_configuration", "S3_NO_ENCRYPTION"),
        ],
    )
    def test_dropping_one_companion_reports_exactly_that_rule(
        self, missing: str, rule: str
    ) -> None:
        assert fired(hcl(v4_bucket(drop=missing)), "aws_s3_bucket.data") == {rule}

    def test_aes256_is_reported_as_missing_the_customer_managed_key(self) -> None:
        assert fired(hcl(v4_bucket(sse="AES256")), "aws_s3_bucket.data") == {"S3_NO_ENCRYPTION"}

    def test_dsse_kms_counts_as_a_kms_key(self) -> None:
        assert fired(hcl(v4_bucket(sse="aws:kms:dsse")), "aws_s3_bucket.data") == set()

    def test_suspended_versioning_is_reported(self) -> None:
        result = hcl(v4_bucket(versioning="Suspended"))
        assert fired(result, "aws_s3_bucket.data") == {"S3_NO_VERSIONING"}

    def test_a_companion_of_another_bucket_does_not_configure_this_one(self) -> None:
        result = hcl(v4_bucket(), res("aws_s3_bucket", "other", bucket="other"))
        assert fired(result, "aws_s3_bucket.data") == set()
        assert ABSENCE <= fired(result, "aws_s3_bucket.other")

    def test_legacy_inline_settings_are_still_honoured(self) -> None:
        default = block("apply_server_side_encryption_by_default", depth=3, sse_algorithm="aws:kms")
        body = (
            block("versioning", enabled=True)
            + block("logging", target_bucket="logs")
            + block("server_side_encryption_configuration", block("rule", default, depth=2))
        )
        result = hcl(res("aws_s3_bucket", "old", body, bucket="old"))
        assert fired(result, "aws_s3_bucket.old") == set()

    @pytest.mark.parametrize(
        "companion", [*COMPANION_TYPES, "aws_s3_bucket_policy", "aws_s3_bucket_acl"]
    )
    def test_no_absence_rule_fires_on_a_companion_type(self, companion: str) -> None:
        result = hcl(res(companion, "x", bucket="b"))
        assert not fired(result, f"{companion}.x") & ABSENCE

    def test_a_link_that_cannot_be_resolved_leaves_the_buckets_unjudged(self) -> None:
        versioning = block("versioning_configuration", status="Enabled")
        result = hcl(
            res("aws_s3_bucket", "data", bucket="data"),
            res("aws_s3_bucket_versioning", "v", versioning, bucket=Raw("var.bucket_id")),
        )
        assert "S3_NO_VERSIONING" not in fired(result, "aws_s3_bucket.data")
        assert is_unknown(derived(result, "aws_s3_bucket.data")["versioning_enabled"])


# ---------------------------------------------------------------------------
# S3 public access
# ---------------------------------------------------------------------------

PUBLIC_POLICY = {
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "s3:GetObject",
    "Resource": "arn:aws:s3:::data/*",
}


def bucket_with_policy(statement: Mapping[str, Any], *extra: str) -> ScanResult:
    return hcl(
        res("aws_s3_bucket", "data", bucket="data"),
        res("aws_s3_bucket_policy", "data", bucket=BUCKET_ID, policy=encoded(statement)),
        *extra,
    )


def bucket_with_acl(acl: str, *extra: str) -> ScanResult:
    return hcl(
        res("aws_s3_bucket", "data", bucket="data"),
        res("aws_s3_bucket_acl", "data", bucket=BUCKET_ID, acl=acl),
        *extra,
    )


class TestS3PublicAccess:
    @pytest.mark.parametrize("acl", ["public-read", "public-read-write", "authenticated-read"])
    def test_a_public_acl_fires_through_the_acl_resource(self, acl: str) -> None:
        result = bucket_with_acl(acl)
        assert "S3_PUBLIC_ACCESS" in fired(result, "aws_s3_bucket.data")
        assert "S3_PUBLIC_ACCESS" not in fired(result, "aws_s3_bucket_acl.data")

    @pytest.mark.parametrize("acl", ["private", "log-delivery-write", "bucket-owner-full-control"])
    def test_other_acls_are_silent(self, acl: str) -> None:
        assert "S3_PUBLIC_ACCESS" not in fired(bucket_with_acl(acl), "aws_s3_bucket.data")

    def test_a_public_acl_inline_on_the_bucket_still_fires(self) -> None:
        result = hcl(res("aws_s3_bucket", "b", bucket="b", acl="public-read"))
        assert "S3_PUBLIC_ACCESS" in fired(result, "aws_s3_bucket.b")

    @pytest.mark.parametrize("principal", [{"AWS": "*"}, "*", {"AWS": ["*"]}])
    def test_a_policy_for_every_principal_fires(self, principal: Any) -> None:
        result = bucket_with_policy({**PUBLIC_POLICY, "Principal": principal})
        assert "S3_PUBLIC_ACCESS" in fired(result, "aws_s3_bucket.data")

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
            {"StringEquals": {"aws:principalorgid": "o-abc123"}},
            {"StringEquals": {"AWS:SourceVpce": "vpce-123"}},
            {"StringEquals": {"aws:SourceVpc": "vpc-123"}},
            {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:t"}},
            {"StringEquals": {"aws:SourceAccount": "111122223333"}},
            {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/*"}},
        ],
    )
    def test_a_restricting_condition_key_makes_the_policy_silent(
        self, condition: dict[str, Any]
    ) -> None:
        result = bucket_with_policy({**PUBLIC_POLICY, "Condition": condition})
        assert "S3_PUBLIC_ACCESS" not in fired(result, "aws_s3_bucket.data")

    @pytest.mark.parametrize(
        "condition",
        [
            {"Bool": {"aws:SecureTransport": "true"}},
            {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}},
            {"StringEquals": {"aws:RequestedRegion": "us-east-1"}},
        ],
    )
    def test_a_condition_that_does_not_say_who_is_calling_still_fires(
        self, condition: dict[str, Any]
    ) -> None:
        result = bucket_with_policy({**PUBLIC_POLICY, "Condition": condition})
        assert "S3_PUBLIC_ACCESS" in fired(result, "aws_s3_bucket.data")

    def test_a_deny_statement_is_never_public_access(self) -> None:
        result = bucket_with_policy({**PUBLIC_POLICY, "Effect": "Deny"})
        assert "S3_PUBLIC_ACCESS" not in fired(result, "aws_s3_bucket.data")

    def test_a_named_principal_is_silent(self) -> None:
        named = {"AWS": "arn:aws:iam::111122223333:root"}
        result = bucket_with_policy({**PUBLIC_POLICY, "Principal": named})
        assert "S3_PUBLIC_ACCESS" not in fired(result, "aws_s3_bucket.data")

    def test_the_public_access_block_stops_a_public_policy_and_a_public_acl(self) -> None:
        blocked = res("aws_s3_bucket_public_access_block", "data", bucket=BUCKET_ID, **ALL_BLOCKED)
        by_policy = bucket_with_policy(PUBLIC_POLICY, blocked)
        by_acl = bucket_with_acl("public-read", blocked)
        assert "S3_PUBLIC_ACCESS" not in fired(by_policy, "aws_s3_bucket.data")
        assert "S3_PUBLIC_ACCESS" not in fired(by_acl, "aws_s3_bucket.data")

    def test_a_block_that_covers_only_acls_does_not_stop_a_policy(self) -> None:
        only_acls = res(
            "aws_s3_bucket_public_access_block",
            "data",
            bucket=BUCKET_ID,
            block_public_acls=True,
            ignore_public_acls=True,
        )
        by_policy = bucket_with_policy(PUBLIC_POLICY, only_acls)
        by_acl = bucket_with_acl("public-read", only_acls)
        assert "S3_PUBLIC_ACCESS" in fired(by_policy, "aws_s3_bucket.data")
        assert "S3_PUBLIC_ACCESS" not in fired(by_acl, "aws_s3_bucket.data")

    def test_a_block_that_covers_only_policies_does_not_stop_an_acl(self) -> None:
        only_policies = res(
            "aws_s3_bucket_public_access_block",
            "data",
            bucket=BUCKET_ID,
            block_public_policy=True,
            restrict_public_buckets=True,
        )
        by_policy = bucket_with_policy(PUBLIC_POLICY, only_policies)
        by_acl = bucket_with_acl("public-read", only_policies)
        assert "S3_PUBLIC_ACCESS" in fired(by_acl, "aws_s3_bucket.data")
        assert "S3_PUBLIC_ACCESS" not in fired(by_policy, "aws_s3_bucket.data")

    def test_a_cloudformation_bucket_blocks_with_its_inline_configuration(self) -> None:
        template = """
            Resources:
              B:
                Type: AWS::S3::Bucket
                Properties:
                  AccessControl: PublicRead
        """
        blocked = """
            Resources:
              B:
                Type: AWS::S3::Bucket
                Properties:
                  AccessControl: PublicRead
                  PublicAccessBlockConfiguration:
                    BlockPublicAcls: true
                    IgnorePublicAcls: true
        """
        assert "S3_PUBLIC_ACCESS" in fired(cfn(template), "B")
        assert "S3_PUBLIC_ACCESS" not in fired(cfn(blocked), "B")

    def test_cloudformation_bucket_policy_resource_is_folded_into_the_bucket(self) -> None:
        result = cfn(
            """
            Resources:
              B:
                Type: AWS::S3::Bucket
              Policy:
                Type: AWS::S3::BucketPolicy
                Properties:
                  Bucket: !Ref B
                  PolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Effect: Allow
                        Principal: "*"
                        Action: "s3:GetObject"
                        Resource: "arn:aws:s3:::b/*"
            """
        )
        assert "S3_PUBLIC_ACCESS" in fired(result, "B")
        assert "S3_PUBLIC_ACCESS" not in fired(result, "Policy")

    def test_a_cloudformation_policy_is_matched_to_its_own_bucket_only(self) -> None:
        result = cfn(
            """
            Resources:
              Open:
                Type: AWS::S3::Bucket
              Closed:
                Type: AWS::S3::Bucket
              OpenPolicy:
                Type: AWS::S3::BucketPolicy
                Properties:
                  Bucket: !Ref Open
                  PolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Effect: Allow
                        Principal: "*"
                        Action: "s3:GetObject"
                        Resource: "*"
              ClosedPolicy:
                Type: AWS::S3::BucketPolicy
                Properties:
                  Bucket: !Ref Closed
                  PolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Effect: Allow
                        Principal: "*"
                        Action: "s3:GetObject"
                        Resource: "*"
                        Condition:
                          StringEquals:
                            "aws:PrincipalOrgID": o-abc123
            """
        )
        assert "S3_PUBLIC_ACCESS" in fired(result, "Open")
        assert "S3_PUBLIC_ACCESS" not in fired(result, "Closed")

    def test_an_unreadable_policy_is_neither_public_nor_safe(self) -> None:
        result = hcl(
            res("aws_s3_bucket", "data", bucket="data"),
            res(
                "aws_s3_bucket_policy",
                "data",
                bucket=BUCKET_ID,
                policy=Raw("data.aws_iam_policy_document.p.json"),
            ),
        )
        assert "S3_PUBLIC_ACCESS" not in fired(result, "aws_s3_bucket.data")
        assert is_unknown(derived(result, "aws_s3_bucket.data")["allows_any_principal"])

    def test_the_inline_policy_attribute_of_a_bucket_is_judged(self) -> None:
        values = {"bucket": "b", "policy": policy(PUBLIC_POLICY)}
        result = plan(("aws_s3_bucket", "b", values))
        assert "S3_PUBLIC_ACCESS" in fired(result, "aws_s3_bucket.b")


FLAGS = tuple(ALL_BLOCKED)
BLOCK_TYPES = ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block")


class TestPublicAccessBlockDisabled:
    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("rtype", BLOCK_TYPES)
    def test_any_flag_that_is_false_fires(self, flag: str, rtype: str) -> None:
        result = hcl(res(rtype, "x", **{**ALL_BLOCKED, flag: False}))
        assert fired(result, f"{rtype}.x") == {"S3_PUBLIC_ACCESS_BLOCK_DISABLED"}

    def test_all_four_true_is_silent(self) -> None:
        result = hcl(res("aws_s3_bucket_public_access_block", "x", **ALL_BLOCKED))
        assert not fired(result, "aws_s3_bucket_public_access_block.x")

    def test_a_flag_left_out_is_false_like_the_provider_default(self) -> None:
        result = hcl(res("aws_s3_bucket_public_access_block", "x", block_public_acls=True))
        address = "aws_s3_bucket_public_access_block.x"
        assert "S3_PUBLIC_ACCESS_BLOCK_DISABLED" in fired(result, address)

    def test_hcl_and_plan_agree_on_a_partial_block(self) -> None:
        values = {**dict.fromkeys(FLAGS, False), "block_public_acls": True}
        in_plan = plan(("aws_s3_bucket_public_access_block", "x", values))
        in_hcl = hcl(res("aws_s3_bucket_public_access_block", "x", block_public_acls=True))
        address = "aws_s3_bucket_public_access_block.x"
        assert fired(in_plan, address) == fired(in_hcl, address)
        assert fired(in_hcl, address) == {"S3_PUBLIC_ACCESS_BLOCK_DISABLED"}

    def test_an_unknown_flag_does_not_fire_when_the_others_are_true(self) -> None:
        flags = {**ALL_BLOCKED, "restrict_public_buckets": Raw("var.restrict")}
        result = hcl(res("aws_s3_bucket_public_access_block", "x", **flags))
        assert not fired(result, "aws_s3_bucket_public_access_block.x")


# ---------------------------------------------------------------------------
# IAM
# ---------------------------------------------------------------------------


def role_policy(statement: Mapping[str, Any], kind: str = "aws_iam_role_policy") -> ScanResult:
    attached = res(kind, "p", name="p", role=Raw("aws_iam_role.app.id"), policy=encoded(statement))
    return hcl(ROLE, attached)


def policy_node(*statements: Mapping[str, Any]) -> ScanResult:
    return plan(("aws_iam_policy", "p", {"name": "p", "policy": policy(*statements)}))


IAM_ADMIN = {"IAM_WILDCARD_ACTION"}


class TestIamPolicies:
    """The four policy shapes the audit found invisible, plus the Deny guardrail."""

    def test_an_inline_role_policy_with_action_star(self) -> None:
        result = role_policy(ALL_ON_ALL)
        assert fired(result, "aws_iam_role_policy.p") == IAM_ADMIN
        assert not fired(result, "aws_iam_role.app")

    def test_pretty_printed_json(self) -> None:
        pretty = json.dumps({"Version": "2012-10-17", "Statement": [ALL_ON_ALL]}, indent=2)
        result = plan(("aws_iam_policy", "p", {"name": "p", "policy": pretty}))
        assert fired(result, "aws_iam_policy.p") == IAM_ADMIN

    def test_a_list_for_action_and_resource(self) -> None:
        result = policy_node({"Effect": "Allow", "Action": ["*"], "Resource": ["*"]})
        assert fired(result, "aws_iam_policy.p") == IAM_ADMIN

    def test_a_service_wide_wildcard(self) -> None:
        result = policy_node({"Effect": "Allow", "Action": "iam:*", "Resource": "*"})
        assert fired(result, "aws_iam_policy.p") == {"IAM_SERVICE_WILDCARD"}

    def test_a_heredoc_policy_in_hcl(self) -> None:
        document = json.dumps({"Version": "2012-10-17", "Statement": [ALL_ON_ALL]}, indent=2)
        result = hcl(res("aws_iam_policy", "p", name="p", policy=Raw(f"<<EOF\n{document}\nEOF")))
        assert fired(result, "aws_iam_policy.p") == IAM_ADMIN

    @pytest.mark.parametrize(
        "kind",
        ["aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"],
    )
    def test_jsonencode_in_hcl_for_every_standalone_policy_type(self, kind: str) -> None:
        assert fired(role_policy(ALL_ON_ALL, kind), f"{kind}.p") == IAM_ADMIN

    def test_a_deny_guardrail_with_action_star_is_silent_in_every_format(self) -> None:
        deny = {"Effect": "Deny", "Action": "*", "Resource": "*"}
        assert fired(role_policy(deny), "aws_iam_role_policy.p") == set()
        assert fired(policy_node(deny), "aws_iam_policy.p") == set()
        template = """
            Resources:
              P:
                Type: AWS::IAM::ManagedPolicy
                Properties:
                  PolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Effect: Deny
                        Action: "*"
                        Resource: "*"
        """
        assert fired(cfn(template), "P") == set()

    def test_a_deny_next_to_an_allow_does_not_hide_the_allow(self) -> None:
        deny = {"Effect": "Deny", "Action": "iam:*", "Resource": "*"}
        assert fired(policy_node(deny, ALL_ON_ALL), "aws_iam_policy.p") == IAM_ADMIN

    @pytest.mark.parametrize(
        "statement",
        [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::one-bucket/*"},
            {"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"},
            {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": ["ec2:Describe*", "s3:ListAllMyBuckets"],
                "Resource": "*",
            },
        ],
    )
    def test_scoped_policies_are_silent(self, statement: dict[str, Any]) -> None:
        assert fired(policy_node(statement), "aws_iam_policy.p") == set()

    def test_action_star_on_a_limited_resource_is_the_service_wildcard_rule(self) -> None:
        statement = {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::ecommerce-*"}
        assert fired(policy_node(statement), "aws_iam_policy.p") == {"IAM_SERVICE_WILDCARD"}

    def test_admin_and_service_wildcards_never_report_the_same_statement(self) -> None:
        assert "IAM_SERVICE_WILDCARD" not in fired(policy_node(ALL_ON_ALL), "aws_iam_policy.p")

    def test_role_inline_policy_blocks_are_judged_on_the_role(self) -> None:
        inline = block("inline_policy", name="all", policy=encoded(ALL_ON_ALL))
        trust = encoded(
            {
                "Effect": "Allow",
                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        )
        result = hcl(res("aws_iam_role", "r", inline, name="r", assume_role_policy=trust))
        assert fired(result, "aws_iam_role.r") == IAM_ADMIN

    def test_a_standalone_role_policy_is_reported_on_the_policy_not_on_the_role(self) -> None:
        result = role_policy(ALL_ON_ALL)
        assert fired(result, "aws_iam_role_policy.p") == IAM_ADMIN
        assert fired(result, "aws_iam_role.app") == set()

    @pytest.mark.parametrize("kind", ["Role", "User", "Group"])
    def test_cloudformation_inline_policies_of_a_role_user_or_group(self, kind: str) -> None:
        trust = (
            """
                  AssumeRolePolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Effect: Allow
                        Principal: {Service: lambda.amazonaws.com}
                        Action: sts:AssumeRole"""
            if kind == "Role"
            else ""
        )
        template = f"""
            Resources:
              Subject:
                Type: AWS::IAM::{kind}
                Properties:{trust}
                  Policies:
                    - PolicyName: all
                      PolicyDocument:
                        Version: "2012-10-17"
                        Statement:
                          - Effect: Allow
                            Action: "*"
                            Resource: "*"
        """
        assert fired(cfn(template), "Subject") == IAM_ADMIN

    def test_an_unreadable_policy_is_neither_flagged_nor_passed(self) -> None:
        unreadable = res(
            "aws_iam_role_policy",
            "p",
            name="p",
            role=Raw("aws_iam_role.app.id"),
            policy=Raw("data.aws_iam_policy_document.p.json"),
        )
        result = hcl(ROLE, unreadable)
        assert fired(result, "aws_iam_role_policy.p") == set()
        assert is_unknown(derived(result, "aws_iam_role_policy.p")["allows_all_actions"])

    def test_an_action_that_is_a_variable_is_unknown(self) -> None:
        result = policy_node({"Effect": "Allow", "Action": "${var.action}", "Resource": "*"})
        assert fired(result, "aws_iam_policy.p") == set()
        assert is_unknown(derived(result, "aws_iam_policy.p")["allows_all_actions"])


class TestPassRole:
    def test_passrole_on_every_resource_fires(self) -> None:
        result = policy_node({"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"})
        assert fired(result, "aws_iam_policy.p") == {"IAM_PASSROLE_WILDCARD"}

    def test_passrole_among_other_actions_and_in_any_case(self) -> None:
        actions = ["iam:passrole", "lambda:CreateFunction"]
        result = policy_node({"Effect": "Allow", "Action": actions, "Resource": "*"})
        assert fired(result, "aws_iam_policy.p") == {"IAM_PASSROLE_WILDCARD"}

    def test_a_pattern_that_covers_passrole_fires(self) -> None:
        result = policy_node({"Effect": "Allow", "Action": "iam:Pass*", "Resource": "*"})
        assert fired(result, "aws_iam_policy.p") == {"IAM_PASSROLE_WILDCARD"}

    @pytest.mark.parametrize(
        "statement",
        [
            {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "arn:aws:iam::1:role/app"},
            {"Effect": "Deny", "Action": "iam:PassRole", "Resource": "*"},
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}},
            },
            {
                "Effect": "Allow",
                "Action": "iam:PassRole",
                "Resource": "*",
                "Condition": {"StringEquals": {"IAM:passedtoservice": "lambda.amazonaws.com"}},
            },
            {"Effect": "Allow", "Action": "iam:GetRole", "Resource": "*"},
        ],
    )
    def test_scoped_passrole_is_silent(self, statement: dict[str, Any]) -> None:
        assert "IAM_PASSROLE_WILDCARD" not in fired(policy_node(statement), "aws_iam_policy.p")

    @pytest.mark.parametrize(
        ("action", "expected"),
        [("*", "IAM_WILDCARD_ACTION"), ("iam:*", "IAM_SERVICE_WILDCARD")],
    )
    def test_the_wildcards_that_include_passrole_are_not_reported_twice(
        self, action: str, expected: str
    ) -> None:
        result = policy_node({"Effect": "Allow", "Action": action, "Resource": "*"})
        assert fired(result, "aws_iam_policy.p") == {expected}


ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"


class TestAdministratorAccess:
    @pytest.mark.parametrize(
        ("kind", "target"),
        [
            ("aws_iam_role_policy_attachment", {"role": "r"}),
            ("aws_iam_user_policy_attachment", {"user": "u"}),
            ("aws_iam_group_policy_attachment", {"group": "g"}),
            ("aws_iam_policy_attachment", {"name": "a", "roles": ["r"]}),
        ],
    )
    def test_each_attachment_type_fires(self, kind: str, target: dict[str, Any]) -> None:
        result = hcl(res(kind, "x", **target, policy_arn=ADMIN_ARN))
        assert fired(result, f"{kind}.x") == {"IAM_ADMIN_POLICY_ATTACHED"}

    @pytest.mark.parametrize(
        "arn",
        [
            "arn:aws-cn:iam::aws:policy/AdministratorAccess",
            "arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
            "arn:${data.aws_partition.current.partition}:iam::aws:policy/AdministratorAccess",
        ],
    )
    def test_other_partitions_count(self, arn: str) -> None:
        result = plan(("aws_iam_role_policy_attachment", "x", {"policy_arn": arn}))
        assert fired(result, "aws_iam_role_policy_attachment.x") == {"IAM_ADMIN_POLICY_ATTACHED"}

    @pytest.mark.parametrize(
        "arn",
        [
            "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "arn:aws:iam::aws:policy/AdministratorAccess-Amplify",
            "arn:aws:iam::aws:policy/PowerUserAccess",
            "arn:aws:iam::111122223333:policy/AdministratorAccess",
        ],
    )
    def test_other_policies_are_silent(self, arn: str) -> None:
        result = plan(("aws_iam_role_policy_attachment", "x", {"policy_arn": arn}))
        assert fired(result, "aws_iam_role_policy_attachment.x") == set()

    def test_managed_policy_arns_of_a_role_are_judged_on_the_role(self) -> None:
        trust = policy(
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        )
        values = {"name": "r", "assume_role_policy": trust, "managed_policy_arns": [ADMIN_ARN]}
        result = plan(("aws_iam_role", "r", values))
        assert fired(result, "aws_iam_role.r") == {"IAM_ADMIN_POLICY_ATTACHED"}

    def test_a_policy_arn_that_is_a_reference_is_unknown(self) -> None:
        source = res(
            "aws_iam_role_policy_attachment",
            "x",
            role="r",
            policy_arn=Raw("data.aws_iam_policy.p.arn"),
        )
        assert fired(hcl(source), "aws_iam_role_policy_attachment.x") == set()


def trust_role(principal: Any, condition: Mapping[str, Any] | None = None) -> ScanResult:
    statement: dict[str, Any] = {
        "Effect": "Allow",
        "Principal": principal,
        "Action": "sts:AssumeRole",
    }
    if condition:
        statement["Condition"] = dict(condition)
    return plan(("aws_iam_role", "r", {"name": "r", "assume_role_policy": policy(statement)}))


OVERPERMISSIVE = {"IAM_OVERPERMISSIVE_ROLE"}


class TestTrustPolicies:
    @pytest.mark.parametrize("principal", ["*", {"AWS": "*"}, {"AWS": ["*"]}])
    def test_a_trust_policy_for_every_principal_fires(self, principal: Any) -> None:
        assert fired(trust_role(principal), "aws_iam_role.r") == OVERPERMISSIVE

    def test_the_organisation_guard_makes_it_silent(self) -> None:
        condition = {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}
        assert fired(trust_role({"AWS": "*"}, condition), "aws_iam_role.r") == set()

    def test_a_condition_on_something_else_still_fires(self) -> None:
        condition = {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
        assert fired(trust_role({"AWS": "*"}, condition), "aws_iam_role.r") == OVERPERMISSIVE

    @pytest.mark.parametrize(
        "principal",
        [
            {"Service": "lambda.amazonaws.com"},
            {"AWS": "arn:aws:iam::111122223333:root"},
            {"Federated": "arn:aws:iam::111122223333:oidc-provider/example.com"},
        ],
    )
    def test_named_principals_are_silent(self, principal: Any) -> None:
        assert fired(trust_role(principal), "aws_iam_role.r") == set()

    def test_hcl_and_cloudformation_agree(self) -> None:
        trust = encoded({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole"})
        in_hcl = hcl(res("aws_iam_role", "r", name="r", assume_role_policy=trust))
        in_cfn = cfn(
            """
            Resources:
              R:
                Type: AWS::IAM::Role
                Properties:
                  AssumeRolePolicyDocument:
                    Version: "2012-10-17"
                    Statement:
                      - Effect: Allow
                        Principal: {AWS: "*"}
                        Action: "sts:AssumeRole"
            """
        )
        assert fired(in_hcl, "aws_iam_role.r") == OVERPERMISSIVE
        assert fired(in_cfn, "R") == OVERPERMISSIVE

    def test_a_role_with_no_policy_attribute_carries_no_fact(self) -> None:
        result = hcl(res("aws_iam_role", "r", name="r"))
        facts = result.graph.nodes["aws_iam_role.r"].properties.get("derived", {})
        assert "allows_any_principal" not in facts
        assert fired(result, "aws_iam_role.r") == set()


# ---------------------------------------------------------------------------
# Resource policies of keys, queues and topics
# ---------------------------------------------------------------------------

EVERYONE = {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "kms:*", "Resource": "*"}


def key_with_policy(statement: Mapping[str, Any]) -> ScanResult:
    values = {"description": "k", "enable_key_rotation": True, "policy": policy(statement)}
    return plan(("aws_kms_key", "k", values))


class TestKms:
    def test_a_key_policy_for_every_principal_fires_one_rule(self) -> None:
        assert fired(key_with_policy(EVERYONE), "aws_kms_key.k") == {"KMS_KEY_EXPOSED"}

    def test_the_merged_rule_has_one_id_and_the_other_is_deprecated(self) -> None:
        assert "KMS_KEY_EXPOSED" in {r.id for r in load_builtin_rules()}
        assert "KMS_WILDCARD_POLICY" in deprecated_rule_ids()

    @pytest.mark.parametrize(
        "condition",
        [
            {"StringEquals": {"kms:CallerAccount": "111122223333"}},
            {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}},
            {"ArnLike": {"aws:SourceArn": "arn:aws:s3:::b"}},
        ],
    )
    def test_a_restricting_condition_is_silent(self, condition: dict[str, Any]) -> None:
        result = key_with_policy({**EVERYONE, "Condition": condition})
        assert fired(result, "aws_kms_key.k") == set()

    def test_the_default_account_root_policy_is_silent(self) -> None:
        root = {"AWS": "arn:aws:iam::111122223333:root"}
        assert fired(key_with_policy({**EVERYONE, "Principal": root}), "aws_kms_key.k") == set()

    def test_a_key_with_no_policy_attribute_carries_no_fact(self) -> None:
        result = hcl(res("aws_kms_key", "k", enable_key_rotation=True))
        facts = result.graph.nodes["aws_kms_key.k"].properties.get("derived", {})
        assert "allows_any_principal" not in facts
        assert fired(result, "aws_kms_key.k") == set()

    def test_hcl_key_policy_in_jsonencode(self) -> None:
        statement = {**EVERYONE, "Principal": "*"}
        source = res("aws_kms_key", "k", enable_key_rotation=True, policy=encoded(statement))
        assert fired(hcl(source), "aws_kms_key.k") == {"KMS_KEY_EXPOSED"}


KEY_CFN = "Resources:\n  K:\n    Type: AWS::KMS::Key\n    Properties:\n      Description: k\n"


class TestKmsRotation:
    def test_hcl_without_the_attribute_fires(self) -> None:
        result = hcl(res("aws_kms_key", "k", description="k"))
        assert fired(result, "aws_kms_key.k") == {"KMS_KEY_ROTATION_DISABLED"}

    def test_hcl_with_rotation_is_silent(self) -> None:
        result = hcl(res("aws_kms_key", "k", enable_key_rotation=True))
        assert fired(result, "aws_kms_key.k") == set()

    @pytest.mark.parametrize(
        "spec", ["RSA_2048", "RSA_4096", "ECC_NIST_P256", "ECC_SECG_P256K1", "HMAC_256", "SM2"]
    )
    def test_asymmetric_and_hmac_keys_are_excluded(self, spec: str) -> None:
        source = res("aws_kms_key", "k", customer_master_key_spec=spec, key_usage="SIGN_VERIFY")
        assert fired(hcl(source), "aws_kms_key.k") == set()
        values = {"enable_key_rotation": False, "customer_master_key_spec": spec}
        assert fired(plan(("aws_kms_key", "k", values)), "aws_kms_key.k") == set()

    def test_an_explicit_symmetric_spec_is_still_judged(self) -> None:
        source = res("aws_kms_key", "k", customer_master_key_spec="SYMMETRIC_DEFAULT")
        assert fired(hcl(source), "aws_kms_key.k") == {"KMS_KEY_ROTATION_DISABLED"}

    def test_cloudformation_key_spec_is_excluded_too(self) -> None:
        template = """
            Resources:
              K:
                Type: AWS::KMS::Key
                Properties:
                  KeySpec: RSA_2048
                  KeyUsage: SIGN_VERIFY
                  KeyPolicy: {Version: "2012-10-17", Statement: []}
        """
        assert fired(cfn(template), "K") == set()

    def test_all_three_formats_agree(self) -> None:
        in_hcl = hcl(res("aws_kms_key", "k", description="k"))
        values = {"enable_key_rotation": False, "customer_master_key_spec": "SYMMETRIC_DEFAULT"}
        in_plan = plan(("aws_kms_key", "k", values))
        in_cfn = cfn(KEY_CFN)
        assert fired(in_hcl, "aws_kms_key.k") == {"KMS_KEY_ROTATION_DISABLED"}
        assert fired(in_plan, "aws_kms_key.k") == {"KMS_KEY_ROTATION_DISABLED"}
        assert fired(in_cfn, "K") == {"KMS_KEY_ROTATION_DISABLED"}

    def test_an_unknown_rotation_flag_does_not_fire(self) -> None:
        source = res("aws_kms_key", "k", enable_key_rotation=Raw("var.rotate"))
        assert fired(hcl(source), "aws_kms_key.k") == set()


ANYONE_QUEUE = {"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage", "Resource": "*"}
SQS_CFN = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n    Properties:\n"


class TestSqsAndSns:
    def test_a_queue_with_managed_sse_is_not_reported(self) -> None:
        for result in (
            hcl(res("aws_sqs_queue", "q", name="q", sqs_managed_sse_enabled=True)),
            plan(("aws_sqs_queue", "q", {"name": "q", "sqs_managed_sse_enabled": True})),
            cfn(SQS_CFN + "      SqsManagedSseEnabled: true\n"),
        ):
            assert "SQS_NO_ENCRYPTION" not in result.rule_ids

    def test_a_queue_with_a_customer_managed_key_is_not_reported(self) -> None:
        result = plan(("aws_sqs_queue", "q", {"name": "q", "kms_master_key_id": "alias/q"}))
        assert "SQS_NO_ENCRYPTION" not in result.rule_ids

    def test_a_queue_with_neither_is_a_low_finding(self) -> None:
        result = hcl(res("aws_sqs_queue", "q", name="q"))
        (threat,) = [t for t in result.threats if t.rule_id == "SQS_NO_ENCRYPTION"]
        assert threat.severity.value == "low"

    def test_a_queue_key_known_after_apply_is_not_reported(self) -> None:
        result = plan(
            ("aws_sqs_queue", "q", {"name": "q"}),
            refs={"aws_sqs_queue.q": {"kms_master_key_id": link("aws_kms_key", "k", "arn")}},
        )
        assert "SQS_NO_ENCRYPTION" not in result.rule_ids

    def test_the_dead_letter_rule_is_gone(self) -> None:
        assert "SQS_NO_DLQ" not in hcl(res("aws_sqs_queue", "q", name="q")).rule_ids

    def test_queue_policy_for_every_principal(self) -> None:
        result = plan(
            ("aws_sqs_queue", "q", {"name": "q"}),
            ("aws_sqs_queue_policy", "p", {"policy": policy(ANYONE_QUEUE)}),
        )
        assert fired(result, "aws_sqs_queue_policy.p") == {"SQS_WILDCARD_POLICY"}
        assert "SQS_WILDCARD_POLICY" not in fired(result, "aws_sqs_queue.q")

    def test_queue_policy_with_a_source_arn_is_silent(self) -> None:
        condition = {"ArnEquals": {"aws:SourceArn": "arn:aws:sns:us-east-1:111122223333:t"}}
        values = {"policy": policy({**ANYONE_QUEUE, "Condition": condition})}
        result = plan(("aws_sqs_queue_policy", "p", values))
        assert fired(result, "aws_sqs_queue_policy.p") == set()

    def test_the_default_sns_topic_policy_is_silent(self) -> None:
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["sns:Publish", "sns:Subscribe"],
            "Resource": "arn:aws:sns:us-east-1:111122223333:t",
            "Condition": {"StringEquals": {"AWS:SourceOwner": "111122223333"}},
        }
        result = plan(("aws_sns_topic_policy", "p", {"policy": policy(statement)}))
        assert fired(result, "aws_sns_topic_policy.p") == set()

    def test_topic_policy_for_every_principal(self) -> None:
        statement = {
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": "sns:Subscribe",
            "Resource": "*",
        }
        result = plan(("aws_sns_topic_policy", "p", {"policy": policy(statement)}))
        assert fired(result, "aws_sns_topic_policy.p") == {"SNS_WORLD_SUBSCRIBABLE"}

    @pytest.mark.parametrize(
        ("protocol", "expected"),
        [("http", {"SNS_NO_HTTPS"}), ("HTTP", {"SNS_NO_HTTPS"}), ("https", set()), ("sqs", set())],
    )
    def test_http_subscriptions_fire_and_others_do_not(
        self, protocol: str, expected: set[str]
    ) -> None:
        values = {"protocol": protocol, "endpoint": "x"}
        result = plan(("aws_sns_topic_subscription", "s", values))
        assert fired(result, "aws_sns_topic_subscription.s") == expected

    def test_a_topic_alone_no_longer_reports_the_https_rule(self) -> None:
        result = hcl(res("aws_sns_topic", "t", name="t"))
        assert fired(result, "aws_sns_topic.t") == {"SNS_NO_ENCRYPTION"}

    def test_a_topic_with_a_key_is_silent(self) -> None:
        result = hcl(res("aws_sns_topic", "t", name="t", kms_master_key_id="alias/t"))
        assert fired(result, "aws_sns_topic.t") == set()


# ---------------------------------------------------------------------------
# Secrets, parameters, data stores
# ---------------------------------------------------------------------------

SECRET = res("aws_secretsmanager_secret", "s", name="s", kms_key_id="alias/s")
ROTATION_LAMBDA = "arn:aws:lambda:us-east-1:111122223333:function:rotate"


def rotation(secret: Any = Raw("aws_secretsmanager_secret.s.id"), days: int = 30) -> str:
    return res(
        "aws_secretsmanager_secret_rotation",
        "r",
        block("rotation_rules", automatically_after_days=days),
        secret_id=secret,
        rotation_lambda_arn=ROTATION_LAMBDA,
    )


class TestSecretsManager:
    def test_a_secret_without_rotation_fires(self) -> None:
        assert fired(hcl(SECRET), "aws_secretsmanager_secret.s") == {"SM_NO_ROTATION"}

    def test_the_rotation_resource_is_folded_into_the_secret(self) -> None:
        result = hcl(SECRET, rotation())
        assert fired(result, "aws_secretsmanager_secret.s") == set()
        assert fired(result, "aws_secretsmanager_secret_rotation.r") == set()

    def test_a_rotation_of_another_secret_does_not_help(self) -> None:
        other = res("aws_secretsmanager_secret", "t", name="t", kms_key_id="alias/s")
        result = hcl(SECRET, other, rotation(Raw("aws_secretsmanager_secret.t.id")))
        assert fired(result, "aws_secretsmanager_secret.s") == {"SM_NO_ROTATION"}
        assert fired(result, "aws_secretsmanager_secret.t") == set()

    @pytest.mark.parametrize(
        ("days", "expected"), [(120, {"SM_LONG_ROTATION"}), (90, set()), (30, set())]
    )
    def test_long_rotation_is_judged_on_the_rotation_resource(
        self, days: int, expected: set[str]
    ) -> None:
        result = hcl(SECRET, rotation(days=days))
        assert fired(result, "aws_secretsmanager_secret_rotation.r") == expected
        assert fired(result, "aws_secretsmanager_secret.s") == set()

    def test_a_secret_without_a_key_is_a_low_finding(self) -> None:
        result = hcl(res("aws_secretsmanager_secret", "s", name="s"))
        (threat,) = [t for t in result.threats if t.rule_id == "SM_NO_KMS_KEY"]
        assert threat.severity.value == "low"

    def test_a_secret_without_a_resource_policy_is_no_longer_reported(self) -> None:
        assert "SM_NO_RESOURCE_POLICY" not in hcl(SECRET).rule_ids

    def test_cloudformation_rotation_schedule(self) -> None:
        template = f"""
            Resources:
              S:
                Type: AWS::SecretsManager::Secret
                Properties:
                  KmsKeyId: alias/s
              R:
                Type: AWS::SecretsManager::RotationSchedule
                Properties:
                  SecretId: !Ref S
                  RotationLambdaARN: {ROTATION_LAMBDA}
                  RotationRules:
                    AutomaticallyAfterDays: 30
        """
        assert fired(cfn(template), "S") == set()

    def test_a_rotation_whose_secret_cannot_be_found_leaves_the_secret_unjudged(self) -> None:
        result = hcl(SECRET, rotation(Raw("var.secret_id")))
        assert "SM_NO_ROTATION" not in fired(result, "aws_secretsmanager_secret.s")


def ssm(name: Any, kind: str = "String", **extra: Any) -> str:
    attributes = {
        "name": name,
        "type": kind,
        "value": "x",
        "description": "d",
        "allowed_pattern": ".*",
    }
    return res("aws_ssm_parameter", "p", **{**attributes, **extra})


class TestSsm:
    @pytest.mark.parametrize(
        "name",
        [
            "/prod/db/password",
            "/prod/db/PASSWORD",
            "/prod/DbPassword",
            "/prod/api-key",
            "/prod/api_key",
            "/prod/ApiKey",
            "/prod/auth_token",
            "/prod/slack/token",
            "/prod/secrets/stripe",
            "/prod/client_secret",
            "/prod/jwt-secret",
            "/prod/private_key",
            "/prod/access-key",
            "/prod/service/credentials",
            "db_passwd",
        ],
    )
    def test_secret_names_are_recognised(self, name: str) -> None:
        assert aws_data.looks_like_secret_name(name), name

    @pytest.mark.parametrize(
        "name",
        [
            "/prod/region",
            "/prod/db/host",
            "/prod/keyboard-layout",
            "/prod/monkey",
            "/prod/password_policy",
            "/prod/token_url",
            "/prod/api_key_file",
            "/prod/secret_name",
            "/prod/passport",
            "/prod/public_key_path",
            "",
        ],
    )
    def test_other_names_are_not(self, name: str) -> None:
        assert not aws_data.looks_like_secret_name(name), name

    def test_a_plain_string_with_a_secret_name_fires(self) -> None:
        result = hcl(ssm("/prod/db/password"))
        assert fired(result, "aws_ssm_parameter.p") == {"SSM_UNENCRYPTED_PARAMETER"}

    def test_a_plain_string_with_an_ordinary_name_is_silent(self) -> None:
        assert fired(hcl(ssm("/prod/region")), "aws_ssm_parameter.p") == set()

    @pytest.mark.parametrize("kind", ["SecureString", "StringList"])
    def test_other_types_are_silent(self, kind: str) -> None:
        assert fired(hcl(ssm("/prod/db/password", kind)), "aws_ssm_parameter.p") == set()

    def test_a_name_known_after_apply_is_unknown(self) -> None:
        result = hcl(ssm(Raw("var.name")))
        assert fired(result, "aws_ssm_parameter.p") == set()
        assert is_unknown(derived(result, "aws_ssm_parameter.p")["secret_name"])

    def test_the_standard_tier_rule_is_gone(self) -> None:
        result = hcl(ssm("/a", "SecureString", tier="Standard"))
        assert fired(result, "aws_ssm_parameter.p") == set()

    def test_missing_description_and_pattern_are_low_findings(self) -> None:
        source = res("aws_ssm_parameter", "p", name="/prod/region", type="String", value="x")
        assert fired(hcl(source), "aws_ssm_parameter.p") == {
            "SSM_NO_DESCRIPTION",
            "SSM_NO_ALLOWED_PATTERN",
        }

    def test_cloudformation_plain_string(self) -> None:
        template = """
            Resources:
              P:
                Type: AWS::SSM::Parameter
                Properties:
                  Name: /prod/db/password
                  Type: String
                  Value: x
                  Description: d
                  AllowedPattern: ".*"
        """
        assert fired(cfn(template), "P") == {"SSM_UNENCRYPTED_PARAMETER"}


def db(**attributes: Any) -> ScanResult:
    return hcl(res("aws_db_instance", "db", identifier="db", **attributes))


def cluster(**attributes: Any) -> ScanResult:
    return hcl(res("aws_rds_cluster", "c", cluster_identifier="c", **attributes))


class TestRds:
    def test_unencrypted_database_fires(self) -> None:
        assert "RDS_NO_ENCRYPTION" in fired(db(), "aws_db_instance.db")
        assert "RDS_NO_ENCRYPTION" in fired(db(storage_encrypted=False), "aws_db_instance.db")

    def test_encrypted_database_is_silent(self) -> None:
        assert "RDS_NO_ENCRYPTION" not in fired(db(storage_encrypted=True), "aws_db_instance.db")

    @pytest.mark.parametrize("attribute", ["snapshot_identifier", "replicate_source_db"])
    def test_restored_and_replica_databases_inherit_encryption(self, attribute: str) -> None:
        result = db(**{attribute: "source"})
        assert "RDS_NO_ENCRYPTION" not in fired(result, "aws_db_instance.db")

    def test_a_cluster_member_inherits_the_clusters_encryption(self) -> None:
        template = """
            Resources:
              Member:
                Type: AWS::RDS::DBInstance
                Properties:
                  DBClusterIdentifier: cluster
                  DBInstanceClass: db.r6g.large
                  Engine: aurora-postgresql
        """
        assert "RDS_NO_ENCRYPTION" not in fired(cfn(template), "Member")

    def test_an_aurora_cluster_is_judged(self) -> None:
        found = fired(cluster(engine="aurora-postgresql"), "aws_rds_cluster.c")
        assert {"RDS_NO_ENCRYPTION", "RDS_NO_DELETION_PROTECTION", "RDS_NO_IAM_AUTH"} <= found

    def test_a_serverless_v1_cluster_is_always_encrypted(self) -> None:
        result = cluster(engine="aurora-postgresql", engine_mode="serverless")
        assert "RDS_NO_ENCRYPTION" not in fired(result, "aws_rds_cluster.c")

    def test_a_hardened_cluster_is_silent(self) -> None:
        result = cluster(
            engine="aurora-postgresql",
            storage_encrypted=True,
            deletion_protection=True,
            iam_database_authentication_enabled=True,
            backup_retention_period=14,
        )
        assert fired(result, "aws_rds_cluster.c") == set()

    def test_backups_are_off_only_when_the_retention_is_zero(self) -> None:
        assert "RDS_NO_BACKUP" in fired(db(backup_retention_period=0), "aws_db_instance.db")
        assert "RDS_NO_BACKUP" not in fired(db(), "aws_db_instance.db")
        assert "RDS_NO_BACKUP" not in fired(db(backup_retention_period=7), "aws_db_instance.db")

    def test_cluster_backups_are_judged_too(self) -> None:
        assert "RDS_NO_BACKUP" in fired(cluster(backup_retention_period=0), "aws_rds_cluster.c")

    def test_public_cluster_instances_fire(self) -> None:
        source = res(
            "aws_rds_cluster_instance",
            "i",
            cluster_identifier="c",
            instance_class="db.r6g.large",
            publicly_accessible=True,
        )
        assert fired(hcl(source), "aws_rds_cluster_instance.i") == {"RDS_PUBLIC_ACCESS"}

    def test_a_postgres_instance_in_plan_json_with_everything_proper_is_silent(self) -> None:
        values = {
            "identifier": "db",
            "storage_encrypted": True,
            "publicly_accessible": False,
            "backup_retention_period": 14,
            "deletion_protection": True,
        }
        assert fired(plan(("aws_db_instance", "db", values)), "aws_db_instance.db") == set()

    def test_instance_deletion_protection_is_not_judged(self) -> None:
        result = db(storage_encrypted=True)
        assert "RDS_NO_DELETION_PROTECTION" not in fired(result, "aws_db_instance.db")


def table(body: str = "") -> ScanResult:
    attribute = block("attribute", name="id", type="S")
    return hcl(
        res(
            "aws_dynamodb_table",
            "t",
            attribute + body,
            name="t",
            hash_key="id",
            billing_mode="PAY_PER_REQUEST",
        )
    )


class TestDynamoDb:
    KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/k"

    def test_default_encryption_is_reported_as_missing_the_customer_key(self) -> None:
        assert fired(table(), "aws_dynamodb_table.t") == {
            "DYNAMODB_NO_ENCRYPTION",
            "DYNAMODB_NO_PITR",
        }

    def test_the_aws_managed_key_is_not_a_customer_managed_one(self) -> None:
        result = table(block("server_side_encryption", enabled=True))
        assert "DYNAMODB_NO_ENCRYPTION" in fired(result, "aws_dynamodb_table.t")

    def test_a_customer_managed_key_and_recovery_is_silent(self) -> None:
        body = block("server_side_encryption", enabled=True, kms_key_arn=self.KEY_ARN)
        body += block("point_in_time_recovery", enabled=True)
        assert fired(table(body), "aws_dynamodb_table.t") == set()

    def test_recovery_switched_off_in_a_block_is_reported(self) -> None:
        result = table(block("point_in_time_recovery", enabled=False))
        assert "DYNAMODB_NO_PITR" in fired(result, "aws_dynamodb_table.t")

    def test_hcl_and_plan_agree_on_recovery(self) -> None:
        values = {"name": "t", "point_in_time_recovery": [{"enabled": False}]}
        in_plan = plan(("aws_dynamodb_table", "t", values))
        assert "DYNAMODB_NO_PITR" in fired(in_plan, "aws_dynamodb_table.t")
        assert "DYNAMODB_NO_PITR" in fired(table(), "aws_dynamodb_table.t")

    def test_the_autoscaling_rule_is_gone(self) -> None:
        provisioned = res(
            "aws_dynamodb_table", "t", name="t", hash_key="id", billing_mode="PROVISIONED"
        )
        assert "DYNAMODB_NO_AUTOSCALING" not in hcl(provisioned).rule_ids


def cache(**attributes: Any) -> ScanResult:
    source = res(
        "aws_elasticache_replication_group",
        "g",
        replication_group_id="g",
        description="g",
        node_type="cache.t3.small",
        **attributes,
    )
    return hcl(source)


class TestElastiCache:
    GROUP = "aws_elasticache_replication_group.g"

    def test_no_authentication_fires(self) -> None:
        assert "ELASTICACHE_NO_AUTH" in fired(cache(), self.GROUP)

    @pytest.mark.parametrize("attributes", [{"auth_token": "x"}, {"user_group_ids": ["g"]}])
    def test_an_auth_token_or_user_groups_pass(self, attributes: dict[str, Any]) -> None:
        assert "ELASTICACHE_NO_AUTH" not in fired(cache(**attributes), self.GROUP)

    def test_encryption_flags_fire_only_when_false(self) -> None:
        both = {"ELASTICACHE_NO_ENCRYPTION_REST", "ELASTICACHE_NO_ENCRYPTION_TRANSIT"}
        off = cache(at_rest_encryption_enabled=False, transit_encryption_enabled=False)
        assert both <= fired(off, self.GROUP)
        on = cache(at_rest_encryption_enabled=True, transit_encryption_enabled=True)
        assert not both & fired(on, self.GROUP)

    def test_the_missing_authentication_finding_is_medium(self) -> None:
        (threat,) = [t for t in cache().threats if t.rule_id == "ELASTICACHE_NO_AUTH"]
        assert threat.severity.value == "medium"


class TestSearchDomains:
    @pytest.mark.parametrize("rtype", ["aws_elasticsearch_domain", "aws_opensearch_domain"])
    def test_both_types_are_judged_by_the_same_rules(self, rtype: str) -> None:
        rules = {"ES_NO_ENCRYPTION", "ES_PUBLIC_DOMAIN", "ES_NO_NODE_TO_NODE_ENCRYPTION"}
        bare = hcl(res(rtype, "d", domain_name="d"))
        assert rules <= fired(bare, f"{rtype}.d")
        body = (
            block("encrypt_at_rest", enabled=True)
            + block("node_to_node_encryption", enabled=True)
            + block("vpc_options", subnet_ids=["subnet-1"])
        )
        hardened = hcl(res(rtype, "d", body, domain_name="d"))
        assert fired(hardened, f"{rtype}.d") == set()

    def test_encryption_switched_off_in_a_block_is_reported_in_plan_json(self) -> None:
        values = {
            "domain_name": "d",
            "encrypt_at_rest": [{"enabled": False}],
            "node_to_node_encryption": [{"enabled": False}],
            "vpc_options": [{"subnet_ids": ["s"]}],
        }
        result = plan(("aws_opensearch_domain", "d", values))
        assert fired(result, "aws_opensearch_domain.d") == {
            "ES_NO_ENCRYPTION",
            "ES_NO_NODE_TO_NODE_ENCRYPTION",
        }

    def test_the_public_domain_finding_is_a_heuristic_capped_at_high(self) -> None:
        result = hcl(res("aws_opensearch_domain", "d", domain_name="d"))
        (threat,) = [t for t in result.threats if t.rule_id == "ES_PUBLIC_DOMAIN"]
        assert threat.severity.value == "high"

    def test_cloudformation_open_search_domain(self) -> None:
        template = """
            Resources:
              D:
                Type: AWS::OpenSearchService::Domain
                Properties:
                  DomainName: d
        """
        assert {"ES_NO_ENCRYPTION", "ES_PUBLIC_DOMAIN"} <= fired(cfn(template), "D")


# ---------------------------------------------------------------------------
# Logging and detection
# ---------------------------------------------------------------------------


def trail(**attributes: Any) -> ScanResult:
    return hcl(res("aws_cloudtrail", "t", name="t", s3_bucket_name="b", **attributes))


class TestCloudTrail:
    def test_a_default_trail_is_enabled_and_does_not_report_the_enabled_rule(self) -> None:
        assert "CLOUDTRAIL_NOT_ENABLED" not in trail().rule_ids

    def test_logging_switched_off_fires_the_enabled_rule(self) -> None:
        assert "CLOUDTRAIL_NOT_ENABLED" in trail(enable_logging=False).rule_ids

    def test_the_enabled_rule_no_longer_duplicates_the_multi_region_rule(self) -> None:
        assert "CLOUDTRAIL_NOT_MULTI_REGION" in trail().rule_ids
        assert "CLOUDTRAIL_NOT_ENABLED" not in trail().rule_ids
        assert "CLOUDTRAIL_NOT_MULTI_REGION" not in trail(is_multi_region_trail=True).rule_ids

    def test_validation_and_multi_region_default_to_false(self) -> None:
        assert {"CLOUDTRAIL_NOT_MULTI_REGION", "CLOUDTRAIL_NO_LOG_VALIDATION"} <= trail().rule_ids

    def test_a_hardened_trail_reports_nothing(self) -> None:
        result = trail(
            is_multi_region_trail=True,
            enable_log_file_validation=True,
            kms_key_id="arn:aws:kms:us-east-1:1:key/k",
        )
        assert result.rule_ids == set()

    def test_a_key_known_after_apply_never_fires_the_encryption_rule(self) -> None:
        result = plan(
            ("aws_cloudtrail", "t", {"name": "t", "s3_bucket_name": "b", "enable_logging": True}),
            refs={"aws_cloudtrail.t": {"kms_key_id": link("aws_kms_key", "k", "arn")}},
        )
        assert "CLOUDTRAIL_NO_ENCRYPTION" not in result.rule_ids
        assert is_unknown(result.graph.nodes["aws_cloudtrail.t"].properties["kms_key_id"])

    def test_a_trail_with_no_key_is_a_low_finding(self) -> None:
        (threat,) = [t for t in trail().threats if t.rule_id == "CLOUDTRAIL_NO_ENCRYPTION"]
        assert threat.severity.value == "low"

    def test_hcl_plan_and_cloudformation_agree_on_the_defaults(self) -> None:
        values = {
            "name": "t",
            "s3_bucket_name": "b",
            "enable_logging": True,
            "is_multi_region_trail": False,
            "enable_log_file_validation": False,
        }
        in_plan = plan(("aws_cloudtrail", "t", values))
        in_cfn = cfn(
            """
            Resources:
              T:
                Type: AWS::CloudTrail::Trail
                Properties:
                  IsLogging: true
                  S3BucketName: b
            """
        )
        expected = {
            "CLOUDTRAIL_NOT_MULTI_REGION",
            "CLOUDTRAIL_NO_LOG_VALIDATION",
            "CLOUDTRAIL_NO_ENCRYPTION",
        }
        assert fired(trail(), "aws_cloudtrail.t") == expected
        assert fired(in_plan, "aws_cloudtrail.t") == expected
        assert fired(in_cfn, "T") == expected

    def test_the_s3_access_logging_rule_is_gone(self) -> None:
        assert "CLOUDTRAIL_NO_S3_ACCESS_LOGGING" not in trail().rule_ids

    def test_a_trail_type_with_cloudformation_names_is_not_matched_by_prefix(self) -> None:
        result = plan(("aws_cloudtrail_trail", "t", {"KMSKeyId": "k"}))
        assert not fired(result, "aws_cloudtrail_trail.t")


RECORDER = res("aws_config_configuration_recorder", "r", name="r", role_arn="arn:aws:iam::1:r")


class TestConfigAndGuardDuty:
    def test_a_recorder_is_off_when_its_status_resource_says_so(self) -> None:
        status = res(
            "aws_config_configuration_recorder_status",
            "s",
            name=Raw("aws_config_configuration_recorder.r.name"),
            is_enabled=False,
        )
        result = hcl(RECORDER, status)
        status_address = "aws_config_configuration_recorder_status.s"
        assert fired(result, status_address) == {"CONFIG_NOT_ENABLED"}
        assert fired(result, "aws_config_configuration_recorder.r") == set()

    def test_a_recorder_with_no_recording_group_records_everything(self) -> None:
        assert fired(hcl(RECORDER), "aws_config_configuration_recorder.r") == set()

    def test_not_all_resources(self) -> None:
        group = block("recording_group", all_supported=False, resource_types=["AWS::S3::Bucket"])
        source = res(
            "aws_config_configuration_recorder", "r", group, name="r", role_arn="arn:aws:iam::1:r"
        )
        found = fired(hcl(source), "aws_config_configuration_recorder.r")
        assert found == {"CONFIG_NOT_ALL_RESOURCES"}

    def test_the_delivery_channel_and_aggregator_rules_are_gone(self) -> None:
        aggregator = block(
            "organization_aggregation_source", all_regions=True, role_arn="arn:aws:iam::1:role/o"
        )
        result = hcl(
            res("aws_config_delivery_channel", "d", name="d"),
            res("aws_config_configuration_aggregator", "a", aggregator, name="a"),
        )
        assert result.rule_ids == set()

    def test_guardduty_defaults_are_silent_and_explicit_off_fires(self) -> None:
        assert hcl(res("aws_guardduty_detector", "d", enable=True)).rule_ids == set()
        assert hcl(res("aws_guardduty_detector", "d")).rule_ids == set()
        off = hcl(res("aws_guardduty_detector", "d", enable=False))
        assert off.rule_ids == {"GUARDDUTY_NOT_ENABLED"}

    @pytest.mark.parametrize(
        ("datasources", "rule"),
        [
            ({"s3_logs": [{"enable": False}]}, "GUARDDUTY_NO_S3_PROTECTION"),
            ({"kubernetes": [{"audit_logs": [{"enable": False}]}]}, "GUARDDUTY_NO_EKS_PROTECTION"),
            (
                {
                    "malware_protection": [
                        {"scan_ec2_instance_with_findings": [{"ebs_volumes": [{"enable": False}]}]}
                    ]
                },
                "GUARDDUTY_NO_MALWARE_SCAN",
            ),
        ],
    )
    def test_each_datasource_switched_off_in_plan_json_fires_its_rule(
        self, datasources: dict[str, Any], rule: str
    ) -> None:
        values = {"enable": True, "datasources": [datasources]}
        result = plan(("aws_guardduty_detector", "d", values))
        assert fired(result, "aws_guardduty_detector.d") == {rule}


def warehouse(body: str = "", *more: str, **attributes: Any) -> ScanResult:
    cluster_resource = res(
        "aws_redshift_cluster",
        "c",
        body,
        cluster_identifier="c",
        node_type="dc2.large",
        manage_master_password=True,
        **attributes,
    )
    return hcl(cluster_resource, *more)


def redshift_logging(cluster_identifier: Any) -> str:
    return res(
        "aws_redshift_logging",
        "l",
        cluster_identifier=cluster_identifier,
        log_destination_type="s3",
        bucket_name="audit",
    )


REDSHIFT_CFN = """
    Resources:
      C:
        Type: AWS::Redshift::Cluster
        Properties:
          ClusterType: single-node
          DBName: dev
          MasterUsername: admin
          ManageMasterPassword: true
          NodeType: dc2.large
"""


class TestRedshift:
    CLUSTER = "aws_redshift_cluster.c"

    def test_the_terraform_default_is_public(self) -> None:
        assert "REDSHIFT_PUBLIC_ACCESS" in fired(warehouse(), self.CLUSTER)

    def test_explicitly_private_is_silent(self) -> None:
        result = warehouse(publicly_accessible=False)
        assert "REDSHIFT_PUBLIC_ACCESS" not in fired(result, self.CLUSTER)

    def test_a_cloudformation_cluster_that_does_not_say_is_not_judged(self) -> None:
        result = cfn(REDSHIFT_CFN)
        assert "REDSHIFT_PUBLIC_ACCESS" not in fired(result, "C")
        assert "publicly_accessible" not in derived(result, "C")

    def test_a_cloudformation_cluster_that_says_so_is_public(self) -> None:
        result = cfn(REDSHIFT_CFN + "          PubliclyAccessible: true\n")
        assert "REDSHIFT_PUBLIC_ACCESS" in fired(result, "C")

    def test_encryption_is_reported_only_when_it_is_switched_off(self) -> None:
        assert "REDSHIFT_NO_ENCRYPTION" in fired(warehouse(encrypted=False), self.CLUSTER)
        assert "REDSHIFT_NO_ENCRYPTION" not in fired(warehouse(), self.CLUSTER)
        assert "REDSHIFT_NO_ENCRYPTION" not in fired(warehouse(encrypted=True), self.CLUSTER)

    def test_no_logging_fires_and_the_logging_resource_fixes_it(self) -> None:
        assert "REDSHIFT_NO_LOGGING" in fired(warehouse(), self.CLUSTER)
        logged = warehouse("", redshift_logging(Raw("aws_redshift_cluster.c.id")))
        assert "REDSHIFT_NO_LOGGING" not in fired(logged, self.CLUSTER)
        assert fired(logged, "aws_redshift_logging.l") == set()

    def test_a_logging_resource_with_a_literal_cluster_name_is_matched(self) -> None:
        logged = warehouse("", redshift_logging("c"))
        assert "REDSHIFT_NO_LOGGING" not in fired(logged, self.CLUSTER)

    def test_a_logging_resource_for_another_cluster_does_not_help(self) -> None:
        other = warehouse("", redshift_logging("other"))
        assert "REDSHIFT_NO_LOGGING" in fired(other, self.CLUSTER)

    def test_a_logging_resource_that_cannot_be_matched_leaves_the_cluster_unjudged(self) -> None:
        result = warehouse("", redshift_logging(Raw("var.cluster")))
        assert "REDSHIFT_NO_LOGGING" not in fired(result, self.CLUSTER)
        assert is_unknown(derived(result, self.CLUSTER)["logging_enabled"])

    def test_the_deprecated_inline_logging_block_counts(self) -> None:
        on = warehouse(block("logging", enable=True, bucket_name="b"))
        off = warehouse(block("logging", enable=False))
        assert "REDSHIFT_NO_LOGGING" not in fired(on, self.CLUSTER)
        assert "REDSHIFT_NO_LOGGING" in fired(off, self.CLUSTER)

    def test_cloudformation_logging_properties_count(self) -> None:
        template = REDSHIFT_CFN + "          LoggingProperties:\n            BucketName: audit\n"
        assert "REDSHIFT_NO_LOGGING" not in fired(cfn(template), "C")

    def test_a_hardened_cluster_is_silent(self) -> None:
        result = warehouse(
            block("logging", enable=True, bucket_name="b"),
            publicly_accessible=False,
            encrypted=True,
        )
        assert fired(result, self.CLUSTER) == set()


# ---------------------------------------------------------------------------
# Provider defaults and the facts module
# ---------------------------------------------------------------------------


class TestProviderDefaults:
    def test_the_defaults_table_names_exact_types_and_plain_values(self) -> None:
        assert aws_data.DEFAULTS == {
            "aws_kms_key": {"enable_key_rotation": False},
            "aws_cloudtrail": {
                "is_multi_region_trail": False,
                "enable_log_file_validation": False,
                "enable_logging": True,
            },
        }

    def test_when_the_graph_records_formats_the_defaults_are_filled_and_the_rules_agree(
        self,
    ) -> None:
        graph = hcl(res("aws_kms_key", "k", description="k")).graph
        assert graph.node_formats["aws_kms_key.k"] == "terraform_hcl"
        node = graph.nodes["aws_kms_key.k"]
        assert node.properties["enable_key_rotation"] is False
        assert "enable_key_rotation" in node.properties["derived"]["defaults_applied"]
        assert matches_rule(_rules()["KMS_KEY_ROTATION_DISABLED"], node)

    def test_a_plan_is_never_filled(self) -> None:
        result = plan(("aws_cloudtrail", "t", {"name": "t", "s3_bucket_name": "b"}))
        assert "is_multi_region_trail" not in result.graph.nodes["aws_cloudtrail.t"].properties


def statement(**fields: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "effect": "Allow",
        "actions": [],
        "not_actions": [],
        "resources": [],
        "not_resources": [],
        "principals": [],
        "has_condition": False,
        "condition_keys": [],
    }
    return {**base, **fields}


class TestPolicyFacts:
    """The facts module on statement dicts, without a graph."""

    def test_all_actions_on_all_resources(self) -> None:
        for actions in (["*"], ["*:*"], ["s3:Get*", "*"]):
            admin = statement(actions=actions, resources=["*"])
            assert aws_data._all_actions_everywhere(admin) is True, actions
        for fields in (
            {"actions": ["s3:*"], "resources": ["*"]},
            {"actions": ["*"], "resources": ["arn:aws:s3:::b"]},
            {"effect": "Deny", "actions": ["*"], "resources": ["*"]},
            {"actions": [], "not_actions": ["iam:*"], "resources": ["*"]},
        ):
            assert aws_data._all_actions_everywhere(statement(**fields)) is False, fields

    def test_an_unknown_entry_decides_nothing_unless_a_known_one_does(self) -> None:
        unknown = Unknown("var.action")
        undecided = statement(actions=[unknown], resources=["*"])
        assert aws_data._all_actions_everywhere(undecided) is None
        decided = statement(actions=[unknown, "*"], resources=["*"])
        assert aws_data._all_actions_everywhere(decided) is True
        scoped = statement(actions=[unknown], resources=["arn:aws:s3:::b"])
        assert aws_data._all_actions_everywhere(scoped) is False

    def test_service_wildcards(self) -> None:
        for action in ("iam:*", "S3:*", "ec2:*", "cloud-9:*"):
            found = statement(actions=[action], resources=["*"])
            assert aws_data._service_wildcard_everywhere(found) is True, action
        for action in ("iam:Get*", "s3:*Object", "iam:PassRole"):
            found = statement(actions=[action], resources=["*"])
            assert aws_data._service_wildcard_everywhere(found) is False, action
        # a service wildcard on a named resource is the normal way to grant a bucket
        scoped = statement(actions=["s3:*"], resources=["arn:aws:s3:::b/*"])
        assert aws_data._service_wildcard_everywhere(scoped) is False
        # every action on every resource is the administrator rule, not this one
        admin = statement(actions=["*"], resources=["*"])
        assert aws_data._service_wildcard_everywhere(admin) is False
        # every action on a limited resource set belongs here
        limited = statement(actions=["*"], resources=["arn:aws:s3:::ecommerce-*"])
        assert aws_data._service_wildcard_everywhere(limited) is True

    def test_passrole_patterns(self) -> None:
        for action in ("iam:PassRole", "IAM:PASSROLE", "iam:Pass*", "iam:*Role", "iam:P*"):
            assert aws_data._covers_passrole(action), action
        for action in ("*", "*:*", "iam:*", "iam:GetRole", "sts:AssumeRole", "iam:CreateRole"):
            assert not aws_data._covers_passrole(action), action

    def test_the_restricting_keys_are_lower_case_and_documented(self) -> None:
        keys = aws_data.RESTRICTING_CONDITION_KEYS
        assert all(key == key.lower() for key in keys)
        assert {
            "aws:principalorgid",
            "aws:sourcevpce",
            "aws:sourcevpc",
            "aws:sourcearn",
            "aws:sourceaccount",
            "aws:principalarn",
            "kms:calleraccount",
        } <= keys
        assert "aws:securetransport" not in keys
        assert "aws:sourceip" not in keys

    def test_any_principal_needs_allow_a_wildcard_and_no_restricting_key(self) -> None:
        assert aws_data._any_principal(statement(principals=["*"])) is True
        assert aws_data._any_principal(statement(principals=["*"], effect="Deny")) is False
        assert aws_data._any_principal(statement(principals=["arn:aws:iam::1:root"])) is False
        restricted = statement(
            principals=["*"], has_condition=True, condition_keys=["AWS:PrincipalOrgId"]
        )
        assert aws_data._any_principal(restricted) is False
        decorative = statement(
            principals=["*"], has_condition=True, condition_keys=["aws:SecureTransport"]
        )
        assert aws_data._any_principal(decorative) is True

    def test_over_leaves_a_node_with_nothing_to_judge_out(self) -> None:
        judge = aws_data._any_principal
        assert aws_data._over([], judge) is None
        assert aws_data._over([None, []], judge) is None
        assert is_unknown(aws_data._over([Unknown()], judge))
        hit = [statement(principals=["*"])]
        assert aws_data._over([Unknown(), hit], judge) is True
        miss = [statement(principals=["arn:aws:iam::1:root"])]
        assert aws_data._over([miss], judge) is False
        assert is_unknown(aws_data._over([miss, Unknown()], judge))


class TestUnknownValuesNeverDecide:
    def test_an_unknown_policy_leaves_every_rule_silent(self) -> None:
        result = plan(
            ("aws_iam_policy", "p", {"name": "p"}),
            refs={"aws_iam_policy.p": {"policy": ["data.aws_iam_policy_document.p.json"]}},
        )
        assert fired(result, "aws_iam_policy.p") == set()

    def test_unknown_flags_leave_the_cloudtrail_rules_silent(self) -> None:
        result = plan(
            ("aws_cloudtrail", "t", {"name": "t", "s3_bucket_name": "b"}),
            refs={
                "aws_cloudtrail.t": {
                    "is_multi_region_trail": ["var.multi"],
                    "enable_log_file_validation": ["var.validate"],
                    "enable_logging": ["var.on"],
                    "kms_key_id": ["aws_kms_key.k.arn"],
                }
            },
        )
        assert fired(result, "aws_cloudtrail.t") == set()

    def test_unknown_bucket_settings_are_not_absences(self) -> None:
        unknown_settings = ("acl", "logging", "versioning", "server_side_encryption_configuration")
        result = plan(
            ("aws_s3_bucket", "b", {"bucket": "b"}),
            refs={"aws_s3_bucket.b": {name: [f"var.{name}"] for name in unknown_settings}},
        )
        assert fired(result, "aws_s3_bucket.b") == set()
