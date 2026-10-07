"""Tests for threatcode.parsers._cfn_properties: translating CloudFormation properties.

The translator turns PascalCase properties into the Terraform attribute names and shapes the
rules read, resolves the intrinsics a template decides, and leaves an `Unknown` where it does
not, so a rule can tell "not configured" from "configured, value not known here".
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from threatcode.exceptions import ParseError
from threatcode.parsers._cfn_properties import (
    RAW_KEY,
    PathMap,
    TemplateContext,
    Translation,
    canonical_json,
    coerce_scalar,
    evaluate_condition,
    snake_case,
    spec_for,
    translate,
)
from threatcode.parsers._cfn_refs import WorkBudget
from threatcode.values import Unknown, is_unknown


def template(**sections: Any) -> TemplateContext:
    return TemplateContext.from_template(sections)


def tr(cfn_type: str, properties: dict[str, Any], context: TemplateContext | None = None) -> Any:
    return translate(cfn_type, properties, context)


def plain(translation: Translation) -> dict[str, Any]:
    """The translated attributes without the raw copy."""
    return {k: v for k, v in translation.properties.items() if k != RAW_KEY}


def unknown_reference(value: Any) -> str:
    assert is_unknown(value), f"{value!r} is not Unknown"
    return value.reference  # type: ignore[no-any-return]


class TestSnakeCase:
    @pytest.mark.parametrize(
        ("pascal", "snake"),
        [
            ("BucketName", "bucket_name"),
            ("DBInstanceClass", "db_instance_class"),
            ("KMSKeyId", "kms_key_id"),
            ("KmsMasterKeyId", "kms_master_key_id"),
            ("IAMDatabaseAuthenticationEnabled", "iam_database_authentication_enabled"),
            ("EnableIAMDatabaseAuthentication", "enable_iam_database_authentication"),
            ("MultiAZ", "multi_az"),
            ("MultiAZEnabled", "multi_az_enabled"),
            ("S3BucketName", "s3_bucket_name"),
            ("SSESpecification", "sse_specification"),
            ("VPCSecurityGroups", "vpc_security_groups"),
            ("VPCZoneIdentifier", "vpc_zone_identifier"),
            ("TargetGroupARNs", "target_group_arns"),
            ("SubnetIds", "subnet_ids"),
            ("VpcSecurityGroupIDs", "vpc_security_group_ids"),
            ("CidrIpv6", "cidr_ipv6"),
            ("IPv6Enabled", "ipv6_enabled"),
            ("EnforceHTTPS", "enforce_https"),
            ("HTTPSPort", "https_port"),
            ("OriginSSLProtocols", "origin_ssl_protocols"),
            ("TLSSecurityPolicy", "tls_security_policy"),
            ("WebACLId", "web_acl_id"),
            ("Ec2SshKey", "ec2_ssh_key"),
            ("RoleARN", "role_arn"),
            ("ScanEc2InstanceWithFindings", "scan_ec2_instance_with_findings"),
            ("Id", "id"),
            ("already_snake", "already_snake"),
            ("x", "x"),
            ("", ""),
        ],
    )
    def test_names(self, pascal: str, snake: str) -> None:
        assert snake_case(pascal) == snake


class TestCoerceScalar:
    @pytest.mark.parametrize(
        ("key", "value", "expected"),
        [
            ("storage_encrypted", "true", True),
            ("storage_encrypted", "false", False),
            ("storage_encrypted", "True", True),
            ("storage_encrypted", " false ", False),
            ("backup_retention_period", "7", 7),
            ("backup_retention_period", "-1", -1),
            ("threshold", "0.5", 0.5),
            ("port", "8080", 8080),
            ("from_port", True, True),
            ("from_port", 22, 22),
        ],
    )
    def test_coerced(self, key: str, value: Any, expected: Any) -> None:
        result = coerce_scalar(key, value)
        assert result == expected
        assert type(result) is type(expected)

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("name", "12345"),
            ("bucket", "000123"),
            ("version", "1.30"),
            ("engine_version", "15"),
            ("kms_key_id", "1234"),
            ("db_subnet_group_name", "true"),
            ("value", "true"),
            ("cpu", "256"),
            ("memory", "512"),
            ("password", "1234"),
            ("protocol", "-1"),
            ("port", "007"),
            ("port", "1e3"),
            ("port", "99999999999999999999"),
            ("cidr_block", "10.0.0.0/16"),
            ("something", "10 apples"),
            ("something", ""),
        ],
    )
    def test_kept_as_text(self, key: str, value: str) -> None:
        assert coerce_scalar(key, value) == value
        assert isinstance(coerce_scalar(key, value), str)

    def test_an_unknown_passes_through(self) -> None:
        value = Unknown("Param")
        assert coerce_scalar("port", value) is value

    def test_non_strings_pass_through(self) -> None:
        assert coerce_scalar("port", None) is None
        assert coerce_scalar("port", [1]) == [1]


class TestCanonicalJson:
    def test_compact_with_sorted_keys(self) -> None:
        assert canonical_json({"b": 1, "a": [True, None]}) == '{"a":[true,null],"b":1}'

    def test_a_string_is_kept(self) -> None:
        assert canonical_json('{"a": 1}') == '{"a": 1}'

    def test_none_and_unknown_are_kept(self) -> None:
        assert canonical_json(None) is None
        unknown = Unknown("X")
        assert canonical_json(unknown) is unknown

    def test_an_unknown_inside_is_written_as_its_text(self) -> None:
        assert canonical_json({"Resource": Unknown("Bucket.Arn")}) == (
            '{"Resource":"(known after apply)"}'
        )

    def test_non_ascii_is_not_escaped(self) -> None:
        assert canonical_json({"k": "café"}) == '{"k":"café"}'


class TestRawCopy:
    def test_the_original_properties_stay_under_cfn(self) -> None:
        raw = {"BucketName": "b", "VersioningConfiguration": {"Status": "Enabled"}}
        result = tr("AWS::S3::Bucket", raw)
        assert result.properties[RAW_KEY] is raw
        assert raw == {"BucketName": "b", "VersioningConfiguration": {"Status": "Enabled"}}

    def test_the_input_is_never_modified(self) -> None:
        raw = {
            "Tags": [{"Key": "a", "Value": "b"}],
            "SecurityGroupIngress": [{"IpProtocol": "tcp", "CidrIp": "0.0.0.0/0"}],
            "PolicyDocument": {"Statement": [{"Action": "*"}]},
            "Env": {"Fn::If": ["C", {"Ref": "AWS::NoValue"}, "x"]},
        }
        before = json.dumps(raw, sort_keys=True)
        for cfn_type in ("AWS::EC2::SecurityGroup", "AWS::IAM::Policy", "AWS::Foo::Bar"):
            tr(cfn_type, raw, template(Conditions={"C": {"Fn::Equals": ["a", "a"]}}))
        assert json.dumps(raw, sort_keys=True) == before

    def test_an_empty_properties_mapping(self) -> None:
        result = tr("AWS::S3::Bucket", {})
        assert plain(result) == {}
        assert result.unresolved == 0


class TestIntrinsicResolution:
    def test_ref_to_a_parameter_with_a_default_is_the_default(self) -> None:
        ctx = template(Parameters={"Cidr": {"Type": "String", "Default": "10.0.0.0/16"}})
        result = tr("AWS::EC2::VPC", {"CidrBlock": {"Ref": "Cidr"}}, ctx)
        assert plain(result) == {"cidr_block": "10.0.0.0/16"}
        assert result.unresolved == 0

    def test_ref_to_a_parameter_without_a_default_is_unknown(self) -> None:
        ctx = template(Parameters={"Pw": {"Type": "String", "NoEcho": True}})
        result = tr("AWS::RDS::DBInstance", {"MasterUserPassword": {"Ref": "Pw"}}, ctx)
        assert unknown_reference(plain(result)["master_user_password"]) == "Pw"
        assert result.unresolved == 1

    def test_ref_to_a_resource_is_unknown_with_the_logical_id(self) -> None:
        result = tr("AWS::EC2::Subnet", {"VpcId": {"Ref": "Vpc"}})
        assert unknown_reference(plain(result)["vpc_id"]) == "Vpc"

    def test_getatt_is_unknown_with_the_dotted_name(self) -> None:
        for argument in (["Role", "Arn"], "Role.Arn"):
            result = tr("AWS::Lambda::Function", {"Role": {"Fn::GetAtt": argument}})
            assert unknown_reference(plain(result)["role"]) == "Role.Arn"

    def test_a_number_parameter_default_is_a_number(self) -> None:
        ctx = template(Parameters={"Days": {"Type": "Number", "Default": "7"}})
        result = tr("AWS::RDS::DBInstance", {"BackupRetentionPeriod": {"Ref": "Days"}}, ctx)
        assert plain(result)["backup_retention_period"] == 7

    def test_a_string_parameter_default_is_text_and_then_coerced_by_the_attribute(self) -> None:
        ctx = template(Parameters={"Encrypted": {"Type": "String", "Default": "true"}})
        result = tr("AWS::RDS::DBInstance", {"StorageEncrypted": {"Ref": "Encrypted"}}, ctx)
        assert plain(result)["storage_encrypted"] is True

    def test_a_list_parameter_default_is_split(self) -> None:
        ctx = template(Parameters={"Subnets": {"Type": "CommaDelimitedList", "Default": "a, b,c"}})
        result = tr("AWS::RDS::DBSubnetGroup", {"SubnetIds": {"Ref": "Subnets"}}, ctx)
        assert plain(result)["subnet_ids"] == ["a", "b", "c"]

    def test_an_ssm_parameter_is_unknown_even_with_a_default(self) -> None:
        # the default of an SSM parameter type is the parameter's name, not its value
        ctx = template(
            Parameters={"Ami": {"Type": "AWS::SSM::Parameter::Value<String>", "Default": "/ami"}}
        )
        result = tr("AWS::EC2::Instance", {"ImageId": {"Ref": "Ami"}}, ctx)
        assert unknown_reference(plain(result)["ami"]) == "Ami"

    def test_a_parameter_default_that_is_a_date_is_text(self) -> None:
        import datetime

        ctx = template(
            Parameters={"Since": {"Type": "String", "Default": datetime.date(2024, 1, 2)}}
        )
        result = tr("AWS::SSM::Parameter", {"Value": {"Ref": "Since"}}, ctx)
        assert plain(result)["value"] == "2024-01-02"

    def test_partition_and_url_suffix_resolve_but_region_and_account_do_not(self) -> None:
        props = {
            "Value": {
                "Fn::Sub": "arn:${AWS::Partition}:s3:::b.${AWS::URLSuffix}",
            },
            "Description": {"Fn::Sub": "in ${AWS::Region}"},
            "Name": {"Ref": "AWS::AccountId"},
        }
        result = plain(tr("AWS::SSM::Parameter", props))
        assert result["value"] == "arn:aws:s3:::b.amazonaws.com"
        assert unknown_reference(result["description"]) == "in ${AWS::Region}"
        assert unknown_reference(result["name"]) == "AWS::AccountId"

    def test_import_value_is_unknown(self) -> None:
        result = tr("AWS::EC2::Subnet", {"VpcId": {"Fn::ImportValue": "network-VpcId"}})
        assert "network-VpcId" in unknown_reference(plain(result)["vpc_id"])

    @pytest.mark.parametrize(
        "function", ["Fn::GetAZs", "Fn::Cidr", "Fn::Transform", "Fn::Whatever"]
    )
    def test_other_functions_are_unknown(self, function: str) -> None:
        result = tr("AWS::EC2::Subnet", {"AvailabilityZone": {function: ["x"]}})
        assert unknown_reference(plain(result)["availability_zone"]) == function

    def test_each_unresolved_intrinsic_is_counted_once(self) -> None:
        props = {
            "A": {"Ref": "R1"},
            "B": {"Fn::GetAtt": ["R2", "Arn"]},
            "C": {"Fn::Join": ["-", [{"Ref": "R3"}, "x"]]},
            "D": "plain",
        }
        assert tr("AWS::Foo::Bar", props).unresolved == 3

    def test_deciding_a_condition_does_not_count(self) -> None:
        ctx = template(
            Parameters={"Env": {"Type": "String", "Default": "prod"}},
            Conditions={"IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}},
        )
        result = tr("AWS::Foo::Bar", {"A": {"Fn::If": ["IsProd", 1, 2]}}, ctx)
        assert result.unresolved == 0


class TestNoValue:
    def test_a_property_set_to_no_value_is_absent(self) -> None:
        result = tr(
            "AWS::RDS::DBInstance", {"KmsKeyId": {"Ref": "AWS::NoValue"}, "Engine": "mysql"}
        )
        assert plain(result) == {"engine": "mysql"}

    def test_a_list_item_that_is_no_value_is_dropped(self) -> None:
        props = {"SubnetIds": ["a", {"Ref": "AWS::NoValue"}, "b"]}
        assert plain(tr("AWS::RDS::DBSubnetGroup", props))["subnet_ids"] == ["a", "b"]

    def test_a_decidable_if_branch_of_no_value_removes_the_property(self) -> None:
        ctx = template(Conditions={"No": {"Fn::Equals": ["a", "b"]}})
        props = {"KmsKeyId": {"Fn::If": ["No", "key", {"Ref": "AWS::NoValue"}]}}
        assert plain(tr("AWS::SQS::Queue", props, ctx)) == {}

    def test_an_undecidable_if_with_no_value_is_unknown_not_absent(self) -> None:
        props = {"KmsKeyId": {"Fn::If": ["Mystery", "key", {"Ref": "AWS::NoValue"}]}}
        result = plain(tr("AWS::SQS::Queue", props))
        assert "kms_key_id" in result
        assert is_unknown(result["kms_key_id"])


class TestConditions:
    PARAMS = {
        "Env": {"Type": "String", "Default": "prod"},
        "Size": {"Type": "Number", "Default": "3"},
        "Open": {"Type": "String"},
    }

    def ctx(self, **conditions: Any) -> TemplateContext:
        return template(Parameters=self.PARAMS, Conditions=conditions)

    def pick(self, condition: Any, **conditions: Any) -> Any:
        ctx = self.ctx(**conditions)
        props = {"Value": {"Fn::If": ["Test", "yes", "no"]}}
        ctx = template(Parameters=self.PARAMS, Conditions={"Test": condition, **conditions})
        return plain(tr("AWS::SSM::Parameter", props, ctx))["value"]

    def test_equals_true_and_false(self) -> None:
        assert self.pick({"Fn::Equals": [{"Ref": "Env"}, "prod"]}) == "yes"
        assert self.pick({"Fn::Equals": [{"Ref": "Env"}, "dev"]}) == "no"

    def test_equals_compares_numbers_as_text_like_cloudformation(self) -> None:
        assert self.pick({"Fn::Equals": [{"Ref": "Size"}, 3]}) == "yes"
        assert self.pick({"Fn::Equals": [{"Ref": "Size"}, "3"]}) == "yes"
        assert self.pick({"Fn::Equals": [{"Ref": "Size"}, 4]}) == "no"

    def test_equals_compares_booleans_as_text(self) -> None:
        assert self.pick({"Fn::Equals": [True, "true"]}) == "yes"

    def test_not(self) -> None:
        assert self.pick({"Fn::Not": [{"Fn::Equals": [{"Ref": "Env"}, "dev"]}]}) == "yes"
        assert self.pick({"Fn::Not": [{"Fn::Equals": [{"Ref": "Env"}, "prod"]}]}) == "no"

    def test_and_or(self) -> None:
        prod = {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
        dev = {"Fn::Equals": [{"Ref": "Env"}, "dev"]}
        assert self.pick({"Fn::And": [prod, prod]}) == "yes"
        assert self.pick({"Fn::And": [prod, dev]}) == "no"
        assert self.pick({"Fn::Or": [dev, prod]}) == "yes"
        assert self.pick({"Fn::Or": [dev, dev]}) == "no"

    def test_and_with_a_known_false_is_false_even_if_another_part_is_unknown(self) -> None:
        dev = {"Fn::Equals": [{"Ref": "Env"}, "dev"]}
        unknown = {"Fn::Equals": [{"Ref": "Open"}, "yes"]}
        assert self.pick({"Fn::And": [unknown, dev]}) == "no"
        assert is_unknown(self.pick({"Fn::And": [unknown, {"Fn::Equals": ["a", "a"]}]}))

    def test_or_with_a_known_true_is_true_even_if_another_part_is_unknown(self) -> None:
        prod = {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
        unknown = {"Fn::Equals": [{"Ref": "Open"}, "yes"]}
        assert self.pick({"Fn::Or": [unknown, prod]}) == "yes"
        assert is_unknown(self.pick({"Fn::Or": [unknown, {"Fn::Equals": ["a", "b"]}]}))

    def test_a_condition_may_name_another_condition(self) -> None:
        value = self.pick({"Condition": "IsProd"}, IsProd={"Fn::Equals": [{"Ref": "Env"}, "prod"]})
        assert value == "yes"

    def test_a_condition_cycle_is_undecidable(self) -> None:
        value = self.pick({"Condition": "Other"}, Other={"Condition": "Test"})
        assert is_unknown(value)

    def test_a_pseudo_parameter_makes_it_undecidable(self) -> None:
        assert is_unknown(self.pick({"Fn::Equals": [{"Ref": "AWS::Region"}, "us-east-1"]}))

    def test_a_parameter_without_a_default_makes_it_undecidable(self) -> None:
        assert is_unknown(self.pick({"Fn::Equals": [{"Ref": "Open"}, "yes"]}))

    def test_a_missing_condition_is_undecidable(self) -> None:
        ctx = template()
        result = plain(tr("AWS::SSM::Parameter", {"Value": {"Fn::If": ["Nope", "a", "b"]}}, ctx))
        assert is_unknown(result["value"])

    def test_the_branch_that_is_not_taken_is_not_resolved(self) -> None:
        ctx = template(Conditions={"Yes": {"Fn::Equals": ["a", "a"]}})
        props = {"Value": {"Fn::If": ["Yes", "x", {"Ref": "SomeResource"}]}}
        result = tr("AWS::SSM::Parameter", props, ctx)
        assert plain(result) == {"value": "x"}
        assert result.unresolved == 0

    def test_a_malformed_if_is_unknown(self) -> None:
        result = plain(tr("AWS::SSM::Parameter", {"Value": {"Fn::If": ["only-one"]}}))
        assert is_unknown(result["value"])

    def test_evaluate_condition_helper(self) -> None:
        ctx = self.ctx(IsProd={"Fn::Equals": [{"Ref": "Env"}, "prod"]})
        assert evaluate_condition("IsProd", ctx) is True
        assert evaluate_condition("Missing", ctx) is None
        assert evaluate_condition({"Fn::Equals": ["a", "b"]}, ctx) is False
        assert evaluate_condition(True, ctx) is True


class TestStringFunctions:
    CTX = template(
        Parameters={"Env": {"Type": "String", "Default": "prod"}, "Open": {"Type": "String"}},
        Mappings={"Sizes": {"prod": {"Type": "m5.large", "Count": 3}}},
    )

    def value(self, expression: Any) -> Any:
        return plain(tr("AWS::SSM::Parameter", {"Value": expression}, self.CTX))["value"]

    def test_join_of_known_parts(self) -> None:
        assert self.value({"Fn::Join": ["-", [{"Ref": "Env"}, "orders", 7]]}) == "prod-orders-7"

    def test_join_with_an_unknown_part_is_that_unknown(self) -> None:
        result = self.value({"Fn::Join": ["-", [{"Ref": "Open"}, "orders"]]})
        assert unknown_reference(result) == "Open"

    def test_sub_with_known_parts(self) -> None:
        assert self.value({"Fn::Sub": "${Env}-bucket"}) == "prod-bucket"

    def test_sub_with_a_variable_map(self) -> None:
        assert self.value({"Fn::Sub": ["${Name}-${Env}", {"Name": "api"}]}) == "api-prod"

    def test_sub_escape_is_literal_text(self) -> None:
        assert self.value({"Fn::Sub": "${!Literal}"}) == "${Literal}"

    def test_sub_with_a_resource_attribute_is_unknown_with_the_template(self) -> None:
        result = self.value({"Fn::Sub": "${Bucket.Arn}/*"})
        assert unknown_reference(result) == "${Bucket.Arn}/*"

    def test_select_and_split(self) -> None:
        assert self.value({"Fn::Select": [1, ["a", "b", "c"]]}) == "b"
        assert self.value({"Fn::Select": [0, {"Fn::Split": [",", "x,y"]}]}) == "x"

    def test_select_out_of_range_is_unknown(self) -> None:
        assert is_unknown(self.value({"Fn::Select": [5, ["a"]]}))

    def test_findinmap_with_known_keys(self) -> None:
        assert self.value({"Fn::FindInMap": ["Sizes", {"Ref": "Env"}, "Type"]}) == "m5.large"
        assert self.value({"Fn::FindInMap": ["Sizes", "prod", "Count"]}) == 3

    def test_findinmap_with_a_missing_key_is_unknown(self) -> None:
        assert is_unknown(self.value({"Fn::FindInMap": ["Sizes", "dev", "Type"]}))
        assert is_unknown(self.value({"Fn::FindInMap": ["Nope", "prod", "Type"]}))

    def test_findinmap_with_an_unknown_key_is_that_unknown(self) -> None:
        result = self.value({"Fn::FindInMap": ["Sizes", {"Ref": "Open"}, "Type"]})
        assert unknown_reference(result) == "Open"

    def test_base64_keeps_the_text(self) -> None:
        assert self.value({"Fn::Base64": "#!/bin/sh\necho hi"}) == "#!/bin/sh\necho hi"

    def test_base64_of_an_unknown_is_unknown(self) -> None:
        assert is_unknown(self.value({"Fn::Base64": {"Fn::Sub": "${Thing.Id}"}}))


class TestTags:
    def test_a_key_value_list_becomes_a_mapping(self) -> None:
        props = {"Tags": [{"Key": "Env", "Value": "prod"}, {"Key": "Team", "Value": "data"}]}
        assert plain(tr("AWS::S3::Bucket", props))["tags"] == {"Env": "prod", "Team": "data"}

    def test_keys_are_not_snake_cased(self) -> None:
        props = {"Tags": [{"Key": "CostCenter", "Value": "A"}, {"Key": "aws:cfn:x", "Value": "b"}]}
        assert set(plain(tr("AWS::S3::Bucket", props))["tags"]) == {"CostCenter", "aws:cfn:x"}

    def test_a_plain_mapping_is_kept(self) -> None:
        props = {"Tags": {"CostCenter": "A"}}
        assert plain(tr("AWS::SSM::Parameter", props))["tags"] == {"CostCenter": "A"}

    def test_values_stay_text(self) -> None:
        props = {"Tags": [{"Key": "flag", "Value": "true"}, {"Key": "n", "Value": "7"}]}
        assert plain(tr("AWS::S3::Bucket", props))["tags"] == {"flag": "true", "n": "7"}

    def test_a_non_text_value_is_written_as_text(self) -> None:
        props = {"Tags": [{"Key": "n", "Value": 7}, {"Key": "b", "Value": True}]}
        assert plain(tr("AWS::S3::Bucket", props))["tags"] == {"n": "7", "b": "true"}

    def test_an_unresolved_value_is_unknown_and_an_unresolved_key_is_skipped(self) -> None:
        props = {
            "Tags": [{"Key": "Name", "Value": {"Ref": "R"}}, {"Key": {"Ref": "R"}, "Value": 1}]
        }
        tags = plain(tr("AWS::S3::Bucket", props))["tags"]
        assert set(tags) == {"Name"}
        assert is_unknown(tags["Name"])

    def test_malformed_entries_are_skipped(self) -> None:
        props = {"Tags": ["text", {"Value": "no key"}, {"Key": "ok", "Value": "v"}]}
        assert plain(tr("AWS::S3::Bucket", props))["tags"] == {"ok": "v"}

    def test_a_missing_value_is_empty_text(self) -> None:
        assert plain(tr("AWS::S3::Bucket", {"Tags": [{"Key": "k"}]}))["tags"] == {"k": ""}

    def test_tags_on_an_unmapped_type_are_translated_too(self) -> None:
        assert plain(tr("AWS::Foo::Bar", {"Tags": [{"Key": "k", "Value": "v"}]}))["tags"] == {
            "k": "v"
        }


class TestFreeFormMaps:
    def test_lambda_environment_variables_keep_their_keys(self) -> None:
        props = {"Environment": {"Variables": {"MY_Var": "1", "camelCase": "2", "Pascal": "3"}}}
        result = plain(tr("AWS::Lambda::Function", props))
        assert result["environment"] == [
            {"variables": {"MY_Var": "1", "camelCase": "2", "Pascal": "3"}}
        ]

    def test_variable_values_are_not_coerced(self) -> None:
        props = {"Environment": {"Variables": {"DEBUG": "true", "PORT": "80"}}}
        result = plain(tr("AWS::Lambda::Function", props))
        assert result["environment"][0]["variables"] == {"DEBUG": "true", "PORT": "80"}

    def test_variable_values_resolve_intrinsics(self) -> None:
        props = {"Environment": {"Variables": {"Q": {"Ref": "Queue"}}}}
        variables = plain(tr("AWS::Lambda::Function", props))["environment"][0]["variables"]
        assert unknown_reference(variables["Q"]) == "Queue"

    def test_nested_stack_parameters_keep_their_keys(self) -> None:
        props = {"TemplateURL": "https://x/t.yaml", "Parameters": {"VpcCidr": "10.0.0.0/16"}}
        result = plain(tr("AWS::CloudFormation::Stack", props))
        assert result["parameters"] == {"VpcCidr": "10.0.0.0/16"}
        assert result["template_url"] == "https://x/t.yaml"

    def test_eks_node_labels_keep_their_keys(self) -> None:
        props = {"Labels": {"NodeRole": "worker", "app.kubernetes.io/name": "x"}}
        assert plain(tr("AWS::EKS::Nodegroup", props))["labels"] == props["Labels"]

    def test_custom_resource_properties_keep_their_keys(self) -> None:
        props = {"ServiceToken": "arn", "MyKey": "Value", "Nested": {"AnotherKey": 1}}
        assert plain(tr("Custom::Thing", props)) == props

    def test_a_custom_resource_still_resolves_intrinsics_and_translates_tags(self) -> None:
        props = {"Token": {"Ref": "Fn"}, "Tags": [{"Key": "a", "Value": "b"}]}
        result = plain(tr("Custom::Thing", props))
        assert is_unknown(result["Token"])
        assert result["tags"] == {"a": "b"}

    def test_the_spec_of_a_custom_type_does_not_snake_case(self) -> None:
        assert spec_for("Custom::Anything").snake_keys is False
        assert spec_for("AWS::CloudFormation::CustomResource").snake_keys is False
        assert spec_for("AWS::Foo::Bar").snake_keys is True


class TestGenericTypes:
    def test_an_unmapped_type_is_snake_cased_recursively(self) -> None:
        props = {"SomeKey": "a", "OtherThing": [{"InnerKey": 1}], "Nested": {"DeepKey": {"X": 1}}}
        assert plain(tr("AWS::Foo::Bar", props)) == {
            "some_key": "a",
            "other_thing": [{"inner_key": 1}],
            "nested": {"deep_key": {"x": 1}},
        }

    def test_booleans_and_numbers_written_as_strings_are_coerced(self) -> None:
        props = {"Enabled": "true", "Disabled": "false", "Count": "3", "Ratio": "0.5"}
        assert plain(tr("AWS::Foo::Bar", props)) == {
            "enabled": True,
            "disabled": False,
            "count": 3,
            "ratio": 0.5,
        }

    def test_scalars_in_a_list_are_coerced_by_the_list_key(self) -> None:
        assert plain(tr("AWS::Foo::Bar", {"Ports": ["80", "443"]})) == {"ports": [80, 443]}

    def test_a_yaml_date_is_written_as_text(self) -> None:
        import datetime

        result = plain(tr("AWS::Foo::Bar", {"Day": datetime.date(2012, 10, 17)}))
        assert result == {"day": "2012-10-17"}
        json.dumps(result)

    def test_non_string_keys_become_text(self) -> None:
        assert plain(tr("AWS::Foo::Bar", {"Map": {1: "a", 2: "b"}})) == {
            "map": {"1": "a", "2": "b"}
        }

    def test_every_unknown_is_json_serializable_as_text(self) -> None:
        result = plain(tr("AWS::Foo::Bar", {"A": {"Ref": "R"}}))
        assert json.loads(json.dumps(result)) == {"a": "(known after apply)"}


class TestS3:
    def test_encryption_versioning_logging_and_public_access_block(self) -> None:
        props = {
            "BucketName": "b",
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": [
                    {
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": "alias/k",
                        },
                        "BucketKeyEnabled": "true",
                    }
                ]
            },
            "VersioningConfiguration": {"Status": "Enabled"},
            "LoggingConfiguration": {"DestinationBucketName": "logs", "LogFilePrefix": "p/"},
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "RestrictPublicBuckets": "true",
            },
        }
        assert plain(tr("AWS::S3::Bucket", props)) == {
            "bucket": "b",
            "server_side_encryption_configuration": [
                {
                    "rule": [
                        {
                            "apply_server_side_encryption_by_default": [
                                {"sse_algorithm": "aws:kms", "kms_master_key_id": "alias/k"}
                            ],
                            "bucket_key_enabled": True,
                        }
                    ]
                }
            ],
            "versioning": [{"enabled": True}],
            "logging": [{"target_bucket": "logs", "target_prefix": "p/"}],
            "public_access_block": [{"block_public_acls": True, "restrict_public_buckets": True}],
        }

    def test_suspended_versioning_is_disabled(self) -> None:
        props = {"VersioningConfiguration": {"Status": "Suspended"}}
        assert plain(tr("AWS::S3::Bucket", props))["versioning"] == [{"enabled": False}]

    def test_an_unresolved_versioning_status_is_unknown(self) -> None:
        props = {"VersioningConfiguration": {"Status": {"Ref": "Status"}}}
        enabled = plain(tr("AWS::S3::Bucket", props))["versioning"][0]["enabled"]
        assert is_unknown(enabled)

    def test_a_bucket_without_the_blocks_has_no_such_attributes(self) -> None:
        # absence must stay absence: the rules fire on it
        assert plain(tr("AWS::S3::Bucket", {"BucketName": "b"})) == {"bucket": "b"}

    @pytest.mark.parametrize(
        ("written", "acl"),
        [
            ("PublicRead", "public-read"),
            ("PublicReadWrite", "public-read-write"),
            ("AuthenticatedRead", "authenticated-read"),
            ("Private", "private"),
            ("LogDeliveryWrite", "log-delivery-write"),
            ("BucketOwnerFullControl", "bucket-owner-full-control"),
            ("public-read", "public-read"),
        ],
    )
    def test_canned_acls_use_terraforms_spelling(self, written: str, acl: str) -> None:
        assert plain(tr("AWS::S3::Bucket", {"AccessControl": written}))["acl"] == acl

    def test_an_unresolved_acl_is_unknown(self) -> None:
        acl = plain(tr("AWS::S3::Bucket", {"AccessControl": {"Ref": "Acl"}}))["acl"]
        assert is_unknown(acl)

    def test_lifecycle_and_cors_rules_are_hoisted(self) -> None:
        props = {
            "LifecycleConfiguration": {"Rules": [{"Id": "x", "Status": "Enabled"}]},
            "CorsConfiguration": {"CorsRules": [{"AllowedMethods": ["GET"]}]},
        }
        result = plain(tr("AWS::S3::Bucket", props))
        assert result["lifecycle_rule"] == [{"id": "x", "status": "Enabled"}]
        assert result["cors_rule"] == [{"allowed_methods": ["GET"]}]

    def test_bucket_policy(self) -> None:
        props = {
            "Bucket": {"Ref": "B"},
            "PolicyDocument": {"Statement": [{"Effect": "Allow", "Principal": "*"}]},
        }
        result = plain(tr("AWS::S3::BucketPolicy", props))
        assert unknown_reference(result["bucket"]) == "B"
        assert result["policy"] == '{"Statement":[{"Effect":"Allow","Principal":"*"}]}'


class TestPolicies:
    DOC = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    WRITTEN = (
        '{"Statement":[{"Action":"*","Effect":"Allow","Resource":"*"}],"Version":"2012-10-17"}'
    )

    @pytest.mark.parametrize("cfn_type", ["AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"])
    def test_policy_documents_are_jsonencode_text(self, cfn_type: str) -> None:
        # the same text a Terraform plan holds, so one rule serves both formats
        assert plain(tr(cfn_type, {"PolicyDocument": self.DOC}))["policy"] == self.WRITTEN

    def test_names_roles_users_and_groups(self) -> None:
        props = {"PolicyName": "p", "PolicyDocument": self.DOC, "Roles": ["r"], "Users": ["u"]}
        result = plain(tr("AWS::IAM::Policy", props))
        assert (result["name"], result["roles"], result["users"]) == ("p", ["r"], ["u"])
        assert plain(tr("AWS::IAM::ManagedPolicy", {"ManagedPolicyName": "m"}))["name"] == "m"

    def test_role(self) -> None:
        props = {
            "RoleName": "r",
            "AssumeRolePolicyDocument": self.DOC,
            "ManagedPolicyArns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "Policies": [{"PolicyName": "inline", "PolicyDocument": self.DOC}],
            "MaxSessionDuration": "7200",
        }
        assert plain(tr("AWS::IAM::Role", props)) == {
            "name": "r",
            "assume_role_policy": self.WRITTEN,
            "managed_policy_arns": ["arn:aws:iam::aws:policy/AdministratorAccess"],
            "inline_policy": [{"name": "inline", "policy": self.WRITTEN}],
            "max_session_duration": 7200,
        }

    def test_user_and_group_inline_policies(self) -> None:
        props = {"Policies": [{"PolicyName": "p", "PolicyDocument": self.DOC}]}
        for cfn_type in ("AWS::IAM::User", "AWS::IAM::Group"):
            assert plain(tr(cfn_type, props))["inline_policy"] == [
                {"name": "p", "policy": self.WRITTEN}
            ]

    def test_an_unresolved_value_inside_a_document_reads_as_the_unknown_text(self) -> None:
        doc = {"Statement": [{"Action": "s3:*", "Resource": {"Fn::GetAtt": ["B", "Arn"]}}]}
        text = plain(tr("AWS::IAM::Policy", {"PolicyDocument": doc}))["policy"]
        assert json.loads(text)["Statement"][0]["Resource"] == "(known after apply)"

    def test_a_document_that_is_itself_an_intrinsic_stays_unknown(self) -> None:
        policy = plain(tr("AWS::IAM::Policy", {"PolicyDocument": {"Ref": "Doc"}}))["policy"]
        assert is_unknown(policy)

    def test_a_document_written_as_text_is_kept(self) -> None:
        text = '{"Statement": []}'
        assert plain(tr("AWS::IAM::Policy", {"PolicyDocument": text}))["policy"] == text

    def test_a_partition_inside_a_document_is_resolved(self) -> None:
        doc = {"Statement": [{"Resource": {"Fn::Sub": "arn:${AWS::Partition}:s3:::b"}}]}
        text = plain(tr("AWS::IAM::Policy", {"PolicyDocument": doc}))["policy"]
        assert "arn:aws:s3:::b" in text

    def test_document_keys_are_not_snake_cased(self) -> None:
        text = plain(tr("AWS::IAM::Policy", {"PolicyDocument": self.DOC}))["policy"]
        assert '"Statement"' in text and "statement" not in text

    def test_instance_profile_binds_its_first_role(self) -> None:
        result = plain(tr("AWS::IAM::InstanceProfile", {"Roles": [{"Ref": "AppRole"}]}))
        assert unknown_reference(result["role"]) == "AppRole"
        assert len(result["roles"]) == 1

    def test_instance_profile_with_a_literal_role(self) -> None:
        assert plain(tr("AWS::IAM::InstanceProfile", {"Roles": ["r1", "r2"]}))["role"] == "r1"

    def test_kms_key_policy_and_rotation(self) -> None:
        props = {
            "KeyPolicy": self.DOC,
            "EnableKeyRotation": "true",
            "PendingWindowInDays": 30,
            "KeySpec": "SYMMETRIC_DEFAULT",
        }
        assert plain(tr("AWS::KMS::Key", props)) == {
            "policy": self.WRITTEN,
            "enable_key_rotation": True,
            "deletion_window_in_days": 30,
            "customer_master_key_spec": "SYMMETRIC_DEFAULT",
        }

    def test_queue_topic_and_endpoint_policies(self) -> None:
        for cfn_type in ("AWS::SQS::QueuePolicy", "AWS::SNS::TopicPolicy"):
            assert plain(tr(cfn_type, {"PolicyDocument": self.DOC}))["policy"] == self.WRITTEN
        assert plain(tr("AWS::EC2::VPCEndpoint", {"PolicyDocument": self.DOC}))["policy"] == (
            self.WRITTEN
        )


class TestSecurityGroups:
    def test_inline_ingress_and_egress(self) -> None:
        props = {
            "GroupDescription": "web",
            "GroupName": "web-sg",
            "VpcId": {"Ref": "Vpc"},
            "SecurityGroupIngress": [
                {"IpProtocol": "tcp", "FromPort": "443", "ToPort": 443, "CidrIp": "0.0.0.0/0"},
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "CidrIpv6": "::/0"},
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5432,
                    "ToPort": 5432,
                    "SourceSecurityGroupId": {"Ref": "Other"},
                    "Description": "db",
                },
            ],
            "SecurityGroupEgress": [{"IpProtocol": -1, "CidrIp": "0.0.0.0/0"}],
        }
        result = plain(tr("AWS::EC2::SecurityGroup", props))
        assert result["description"] == "web" and result["name"] == "web-sg"
        ingress = result["ingress"]
        assert ingress[0] == {
            "cidr_blocks": ["0.0.0.0/0"],
            "description": "",
            "ipv6_cidr_blocks": [],
            "prefix_list_ids": [],
            "security_groups": [],
            "self": False,
            "protocol": "tcp",
            "from_port": 443,
            "to_port": 443,
        }
        assert ingress[1]["ipv6_cidr_blocks"] == ["::/0"] and ingress[1]["cidr_blocks"] == []
        assert unknown_reference(ingress[2]["security_groups"][0]) == "Other"
        assert ingress[2]["description"] == "db"
        # an all-protocols rule has ports 0 to 0 and a text protocol, as in a plan
        assert result["egress"][0]["protocol"] == "-1"
        assert (result["egress"][0]["from_port"], result["egress"][0]["to_port"]) == (0, 0)

    def test_a_group_without_rules_has_no_ingress_attribute(self) -> None:
        assert "ingress" not in plain(tr("AWS::EC2::SecurityGroup", {"GroupDescription": "x"}))

    def test_a_single_rule_mapping_is_accepted(self) -> None:
        props = {"SecurityGroupIngress": {"IpProtocol": "tcp", "CidrIp": "10.0.0.0/8"}}
        assert plain(tr("AWS::EC2::SecurityGroup", props))["ingress"][0]["cidr_blocks"] == [
            "10.0.0.0/8"
        ]

    def test_malformed_rules_are_skipped(self) -> None:
        props = {
            "SecurityGroupIngress": ["text", None, {"IpProtocol": "tcp", "CidrIp": "1.2.3.4/32"}]
        }
        assert len(plain(tr("AWS::EC2::SecurityGroup", props))["ingress"]) == 1

    def test_an_unresolved_rule_list_is_unknown(self) -> None:
        props = {"SecurityGroupIngress": {"Ref": "Rules"}}
        assert is_unknown(plain(tr("AWS::EC2::SecurityGroup", props))["ingress"])

    def test_an_unresolved_cidr_stays_in_the_list(self) -> None:
        props = {"SecurityGroupIngress": [{"IpProtocol": "tcp", "CidrIp": {"Ref": "Cidr"}}]}
        cidr = plain(tr("AWS::EC2::SecurityGroup", props))["ingress"][0]["cidr_blocks"]
        assert len(cidr) == 1 and is_unknown(cidr[0])

    def test_standalone_ingress_has_the_shape_of_a_security_group_rule(self) -> None:
        props = {
            "GroupId": {"Ref": "Sg"},
            "IpProtocol": "tcp",
            "FromPort": "22",
            "ToPort": "22",
            "CidrIp": "0.0.0.0/0",
            "Description": "ssh",
        }
        result = plain(tr("AWS::EC2::SecurityGroupIngress", props))
        assert result["type"] == "ingress"
        assert result["cidr_blocks"] == ["0.0.0.0/0"]
        assert (result["protocol"], result["from_port"], result["to_port"]) == ("tcp", 22, 22)
        assert result["self"] is False and result["description"] == "ssh"
        assert unknown_reference(result["security_group_id"]) == "Sg"

    def test_standalone_egress_with_a_destination_group(self) -> None:
        props = {"GroupId": "sg-1", "IpProtocol": -1, "DestinationSecurityGroupId": "sg-2"}
        result = plain(tr("AWS::EC2::SecurityGroupEgress", props))
        assert result["type"] == "egress"
        assert result["source_security_group_id"] == "sg-2"
        assert (result["protocol"], result["from_port"], result["to_port"]) == ("-1", 0, 0)


class TestEc2:
    def test_instance_attributes(self) -> None:
        props = {
            "ImageId": "ami-1",
            "InstanceType": "t3.small",
            "SubnetId": "subnet-1",
            "SecurityGroupIds": ["sg-1"],
            "IamInstanceProfile": "profile",
            "Monitoring": "true",
            "MetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": "1"},
        }
        assert plain(tr("AWS::EC2::Instance", props)) == {
            "ami": "ami-1",
            "instance_type": "t3.small",
            "subnet_id": "subnet-1",
            "vpc_security_group_ids": ["sg-1"],
            "iam_instance_profile": "profile",
            "monitoring": True,
            "metadata_options": [{"http_tokens": "required", "http_put_response_hop_limit": 1}],
        }

    def test_a_public_ip_on_a_network_interface_is_hoisted(self) -> None:
        props = {
            "NetworkInterfaces": [
                {
                    "DeviceIndex": "0",
                    "AssociatePublicIpAddress": "true",
                    "SubnetId": "subnet-1",
                    "GroupSet": ["sg-1"],
                }
            ]
        }
        result = plain(tr("AWS::EC2::Instance", props))
        assert result["associate_public_ip_address"] is True
        assert result["subnet_id"] == "subnet-1"
        assert result["vpc_security_group_ids"] == ["sg-1"]
        assert result["network_interface"][0]["associate_public_ip_address"] is True

    def test_a_private_network_interface_hoists_false(self) -> None:
        props = {"NetworkInterfaces": [{"AssociatePublicIpAddress": False}]}
        assert plain(tr("AWS::EC2::Instance", props))["associate_public_ip_address"] is False

    def test_an_unresolved_public_ip_hoists_unknown(self) -> None:
        props = {"NetworkInterfaces": [{"AssociatePublicIpAddress": {"Ref": "Public"}}]}
        assert is_unknown(plain(tr("AWS::EC2::Instance", props))["associate_public_ip_address"])

    def test_top_level_values_win_over_the_interface(self) -> None:
        props = {
            "SubnetId": "top",
            "SecurityGroupIds": ["top-sg"],
            "NetworkInterfaces": [{"SubnetId": "nic", "GroupSet": ["nic-sg"]}],
        }
        result = plain(tr("AWS::EC2::Instance", props))
        assert (result["subnet_id"], result["vpc_security_group_ids"]) == ("top", ["top-sg"])

    def test_block_devices(self) -> None:
        props = {
            "BlockDeviceMappings": [
                {"DeviceName": "/dev/xvda", "Ebs": {"Encrypted": "true", "VolumeSize": "30"}},
                {"DeviceName": "/dev/sdf", "Ebs": {"Encrypted": False, "VolumeType": "gp3"}},
                {"DeviceName": "/dev/sdg", "VirtualName": "ephemeral0"},
            ]
        }
        result = plain(tr("AWS::EC2::Instance", props))
        assert result["root_block_device"] == [{"encrypted": True, "volume_size": 30}]
        assert result["ebs_block_device"] == [
            {"encrypted": False, "volume_type": "gp3", "device_name": "/dev/sdf"}
        ]

    def test_launch_template_data_is_hoisted(self) -> None:
        props = {
            "LaunchTemplateName": "lt",
            "LaunchTemplateData": {
                "ImageId": "ami",
                "SecurityGroupIds": ["sg"],
                "MetadataOptions": {"HttpTokens": "optional"},
                "IamInstanceProfile": {"Name": "p"},
            },
        }
        assert plain(tr("AWS::EC2::LaunchTemplate", props)) == {
            "name": "lt",
            "image_id": "ami",
            "vpc_security_group_ids": ["sg"],
            "metadata_options": [{"http_tokens": "optional"}],
            "iam_instance_profile": [{"name": "p"}],
        }

    def test_volume(self) -> None:
        props = {"Encrypted": "true", "Size": "100", "VolumeType": "gp3", "KmsKeyId": "k"}
        assert plain(tr("AWS::EC2::Volume", props)) == {
            "encrypted": True,
            "size": 100,
            "type": "gp3",
            "kms_key_id": "k",
        }

    def test_flow_log_names_the_resource_it_covers(self) -> None:
        props = {"ResourceId": "vpc-1", "ResourceType": "VPC", "TrafficType": "ALL"}
        result = plain(tr("AWS::EC2::FlowLog", props))
        assert result["vpc_id"] == "vpc-1" and "resource_id" not in result
        subnet = plain(tr("AWS::EC2::FlowLog", {"ResourceId": "s", "ResourceType": "Subnet"}))
        assert subnet["subnet_id"] == "s"

    def test_vpc_subnet_and_endpoint(self) -> None:
        assert plain(
            tr("AWS::EC2::VPC", {"CidrBlock": "10.0.0.0/16", "EnableDnsHostnames": "true"})
        ) == {
            "cidr_block": "10.0.0.0/16",
            "enable_dns_hostnames": True,
        }
        subnet = plain(tr("AWS::EC2::Subnet", {"MapPublicIpOnLaunch": "true", "VpcId": "v"}))
        assert subnet == {"map_public_ip_on_launch": True, "vpc_id": "v"}
        endpoint = plain(tr("AWS::EC2::VPCEndpoint", {"ServiceName": "s3", "SubnetIds": ["a"]}))
        assert endpoint == {"service_name": "s3", "subnet_ids": ["a"]}


class TestRds:
    def test_instance_attributes_the_rules_read(self) -> None:
        props = {
            "DBInstanceIdentifier": "orders",
            "DBInstanceClass": "db.t3.medium",
            "Engine": "postgres",
            "EngineVersion": "15",
            "AllocatedStorage": "50",
            "StorageEncrypted": "true",
            "PubliclyAccessible": "false",
            "BackupRetentionPeriod": "7",
            "MultiAZ": "true",
            "DeletionProtection": True,
            "EnableIAMDatabaseAuthentication": True,
            "MasterUsername": "admin",
            "VPCSecurityGroups": ["sg-1"],
            "DBSubnetGroupName": "subnets",
            "EnablePerformanceInsights": "true",
        }
        assert plain(tr("AWS::RDS::DBInstance", props)) == {
            "identifier": "orders",
            "instance_class": "db.t3.medium",
            "engine": "postgres",
            "engine_version": "15",
            "allocated_storage": 50,
            "storage_encrypted": True,
            "publicly_accessible": False,
            "backup_retention_period": 7,
            "multi_az": True,
            "deletion_protection": True,
            "iam_database_authentication_enabled": True,
            "master_username": "admin",
            "vpc_security_group_ids": ["sg-1"],
            "db_subnet_group_name": "subnets",
            "performance_insights_enabled": True,
        }

    def test_zero_backups_is_the_number_zero(self) -> None:
        result = plain(tr("AWS::RDS::DBInstance", {"BackupRetentionPeriod": "0"}))
        assert result["backup_retention_period"] == 0

    def test_cluster_and_subnet_group(self) -> None:
        cluster = plain(
            tr(
                "AWS::RDS::DBCluster",
                {
                    "DBClusterIdentifier": "c",
                    "StorageEncrypted": "true",
                    "EnableIAMDatabaseAuthentication": 1,
                },
            )
        )
        assert cluster["cluster_identifier"] == "c" and cluster["storage_encrypted"] is True
        group = plain(
            tr(
                "AWS::RDS::DBSubnetGroup",
                {"DBSubnetGroupName": "g", "DBSubnetGroupDescription": "d"},
            )
        )
        assert group == {"name": "g", "description": "d"}


class TestLambda:
    def test_function_blocks(self) -> None:
        props = {
            "FunctionName": "f",
            "Runtime": "python3.12",
            "Role": "arn:aws:iam::1:role/r",
            "MemorySize": "256",
            "Timeout": 30,
            "VpcConfig": {"SubnetIds": ["s"], "SecurityGroupIds": ["g"]},
            "DeadLetterConfig": {"TargetArn": "arn"},
            "TracingConfig": {"Mode": "Active"},
            "KmsKeyArn": "k",
            "Code": {"S3Bucket": "b", "S3Key": "k.zip"},
        }
        assert plain(tr("AWS::Lambda::Function", props)) == {
            "function_name": "f",
            "runtime": "python3.12",
            "role": "arn:aws:iam::1:role/r",
            "memory_size": 256,
            "timeout": 30,
            "vpc_config": [{"subnet_ids": ["s"], "security_group_ids": ["g"]}],
            "dead_letter_config": [{"target_arn": "arn"}],
            "tracing_config": [{"mode": "Active"}],
            "kms_key_arn": "k",
            "s3_bucket": "b",
            "s3_key": "k.zip",
        }

    def test_url_and_permission(self) -> None:
        url = plain(tr("AWS::Lambda::Url", {"AuthType": "NONE", "TargetFunctionArn": "f"}))
        assert url == {"authorization_type": "NONE", "function_name": "f"}
        permission = plain(
            tr("AWS::Lambda::Permission", {"Action": "lambda:InvokeFunction", "Principal": "*"})
        )
        assert permission == {"action": "lambda:InvokeFunction", "principal": "*"}


class TestMessagingAndData:
    def test_sqs_queue(self) -> None:
        props = {
            "QueueName": "q",
            "KmsMasterKeyId": "alias/k",
            "SqsManagedSseEnabled": "true",
            "RedrivePolicy": {"deadLetterTargetArn": "arn", "maxReceiveCount": 5},
        }
        assert plain(tr("AWS::SQS::Queue", props)) == {
            "name": "q",
            "kms_master_key_id": "alias/k",
            "sqs_managed_sse_enabled": True,
            "redrive_policy": '{"deadLetterTargetArn":"arn","maxReceiveCount":5}',
        }

    def test_sns_topic_and_subscription(self) -> None:
        assert plain(tr("AWS::SNS::Topic", {"TopicName": "t", "KmsMasterKeyId": "k"})) == {
            "name": "t",
            "kms_master_key_id": "k",
        }
        sub = plain(
            tr("AWS::SNS::Subscription", {"TopicArn": "a", "Protocol": "http", "Endpoint": "x"})
        )
        assert sub == {"topic_arn": "a", "protocol": "http", "endpoint": "x"}

    def test_dynamodb_table(self) -> None:
        props = {
            "TableName": "t",
            "BillingMode": "PROVISIONED",
            "ProvisionedThroughput": {"ReadCapacityUnits": "5", "WriteCapacityUnits": 5},
            "KeySchema": [
                {"AttributeName": "a", "KeyType": "HASH"},
                {"AttributeName": "b", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [{"AttributeName": "a", "AttributeType": "S"}],
            "SSESpecification": {"SSEEnabled": True, "KMSMasterKeyId": "k"},
            "PointInTimeRecoverySpecification": {"PointInTimeRecoveryEnabled": "true"},
            "TimeToLiveSpecification": {"AttributeName": "ttl", "Enabled": True},
        }
        assert plain(tr("AWS::DynamoDB::Table", props)) == {
            "name": "t",
            "billing_mode": "PROVISIONED",
            "read_capacity": 5,
            "write_capacity": 5,
            "hash_key": "a",
            "range_key": "b",
            "attribute": [{"name": "a", "type": "S"}],
            "server_side_encryption": [{"enabled": True, "kms_key_arn": "k"}],
            "point_in_time_recovery": [{"enabled": True}],
            "ttl": [{"attribute_name": "ttl", "enabled": True}],
        }

    def test_a_table_without_the_specifications_has_none(self) -> None:
        result = plain(tr("AWS::DynamoDB::Table", {"TableName": "t"}))
        assert "server_side_encryption" not in result and "point_in_time_recovery" not in result

    def test_cloudtrail(self) -> None:
        props = {
            "TrailName": "t",
            "IsLogging": "true",
            "IsMultiRegionTrail": True,
            "EnableLogFileValidation": "false",
            "KMSKeyId": {"Ref": "Key"},
            "S3BucketName": "logs",
            "EventSelectors": [
                {
                    "ReadWriteType": "All",
                    "DataResources": [{"Type": "AWS::S3::Object", "Values": ["a"]}],
                }
            ],
        }
        result = plain(tr("AWS::CloudTrail::Trail", props))
        assert result["name"] == "t" and result["enable_logging"] is True
        assert result["is_multi_region_trail"] is True
        assert result["enable_log_file_validation"] is False
        assert unknown_reference(result["kms_key_id"]) == "Key"
        assert result["s3_bucket_name"] == "logs"
        assert result["event_selector"][0]["data_resource"][0]["values"] == ["a"]

    def test_elasticache_replication_group(self) -> None:
        props = {
            "ReplicationGroupDescription": "d",
            "AtRestEncryptionEnabled": "true",
            "TransitEncryptionEnabled": True,
            "AuthToken": "t",
            "CacheNodeType": "cache.t3",
            "MultiAZEnabled": "true",
        }
        assert plain(tr("AWS::ElastiCache::ReplicationGroup", props)) == {
            "description": "d",
            "at_rest_encryption_enabled": True,
            "transit_encryption_enabled": True,
            "auth_token": "t",
            "node_type": "cache.t3",
            "multi_az_enabled": True,
        }

    @pytest.mark.parametrize(
        "cfn_type", ["AWS::OpenSearchService::Domain", "AWS::Elasticsearch::Domain"]
    )
    def test_search_domains(self, cfn_type: str) -> None:
        props = {
            "DomainName": "d",
            "EncryptionAtRestOptions": {"Enabled": True, "KmsKeyId": "k"},
            "NodeToNodeEncryptionOptions": {"Enabled": "true"},
            "VPCOptions": {"SubnetIds": ["s"], "SecurityGroupIds": ["g"]},
            "DomainEndpointOptions": {"EnforceHTTPS": True, "TLSSecurityPolicy": "p"},
            "AccessPolicies": {"Statement": []},
        }
        assert plain(tr(cfn_type, props)) == {
            "domain_name": "d",
            "encrypt_at_rest": [{"enabled": True, "kms_key_id": "k"}],
            "node_to_node_encryption": [{"enabled": True}],
            "vpc_options": [{"subnet_ids": ["s"], "security_group_ids": ["g"]}],
            "domain_endpoint_options": [{"enforce_https": True, "tls_security_policy": "p"}],
            "access_policies": '{"Statement":[]}',
        }

    def test_secrets_manager_rotation(self) -> None:
        props = {"SecretId": "s", "RotationRules": {"AutomaticallyAfterDays": "30"}}
        assert plain(tr("AWS::SecretsManager::RotationSchedule", props)) == {
            "secret_id": "s",
            "rotation_rules": [{"automatically_after_days": 30}],
        }

    def test_ssm_parameter(self) -> None:
        props = {"Name": "/a", "Type": "String", "Value": "123", "Tier": "Standard"}
        assert plain(tr("AWS::SSM::Parameter", props)) == {
            "name": "/a",
            "type": "String",
            "value": "123",
            "tier": "Standard",
        }

    def test_redshift_cluster_logging(self) -> None:
        props = {
            "ClusterIdentifier": "c",
            "PubliclyAccessible": "false",
            "Encrypted": True,
            "LoggingProperties": {"BucketName": "b"},
        }
        result = plain(tr("AWS::Redshift::Cluster", props))
        assert result["logging"] == [{"bucket_name": "b", "enable": True}]
        assert result["publicly_accessible"] is False and result["encrypted"] is True


class TestLoadBalancers:
    @pytest.mark.parametrize(
        ("scheme", "internal"), [("internet-facing", False), ("internal", True)]
    )
    def test_scheme_is_the_internal_flag(self, scheme: str, internal: bool) -> None:
        result = plain(tr("AWS::ElasticLoadBalancingV2::LoadBalancer", {"Scheme": scheme}))
        assert result["internal"] is internal and "scheme" not in result

    def test_an_unresolved_scheme_is_unknown(self) -> None:
        result = plain(tr("AWS::ElasticLoadBalancingV2::LoadBalancer", {"Scheme": {"Ref": "S"}}))
        assert is_unknown(result["internal"])

    def test_attributes_become_access_logs_and_flags(self) -> None:
        props = {
            "Type": "application",
            "LoadBalancerAttributes": [
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": "logs"},
                {"Key": "idle_timeout.timeout_seconds", "Value": "120"},
                {"Key": "deletion_protection.enabled", "Value": "true"},
                {"Key": "routing.http.drop_invalid_header_fields.enabled", "Value": "true"},
            ],
        }
        assert plain(tr("AWS::ElasticLoadBalancingV2::LoadBalancer", props)) == {
            "load_balancer_type": "application",
            "access_logs": [{"enabled": True, "bucket": "logs"}],
            "idle_timeout": 120,
            "enable_deletion_protection": True,
            "drop_invalid_header_fields": True,
        }

    def test_disabled_access_logs_leave_no_access_logs_block(self) -> None:
        props = {"LoadBalancerAttributes": [{"Key": "access_logs.s3.enabled", "Value": "false"}]}
        result = plain(tr("AWS::ElasticLoadBalancingV2::LoadBalancer", props))
        assert "access_logs" not in result

    def test_listener_redirect_and_certificate(self) -> None:
        props = {
            "LoadBalancerArn": "lb",
            "Port": "80",
            "Protocol": "HTTP",
            "SslPolicy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "Certificates": [{"CertificateArn": "arn:cert"}],
            "DefaultActions": [
                {
                    "Type": "redirect",
                    "RedirectConfig": {
                        "Protocol": "HTTPS",
                        "Port": "443",
                        "StatusCode": "HTTP_301",
                    },
                },
                {"Type": "forward", "TargetGroupArn": "tg"},
            ],
        }
        assert plain(tr("AWS::ElasticLoadBalancingV2::Listener", props)) == {
            "load_balancer_arn": "lb",
            "port": 80,
            "protocol": "HTTP",
            "ssl_policy": "ELBSecurityPolicy-TLS13-1-2-2021-06",
            "certificate_arn": "arn:cert",
            "default_action": [
                {
                    "type": "redirect",
                    "redirect": [{"protocol": "HTTPS", "port": 443, "status_code": "HTTP_301"}],
                },
                {"type": "forward", "target_group_arn": "tg"},
            ],
        }


class TestContainersAndEdge:
    def test_ecs_container_definitions_are_json_text_in_the_api_spelling(self) -> None:
        props = {
            "Family": "f",
            "Cpu": "256",
            "Memory": "512",
            "ContainerDefinitions": [
                {
                    "Name": "app",
                    "Image": "nginx:latest",
                    "Privileged": True,
                    "ReadonlyRootFilesystem": False,
                    "PortMappings": [{"ContainerPort": 80}],
                    "DockerLabels": {"Team": "web"},
                    "LogConfiguration": {"LogDriver": "awslogs", "Options": {"awslogs-group": "g"}},
                }
            ],
        }
        result = plain(tr("AWS::ECS::TaskDefinition", props))
        assert (result["cpu"], result["memory"], result["family"]) == ("256", "512", "f")
        text = result["container_definitions"]
        assert '"privileged":true' in text and '"readonlyRootFilesystem":false' in text
        container = json.loads(text)[0]
        assert container["portMappings"] == [{"containerPort": 80}]
        assert container["dockerLabels"] == {"Team": "web"}
        assert container["logConfiguration"]["options"] == {"awslogs-group": "g"}

    def test_ecs_service(self) -> None:
        props = {
            "EnableExecuteCommand": "true",
            "NetworkConfiguration": {
                "AwsvpcConfiguration": {
                    "AssignPublicIp": "ENABLED",
                    "Subnets": ["s"],
                    "SecurityGroups": ["g"],
                }
            },
        }
        assert plain(tr("AWS::ECS::Service", props)) == {
            "enable_execute_command": True,
            "network_configuration": [
                {"assign_public_ip": True, "subnets": ["s"], "security_groups": ["g"]}
            ],
        }

    def test_eks_cluster(self) -> None:
        props = {
            "Name": "c",
            "Version": "1.29",
            "RoleArn": "arn:role",
            "ResourcesVpcConfig": {"SubnetIds": ["a"], "EndpointPublicAccess": "false"},
            "Logging": {"ClusterLogging": {"EnabledTypes": [{"Type": "api"}, {"Type": "audit"}]}},
            "EncryptionConfig": [{"Provider": {"KeyArn": "k"}, "Resources": ["secrets"]}],
        }
        assert plain(tr("AWS::EKS::Cluster", props)) == {
            "name": "c",
            "version": "1.29",
            "role_arn": "arn:role",
            "vpc_config": [{"subnet_ids": ["a"], "endpoint_public_access": False}],
            "enabled_cluster_log_types": ["api", "audit"],
            "encryption_config": [{"provider": [{"key_arn": "k"}], "resources": ["secrets"]}],
        }

    def test_eks_node_group_and_fargate_profile(self) -> None:
        group = plain(
            tr(
                "AWS::EKS::Nodegroup",
                {
                    "NodegroupName": "n",
                    "NodeRole": "r",
                    "Subnets": ["s"],
                    "RemoteAccess": {"Ec2SshKey": "key"},
                    "ScalingConfig": {"MinSize": "1", "MaxSize": 3},
                },
            )
        )
        assert group["node_group_name"] == "n" and group["node_role_arn"] == "r"
        assert group["subnet_ids"] == ["s"]
        assert group["remote_access"] == [{"ec2_ssh_key": "key"}]
        assert group["scaling_config"] == [{"min_size": 1, "max_size": 3}]
        profile = plain(tr("AWS::EKS::FargateProfile", {"Selectors": [{"Namespace": "default"}]}))
        assert profile["selector"] == [{"namespace": "default"}]

    def test_cloudfront_distribution_config_is_hoisted(self) -> None:
        props = {
            "DistributionConfig": {
                "Enabled": True,
                "IPV6Enabled": True,
                "WebACLId": "w",
                "Origins": [
                    {"Id": "o", "DomainName": "d", "CustomOriginConfig": {"HTTPSPort": 443}}
                ],
                "DefaultCacheBehavior": {
                    "TargetOriginId": "o",
                    "ViewerProtocolPolicy": "allow-all",
                },
                "Restrictions": {"GeoRestriction": {"RestrictionType": "none"}},
                "Logging": {"Bucket": "b"},
                "ViewerCertificate": {"CloudFrontDefaultCertificate": True},
            }
        }
        assert plain(tr("AWS::CloudFront::Distribution", props)) == {
            "enabled": True,
            "is_ipv6_enabled": True,
            "web_acl_id": "w",
            "origin": [
                {
                    "origin_id": "o",
                    "domain_name": "d",
                    "custom_origin_config": [{"https_port": 443}],
                }
            ],
            "default_cache_behavior": [
                {"target_origin_id": "o", "viewer_protocol_policy": "allow-all"}
            ],
            "restrictions": [{"geo_restriction": [{"restriction_type": "none"}]}],
            "logging_config": [{"bucket": "b"}],
            "viewer_certificate": [{"cloudfront_default_certificate": True}],
        }

    def test_wafv2_web_acl_default_action(self) -> None:
        block = plain(tr("AWS::WAFv2::WebACL", {"DefaultAction": {"Block": {}}}))
        allow = plain(tr("AWS::WAFv2::WebACL", {"DefaultAction": {"Allow": {}}}))
        assert block["default_action"] == [{"block": [{}]}]
        assert allow["default_action"] == [{"allow": [{}]}]

    def test_guardduty_data_sources(self) -> None:
        props = {
            "Enable": True,
            "DataSources": {
                "S3Logs": {"Enable": True},
                "Kubernetes": {"AuditLogs": {"Enable": False}},
                "MalwareProtection": {"ScanEc2InstanceWithFindings": {"EbsVolumes": True}},
            },
        }
        result = plain(tr("AWS::GuardDuty::Detector", props))
        sources = result["datasources"][0]
        assert sources["s3_logs"] == [{"enable": True}]
        assert sources["kubernetes"][0]["audit_logs"] == [{"enable": False}]
        malware = sources["malware_protection"][0]["scan_ec2_instance_with_findings"][0]
        assert malware["ebs_volumes"] == [{"enable": True}]

    def test_config_recorder_delivery_channel_and_aggregator(self) -> None:
        recorder = plain(
            tr(
                "AWS::Config::ConfigurationRecorder",
                {"RoleARN": "r", "RecordingGroup": {"AllSupported": "true"}},
            )
        )
        assert recorder == {"role_arn": "r", "recording_group": [{"all_supported": True}]}
        channel = plain(tr("AWS::Config::DeliveryChannel", {"S3BucketName": "b"}))
        assert channel == {"s3_bucket_name": "b"}
        aggregator = plain(
            tr(
                "AWS::Config::ConfigurationAggregator",
                {
                    "ConfigurationAggregatorName": "a",
                    "AccountAggregationSources": [{"AllAwsRegions": True}],
                },
            )
        )
        assert aggregator == {"name": "a", "account_aggregation_source": [{"all_regions": True}]}


class TestPathMap:
    def test_an_unmoved_path_is_snake_cased_segment_by_segment(self) -> None:
        assert PathMap().map("DBSubnetGroupName") == "db_subnet_group_name"
        assert PathMap().map("A.BcDe[].FgHi") == "a.bc_de[].fg_hi"

    def test_a_renamed_prefix_carries_what_is_below_it(self) -> None:
        paths = PathMap()
        paths.add("SecurityGroupIds", "vpc_security_group_ids")
        assert paths.map("SecurityGroupIds") == "vpc_security_group_ids"
        assert paths.map("SecurityGroupIds[].Inner") == "vpc_security_group_ids[].inner"

    def test_a_collapsed_path_swallows_everything_below_it(self) -> None:
        paths = PathMap()
        paths.add("PolicyDocument", "policy", collapse=True)
        assert paths.map("PolicyDocument.Statement[].Resource") == "policy"

    def test_the_longest_rule_wins(self) -> None:
        paths = PathMap()
        paths.add("A", "x")
        paths.add("A.B", "y.z")
        assert paths.map("A.B.C") == "y.z.c"
        assert paths.map("A.Other") == "x.other"

    def test_a_rule_can_move_a_path_to_the_top(self) -> None:
        paths = PathMap()
        paths.add("LaunchTemplateData", "")
        assert paths.map("LaunchTemplateData.ImageId") == "image_id"

    def test_the_translator_records_where_attributes_moved(self) -> None:
        props = {
            "VpcConfig": {"SubnetIds": ["a"]},
            "SecurityGroupIngress": [{"SourceSecurityGroupId": "g", "CidrIp": "1.2.3.4/32"}],
        }
        paths = tr("AWS::Lambda::Function", props).paths
        assert paths.map("VpcConfig.SubnetIds") == "vpc_config[].subnet_ids"
        sg = tr("AWS::EC2::SecurityGroup", props).paths
        assert sg.map("SecurityGroupIngress[].SourceSecurityGroupId") == "ingress[].security_groups"
        assert sg.map("SecurityGroupIngress[].CidrIp") == "ingress[].cidr_blocks"

    @pytest.mark.parametrize(
        ("cfn_type", "props", "raw", "translated"),
        [
            ("AWS::EC2::Subnet", {"VpcId": "v"}, "VpcId", "vpc_id"),
            (
                "AWS::EC2::Instance",
                {"SecurityGroupIds": ["g"]},
                "SecurityGroupIds",
                "vpc_security_group_ids",
            ),
            (
                "AWS::EC2::Instance",
                {"NetworkInterfaces": [{"SubnetId": "s"}]},
                "NetworkInterfaces[].SubnetId",
                "network_interface[].subnet_id",
            ),
            (
                "AWS::IAM::Role",
                {"Policies": [{"PolicyName": "p", "PolicyDocument": {}}]},
                "Policies[].PolicyDocument.Statement[].Resource",
                "inline_policy[].policy",
            ),
            ("AWS::IAM::InstanceProfile", {"Roles": ["r"]}, "Roles", "role"),
            (
                "AWS::Lambda::Function",
                {"Environment": {"Variables": {"A": "b"}}},
                "Environment.Variables.A",
                "environment[].variables",
            ),
            ("AWS::S3::Bucket", {"Tags": [{"Key": "k", "Value": "v"}]}, "Tags", "tags"),
            ("AWS::S3::Bucket", {"BucketName": "b"}, "BucketName", "bucket"),
            (
                "AWS::CloudFront::Distribution",
                {"DistributionConfig": {"WebACLId": "w"}},
                "DistributionConfig.WebACLId",
                "web_acl_id",
            ),
            (
                "AWS::ECS::Service",
                {"NetworkConfiguration": {"AwsvpcConfiguration": {"Subnets": ["s"]}}},
                "NetworkConfiguration.AwsvpcConfiguration.Subnets",
                "network_configuration[].subnets",
            ),
            (
                "AWS::ElasticLoadBalancingV2::LoadBalancer",
                {"Scheme": "internal"},
                "Scheme",
                "internal",
            ),
        ],
    )
    def test_the_attributes_the_graph_attaches_edges_to(
        self, cfn_type: str, props: dict[str, Any], raw: str, translated: str
    ) -> None:
        assert tr(cfn_type, props).paths.map(raw) == translated


class TestBounds:
    def test_an_alias_bomb_is_refused(self) -> None:
        level: Any = ["lol"] * 9
        for _ in range(9):
            level = [level] * 9
        ctx = TemplateContext(budget=WorkBudget(300_000))
        with pytest.raises(ParseError, match="aliases are expanded"):
            tr("AWS::Foo::Bar", {"Data": level}, ctx)

    def test_a_structure_that_contains_itself_terminates(self) -> None:
        loop: dict[str, Any] = {"Name": "x"}
        loop["Self"] = loop
        result = plain(tr("AWS::Foo::Bar", {"Loop": loop}))
        assert result["loop"]["name"] == "x"
        assert is_unknown(result["loop"]["self"])

    def test_values_below_the_depth_cap_are_unknown(self) -> None:
        deep: Any = "leaf"
        for _ in range(200):
            deep = {"Level": deep}
        result = plain(tr("AWS::Foo::Bar", {"Deep": deep}))
        json.dumps(result)  # finite and serializable

    def test_a_condition_chain_that_is_too_deep_is_undecidable(self) -> None:
        conditions = {f"C{i}": {"Condition": f"C{i + 1}"} for i in range(200)}
        conditions["C200"] = {"Fn::Equals": ["a", "a"]}
        assert evaluate_condition("C0", template(Conditions=conditions)) is None

    def test_a_large_resource_translates(self) -> None:
        props = {"Items": [{"Name": str(i), "Port": str(i)} for i in range(20_000)]}
        assert len(plain(tr("AWS::Foo::Bar", props))["items"]) == 20_000
