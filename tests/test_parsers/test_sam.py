"""Tests for threatcode.parsers._sam: AWS SAM written out as plain CloudFormation."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from threatcode.ir.graph import InfraGraph
from threatcode.parsers import detect_and_parse
from threatcode.parsers._sam import SAM_TRANSFORM, expand, is_sam_type, transform_names, uses_sam
from threatcode.parsers.cloudformation import CloudFormationParser

FIXTURES = Path(__file__).parent.parent / "fixtures"
SAM_FIXTURE = FIXTURES / "cloudformation" / "sam_function.yaml"
SAM_API_FIXTURE = FIXTURES / "real_shapes" / "cloudformation" / "sam_api.yaml"


def function(**properties: Any) -> dict[str, Any]:
    return {"Type": "AWS::Serverless::Function", "Properties": {"Handler": "a.b", **properties}}


def roles(expansion: Any) -> dict[str, dict[str, Any]]:
    return {
        lid: definition["Properties"]
        for lid, definition in expansion.resources.items()
        if definition["Type"] == "AWS::IAM::Role"
    }


def types(expansion: Any) -> dict[str, str]:
    return {lid: definition["Type"] for lid, definition in expansion.resources.items()}


class TestTransformNames:
    @pytest.mark.parametrize(
        ("transform", "names"),
        [
            (SAM_TRANSFORM, [SAM_TRANSFORM]),
            (
                [SAM_TRANSFORM, "AWS::LanguageExtensions"],
                [SAM_TRANSFORM, "AWS::LanguageExtensions"],
            ),
            ({"Name": "AWS::Include", "Parameters": {"Location": "s3://x"}}, ["AWS::Include"]),
            ([{"Name": "MyMacro"}, "Other"], ["MyMacro", "Other"]),
            (None, []),
            (5, []),
            ({"Name": 3}, []),
            ({}, []),
        ],
    )
    def test_names(self, transform: Any, names: list[str]) -> None:
        assert transform_names(transform) == names

    def test_uses_sam(self) -> None:
        assert uses_sam(SAM_TRANSFORM)
        assert uses_sam(["AWS::Serverless-2016-10-31", "X"])
        assert not uses_sam("AWS::Include")
        assert not uses_sam(None)

    def test_is_sam_type(self) -> None:
        assert is_sam_type("AWS::Serverless::Function")
        assert not is_sam_type("AWS::Lambda::Function")
        assert not is_sam_type(None)


class TestFunction:
    def test_a_function_becomes_a_lambda_function_and_an_implicit_role(self) -> None:
        expansion = expand({"Fn": function(Runtime="python3.12", MemorySize=256)})
        assert types(expansion) == {"Fn": "AWS::Lambda::Function", "FnRole": "AWS::IAM::Role"}
        properties = expansion.resources["Fn"]["Properties"]
        assert properties["Role"] == {"Fn::GetAtt": ["FnRole", "Arn"]}
        assert (properties["Handler"], properties["Runtime"], properties["MemorySize"]) == (
            "a.b",
            "python3.12",
            256,
        )

    def test_the_role_is_assumable_by_lambda_and_has_the_basic_execution_policy(self) -> None:
        role = roles(expand({"Fn": function()}))["FnRole"]
        statement = role["AssumeRolePolicyDocument"]["Statement"][0]
        assert statement["Principal"] == {"Service": ["lambda.amazonaws.com"]}
        assert role["ManagedPolicyArns"] == [
            "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        ]

    def test_origins_name_the_sam_resource(self) -> None:
        expansion = expand({"Fn": function()})
        assert expansion.origins["Fn"].logical_id == "Fn"
        assert expansion.origins["Fn"].cfn_type == "AWS::Serverless::Function"
        assert expansion.origins["FnRole"].logical_id == "Fn"
        assert expansion.expanded

    def test_the_function_comes_before_its_role(self) -> None:
        assert list(expand({"Fn": function()}).resources) == ["Fn", "FnRole"]

    def test_code_uri_names_a_bucket_only_when_it_is_one(self) -> None:
        local = expand({"Fn": function(CodeUri="src/")}).resources["Fn"]["Properties"]
        assert "Code" not in local
        s3 = expand({"Fn": function(CodeUri="s3://bkt/dir/key.zip")}).resources["Fn"]["Properties"]
        assert s3["Code"] == {"S3Bucket": "bkt", "S3Key": "dir/key.zip"}
        mapping = {"Bucket": "b", "Key": "k"}
        both = expand({"Fn": function(CodeUri=mapping)}).resources["Fn"]["Properties"]
        assert both["Code"] == {"S3Bucket": "b", "S3Key": "k"}
        image = expand({"Fn": function(ImageUri="repo:tag")}).resources["Fn"]["Properties"]
        assert image["Code"] == {"ImageUri": "repo:tag"}
        inline = expand({"Fn": function(InlineCode="x = 1")}).resources["Fn"]["Properties"]
        assert inline["Code"] == {"ZipFile": "x = 1"}

    def test_sam_only_properties_do_not_reach_the_lambda_function(self) -> None:
        expansion = expand(
            {"Fn": function(CodeUri="x", Policies=[], Events={}, AutoPublishAlias="live")}
        )
        properties = expansion.resources["Fn"]["Properties"]
        for key in ("CodeUri", "Policies", "Events", "AutoPublishAlias"):
            assert key not in properties

    def test_tags_tracing_and_dead_letter_queue_are_translated(self) -> None:
        expansion = expand(
            {
                "Fn": function(
                    Tags={"Team": "data"},
                    Tracing="Active",
                    DeadLetterQueue={"Type": "SQS", "TargetArn": "arn:q"},
                )
            }
        )
        properties = expansion.resources["Fn"]["Properties"]
        assert properties["Tags"] == [{"Key": "Team", "Value": "data"}]
        assert properties["TracingConfig"] == {"Mode": "Active"}
        assert properties["DeadLetterConfig"] == {"TargetArn": "arn:q"}
        managed = roles(expansion)["FnRole"]["ManagedPolicyArns"]
        assert "arn:aws:iam::aws:policy/AWSXrayWriteOnlyAccess" in managed

    def test_a_vpc_function_gets_the_vpc_access_policy(self) -> None:
        expansion = expand({"Fn": function(VpcConfig={"SubnetIds": ["s"], "SecurityGroupIds": []})})
        managed = roles(expansion)["FnRole"]["ManagedPolicyArns"]
        assert "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole" in managed

    def test_resource_level_attributes_carry_over(self) -> None:
        definition = function()
        definition.update({"DependsOn": "Other", "Condition": "C", "DeletionPolicy": "Retain"})
        resource = expand({"Fn": definition}).resources["Fn"]
        assert (resource["DependsOn"], resource["Condition"], resource["DeletionPolicy"]) == (
            "Other",
            "C",
            "Retain",
        )

    def test_the_input_is_not_modified(self) -> None:
        resources = {
            "Fn": function(Policies=["AdministratorAccess"], Events={"E": {"Type": "Api"}}),
        }
        before = copy.deepcopy(resources)
        expand(resources, {"Function": {"Timeout": 5}})
        assert resources == before

    def test_expansion_is_deterministic(self) -> None:
        resources = {"A": function(Events={"E": {"Type": "Api", "Properties": {"Path": "/"}}})}
        first = json.dumps(expand(resources).resources, sort_keys=True)
        second = json.dumps(expand(resources).resources, sort_keys=True)
        assert first == second


class TestPolicies:
    def test_a_managed_policy_name_becomes_its_arn(self) -> None:
        role = roles(expand({"Fn": function(Policies=["AdministratorAccess"])}))["FnRole"]
        assert "arn:aws:iam::aws:policy/AdministratorAccess" in role["ManagedPolicyArns"]

    def test_a_service_role_policy_gets_its_path(self) -> None:
        role = roles(expand({"Fn": function(Policies=["AWSLambdaRole"])}))["FnRole"]
        assert "arn:aws:iam::aws:policy/service-role/AWSLambdaRole" in role["ManagedPolicyArns"]

    def test_an_arn_is_kept_as_it_is(self) -> None:
        arn = "arn:aws:iam::111122223333:policy/mine"
        role = roles(expand({"Fn": function(Policies=arn)}))["FnRole"]
        assert arn in role["ManagedPolicyArns"]

    def test_a_ref_or_sub_names_a_managed_policy(self) -> None:
        reference = {"Ref": "MyPolicy"}
        role = roles(expand({"Fn": function(Policies=[reference])}))["FnRole"]
        assert reference in role["ManagedPolicyArns"]

    def test_an_inline_statement_becomes_an_inline_policy(self) -> None:
        document = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*"}]}
        role = roles(expand({"Fn": function(Policies=[document])}))["FnRole"]
        assert role["Policies"] == [{"PolicyName": "FnRolePolicy1", "PolicyDocument": document}]

    def test_a_policy_template_is_an_unknown_policy_with_a_note(self) -> None:
        template = {"DynamoDBCrudPolicy": {"TableName": {"Ref": "Table"}}}
        expansion = expand({"Fn": function(Policies=[template])})
        policy = roles(expansion)["FnRole"]["Policies"][0]
        assert policy["PolicyName"] == "FnRoleDynamoDBCrudPolicy"
        assert policy["PolicyDocument"] == {"Fn::SamPolicyTemplate": template}
        assert [(n.code, n.level, n.logical_id) for n in expansion.notes] == [
            ("cfn.sam_policy_template", "info", "Fn")
        ]
        assert "DynamoDBCrudPolicy" in expansion.notes[0].message

    def test_a_single_policy_need_not_be_a_list(self) -> None:
        role = roles(expand({"Fn": function(Policies="AmazonS3ReadOnlyAccess")}))["FnRole"]
        assert "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess" in role["ManagedPolicyArns"]

    def test_an_explicit_role_means_no_implicit_role(self) -> None:
        expansion = expand({"Fn": function(Role="arn:aws:iam::1:role/r", Policies=["X"])})
        assert types(expansion) == {"Fn": "AWS::Lambda::Function"}
        assert expansion.resources["Fn"]["Properties"]["Role"] == "arn:aws:iam::1:role/r"

    def test_a_permissions_boundary_is_set_on_the_role(self) -> None:
        role = roles(expand({"Fn": function(PermissionsBoundary="arn:pb")}))["FnRole"]
        assert role["PermissionsBoundary"] == "arn:pb"

    def test_junk_policy_entries_are_ignored(self) -> None:
        role = roles(expand({"Fn": function(Policies=[None, 5, {"A": 1, "B": 2}])}))["FnRole"]
        assert "Policies" not in role

    def test_a_generated_role_id_never_collides_with_a_template_id(self) -> None:
        resources = {"Fn": function(), "FnRole": {"Type": "AWS::IAM::Role", "Properties": {}}}
        expansion = expand(resources)
        assert expansion.resources["FnRole"] is resources["FnRole"]
        assert "FnRole2" in expansion.resources
        assert expansion.resources["Fn"]["Properties"]["Role"] == {"Fn::GetAtt": ["FnRole2", "Arn"]}


class TestGlobals:
    def test_scalars_come_from_the_global_unless_the_resource_sets_them(self) -> None:
        expansion = expand(
            {"A": function(), "B": function(Timeout=60)},
            {"Function": {"Timeout": 10, "Runtime": "r"}},
        )
        a, b = (expansion.resources[k]["Properties"] for k in ("A", "B"))
        assert (a["Timeout"], a["Runtime"]) == (10, "r")
        assert (b["Timeout"], b["Runtime"]) == (60, "r")

    def test_mappings_merge_recursively(self) -> None:
        expansion = expand(
            {"A": function(Environment={"Variables": {"OWN": "1"}})},
            {"Function": {"Environment": {"Variables": {"GLOBAL": "2", "OWN": "0"}}}},
        )
        variables = expansion.resources["A"]["Properties"]["Environment"]["Variables"]
        assert variables == {"GLOBAL": "2", "OWN": "1"}

    def test_lists_are_concatenated_with_the_global_first(self) -> None:
        expansion = expand({"A": function(Layers=["own"])}, {"Function": {"Layers": ["global"]}})
        assert expansion.resources["A"]["Properties"]["Layers"] == ["global", "own"]

    def test_globals_apply_to_apis_and_tables_too(self) -> None:
        expansion = expand(
            {
                "Api": {"Type": "AWS::Serverless::Api", "Properties": {"StageName": "Prod"}},
                "Table": {"Type": "AWS::Serverless::SimpleTable", "Properties": {}},
            },
            {
                "Api": {"TracingEnabled": True},
                "SimpleTable": {"SSESpecification": {"SSEEnabled": True}},
            },
        )
        stage = expansion.resources["ApiProdStage"]["Properties"]
        assert stage["TracingEnabled"] is True
        assert expansion.resources["Table"]["Properties"]["SSESpecification"] == {
            "SSEEnabled": True
        }

    def test_a_template_without_globals_or_with_junk_globals_expands(self) -> None:
        assert "Fn" in expand({"Fn": function()}, None).resources
        assert "Fn" in expand({"Fn": function()}, "text").resources
        assert "Fn" in expand({"Fn": function()}, {"Function": "text"}).resources

    def test_the_globals_are_not_modified(self) -> None:
        template_globals = {"Function": {"Layers": ["g"], "Environment": {"Variables": {"A": "1"}}}}
        before = copy.deepcopy(template_globals)
        expand(
            {"A": function(Layers=["x"], Environment={"Variables": {"B": "2"}})}, template_globals
        )
        assert template_globals == before


class TestEvents:
    def test_an_api_event_creates_the_implicit_rest_api_and_a_permission(self) -> None:
        events = {"Get": {"Type": "Api", "Properties": {"Path": "/orders", "Method": "get"}}}
        expansion = expand({"Fn": function(Events=events)})
        assert types(expansion)["ServerlessRestApi"] == "AWS::ApiGateway::RestApi"
        permission = expansion.resources["FnGetPermission"]["Properties"]
        assert permission["Principal"] == "apigateway.amazonaws.com"
        assert permission["FunctionName"] == {"Ref": "Fn"}
        assert permission["Action"] == "lambda:InvokeFunction"
        assert "${ServerlessRestApi}/*/GET/orders" in permission["SourceArn"]["Fn::Sub"]
        assert [(e.source, e.target, e.relation) for e in expansion.edges] == [
            ("ServerlessRestApi", "Fn", "invokes")
        ]

    def test_several_events_share_one_implicit_api(self) -> None:
        events = {
            "A": {"Type": "Api", "Properties": {"Path": "/a", "Method": "get"}},
            "B": {"Type": "Api", "Properties": {"Path": "/b", "Method": "post"}},
        }
        expansion = expand({"F1": function(Events=events), "F2": function(Events=events)})
        apis = [k for k, v in types(expansion).items() if v == "AWS::ApiGateway::RestApi"]
        assert apis == ["ServerlessRestApi"]
        assert len(expansion.edges) == 4

    def test_an_api_event_may_name_an_explicit_serverless_api(self) -> None:
        events = {
            "E": {
                "Type": "Api",
                "Properties": {"Path": "/", "Method": "any", "RestApiId": {"Ref": "MyApi"}},
            }
        }
        resources = {
            "MyApi": {"Type": "AWS::Serverless::Api", "Properties": {"StageName": "prod"}},
            "Fn": function(Events=events),
        }
        expansion = expand(resources)
        assert "ServerlessRestApi" not in expansion.resources
        assert [(e.source, e.target) for e in expansion.edges] == [("MyApi", "Fn")]
        assert (
            "${MyApi}/*/*/"
            in expansion.resources["FnEPermission"]["Properties"]["SourceArn"]["Fn::Sub"]
        )

    def test_a_template_resource_named_like_the_implicit_api_is_used(self) -> None:
        events = {"E": {"Type": "Api", "Properties": {"Path": "/", "Method": "get"}}}
        resources = {
            "ServerlessRestApi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {"Name": "mine"},
            },
            "Fn": function(Events=events),
        }
        expansion = expand(resources)
        assert expansion.resources["ServerlessRestApi"] is resources["ServerlessRestApi"]

    def test_an_http_api_event_creates_the_implicit_http_api(self) -> None:
        events = {"E": {"Type": "HttpApi", "Properties": {"Path": "/x", "Method": "get"}}}
        expansion = expand({"Fn": function(Events=events)})
        assert types(expansion)["ServerlessHttpApi"] == "AWS::ApiGatewayV2::Api"
        assert expansion.resources["ServerlessHttpApi"]["Properties"]["ProtocolType"] == "HTTP"
        assert [(e.source, e.target, e.relation) for e in expansion.edges] == [
            ("ServerlessHttpApi", "Fn", "invokes")
        ]

    def test_an_sqs_event_is_an_event_source_mapping_with_the_execution_policy(self) -> None:
        events = {
            "Q": {
                "Type": "SQS",
                "Properties": {"Queue": {"Fn::GetAtt": ["Work", "Arn"]}, "BatchSize": 5},
            }
        }
        resources = {"Work": {"Type": "AWS::SQS::Queue"}, "Fn": function(Events=events)}
        expansion = expand(resources)
        mapping = expansion.resources["FnQ"]
        assert mapping["Type"] == "AWS::Lambda::EventSourceMapping"
        assert mapping["Properties"]["EventSourceArn"] == {"Fn::GetAtt": ["Work", "Arn"]}
        assert mapping["Properties"]["BatchSize"] == 5
        managed = roles(expansion)["FnRole"]["ManagedPolicyArns"]
        assert "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole" in managed
        assert [(e.source, e.target, e.relation) for e in expansion.edges] == [
            ("Work", "Fn", "triggers")
        ]

    def test_an_sns_event_is_a_subscription_and_a_permission(self) -> None:
        events = {"T": {"Type": "SNS", "Properties": {"Topic": {"Ref": "Alerts"}}}}
        resources = {"Alerts": {"Type": "AWS::SNS::Topic"}, "Fn": function(Events=events)}
        expansion = expand(resources)
        subscription = expansion.resources["FnT"]["Properties"]
        assert subscription["Protocol"] == "lambda" and subscription["TopicArn"] == {
            "Ref": "Alerts"
        }
        assert (
            expansion.resources["FnTPermission"]["Properties"]["Principal"] == "sns.amazonaws.com"
        )

    def test_an_s3_event_is_a_permission_from_the_bucket(self) -> None:
        events = {
            "U": {
                "Type": "S3",
                "Properties": {"Bucket": {"Ref": "Uploads"}, "Events": "s3:ObjectCreated:*"},
            }
        }
        resources = {"Uploads": {"Type": "AWS::S3::Bucket"}, "Fn": function(Events=events)}
        expansion = expand(resources)
        permission = expansion.resources["FnUPermission"]["Properties"]
        assert permission["Principal"] == "s3.amazonaws.com"
        assert permission["SourceArn"] == {"Fn::GetAtt": ["Uploads", "Arn"]}

    def test_a_schedule_event_is_a_rule_that_targets_the_function(self) -> None:
        events = {"Cron": {"Type": "Schedule", "Properties": {"Schedule": "rate(5 minutes)"}}}
        expansion = expand({"Fn": function(Events=events)})
        rule = expansion.resources["FnCron"]
        assert rule["Type"] == "AWS::Events::Rule"
        assert rule["Properties"]["ScheduleExpression"] == "rate(5 minutes)"
        assert rule["Properties"]["Targets"][0]["Arn"] == {"Fn::GetAtt": ["Fn", "Arn"]}
        assert expansion.resources["FnCronPermission"]["Properties"]["Principal"] == (
            "events.amazonaws.com"
        )

    def test_events_that_are_not_modelled_are_ignored(self) -> None:
        events = {
            "X": {"Type": "Alexa"},
            "Y": "not a mapping",
            "Z": {"Type": "Api", "Properties": "x"},
        }
        expansion = expand({"Fn": function(Events=events)})
        assert "FnXPermission" not in expansion.resources

    def test_a_public_function_url_adds_the_url_and_the_open_permission(self) -> None:
        expansion = expand({"Fn": function(FunctionUrlConfig={"AuthType": "NONE"})})
        url = expansion.resources["FnUrl"]
        assert url["Type"] == "AWS::Lambda::Url"
        assert url["Properties"] == {"AuthType": "NONE", "TargetFunctionArn": {"Ref": "Fn"}}
        permission = expansion.resources["FnUrlPublicPermission"]["Properties"]
        assert permission["Principal"] == "*" and permission["FunctionUrlAuthType"] == "NONE"

    def test_an_authenticated_function_url_adds_no_open_permission(self) -> None:
        expansion = expand({"Fn": function(FunctionUrlConfig={"AuthType": "AWS_IAM"})})
        assert "FnUrl" in expansion.resources
        assert "FnUrlPublicPermission" not in expansion.resources


class TestOtherSamTypes:
    def test_simple_table(self) -> None:
        resources = {
            "T": {
                "Type": "AWS::Serverless::SimpleTable",
                "Properties": {"PrimaryKey": {"Name": "pk", "Type": "Number"}, "TableName": "t"},
            }
        }
        properties = expand(resources).resources["T"]["Properties"]
        assert expand(resources).resources["T"]["Type"] == "AWS::DynamoDB::Table"
        assert properties["AttributeDefinitions"] == [{"AttributeName": "pk", "AttributeType": "N"}]
        assert properties["KeySchema"] == [{"AttributeName": "pk", "KeyType": "HASH"}]
        assert properties["ProvisionedThroughput"] == {
            "ReadCapacityUnits": 5,
            "WriteCapacityUnits": 5,
        }
        assert properties["TableName"] == "t"

    def test_simple_table_defaults_to_a_string_key_named_id(self) -> None:
        table = expand({"T": {"Type": "AWS::Serverless::SimpleTable"}}).resources["T"]
        assert table["Properties"]["KeySchema"] == [{"AttributeName": "id", "KeyType": "HASH"}]
        assert table["Properties"]["AttributeDefinitions"][0]["AttributeType"] == "S"

    def test_serverless_api_becomes_a_rest_api_and_a_stage(self) -> None:
        resources = {
            "Api": {
                "Type": "AWS::Serverless::Api",
                "Properties": {
                    "StageName": "Prod",
                    "EndpointConfiguration": "REGIONAL",
                    "TracingEnabled": True,
                    "Name": "orders",
                },
            }
        }
        expansion = expand(resources)
        assert types(expansion) == {
            "Api": "AWS::ApiGateway::RestApi",
            "ApiProdStage": "AWS::ApiGateway::Stage",
        }
        stage = expansion.resources["ApiProdStage"]["Properties"]
        assert stage["RestApiId"] == {"Ref": "Api"} and stage["TracingEnabled"] is True
        api = expansion.resources["Api"]["Properties"]
        assert api["Name"] == "orders" and api["EndpointConfiguration"] == {"Types": ["REGIONAL"]}

    def test_serverless_http_api_becomes_an_api_and_a_default_stage(self) -> None:
        resources = {"H": {"Type": "AWS::Serverless::HttpApi", "Properties": {}}}
        expansion = expand(resources)
        assert types(expansion) == {
            "H": "AWS::ApiGatewayV2::Api",
            "HApiGatewayDefaultStage": "AWS::ApiGatewayV2::Stage",
        }
        assert (
            expansion.resources["HApiGatewayDefaultStage"]["Properties"]["StageName"] == "$default"
        )

    def test_state_machine_gets_a_role_unless_it_names_one(self) -> None:
        machine = {
            "Type": "AWS::Serverless::StateMachine",
            "Properties": {"Definition": {}, "Policies": ["AWSLambdaRole"]},
        }
        expansion = expand({"M": machine})
        assert types(expansion) == {
            "M": "AWS::StepFunctions::StateMachine",
            "MRole": "AWS::IAM::Role",
        }
        statement = roles(expansion)["MRole"]["AssumeRolePolicyDocument"]["Statement"][0]
        assert statement["Principal"] == {"Service": ["states.amazonaws.com"]}
        assert expansion.resources["M"]["Properties"]["RoleArn"] == {"Fn::GetAtt": ["MRole", "Arn"]}
        named = {"Type": "AWS::Serverless::StateMachine", "Properties": {"Role": "arn:r"}}
        assert types(expand({"M": named})) == {"M": "AWS::StepFunctions::StateMachine"}

    def test_application_becomes_a_nested_stack(self) -> None:
        app = {
            "Type": "AWS::Serverless::Application",
            "Properties": {"Location": "https://x/t.yaml", "Parameters": {"A": "1"}},
        }
        stack = expand({"App": app}).resources["App"]
        assert stack["Type"] == "AWS::CloudFormation::Stack"
        assert stack["Properties"]["TemplateURL"] == "https://x/t.yaml"
        assert stack["Properties"]["Parameters"] == {"A": "1"}

    def test_layer_version(self) -> None:
        layer = {
            "Type": "AWS::Serverless::LayerVersion",
            "Properties": {"LayerName": "l", "ContentUri": "x"},
        }
        resource = expand({"L": layer}).resources["L"]
        assert resource["Type"] == "AWS::Lambda::LayerVersion"
        assert resource["Properties"] == {"LayerName": "l", "Content": "x"}

    def test_a_connector_is_kept_and_reported(self) -> None:
        connector = {"Type": "AWS::Serverless::Connector", "Properties": {}}
        expansion = expand({"C": connector})
        assert expansion.resources["C"] is connector
        assert [(n.code, n.logical_id) for n in expansion.notes] == [
            ("cfn.sam_policy_template", "C")
        ]

    def test_other_resources_pass_through_unchanged(self) -> None:
        bucket = {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": "b"}}
        junk = "not a mapping"
        expansion = expand({"B": bucket, "J": junk})
        assert expansion.resources["B"] is bucket
        assert expansion.resources["J"] is junk
        assert not expansion.expanded
        assert expansion.edges == [] and expansion.notes == []


class TestParserIntegration:
    def parse(self, resources: dict[str, Any], **top: Any) -> Any:
        template = {"Transform": SAM_TRANSFORM, "Resources": resources, **top}
        return CloudFormationParser().parse(template)

    def test_a_function_with_administrator_access_has_an_admin_role(self) -> None:
        output = self.parse({"Fn": function(Policies=["AdministratorAccess"])})
        by_name = {r.name: r for r in output.resources}
        assert by_name["Fn"].resource_type == "aws_lambda_function"
        role = by_name["FnRole"]
        assert role.resource_type == "aws_iam_role"
        assert (
            "arn:aws:iam::aws:policy/AdministratorAccess" in role.properties["managed_policy_arns"]
        )

    def test_the_function_is_bound_to_its_role_by_a_reference(self) -> None:
        output = self.parse({"Fn": function()})
        fn = next(r for r in output.resources if r.name == "Fn")
        assert fn.references["role"] == ["FnRole"]
        assert fn.dependencies == []  # the typed iam_binding edge already covers the role
        graph = InfraGraph.from_parsed(output)
        edges = [(e.source, e.target, e.edge_type.value) for e in graph.edges]
        assert ("Fn", "FnRole", "iam_binding") in edges

    def test_generated_resources_record_where_they_came_from_and_share_its_lines(self) -> None:
        output = detect_and_parse(SAM_FIXTURE)
        admin = {r.name: r for r in output.resources}
        assert admin["AdminFunctionRole"].meta["sam_origin"] == "AdminFunction"
        assert admin["AdminFunctionRole"].meta["sam_type"] == "AWS::Serverless::Function"
        assert admin["AdminFunctionRole"].start_line == admin["AdminFunction"].start_line
        assert "sam_origin" in admin["ServerlessRestApi"].meta
        assert output.metadata["sam"] is True
        assert output.metadata["transform"] == [SAM_TRANSFORM]

    def test_the_api_to_function_flow_is_an_inferred_edge(self) -> None:
        output = detect_and_parse(SAM_FIXTURE)
        flows = {(e.source, e.target, e.edge_type, e.declared) for e in output.edges}
        assert ("ServerlessRestApi", "AdminFunction", "network_flow", False) in flows
        assert ("ServerlessHttpApi", "ReaderFunction", "network_flow", False) in flows
        assert ("WorkQueue", "ReaderFunction", "data_flow", False) in flows
        graph = InfraGraph.from_parsed(output)
        assert any(
            (e.source, e.target) == ("ServerlessRestApi", "AdminFunction") for e in graph.edges
        )

    def test_a_flow_to_a_resource_that_is_not_modelled_is_dropped(self) -> None:
        # the event names an API the template does not define, so no edge is drawn to it
        events = {
            "E": {"Type": "Api", "Properties": {"Path": "/", "RestApiId": {"Ref": "Elsewhere"}}}
        }
        output = self.parse({"Fn": function(Events=events)})
        assert all(edge.source != "Elsewhere" for edge in output.edges)

    def test_policy_templates_are_reported_as_diagnostics(self) -> None:
        output = detect_and_parse(SAM_FIXTURE)
        codes = {d.code for d in output.diagnostics}
        assert "cfn.sam_policy_template" in codes
        note = next(d for d in output.diagnostics if d.code == "cfn.sam_policy_template")
        assert note.line is not None and "DynamoDBCrudPolicy" in note.message

    def test_an_application_is_a_nested_stack_with_a_diagnostic(self) -> None:
        app = {
            "Type": "AWS::Serverless::Application",
            "Properties": {"Location": "https://x/t.yaml"},
        }
        output = self.parse({"App": app})
        assert output.resources[0].resource_type == "aws_cloudformation_stack"
        assert [d.code for d in output.diagnostics if d.level == "warning"] == ["cfn.nested_stack"]
        assert output.metadata["incomplete"] is True

    def test_a_template_without_the_transform_still_expands_sam_resources(self) -> None:
        output = CloudFormationParser().parse({"Resources": {"Fn": function()}})
        assert {r.name for r in output.resources} == {"Fn", "FnRole"}

    def test_real_shape_sam_api_template(self) -> None:
        output = detect_and_parse(SAM_API_FIXTURE)
        by_name = {r.name: r for r in output.resources}
        assert by_name["OrdersFunction"].resource_type == "aws_lambda_function"
        assert by_name["OrdersTable"].resource_type == "aws_dynamodb_table"
        assert [r.name for r in output.resources if r.resource_type == "aws_iam_role"] == [
            "OrdersFunctionRole",
            "AdminFunctionRole",
        ]
        # Globals put the table name into both functions' environments
        for name in ("OrdersFunction", "AdminFunction"):
            assert by_name[name].references.get("environment[].variables") == ["OrdersTable"]
        admin = by_name["AdminFunctionRole"].properties["managed_policy_arns"]
        assert "arn:aws:iam::aws:policy/AdministratorAccess" in admin
