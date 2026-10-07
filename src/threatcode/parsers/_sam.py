"""Expanding the AWS Serverless Application Model (SAM) into plain CloudFormation.

A template with ``Transform: AWS::Serverless-2016-10-31`` describes a function, an API or a
table in a few lines and leaves the IAM role, the Lambda permission and the API Gateway
resources to the transform.
Those generated resources are exactly what a threat model needs (the role is where the
privilege is, the permission and the API are how the internet reaches the function), so
`expand` writes them out as ordinary CloudFormation resources, which then go through the same
type table, property translation and reference scan as everything else.

The expansion is deterministic.
A generated resource gets the id SAM would give it (``<Function>Role``,
``ServerlessRestApi``), made unique when the template already uses the id, and
`SamExpansion.origins` records which SAM resource each came from.
`Globals` are merged the way SAM does: a mapping merges recursively, a list is
concatenated, and the resource's own value wins over a global scalar.

What is not expanded is reported rather than guessed:
a policy template (``DynamoDBCrudPolicy`` and the like) becomes a policy whose document is
unknown, an ``AWS::Serverless::Application`` stays a nested stack, and an
``AWS::Serverless::Connector`` is left as it is.
"""

from __future__ import annotations

import copy
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from threatcode.diagnostics import Level, register_code
from threatcode.parsers._cfn_refs import intrinsic_of

SAM_TRANSFORM = "AWS::Serverless-2016-10-31"
SAM_PREFIX = "AWS::Serverless::"

register_code(
    "cfn.sam_policy_template",
    "A SAM policy template or connector was not expanded, so the permissions it grants are unknown",
)


def _assume_role(service: str) -> dict[str, Any]:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": ["sts:AssumeRole"],
                "Effect": "Allow",
                "Principal": {"Service": [service]},
            }
        ],
    }


# Managed policies that live under the service-role/ path
_SERVICE_ROLE_POLICIES = frozenset(
    {
        "AWSLambdaBasicExecutionRole",
        "AWSLambdaVPCAccessExecutionRole",
        "AWSLambdaRole",
        "AWSLambdaKinesisExecutionRole",
        "AWSLambdaDynamoDBExecutionRole",
        "AWSLambdaSQSQueueExecutionRole",
        "AWSLambdaMSKExecutionRole",
        "AWSGlueServiceRole",
        "AmazonECSTaskExecutionRolePolicy",
        "AWSConfigRulesExecutionRole",
    }
)

_STREAM_POLICIES = {
    "SQS": "AWSLambdaSQSQueueExecutionRole",
    "Kinesis": "AWSLambdaKinesisExecutionRole",
    "DynamoDB": "AWSLambdaDynamoDBExecutionRole",
    "MSK": "AWSLambdaMSKExecutionRole",
}

# Function properties SAM adds to CloudFormation's; they never reach the Lambda resource
_FUNCTION_SAM_ONLY = frozenset(
    {
        "CodeUri",
        "InlineCode",
        "ImageUri",
        "Policies",
        "Events",
        "AutoPublishAlias",
        "AutoPublishAliasAllProperties",
        "DeploymentPreference",
        "DeadLetterQueue",
        "Tracing",
        "Tags",
        "PermissionsBoundary",
        "FunctionUrlConfig",
        "EventInvokeConfig",
        "ProvisionedConcurrencyConfig",
        "VersionDescription",
        "RolePath",
        "AssumeRolePolicyDocument",
        "RuntimeManagementConfig",
    }
)

_ATTRIBUTE_TYPES = {"String": "S", "Number": "N", "Binary": "B"}
_EVENT_SOURCES = frozenset({"SQS", "Kinesis", "DynamoDB", "MSK", "MQ", "DocumentDB"})
_SCHEDULES = frozenset({"Schedule", "ScheduleV2", "CloudWatchEvent", "EventBridgeRule"})
_NOT_ID = re.compile(r"[^A-Za-z0-9]")


@dataclass(frozen=True)
class SamNote:
    """Something the expansion could not model, for the parser to report."""

    level: Level
    code: str
    message: str
    logical_id: str


@dataclass(frozen=True)
class SamOrigin:
    """The SAM resource a resource of the expanded template came from."""

    logical_id: str
    cfn_type: str


@dataclass(frozen=True)
class SamEdge:
    """A flow the events of a SAM function declare: `source` reaches `target`."""

    source: str
    target: str
    relation: str


@dataclass
class SamExpansion:
    """A template's resources with the SAM ones written out as CloudFormation."""

    resources: dict[str, Any] = field(default_factory=dict)
    # generated or rewritten logical id -> the SAM resource it came from
    origins: dict[str, SamOrigin] = field(default_factory=dict)
    edges: list[SamEdge] = field(default_factory=list)
    notes: list[SamNote] = field(default_factory=list)

    @property
    def expanded(self) -> bool:
        return bool(self.origins)


def is_sam_type(cfn_type: Any) -> bool:
    return isinstance(cfn_type, str) and cfn_type.startswith(SAM_PREFIX)


def transform_names(transform: Any) -> list[str]:
    """The names in a template's ``Transform`` (a string, a list or ``{Name: ...}`` entries)."""
    if isinstance(transform, str):
        return [transform]
    if isinstance(transform, Mapping):
        name = transform.get("Name")
        return [name] if isinstance(name, str) else []
    if isinstance(transform, list):
        return [name for item in transform for name in transform_names(item)]
    return []


def uses_sam(transform: Any) -> bool:
    return any(name.startswith("AWS::Serverless") for name in transform_names(transform))


def _merge_globals(base: Any, own: Any) -> Any:
    """Merge a Globals section into a resource's value: the resource wins, lists add up."""
    if isinstance(base, Mapping) and isinstance(own, Mapping):
        merged = {key: copy.copy(value) for key, value in base.items()}
        for key, value in own.items():
            merged[key] = _merge_globals(merged[key], value) if key in merged else value
        return merged
    if isinstance(base, list) and isinstance(own, list):
        return [*base, *own]
    return own


def _is_intrinsic(value: Any) -> bool:
    return intrinsic_of(value) is not None


def _policy_arn(name: str) -> str:
    if name.startswith("arn:"):
        return name
    path = "service-role/" if name in _SERVICE_ROLE_POLICIES else ""
    return f"arn:aws:iam::aws:policy/{path}{name}"


def _tags_list(tags: Any) -> Any:
    """SAM takes tags as a mapping; CloudFormation resources take a list of Key and Value."""
    if isinstance(tags, Mapping):
        return [{"Key": key, "Value": value} for key, value in tags.items()]
    return tags


class _Expander:
    def __init__(self, resources: Mapping[str, Any], template_globals: Any) -> None:
        self.source = resources
        self.globals: Mapping[str, Any] = (
            template_globals if isinstance(template_globals, Mapping) else {}
        )
        self.taken: set[str] = {str(key) for key in resources}
        self.result = SamExpansion()

    # -- bookkeeping -----------------------------------------------------------------

    def unique(self, base: str) -> str:
        base = _NOT_ID.sub("", base) or "Resource"
        candidate, number = base, 2
        while candidate in self.taken:
            candidate = f"{base}{number}"
            number += 1
        self.taken.add(candidate)
        return candidate

    def add(
        self,
        logical_id: str,
        cfn_type: str,
        properties: dict[str, Any],
        origin: tuple[str, str],
        **extra: Any,
    ) -> None:
        definition: dict[str, Any] = {"Type": cfn_type, "Properties": properties, **extra}
        self.result.resources[logical_id] = definition
        self.result.origins[logical_id] = SamOrigin(*origin)

    def note(self, level: Level, code: str, message: str, logical_id: str) -> None:
        self.result.notes.append(SamNote(level, code, message, logical_id))

    def globals_for(self, kind: str, properties: Mapping[str, Any]) -> dict[str, Any]:
        merged = _merge_globals(self.globals.get(kind), properties)
        return dict(merged) if isinstance(merged, Mapping) else dict(properties)

    # -- the walk --------------------------------------------------------------------

    def run(self) -> SamExpansion:
        for logical_id, definition in self.source.items():
            handler = None
            if isinstance(definition, Mapping) and is_sam_type(definition.get("Type")):
                handler = self._handlers().get(definition["Type"])
            if handler is None:
                self.result.resources[str(logical_id)] = definition
                continue
            properties = definition.get("Properties")
            handler(
                str(logical_id), definition, properties if isinstance(properties, Mapping) else {}
            )
        return self.result

    def _handlers(self) -> dict[str, Any]:
        return {
            "AWS::Serverless::Function": self.function,
            "AWS::Serverless::Api": self.api,
            "AWS::Serverless::HttpApi": self.http_api,
            "AWS::Serverless::SimpleTable": self.simple_table,
            "AWS::Serverless::StateMachine": self.state_machine,
            "AWS::Serverless::Application": self.application,
            "AWS::Serverless::LayerVersion": self.layer_version,
        }

    def passthrough(self, definition: Mapping[str, Any]) -> dict[str, Any]:
        """Resource-level attributes (DependsOn, Condition, DeletionPolicy) carry over."""
        keys = ("DependsOn", "Condition", "DeletionPolicy", "UpdateReplacePolicy", "Metadata")
        return {key: definition[key] for key in keys if key in definition}

    # -- roles -----------------------------------------------------------------------

    def role(
        self,
        owner: str,
        service: str,
        policies: Any,
        extra_managed: list[str],
        boundary: Any = None,
    ) -> tuple[str, dict[str, Any]]:
        """The implicit execution role of a function or state machine: its id and properties."""
        role_id = self.unique(f"{owner}Role")
        managed: list[Any] = [_policy_arn(name) for name in extra_managed]
        inline: list[dict[str, Any]] = []
        if policies is None:
            entries: list[Any] = []
        else:
            entries = policies if isinstance(policies, list) else [policies]
        for entry in entries:
            self._policy_entry(owner, role_id, entry, managed, inline)
        properties: dict[str, Any] = {"AssumeRolePolicyDocument": _assume_role(service)}
        if managed:
            properties["ManagedPolicyArns"] = managed
        if inline:
            properties["Policies"] = inline
        if boundary is not None:
            properties["PermissionsBoundary"] = boundary
        return role_id, properties

    def _policy_entry(
        self,
        owner: str,
        role_id: str,
        entry: Any,
        managed: list[Any],
        inline: list[dict[str, Any]],
    ) -> None:
        if isinstance(entry, str):
            managed.append(_policy_arn(entry))
        elif _is_intrinsic(entry):
            managed.append(entry)  # a Ref or Sub that names a managed policy
        elif isinstance(entry, Mapping) and ("Statement" in entry or "Version" in entry):
            inline.append(
                {"PolicyName": f"{role_id}Policy{len(inline) + 1}", "PolicyDocument": dict(entry)}
            )
        elif isinstance(entry, Mapping) and len(entry) == 1:
            name = str(next(iter(entry)))
            inline.append(
                {
                    "PolicyName": f"{role_id}{name}",
                    "PolicyDocument": {"Fn::SamPolicyTemplate": {name: entry[name]}},
                }
            )
            self.note(
                "info",
                "cfn.sam_policy_template",
                f"SAM policy template {name} on {owner} is not expanded; "
                "the permissions it grants are unknown",
                owner,
            )

    # -- functions -------------------------------------------------------------------

    def function(self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]) -> None:
        props = self.globals_for("Function", raw)
        cfn: dict[str, Any] = {k: v for k, v in props.items() if k not in _FUNCTION_SAM_ONLY}
        self._function_code(props, cfn)
        if "Tags" in props:
            cfn["Tags"] = _tags_list(props["Tags"])
        queue = props.get("DeadLetterQueue")
        if isinstance(queue, Mapping) and "TargetArn" in queue:
            cfn["DeadLetterConfig"] = {"TargetArn": queue["TargetArn"]}
        tracing = props.get("Tracing")
        if tracing is not None and "TracingConfig" not in cfn:
            cfn["TracingConfig"] = {"Mode": tracing}

        found_events = props.get("Events")
        events: Mapping[str, Any] = found_events if isinstance(found_events, Mapping) else {}
        managed = ["AWSLambdaBasicExecutionRole"]
        if "VpcConfig" in props:
            managed.append("AWSLambdaVPCAccessExecutionRole")
        if tracing == "Active":
            managed.append("AWSXrayWriteOnlyAccess")
        for event in events.values():
            policy = (
                _STREAM_POLICIES.get(str(event.get("Type"))) if isinstance(event, Mapping) else None
            )
            if policy and policy not in managed:
                managed.append(policy)

        role: tuple[str, dict[str, Any]] | None = None
        if "Role" not in props:
            role = self.role(
                lid,
                "lambda.amazonaws.com",
                props.get("Policies"),
                managed,
                props.get("PermissionsBoundary"),
            )
            cfn["Role"] = {"Fn::GetAtt": [role[0], "Arn"]}
        origin = (lid, "AWS::Serverless::Function")
        self.add(lid, "AWS::Lambda::Function", cfn, origin, **self.passthrough(definition))
        if role is not None:
            self.add(role[0], "AWS::IAM::Role", role[1], origin)
        for event_id, event in events.items():
            if isinstance(event, Mapping):
                self._event(lid, str(event_id), event)
        url = props.get("FunctionUrlConfig")
        if isinstance(url, Mapping):
            self._function_url(lid, url)

    @staticmethod
    def _function_code(props: Mapping[str, Any], cfn: dict[str, Any]) -> None:
        """Where the code lives; a local CodeUri path is packaged later and names no bucket."""
        uri = props.get("CodeUri")
        if "ImageUri" in props:
            cfn["Code"] = {"ImageUri": props["ImageUri"]}
        elif "InlineCode" in props:
            cfn["Code"] = {"ZipFile": props["InlineCode"]}
        elif isinstance(uri, Mapping):
            cfn["Code"] = {"S3Bucket": uri.get("Bucket"), "S3Key": uri.get("Key")}
        elif isinstance(uri, str) and uri.startswith("s3://"):
            bucket, _, key = uri[len("s3://") :].partition("/")
            cfn["Code"] = {"S3Bucket": bucket, "S3Key": key}

    def _permission(
        self, lid: str, name: str, principal: str, source_arn: Any = None, **extra: Any
    ) -> str:
        permission_id = self.unique(f"{lid}{name}Permission")
        properties: dict[str, Any] = {
            "Action": "lambda:InvokeFunction",
            "FunctionName": {"Ref": lid},
            "Principal": principal,
        }
        if source_arn is not None:
            properties["SourceArn"] = source_arn
        properties.update(extra)
        self.add(
            permission_id, "AWS::Lambda::Permission", properties, (lid, "AWS::Serverless::Function")
        )
        return permission_id

    def _event(self, lid: str, event_id: str, event: Mapping[str, Any]) -> None:
        kind = str(event.get("Type", ""))
        raw = event.get("Properties")
        props: Mapping[str, Any] = raw if isinstance(raw, Mapping) else {}
        if kind == "Api":
            api = self._api_target(
                props.get("RestApiId"), "ServerlessRestApi", self._implicit_rest_api
            )
            path, method = str(props.get("Path", "/")), str(props.get("Method", "any")).upper()
            method = "*" if method == "ANY" else method
            arn = {
                "Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:"
                f"${{{api}}}/*/{method}{path}"
            }
            self._permission(lid, event_id, "apigateway.amazonaws.com", arn)
            self.result.edges.append(SamEdge(api, lid, "invokes"))
        elif kind == "HttpApi":
            api = self._api_target(props.get("ApiId"), "ServerlessHttpApi", self._implicit_http_api)
            arn = {
                "Fn::Sub": "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:"
                f"${{{api}}}/*"
            }
            self._permission(lid, event_id, "apigateway.amazonaws.com", arn)
            self.result.edges.append(SamEdge(api, lid, "invokes"))
        elif kind == "S3":
            bucket = props.get("Bucket")
            self._permission(lid, event_id, "s3.amazonaws.com", self._arn_of(bucket))
            self._trigger_edge(bucket, lid)
        elif kind == "SNS":
            topic = props.get("Topic")
            subscription = self.unique(f"{lid}{event_id}")
            self.add(
                subscription,
                "AWS::SNS::Subscription",
                {
                    "TopicArn": topic,
                    "Protocol": "lambda",
                    "Endpoint": {"Fn::GetAtt": [lid, "Arn"]},
                },
                (lid, "AWS::Serverless::Function"),
            )
            self._permission(lid, event_id, "sns.amazonaws.com", topic)
            self._trigger_edge(topic, lid)
        elif kind in _EVENT_SOURCES:
            mapping = self.unique(f"{lid}{event_id}")
            source = props.get("Queue") or props.get("Stream") or props.get("Broker")
            properties: dict[str, Any] = {
                "FunctionName": {"Ref": lid},
                "EventSourceArn": source,
            }
            for key in (
                "BatchSize",
                "Enabled",
                "MaximumBatchingWindowInSeconds",
                "StartingPosition",
            ):
                if key in props:
                    properties[key] = props[key]
            self.add(
                mapping,
                "AWS::Lambda::EventSourceMapping",
                properties,
                (lid, "AWS::Serverless::Function"),
            )
            self._trigger_edge(source, lid)
        elif kind in _SCHEDULES:
            rule = self.unique(f"{lid}{event_id}")
            properties = {
                "Targets": [{"Arn": {"Fn::GetAtt": [lid, "Arn"]}, "Id": f"{event_id}LambdaTarget"}],
                "State": "DISABLED" if props.get("Enabled") is False else "ENABLED",
            }
            if "Schedule" in props:
                properties["ScheduleExpression"] = props["Schedule"]
            if "Pattern" in props:
                properties["EventPattern"] = props["Pattern"]
            self.add(rule, "AWS::Events::Rule", properties, (lid, "AWS::Serverless::Function"))
            self._permission(lid, event_id, "events.amazonaws.com", {"Fn::GetAtt": [rule, "Arn"]})
            self.result.edges.append(SamEdge(rule, lid, "triggers"))

    def _api_target(self, explicit: Any, implicit_id: str, create: Any) -> str:
        """The API an event attaches to: the one it names, else the implicit one."""
        named = explicit.get("Ref") if isinstance(explicit, Mapping) else None
        if isinstance(named, str) and named in self.source:
            return named
        return str(create(implicit_id))

    def _implicit_rest_api(self, implicit_id: str) -> str:
        if implicit_id not in self.result.resources and implicit_id not in self.source:
            self.add(
                implicit_id,
                "AWS::ApiGateway::RestApi",
                {"Name": implicit_id, "EndpointConfiguration": {"Types": ["EDGE"]}},
                (implicit_id, "AWS::Serverless::Api"),
            )
        return implicit_id

    def _implicit_http_api(self, implicit_id: str) -> str:
        if implicit_id not in self.result.resources and implicit_id not in self.source:
            self.add(
                implicit_id,
                "AWS::ApiGatewayV2::Api",
                {"Name": implicit_id, "ProtocolType": "HTTP"},
                (implicit_id, "AWS::Serverless::HttpApi"),
            )
        return implicit_id

    @staticmethod
    def _arn_of(target: Any) -> Any:
        ref = target.get("Ref") if isinstance(target, Mapping) else None
        return {"Fn::GetAtt": [ref, "Arn"]} if isinstance(ref, str) else target

    def _trigger_edge(self, source: Any, lid: str) -> None:
        name = None
        if isinstance(source, Mapping):
            ref = source.get("Ref")
            getatt = source.get("Fn::GetAtt")
            name = (
                ref
                if isinstance(ref, str)
                else (getatt[0] if isinstance(getatt, list) and getatt else None)
            )
        if isinstance(name, str) and name in self.source:
            self.result.edges.append(SamEdge(name, lid, "triggers"))

    def _function_url(self, lid: str, config: Mapping[str, Any]) -> None:
        auth = config.get("AuthType", "NONE")
        url_id = self.unique(f"{lid}Url")
        properties: dict[str, Any] = {"AuthType": auth, "TargetFunctionArn": {"Ref": lid}}
        for key in ("Cors", "InvokeMode"):
            if key in config:
                properties[key] = config[key]
        self.add(url_id, "AWS::Lambda::Url", properties, (lid, "AWS::Serverless::Function"))
        self.result.edges.append(SamEdge(url_id, lid, "invokes"))
        if auth == "NONE":
            permission = self.unique(f"{lid}UrlPublicPermission")
            self.add(
                permission,
                "AWS::Lambda::Permission",
                {
                    "Action": "lambda:InvokeFunctionUrl",
                    "FunctionName": {"Ref": lid},
                    "Principal": "*",
                    "FunctionUrlAuthType": "NONE",
                },
                (lid, "AWS::Serverless::Function"),
            )

    # -- APIs, tables, state machines ------------------------------------------------

    def api(self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]) -> None:
        props = self.globals_for("Api", raw)
        cfn: dict[str, Any] = {"Name": props.get("Name", lid)}
        endpoint = props.get("EndpointConfiguration")
        if isinstance(endpoint, str):
            cfn["EndpointConfiguration"] = {"Types": [endpoint]}
        elif isinstance(endpoint, Mapping):
            kind = endpoint.get("Type")
            cfn["EndpointConfiguration"] = {"Types": [kind] if kind is not None else ["EDGE"]}
        else:
            cfn["EndpointConfiguration"] = {"Types": ["EDGE"]}
        if "DefinitionBody" in props:
            cfn["Body"] = props["DefinitionBody"]
        if "DefinitionUri" in props:
            cfn["BodyS3Location"] = props["DefinitionUri"]
        for key in ("BinaryMediaTypes", "MinimumCompressionSize", "DisableExecuteApiEndpoint"):
            if key in props:
                cfn[key] = props[key]
        if "Tags" in props:
            cfn["Tags"] = _tags_list(props["Tags"])
        origin = (lid, "AWS::Serverless::Api")
        self.add(lid, "AWS::ApiGateway::RestApi", cfn, origin, **self.passthrough(definition))
        stage = props.get("StageName")
        if stage is not None:
            stage_props: dict[str, Any] = {"StageName": stage, "RestApiId": {"Ref": lid}}
            for key in (
                "TracingEnabled",
                "AccessLogSetting",
                "MethodSettings",
                "CacheClusterEnabled",
            ):
                if key in props:
                    stage_props[key] = props[key]
            if "Variables" in props:
                stage_props["Variables"] = props["Variables"]
            stage_id = self.unique(f"{lid}{stage if isinstance(stage, str) else ''}Stage")
            self.add(stage_id, "AWS::ApiGateway::Stage", stage_props, origin)

    def http_api(self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]) -> None:
        props = self.globals_for("HttpApi", raw)
        cfn: dict[str, Any] = {"Name": props.get("Name", lid), "ProtocolType": "HTTP"}
        if "DefinitionBody" in props:
            cfn["Body"] = props["DefinitionBody"]
        if "CorsConfiguration" in props:
            cfn["CorsConfiguration"] = props["CorsConfiguration"]
        if "DisableExecuteApiEndpoint" in props:
            cfn["DisableExecuteApiEndpoint"] = props["DisableExecuteApiEndpoint"]
        if "Tags" in props:
            cfn["Tags"] = props["Tags"]
        origin = (lid, "AWS::Serverless::HttpApi")
        self.add(lid, "AWS::ApiGatewayV2::Api", cfn, origin, **self.passthrough(definition))
        stage_props: dict[str, Any] = {
            "ApiId": {"Ref": lid},
            "StageName": props.get("StageName", "$default"),
            "AutoDeploy": True,
        }
        if "AccessLogSettings" in props:
            stage_props["AccessLogSettings"] = props["AccessLogSettings"]
        self.add(
            self.unique(f"{lid}ApiGatewayDefaultStage"),
            "AWS::ApiGatewayV2::Stage",
            stage_props,
            origin,
        )

    def simple_table(self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]) -> None:
        props = self.globals_for("SimpleTable", raw)
        primary = props.get("PrimaryKey")
        key: Mapping[str, Any] = primary if isinstance(primary, Mapping) else {}
        name = key.get("Name", "id")
        kind = _ATTRIBUTE_TYPES.get(str(key.get("Type", "String")), "S")
        cfn: dict[str, Any] = {
            "AttributeDefinitions": [{"AttributeName": name, "AttributeType": kind}],
            "KeySchema": [{"AttributeName": name, "KeyType": "HASH"}],
            "ProvisionedThroughput": props.get(
                "ProvisionedThroughput", {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
            ),
        }
        for source, target in (
            ("TableName", "TableName"),
            ("SSESpecification", "SSESpecification"),
            ("PointInTimeRecoverySpecification", "PointInTimeRecoverySpecification"),
        ):
            if source in props:
                cfn[target] = props[source]
        if "Tags" in props:
            cfn["Tags"] = _tags_list(props["Tags"])
        self.add(
            lid,
            "AWS::DynamoDB::Table",
            cfn,
            (lid, "AWS::Serverless::SimpleTable"),
            **self.passthrough(definition),
        )

    def state_machine(
        self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]
    ) -> None:
        props = self.globals_for("StateMachine", raw)
        cfn: dict[str, Any] = {}
        for source, target in (
            ("Name", "StateMachineName"),
            ("Type", "StateMachineType"),
            ("Logging", "LoggingConfiguration"),
            ("Tracing", "TracingConfiguration"),
            ("DefinitionSubstitutions", "DefinitionSubstitutions"),
        ):
            if source in props:
                cfn[target] = props[source]
        if "Definition" in props:
            cfn["Definition"] = props["Definition"]
        if "DefinitionUri" in props:
            cfn["DefinitionS3Location"] = props["DefinitionUri"]
        if "Tags" in props:
            cfn["Tags"] = _tags_list(props["Tags"])
        role: tuple[str, dict[str, Any]] | None = None
        if "Role" in props:
            cfn["RoleArn"] = props["Role"]
        else:
            role = self.role(
                lid,
                "states.amazonaws.com",
                props.get("Policies"),
                [],
                props.get("PermissionsBoundary"),
            )
            cfn["RoleArn"] = {"Fn::GetAtt": [role[0], "Arn"]}
        origin = (lid, "AWS::Serverless::StateMachine")
        self.add(
            lid, "AWS::StepFunctions::StateMachine", cfn, origin, **self.passthrough(definition)
        )
        if role is not None:
            self.add(role[0], "AWS::IAM::Role", role[1], origin)

    def application(self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]) -> None:
        cfn: dict[str, Any] = {}
        location = raw.get("Location")
        if isinstance(location, str):
            cfn["TemplateURL"] = location
        elif isinstance(location, Mapping):
            cfn["TemplateURL"] = location.get("ApplicationId", "")
        for source, target in (
            ("Parameters", "Parameters"),
            ("TimeoutInMinutes", "TimeoutInMinutes"),
            ("NotificationARNs", "NotificationARNs"),
        ):
            if source in raw:
                cfn[target] = raw[source]
        if "Tags" in raw:
            cfn["Tags"] = _tags_list(raw["Tags"])
        self.add(
            lid,
            "AWS::CloudFormation::Stack",
            cfn,
            (lid, "AWS::Serverless::Application"),
            **self.passthrough(definition),
        )

    def layer_version(
        self, lid: str, definition: Mapping[str, Any], raw: Mapping[str, Any]
    ) -> None:
        cfn: dict[str, Any] = {}
        for source, target in (
            ("LayerName", "LayerName"),
            ("Description", "Description"),
            ("ContentUri", "Content"),
            ("CompatibleRuntimes", "CompatibleRuntimes"),
            ("LicenseInfo", "LicenseInfo"),
        ):
            if source in raw:
                cfn[target] = raw[source]
        self.add(
            lid,
            "AWS::Lambda::LayerVersion",
            cfn,
            (lid, "AWS::Serverless::LayerVersion"),
            **self.passthrough(definition),
        )


def expand(resources: Mapping[str, Any], template_globals: Any = None) -> SamExpansion:
    """Write the SAM resources of a template out as CloudFormation resources.

    Args:
        resources: The template's ``Resources`` mapping.
        template_globals: The template's ``Globals`` section, merged into functions, APIs
            and tables.

    Returns:
        Every resource of the template in order, each SAM resource replaced by its expansion
        (the resource itself under its own id, then the resources generated for it), the
        origin of every rewritten or generated resource, the flows its events declare and
        the notes for what could not be expanded.
        Resources that are not SAM resources, and SAM types that are not expanded
        (``AWS::Serverless::Connector``), pass through unchanged.
    """
    expander = _Expander(resources, template_globals)
    expansion = expander.run()
    for logical_id, definition in resources.items():
        if (
            isinstance(definition, Mapping)
            and definition.get("Type") == "AWS::Serverless::Connector"
        ):
            expansion.notes.append(
                SamNote(
                    "info",
                    "cfn.sam_policy_template",
                    f"SAM connector {logical_id} is not expanded; "
                    "the permissions it grants are unknown",
                    str(logical_id),
                )
            )
    return expansion
