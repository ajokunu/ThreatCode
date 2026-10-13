"""Tests for threatcode.ir.iam: roles, policies and the resources a role may reach."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from threatcode.ir import iam
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import InfraGraph
from threatcode.ir.iam import MAX_WILDCARD_TARGETS, classify_access
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.values import Unknown

REALISTIC = Path(__file__).parent.parent / "fixtures" / "realistic"


def _pr(rtype: str, name: str, **kwargs: Any) -> ParsedResource:
    return ParsedResource(rtype, f"{rtype}.{name}", name, rtype.split("_", 1)[0], **kwargs)


def _graph(*resources: ParsedResource) -> InfraGraph:
    return InfraGraph.from_parsed(
        ParsedOutput(resources=list(resources), format_type="terraform_plan")
    )


def _edges(graph: InfraGraph, relation: str) -> set[tuple[str, str]]:
    return {
        (e.source, e.target)
        for e in graph.edges
        if e.edge_type is EdgeType.IAM_BINDING and e.relation == relation
    }


def _statement(
    actions: Any, resources: Any, *, effect: str = "Allow", condition: Any = None
) -> dict[str, Any]:
    found: dict[str, Any] = {"Effect": effect, "Action": actions, "Resource": resources}
    if condition is not None:
        found["Condition"] = condition
    return found


def _policy_json(*statements: dict[str, Any]) -> str:
    return json.dumps({"Version": "2012-10-17", "Statement": list(statements)})


def _role_with(*statements: dict[str, Any], name: str = "app") -> list[ParsedResource]:
    """A role named `name` with one managed policy that holds the statements."""
    return [
        _pr("aws_iam_role", name, properties={"name": name}),
        _pr("aws_iam_policy", name, properties={"name": name, "policy": _policy_json(*statements)}),
        _pr(
            "aws_iam_role_policy_attachment",
            name,
            properties={"role": name, "policy_arn": f"aws_iam_policy.{name}"},
        ),
    ]


def _bucket(label: str, name: str | None = None) -> ParsedResource:
    return _pr("aws_s3_bucket", label, properties={"bucket": name or label})


def _permission(graph: InfraGraph, role: str, target: str) -> dict[str, Any]:
    matches = [
        e.attributes
        for e in graph.edges
        if (e.source, e.target, e.relation) == (role, target, "permission")
    ]
    assert len(matches) == 1, f"{role} -> {target}: {matches}"
    return matches[0]


class TestClassifyAccess:
    @pytest.mark.parametrize(
        ("actions", "expected"),
        [
            (["s3:GetObject"], "read"),
            (["s3:ListBucket", "s3:GetObject"], "read"),
            (["dynamodb:Query", "dynamodb:Scan", "dynamodb:BatchGetItem"], "read"),
            (["ec2:DescribeInstances"], "read"),
            (["kms:Decrypt"], "read"),
            (["s3:PutObject"], "write"),
            (["s3:GetObject", "s3:DeleteObject"], "write"),
            (["sqs:SendMessage"], "write"),
            (["lambda:InvokeFunction"], "write"),
            (["s3:*Object*"], "write"),
            (["iam:PassRole"], "write"),
            (["s3:*"], "admin"),
            (["iam:*"], "admin"),
            (["*"], "admin"),
            (["s3:GetObject", "*"], "admin"),
            ([], "read"),
        ],
    )
    def test_read_write_admin(self, actions: list[str], expected: str) -> None:
        assert classify_access(actions) == expected

    def test_an_unreadable_action_is_ignored(self) -> None:
        assert classify_access([Unknown("var.a"), "s3:GetObject"]) == "read"
        assert classify_access([Unknown()]) == "read"


class TestRoleResolution:
    def _holder(self, **props: Any) -> ParsedResource:
        return _pr("aws_lambda_function", "fn", properties=props)

    def test_by_reference(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "a", properties={"name": "a-role"}),
            _pr("aws_iam_role", "b", properties={"name": "b-role"}),
            _pr("aws_lambda_function", "fn", references={"role": ["aws_iam_role.b.arn"]}),
        )
        assert _edges(graph, "assumes") == {("aws_lambda_function.fn", "aws_iam_role.b")}

    def test_by_name_attribute(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "a", properties={"name": "alpha"}),
            _pr("aws_iam_role", "b", properties={"name": "beta"}),
            self._holder(role="beta"),
        )
        assert _edges(graph, "assumes") == {("aws_lambda_function.fn", "aws_iam_role.b")}

    def test_by_arn(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "a", properties={"name": "alpha"}),
            _pr("aws_iam_role", "b", properties={"name": "beta"}),
            self._holder(role="arn:aws:iam::123456789012:role/path/beta"),
        )
        assert _edges(graph, "assumes") == {("aws_lambda_function.fn", "aws_iam_role.b")}

    def test_by_label_as_the_last_resort(self) -> None:
        graph = _graph(_pr("aws_iam_role", "worker"), self._holder(role="worker"))
        assert _edges(graph, "assumes") == {("aws_lambda_function.fn", "aws_iam_role.worker")}

    def test_the_name_attribute_beats_a_label(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "beta", properties={"name": "other"}),
            _pr("aws_iam_role", "b", properties={"name": "beta"}),
            self._holder(role="beta"),
        )
        assert _edges(graph, "assumes") == {("aws_lambda_function.fn", "aws_iam_role.b")}

    def test_a_role_outside_the_graph_links_to_nothing(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "a", properties={"name": "alpha"}),
            self._holder(role="arn:aws:iam::123456789012:role/elsewhere"),
        )
        assert _edges(graph, "assumes") == set()

    @pytest.mark.parametrize(
        ("rtype", "attribute"),
        [
            ("aws_lambda_function", "role"),
            ("aws_ecs_task_definition", "task_role_arn"),
            ("aws_ecs_task_definition", "execution_role_arn"),
            ("aws_sagemaker_notebook_instance", "role_arn"),
            ("aws_eks_cluster", "role_arn"),
            ("aws_eks_node_group", "node_role_arn"),
            ("aws_iam_instance_profile", "role"),
        ],
    )
    def test_every_compute_role_attribute_binds(self, rtype: str, attribute: str) -> None:
        graph = _graph(
            _pr("aws_iam_role", "r", properties={"name": "the-role"}),
            _pr(rtype, "holder", properties={attribute: "the-role"}),
        )
        assert _edges(graph, "assumes") == {(f"{rtype}.holder", "aws_iam_role.r")}

    def test_an_instance_reaches_its_role_through_the_instance_profile(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "r", properties={"name": "the-role"}),
            _pr(
                "aws_iam_instance_profile",
                "p",
                properties={"name": "the-profile", "role": "the-role"},
            ),
            _pr("aws_instance", "web", properties={"iam_instance_profile": "the-profile"}),
        )
        assert _edges(graph, "instance_profile") == {
            ("aws_instance.web", "aws_iam_instance_profile.p")
        }
        assert _edges(graph, "assumes") == {("aws_iam_instance_profile.p", "aws_iam_role.r")}

    def test_a_launch_template_profile_block_binds(self) -> None:
        graph = _graph(
            _pr("aws_iam_instance_profile", "p", properties={"name": "the-profile"}),
            _pr(
                "aws_launch_template",
                "lt",
                properties={"iam_instance_profile": [{"name": "the-profile"}]},
            ),
        )
        assert _edges(graph, "instance_profile") == {
            ("aws_launch_template.lt", "aws_iam_instance_profile.p")
        }


class TestPolicyLinks:
    def test_an_attachment_names_its_role_and_its_policy_and_the_role_holds_the_policy(
        self,
    ) -> None:
        graph = _graph(*_role_with(_statement("s3:GetObject", "*")))
        attachment = "aws_iam_role_policy_attachment.app"
        assert _edges(graph, "assumes") == {(attachment, "aws_iam_role.app")}
        assert _edges(graph, "attaches") == {(attachment, "aws_iam_policy.app")}
        assert _edges(graph, "has_policy") == {("aws_iam_role.app", "aws_iam_policy.app")}

    def test_an_inline_policy_belongs_to_its_role(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "app", properties={"name": "app"}),
            _pr(
                "aws_iam_role_policy",
                "inline",
                properties={"role": "app", "policy": _policy_json(_statement("s3:*", "*"))},
            ),
        )
        assert _edges(graph, "assumes") == {("aws_iam_role_policy.inline", "aws_iam_role.app")}
        assert _edges(graph, "has_policy") == {("aws_iam_role.app", "aws_iam_role_policy.inline")}

    def test_a_policy_attachment_with_several_roles_links_each(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "a", properties={"name": "a"}),
            _pr("aws_iam_role", "b", properties={"name": "b"}),
            _pr("aws_iam_policy", "p", properties={"name": "p"}),
            _pr(
                "aws_iam_policy_attachment",
                "both",
                properties={"roles": ["a", "b"], "policy_arn": "aws_iam_policy.p"},
            ),
        )
        assert _edges(graph, "has_policy") == {
            ("aws_iam_role.a", "aws_iam_policy.p"),
            ("aws_iam_role.b", "aws_iam_policy.p"),
        }

    def test_an_aws_managed_policy_has_no_node_and_no_edge(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "app", properties={"name": "app"}),
            _pr(
                "aws_iam_role_policy_attachment",
                "managed",
                properties={"role": "app", "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"},
            ),
        )
        assert _edges(graph, "attaches") == set()
        assert _edges(graph, "has_policy") == set()

    def test_the_policy_arn_attribute_resolves_a_customer_policy(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "app", properties={"name": "app"}),
            _pr(
                "aws_iam_policy",
                "mine",
                properties={"name": "mine", "arn": "arn:aws:iam::123456789012:policy/mine"},
            ),
            _pr(
                "aws_iam_role_policy_attachment",
                "a",
                properties={"role": "app", "policy_arn": "arn:aws:iam::123456789012:policy/mine"},
            ),
        )
        assert _edges(graph, "has_policy") == {("aws_iam_role.app", "aws_iam_policy.mine")}


class TestResourcePolicies:
    def test_a_bucket_policy_links_to_its_bucket_and_says_whether_it_is_public(self) -> None:
        public = _policy_json(
            {"Effect": "Allow", "Principal": "*", "Action": "s3:*", "Resource": "*"}
        )
        graph = _graph(
            _bucket("b"),
            _pr(
                "aws_s3_bucket_policy",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "policy": public},
            ),
        )
        assert _edges(graph, "resource_policy") == {("aws_s3_bucket_policy.b", "aws_s3_bucket.b")}
        (edge,) = [e for e in graph.edges if e.relation == "resource_policy"]
        assert edge.attributes == {"public": True}

    def test_a_conditional_or_named_policy_is_not_public(self) -> None:
        scoped = _policy_json(
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
            }
        )
        graph = _graph(
            _bucket("b"),
            _pr(
                "aws_s3_bucket_policy",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "policy": scoped},
            ),
        )
        (edge,) = [e for e in graph.edges if e.relation == "resource_policy"]
        assert edge.attributes == {"public": False}

    @pytest.mark.parametrize(
        ("rtype", "attribute", "target_type"),
        [
            ("aws_sqs_queue_policy", "queue_url", "aws_sqs_queue"),
            ("aws_sns_topic_policy", "arn", "aws_sns_topic"),
            ("aws_secretsmanager_secret_policy", "secret_arn", "aws_secretsmanager_secret"),
        ],
    )
    def test_queue_topic_and_secret_policies_link_to_their_resource(
        self, rtype: str, attribute: str, target_type: str
    ) -> None:
        graph = _graph(
            _pr(target_type, "t"),
            _pr(rtype, "t", properties={attribute: f"{target_type}.t"}),
        )
        assert _edges(graph, "resource_policy") == {(f"{rtype}.t", f"{target_type}.t")}

    def test_a_policy_whose_resource_the_scan_cannot_find_links_to_nothing(self) -> None:
        graph = _graph(
            _bucket("b"),
            _pr("aws_s3_bucket_policy", "x", properties={"bucket": Unknown("var.bucket")}),
        )
        assert _edges(graph, "resource_policy") == set()


class TestTrustPolicies:
    def _trust(self, *principals: Any) -> dict[str, Any]:
        return {
            "Statement": [
                {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}
                for principal in principals
            ]
        }

    def _role(self, name: str, trust: dict[str, Any] | None = None) -> ParsedResource:
        props: dict[str, Any] = {"name": name}
        if trust is not None:
            props["assume_role_policy"] = json.dumps(trust)
        return _pr("aws_iam_role", name, properties=props)

    def _trust_of(self, graph: InfraGraph, role: str) -> dict[str, Any]:
        node = graph.get_node(role)
        assert node is not None
        trust = node.properties["derived"]["assume_role_trust"]
        assert isinstance(trust, dict)
        return trust

    def test_a_role_principal_may_assume_the_role_and_a_service_principal_stays_metadata(
        self,
    ) -> None:
        trust = self._trust(
            {"Service": "ec2.amazonaws.com"},
            {"AWS": "arn:aws:iam::123456789012:role/admin"},
        )
        graph = _graph(self._role("admin"), self._role("target", trust))
        assert _edges(graph, "can_assume") == {("aws_iam_role.admin", "aws_iam_role.target")}
        assert self._trust_of(graph, "aws_iam_role.target") == {
            "services": ["ec2.amazonaws.com"],
            "accounts": [],
            "principals": [],
            "any_principal": False,
        }

    def test_the_edge_points_from_the_principal_to_the_role(self) -> None:
        graph = _graph(
            self._role("admin"),
            self._role("target", self._trust({"AWS": "arn:aws:iam::1:role/admin"})),
        )
        assert _edges(graph, "can_assume") == {("aws_iam_role.admin", "aws_iam_role.target")}
        assert ("aws_iam_role.target", "aws_iam_role.admin") not in _edges(graph, "can_assume")

    def test_an_account_root_and_a_wildcard_are_metadata(self) -> None:
        graph = _graph(
            self._role(
                "target",
                self._trust({"AWS": "arn:aws:iam::210987654321:root"}, {"AWS": "*"}),
            )
        )
        assert _edges(graph, "can_assume") == set()
        data = self._trust_of(graph, "aws_iam_role.target")
        assert data["accounts"] == ["210987654321"]
        assert data["any_principal"] is True

    def test_a_principal_outside_the_graph_is_listed_not_linked(self) -> None:
        graph = _graph(
            self._role(
                "target",
                self._trust(
                    {"AWS": "arn:aws:iam::1:role/outsider"},
                    {"Federated": "arn:aws:iam::1:saml-provider/idp"},
                ),
            )
        )
        assert _edges(graph, "can_assume") == set()
        assert self._trust_of(graph, "aws_iam_role.target")["principals"] == [
            "arn:aws:iam::1:role/outsider",
            "arn:aws:iam::1:saml-provider/idp",
        ]

    def test_a_reference_principal_resolves_to_the_role(self) -> None:
        trust = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Principal": {"AWS": "${aws_iam_role.admin.arn}"},
                }
            ]
        }
        graph = _graph(self._role("admin"), self._role("target", trust))
        assert _edges(graph, "can_assume") == {("aws_iam_role.admin", "aws_iam_role.target")}

    def test_a_role_never_trusts_itself_in_the_graph(self) -> None:
        graph = _graph(self._role("loop", self._trust({"AWS": "arn:aws:iam::1:role/loop"})))
        assert _edges(graph, "can_assume") == set()

    def test_a_deny_statement_trusts_nobody(self) -> None:
        trust = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                }
            ]
        }
        graph = _graph(self._role("target", trust))
        assert self._trust_of(graph, "aws_iam_role.target")["services"] == []

    def test_a_role_without_a_trust_policy_gets_no_trust_metadata(self) -> None:
        graph = _graph(self._role("plain"))
        node = graph.get_node("aws_iam_role.plain")
        assert node is not None
        assert "assume_role_trust" not in node.properties.get("derived", {})


class TestPermissions:
    def test_a_concrete_arn_links_the_bucket_with_the_actions_and_the_access(self) -> None:
        graph = _graph(
            *_role_with(_statement(["s3:GetObject", "s3:ListBucket"], "arn:aws:s3:::data/*")),
            _bucket("data"),
            _bucket("other"),
        )
        assert _permission(graph, "aws_iam_role.app", "aws_s3_bucket.data") == {
            "actions": ["s3:GetObject", "s3:ListBucket"],
            "access": "read",
            "wildcard": False,
            "conditional": False,
        }
        assert [e for e in graph.edges if e.target == "aws_s3_bucket.other"] == []

    def test_a_reference_in_the_resource_links_the_node(self) -> None:
        graph = _graph(
            *_role_with(_statement("s3:PutObject", "${aws_s3_bucket.data.arn}/*")),
            _bucket("data"),
        )
        attrs = _permission(graph, "aws_iam_role.app", "aws_s3_bucket.data")
        assert (attrs["access"], attrs["wildcard"]) == ("write", False)

    def test_an_unknown_resource_that_carries_a_reference_links_the_node(self) -> None:
        graph = _graph(
            _pr("aws_iam_role", "app", properties={"name": "app"}),
            _pr(
                "aws_iam_role_policy",
                "p",
                properties={
                    "role": "app",
                    "policy": _policy_json(_statement("s3:GetObject", "${aws_s3_bucket.data.arn}")),
                },
            ),
            _bucket("data"),
        )
        assert _permission(graph, "aws_iam_role.app", "aws_s3_bucket.data")["access"] == "read"

    @pytest.mark.parametrize(
        ("action", "arn", "rtype", "props"),
        [
            (
                "dynamodb:Query",
                "arn:aws:dynamodb:us-east-1:1:table/orders",
                "aws_dynamodb_table",
                {"name": "orders"},
            ),
            (
                "dynamodb:Query",
                "arn:aws:dynamodb:us-east-1:1:table/orders/index/i",
                "aws_dynamodb_table",
                {"name": "orders"},
            ),
            ("sqs:SendMessage", "arn:aws:sqs:us-east-1:1:jobs", "aws_sqs_queue", {"name": "jobs"}),
            ("sns:Publish", "arn:aws:sns:us-east-1:1:alerts", "aws_sns_topic", {"name": "alerts"}),
            (
                "lambda:InvokeFunction",
                "arn:aws:lambda:us-east-1:1:function:orders",
                "aws_lambda_function",
                {"function_name": "orders"},
            ),
            (
                "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:us-east-1:1:secret:db-pass-AbC123",
                "aws_secretsmanager_secret",
                {"name": "db-pass"},
            ),
            # The pattern Terraform authors write for the suffix Secrets Manager adds
            (
                "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:us-east-1:1:secret:db-pass-*",
                "aws_secretsmanager_secret",
                {"name": "db-pass"},
            ),
            (
                "secretsmanager:GetSecretValue",
                "arn:aws:secretsmanager:us-east-1:1:secret:db-pass-??????",
                "aws_secretsmanager_secret",
                {"name": "db-pass"},
            ),
            (
                "ssm:GetParameter",
                "arn:aws:ssm:us-east-1:1:parameter/app/db",
                "aws_ssm_parameter",
                {"name": "/app/db"},
            ),
            (
                "rds:DescribeDBInstances",
                "arn:aws:rds:us-east-1:1:db:orders",
                "aws_db_instance",
                {"identifier": "orders"},
            ),
            (
                "ecr:GetDownloadUrlForLayer",
                "arn:aws:ecr:us-east-1:1:repository/app",
                "aws_ecr_repository",
                {"name": "app"},
            ),
            (
                "kinesis:PutRecord",
                "arn:aws:kinesis:us-east-1:1:stream/events",
                "aws_kinesis_stream",
                {"name": "events"},
            ),
            (
                "kms:Decrypt",
                "arn:aws:kms:us-east-1:1:key/abc-123",
                "aws_kms_key",
                {"key_id": "abc-123"},
            ),
            ("iam:PassRole", "arn:aws:iam::1:role/other", "aws_iam_role", {"name": "other"}),
        ],
    )
    def test_each_service_arn_finds_its_node_by_name(
        self, action: str, arn: str, rtype: str, props: dict[str, Any]
    ) -> None:
        graph = _graph(*_role_with(_statement(action, arn)), _pr(rtype, "target", properties=props))
        assert _permission(graph, "aws_iam_role.app", f"{rtype}.target")["actions"] == [action]

    def test_a_kms_key_is_found_by_its_arn_property(self) -> None:
        arn = "arn:aws:kms:us-east-1:1:key/abc"
        graph = _graph(
            *_role_with(_statement("kms:Decrypt", arn)),
            _pr("aws_kms_key", "k", properties={"arn": arn}),
        )
        assert _permission(graph, "aws_iam_role.app", "aws_kms_key.k")["access"] == "read"

    def test_statements_merge_into_one_edge_with_the_strongest_access(self) -> None:
        graph = _graph(
            *_role_with(
                _statement("s3:GetObject", "arn:aws:s3:::data/*"),
                _statement("s3:PutObject", "arn:aws:s3:::data/uploads/*"),
            ),
            _bucket("data"),
        )
        assert _permission(graph, "aws_iam_role.app", "aws_s3_bucket.data") == {
            "actions": ["s3:GetObject", "s3:PutObject"],
            "access": "write",
            "wildcard": False,
            "conditional": False,
        }

    def test_a_condition_marks_the_edge_conditional_only_when_every_grant_is(self) -> None:
        cond = {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
        only_conditional = _graph(
            *_role_with(_statement("s3:GetObject", "arn:aws:s3:::data/*", condition=cond)),
            _bucket("data"),
        )
        assert (
            _permission(only_conditional, "aws_iam_role.app", "aws_s3_bucket.data")["conditional"]
            is True
        )
        mixed = _graph(
            *_role_with(
                _statement("s3:GetObject", "arn:aws:s3:::data/*", condition=cond),
                _statement("s3:GetObject", "arn:aws:s3:::data/*"),
            ),
            _bucket("data"),
        )
        assert _permission(mixed, "aws_iam_role.app", "aws_s3_bucket.data")["conditional"] is False

    def test_a_deny_statement_grants_nothing(self) -> None:
        graph = _graph(
            *_role_with(_statement("s3:*", "arn:aws:s3:::data/*", effect="Deny")), _bucket("data")
        )
        assert [e for e in graph.edges if e.relation == "permission"] == []

    def test_not_action_and_not_resource_statements_are_not_read(self) -> None:
        document = {
            "Statement": [
                {"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:*", "NotResource": "arn:aws:s3:::data"},
            ]
        }
        graph = _graph(
            _pr("aws_iam_role", "app", properties={"name": "app"}),
            _pr(
                "aws_iam_role_policy",
                "p",
                properties={"role": "app", "policy": json.dumps(document)},
            ),
            _bucket("data"),
        )
        assert [e for e in graph.edges if e.relation == "permission"] == []

    def test_an_action_of_another_service_does_not_reach_the_node(self) -> None:
        graph = _graph(
            *_role_with(_statement("dynamodb:Query", "arn:aws:s3:::data/*")), _bucket("data")
        )
        assert [e for e in graph.edges if e.relation == "permission"] == []

    def test_an_arn_that_names_no_node_adds_nothing(self) -> None:
        graph = _graph(
            *_role_with(_statement("s3:GetObject", "arn:aws:s3:::elsewhere/*")), _bucket("data")
        )
        assert [e for e in graph.edges if e.relation == "permission"] == []

    def test_a_role_never_gets_a_permission_edge_to_itself(self) -> None:
        graph = _graph(*_role_with(_statement("iam:*", "*")))
        assert [e for e in graph.edges if e.relation == "permission" and e.source == e.target] == []

    def test_the_inline_statements_of_the_role_itself_count(self) -> None:
        graph = _graph(
            _pr(
                "aws_iam_role",
                "app",
                properties={
                    "name": "app",
                    "inline_policy": [
                        {
                            "name": "i",
                            "policy": _policy_json(
                                _statement("s3:GetObject", "arn:aws:s3:::data/*")
                            ),
                        }
                    ],
                },
            ),
            _bucket("data"),
        )
        assert _permission(graph, "aws_iam_role.app", "aws_s3_bucket.data")["access"] == "read"


class TestWildcards:
    def test_a_wildcard_resource_fans_out_to_the_nodes_of_the_actions_service_only(self) -> None:
        graph = _graph(
            *_role_with(_statement("s3:GetObject", "*")),
            _bucket("a"),
            _bucket("b"),
            _pr("aws_dynamodb_table", "t", properties={"name": "t"}),
        )
        targets = {e.target for e in graph.edges if e.relation == "permission"}
        assert targets == {"aws_s3_bucket.a", "aws_s3_bucket.b"}
        assert all(
            e.attributes["wildcard"] is True for e in graph.edges if e.relation == "permission"
        )

    def test_an_arn_pattern_matches_by_name_and_is_a_wildcard(self) -> None:
        graph = _graph(
            *_role_with(_statement("s3:GetObject", "arn:aws:s3:::logs-*/*")),
            _bucket("logs_a", "logs-prod"),
            _bucket("logs_b", "logs-dev"),
            _bucket("data"),
        )
        assert {e.target for e in graph.edges if e.relation == "permission"} == {
            "aws_s3_bucket.logs_a",
            "aws_s3_bucket.logs_b",
        }

    def test_every_bucket_pattern_is_a_wildcard(self) -> None:
        graph = _graph(
            *_role_with(_statement("s3:*", "arn:aws:s3:::*")), _bucket("a"), _bucket("b")
        )
        edges = [e for e in graph.edges if e.relation == "permission"]
        assert len(edges) == 2
        assert all(e.attributes["wildcard"] and e.attributes["access"] == "admin" for e in edges)

    def test_a_concrete_grant_and_a_wildcard_grant_to_one_node_make_one_wildcard_edge(self) -> None:
        graph = _graph(
            *_role_with(
                _statement("s3:GetObject", "arn:aws:s3:::data/*"),
                _statement("s3:PutObject", "*"),
            ),
            _bucket("data"),
        )
        assert _permission(graph, "aws_iam_role.app", "aws_s3_bucket.data") == {
            "actions": ["s3:GetObject", "s3:PutObject"],
            "access": "write",
            "wildcard": True,
            "conditional": False,
        }

    def test_the_admin_wildcard_reaches_every_service(self) -> None:
        graph = _graph(
            *_role_with(_statement("*", "*")),
            _bucket("data"),
            _pr("aws_dynamodb_table", "t", properties={"name": "t"}),
            _pr("aws_kms_key", "k"),
            _pr("aws_instance", "i"),
        )
        targets = {e.target for e in graph.edges if e.relation == "permission"}
        assert targets == {
            "aws_s3_bucket.data",
            "aws_dynamodb_table.t",
            "aws_kms_key.k",
            "aws_instance.i",
        }

    def test_the_fan_out_is_capped_per_role_and_the_cap_is_reported(self) -> None:
        buckets = [_bucket(f"b{i:03d}") for i in range(MAX_WILDCARD_TARGETS + 10)]
        graph = _graph(*_role_with(_statement("s3:*", "*")), *buckets)
        edges = [e for e in graph.edges if e.relation == "permission"]
        assert len(edges) == MAX_WILDCARD_TARGETS
        assert sorted(e.target for e in edges)[0] == "aws_s3_bucket.b000"
        (diag,) = [d for d in graph.diagnostics if d.code == "graph.iam_fanout_capped"]
        assert diag.level == "info"
        assert "aws_iam_role.app" in diag.message
        assert str(MAX_WILDCARD_TARGETS) in diag.message

    def test_the_cap_is_per_role(self) -> None:
        buckets = [_bucket(f"b{i:03d}") for i in range(MAX_WILDCARD_TARGETS + 5)]
        graph = _graph(
            *_role_with(_statement("s3:*", "*"), name="one"),
            *_role_with(_statement("s3:*", "*"), name="two"),
            *buckets,
        )
        for role in ("aws_iam_role.one", "aws_iam_role.two"):
            assert (
                len([e for e in graph.edges if e.relation == "permission" and e.source == role])
                == MAX_WILDCARD_TARGETS
            )

    def test_a_capped_fan_out_keeps_the_concrete_grants(self) -> None:
        buckets = [_bucket(f"b{i:03d}") for i in range(MAX_WILDCARD_TARGETS + 5)]
        graph = _graph(
            *_role_with(
                _statement("s3:*", "*"),
                _statement("s3:GetObject", "arn:aws:s3:::b029/*"),
            ),
            *buckets,
        )
        targets = {e.target for e in graph.edges if e.relation == "permission"}
        assert "aws_s3_bucket.b029" in targets
        assert len(targets) == MAX_WILDCARD_TARGETS + 1

    def test_the_cap_prefers_data_stores_over_compute(self) -> None:
        instances = [_pr("aws_instance", f"i{i:03d}") for i in range(MAX_WILDCARD_TARGETS + 5)]
        graph = _graph(*_role_with(_statement("*", "*")), *instances, _bucket("data"))
        targets = {e.target for e in graph.edges if e.relation == "permission"}
        assert "aws_s3_bucket.data" in targets


class TestEdgeBudget:
    def test_iam_edges_respect_the_edge_limit(self) -> None:
        buckets = [_bucket(f"b{i}") for i in range(10)]
        parsed = ParsedOutput(resources=[*_role_with(_statement("s3:*", "*")), *buckets])
        graph = InfraGraph.from_parsed(parsed, max_edges=4)
        assert len(graph.edges) == 4
        assert [d for d in graph.diagnostics if d.code == "graph.edge_cap"]


class TestFixture08:
    """The ML platform plan: a SageMaker role attached to a policy that allows everything."""

    def _graph(self) -> InfraGraph:
        return InfraGraph.from_parsed(
            detect_and_parse(REALISTIC / "08_aws_ml_training_platform.json")
        )

    def test_the_sagemaker_role_attachment_edge_exists(self) -> None:
        graph = self._graph()
        assert (
            "aws_iam_role_policy_attachment.sagemaker_execution",
            "aws_iam_role.sagemaker_execution",
        ) in _edges(graph, "assumes")

    def test_the_attachment_names_the_policy_and_the_role_holds_it(self) -> None:
        graph = self._graph()
        assert _edges(graph, "attaches") == {
            (
                "aws_iam_role_policy_attachment.sagemaker_execution",
                "aws_iam_policy.sagemaker_execution",
            )
        }
        assert _edges(graph, "has_policy") == {
            ("aws_iam_role.sagemaker_execution", "aws_iam_policy.sagemaker_execution")
        }

    def test_the_notebook_runs_as_the_role(self) -> None:
        graph = self._graph()
        assert (
            "aws_sagemaker_notebook_instance.research",
            "aws_iam_role.sagemaker_execution",
        ) in _edges(graph, "assumes")

    def test_the_admin_policy_reaches_the_buckets_as_an_admin_wildcard(self) -> None:
        graph = self._graph()
        reached = {
            e.target: e.attributes
            for e in graph.edges
            if e.relation == "permission" and e.source == "aws_iam_role.sagemaker_execution"
        }
        for bucket in ("training_data", "model_artifacts", "notebook_outputs"):
            attrs = reached[f"aws_s3_bucket.{bucket}"]
            assert (attrs["access"], attrs["wildcard"]) == ("admin", True)

    def test_the_second_role_has_no_policy_and_so_no_permission_edges(self) -> None:
        graph = self._graph()
        assert not [
            e
            for e in graph.edges
            if e.relation == "permission" and e.source == "aws_iam_role.lambda_model_deploy"
        ]

    def test_the_service_principal_stays_metadata(self) -> None:
        node = self._graph().get_node("aws_iam_role.sagemaker_execution")
        assert node is not None
        assert node.properties["derived"]["assume_role_trust"]["services"] == [
            "sagemaker.amazonaws.com"
        ]


def test_the_module_registers_its_diagnostic_code() -> None:
    from threatcode.diagnostics import DIAGNOSTIC_CODES

    assert "graph.iam_fanout_capped" in DIAGNOSTIC_CODES
    assert iam.MAX_WILDCARD_TARGETS == MAX_WILDCARD_TARGETS


class TestSeveralInputs:
    """A repository graph holds several inputs; roles, policies and resources stay in their own."""

    def _unit(self, label: str, bucket: str) -> ParsedOutput:
        return ParsedOutput(
            resources=[
                *_role_with(_statement("s3:GetObject", f"arn:aws:s3:::{bucket}/*")),
                _bucket("data", bucket),
                _pr("aws_lambda_function", "fn", properties={"role": "app"}),
            ],
            source_path=label,
            format_type="terraform_plan",
        )

    def test_a_role_reaches_only_the_bucket_of_its_own_input(self) -> None:
        graph = InfraGraph.from_units([self._unit("a", "bucket-a"), self._unit("b", "bucket-b")])
        grants = {
            (e.source, e.target)
            for e in graph.edges
            if e.edge_type is EdgeType.IAM_BINDING and e.relation == "permission"
        }
        assert grants == {
            ("a::aws_iam_role.app", "a::aws_s3_bucket.data"),
            ("b::aws_iam_role.app", "b::aws_s3_bucket.data"),
        }

    def test_a_function_assumes_the_role_of_its_own_input(self) -> None:
        graph = InfraGraph.from_units([self._unit("a", "bucket-a"), self._unit("b", "bucket-b")])
        assert _edges(graph, "assumes") >= {
            ("a::aws_lambda_function.fn", "a::aws_iam_role.app"),
            ("b::aws_lambda_function.fn", "b::aws_iam_role.app"),
        }
        assert ("a::aws_lambda_function.fn", "b::aws_iam_role.app") not in _edges(graph, "assumes")


class TestAWildcardReachesTheNodesOfItsOwnInput:
    """RW-07: the administrator role of one template is not the administrator of every other."""

    def _unit(self, label: str, bucket: str, resource: str) -> ParsedOutput:
        return ParsedOutput(
            resources=[
                *_role_with(_statement("s3:*", resource)),
                _bucket("data", bucket),
            ],
            source_path=label,
            format_type="terraform_plan",
        )

    def _grants(self, graph: InfraGraph) -> set[tuple[str, str]]:
        return {
            (e.source, e.target)
            for e in graph.edges
            if e.edge_type is EdgeType.IAM_BINDING and e.relation == "permission"
        }

    def test_a_star_resource_stops_at_the_input_of_the_role(self) -> None:
        graph = InfraGraph.from_units(
            [self._unit("a", "bucket-a", "*"), self._unit("b", "bucket-b", "*")]
        )
        assert self._grants(graph) == {
            ("a::aws_iam_role.app", "a::aws_s3_bucket.data"),
            ("b::aws_iam_role.app", "b::aws_s3_bucket.data"),
        }

    def test_a_star_resource_still_reaches_every_bucket_of_its_own_input(self) -> None:
        unit = ParsedOutput(
            resources=[
                *_role_with(_statement("s3:*", "*")),
                _bucket("one"),
                _bucket("two"),
            ],
            source_path="a",
            format_type="terraform_plan",
        )
        other = ParsedOutput(
            resources=[_bucket("elsewhere")], source_path="b", format_type="terraform_plan"
        )
        graph = InfraGraph.from_units([unit, other])
        assert self._grants(graph) == {
            ("aws_iam_role.app", "aws_s3_bucket.one"),
            ("aws_iam_role.app", "aws_s3_bucket.two"),
        }

    def test_an_arn_that_matches_any_name_is_scoped_like_a_star(self) -> None:
        graph = InfraGraph.from_units(
            [
                self._unit("a", "bucket-a", "arn:aws:s3:::*"),
                self._unit("b", "bucket-b", "arn:aws:s3:::*"),
            ]
        )
        assert self._grants(graph) == {
            ("a::aws_iam_role.app", "a::aws_s3_bucket.data"),
            ("b::aws_iam_role.app", "b::aws_s3_bucket.data"),
        }

    def test_a_pattern_with_a_literal_prefix_names_its_targets_in_any_input(self) -> None:
        graph = InfraGraph.from_units(
            [
                self._unit("a", "acme-logs-a", "arn:aws:s3:::acme-logs-*"),
                ParsedOutput(
                    resources=[_bucket("logs", "acme-logs-b")],
                    source_path="b",
                    format_type="terraform_plan",
                ),
            ]
        )
        assert self._grants(graph) == {
            ("aws_iam_role.app", "aws_s3_bucket.data"),
            ("aws_iam_role.app", "aws_s3_bucket.logs"),
        }

    def test_an_exact_arn_names_its_target_in_any_input(self) -> None:
        graph = InfraGraph.from_units(
            [
                ParsedOutput(
                    resources=[*_role_with(_statement("s3:GetObject", "arn:aws:s3:::shared/*"))],
                    source_path="a",
                    format_type="terraform_plan",
                ),
                ParsedOutput(
                    resources=[_bucket("shared")], source_path="b", format_type="terraform_plan"
                ),
            ]
        )
        assert self._grants(graph) == {("aws_iam_role.app", "aws_s3_bucket.shared")}
