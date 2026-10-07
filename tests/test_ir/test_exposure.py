"""Tests for threatcode.ir.exposure: which nodes face the internet, and the zones that follow."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.ir.exposure import DEFAULTS, PUBLIC_NETWORK_TYPES, is_world_cidr
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import TrustZone
from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.values import Unknown

PLAN = "terraform_plan"
HCL = "terraform_hcl"
CFN = "cloudformation"


def _pr(rtype: str, name: str, **kwargs: Any) -> ParsedResource:
    provider = rtype.split("_", 1)[0]
    return ParsedResource(rtype, f"{rtype}.{name}", name, provider, **kwargs)


def _graph(*resources: ParsedResource, fmt: str = PLAN) -> InfraGraph:
    return InfraGraph.from_parsed(ParsedOutput(resources=list(resources), format_type=fmt))


def _of(graph: InfraGraph, address: str) -> tuple[str, str]:
    node = graph.get_node(address)
    assert node is not None, address
    return node.exposure, node.trust_zone.value


def _exposure(rtype: str, props: dict[str, Any], *, fmt: str = PLAN, **kwargs: Any) -> str:
    graph = _graph(_pr(rtype, "x", properties=props, **kwargs), fmt=fmt)
    return _of(graph, f"{rtype}.x")[0]


class TestIsWorldCidr:
    @pytest.mark.parametrize(
        "value", ["0.0.0.0/0", "::/0", "*", "Internet", "any", " 0.0.0.0/0 ", "0.0.0.0/00", "0::/0"]
    )
    def test_the_whole_internet(self, value: str) -> None:
        assert is_world_cidr(value) is True

    @pytest.mark.parametrize(
        "value", ["10.0.0.0/8", "0.0.0.0/1", "192.168.1.1", "", "sg-1234", None, 0, Unknown()]
    )
    def test_anything_narrower_or_unreadable(self, value: Any) -> None:
        assert is_world_cidr(value) is False


class TestLoadBalancers:
    @pytest.mark.parametrize("rtype", ["aws_lb", "aws_alb", "aws_nlb", "aws_elb"])
    def test_an_internal_balancer_is_internal_and_private(self, rtype: str) -> None:
        graph = _graph(_pr(rtype, "x", properties={"internal": True}))
        assert _of(graph, f"{rtype}.x") == ("internal", "private")

    @pytest.mark.parametrize("rtype", ["aws_lb", "aws_alb", "aws_nlb", "aws_elb"])
    def test_an_internet_facing_balancer_is_exposed_in_the_dmz(self, rtype: str) -> None:
        graph = _graph(_pr(rtype, "x", properties={"internal": False}))
        assert _of(graph, f"{rtype}.x") == ("internet", "dmz")

    def test_the_string_spellings_are_read(self) -> None:
        assert _exposure("aws_lb", {"internal": "true"}) == "internal"
        assert _exposure("aws_lb", {"internal": "false"}) == "internet"

    def test_an_absent_flag_is_the_provider_default_in_hcl_and_templates(self) -> None:
        assert _exposure("aws_lb", {}, fmt=HCL) == "internet"
        assert _exposure("aws_lb", {}, fmt=CFN) == "internet"

    def test_an_absent_flag_in_a_plan_is_not_an_answer(self) -> None:
        assert _exposure("aws_lb", {}, fmt=PLAN) == "unknown"

    @pytest.mark.parametrize(
        "value", [Unknown("var.internal"), "${var.internal}", "!var.private", {"Ref": "Internal"}]
    )
    def test_an_unreadable_flag_leaves_the_exposure_unknown_and_the_zone_at_its_default(
        self, value: Any
    ) -> None:
        graph = _graph(_pr("aws_lb", "x", properties={"internal": value}))
        assert _of(graph, "aws_lb.x") == ("unknown", "dmz")

    def test_a_design_node_without_the_flag_is_unknown(self) -> None:
        graph = _graph(_pr("aws_lb", "x", evidence="design"))
        assert _of(graph, "aws_lb.x")[0] == "unknown"

    def test_a_listener_takes_the_exposure_and_the_zone_of_its_balancer(self) -> None:
        graph = _graph(
            _pr("aws_lb", "inner", properties={"internal": True}),
            _pr("aws_lb", "outer", properties={"internal": False}),
            _pr("aws_lb_listener", "a", properties={"load_balancer_arn": "aws_lb.inner"}),
            _pr("aws_lb_listener", "b", properties={"load_balancer_arn": "aws_lb.outer"}),
        )
        assert _of(graph, "aws_lb_listener.a") == ("internal", "private")
        assert _of(graph, "aws_lb_listener.b") == ("internet", "dmz")

    def test_a_listener_of_an_unknown_balancer_stays_unknown(self) -> None:
        graph = _graph(
            _pr("aws_lb", "x", properties={"internal": Unknown()}),
            _pr("aws_lb_listener", "a", properties={"load_balancer_arn": "aws_lb.x"}),
        )
        assert _of(graph, "aws_lb_listener.a")[0] == "unknown"


class TestApiEntryPoints:
    @pytest.mark.parametrize(
        ("auth", "expected"),
        [
            ("NONE", "internet"),
            ("none", "internet"),
            ("AWS_IAM", "unknown"),
            (Unknown(), "unknown"),
        ],
    )
    def test_a_lambda_function_url_is_exposed_only_without_authorization(
        self, auth: Any, expected: str
    ) -> None:
        assert _exposure("aws_lambda_function_url", {"authorization_type": auth}) == expected

    @pytest.mark.parametrize(
        ("types", "expected"),
        [
            (["EDGE"], "internet"),
            (["REGIONAL"], "internet"),
            (["PRIVATE", "REGIONAL"], "internet"),
            (["PRIVATE"], "internal"),
            ([Unknown()], "unknown"),
        ],
    )
    def test_a_rest_api_follows_its_endpoint_types(self, types: list[Any], expected: str) -> None:
        props = {"endpoint_configuration": [{"types": types}]}
        assert _exposure("aws_api_gateway_rest_api", props) == expected

    def test_a_private_rest_api_is_internal_in_the_private_zone(self) -> None:
        props = {"endpoint_configuration": {"types": ["PRIVATE"]}}
        graph = _graph(_pr("aws_api_gateway_rest_api", "x", properties=props))
        assert _of(graph, "aws_api_gateway_rest_api.x") == ("internal", "private")

    def test_a_rest_api_without_a_configuration_is_edge_optimised_in_hcl_only(self) -> None:
        assert _exposure("aws_api_gateway_rest_api", {}, fmt=HCL) == "internet"
        assert _exposure("aws_api_gateway_rest_api", {}, fmt=PLAN) == "unknown"

    def test_an_http_api_is_exposed_unless_its_default_endpoint_is_disabled(self) -> None:
        assert _exposure("aws_apigatewayv2_api", {"disable_execute_api_endpoint": False}) == (
            "internet"
        )
        assert _exposure("aws_apigatewayv2_api", {}, fmt=HCL) == "internet"
        assert _exposure("aws_apigatewayv2_api", {"disable_execute_api_endpoint": True}) == (
            "unknown"
        )

    def test_a_cloudfront_distribution_is_exposed_by_type(self) -> None:
        assert _exposure("aws_cloudfront_distribution", {}) == "internet"


class TestPublicDatabases:
    @pytest.mark.parametrize(
        "rtype",
        ["aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_redshift_cluster"],
    )
    def test_a_public_database_is_exposed_and_keeps_the_data_zone(self, rtype: str) -> None:
        graph = _graph(_pr(rtype, "x", properties={"publicly_accessible": True}))
        assert _of(graph, f"{rtype}.x") == ("internet", "data")

    @pytest.mark.parametrize("value", [False, "false", None, Unknown(), "${var.public}", "yes"])
    def test_anything_but_a_true_flag_leaves_the_database_unknown(self, value: Any) -> None:
        graph = _graph(_pr("aws_db_instance", "x", properties={"publicly_accessible": value}))
        assert _of(graph, "aws_db_instance.x") == ("unknown", "data")

    def test_the_string_true_is_read(self) -> None:
        assert _exposure("aws_db_instance", {"publicly_accessible": "true"}) == "internet"


class TestS3Buckets:
    def _bucket(self, **props: Any) -> InfraGraph:
        return _graph(_pr("aws_s3_bucket", "b", properties=props))

    @pytest.mark.parametrize("acl", ["public-read", "public-read-write"])
    def test_a_public_acl_exposes_the_bucket_and_keeps_the_data_zone(self, acl: str) -> None:
        assert _of(self._bucket(acl=acl), "aws_s3_bucket.b") == ("internet", "data")

    @pytest.mark.parametrize("acl", ["private", "authenticated-read", "log-delivery-write"])
    def test_other_acls_do_not(self, acl: str) -> None:
        assert _of(self._bucket(acl=acl), "aws_s3_bucket.b")[0] == "unknown"

    def test_no_acl_and_no_policy_is_not_exposed(self) -> None:
        assert _of(self._bucket(), "aws_s3_bucket.b")[0] == "unknown"

    def test_a_policy_for_everyone_without_a_condition_exposes_the_bucket(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::b/*",
                }
            ]
        }
        assert _of(self._bucket(policy=policy), "aws_s3_bucket.b") == ("internet", "data")

    def test_the_aws_wildcard_principal_form_counts(self) -> None:
        policy = {
            "Statement": [
                {"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "s3:*", "Resource": "*"}
            ]
        }
        assert self._bucket(policy=policy).get_node("aws_s3_bucket.b").exposure == "internet"  # type: ignore[union-attr]

    @pytest.mark.parametrize(
        "statement",
        [
            {  # a condition restricts it
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}},
            },
            {  # a deny is not a grant
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": "*",
            },
            {  # a named principal is not everyone
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::1:root"},
                "Action": "s3:*",
                "Resource": "*",
            },
        ],
    )
    def test_a_restricted_or_denying_or_named_policy_does_not(
        self, statement: dict[str, Any]
    ) -> None:
        graph = self._bucket(policy={"Statement": [statement]})
        assert _of(graph, "aws_s3_bucket.b")[0] == "unknown"

    def test_a_public_access_block_that_blocks_acls_cancels_the_acl_path(self) -> None:
        graph = _graph(
            _pr("aws_s3_bucket", "b", properties={"acl": "public-read"}),
            _pr(
                "aws_s3_bucket_public_access_block",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "block_public_acls": True},
            ),
        )
        assert _of(graph, "aws_s3_bucket.b")[0] == "unknown"

    def test_ignoring_public_acls_blocks_the_acl_path_too(self) -> None:
        graph = _graph(
            _pr("aws_s3_bucket", "b", properties={"acl": "public-read"}),
            _pr(
                "aws_s3_bucket_public_access_block",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "ignore_public_acls": True},
            ),
        )
        assert _of(graph, "aws_s3_bucket.b")[0] == "unknown"

    def test_blocking_acls_does_not_cancel_a_public_policy(self) -> None:
        policy = {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]
        }
        graph = _graph(
            _pr("aws_s3_bucket", "b", properties={"policy": policy}),
            _pr(
                "aws_s3_bucket_public_access_block",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "block_public_acls": True},
            ),
        )
        assert _of(graph, "aws_s3_bucket.b")[0] == "internet"

    @pytest.mark.parametrize("flag", ["block_public_policy", "restrict_public_buckets"])
    def test_blocking_policy_cancels_a_public_policy(self, flag: str) -> None:
        policy = {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]
        }
        graph = _graph(
            _pr("aws_s3_bucket", "b", properties={"policy": policy}),
            _pr(
                "aws_s3_bucket_public_access_block",
                "b",
                properties={"bucket": "aws_s3_bucket.b", flag: True},
            ),
        )
        assert _of(graph, "aws_s3_bucket.b")[0] == "unknown"

    def test_a_block_that_sets_no_flag_blocks_nothing(self) -> None:
        graph = _graph(
            _pr("aws_s3_bucket", "b", properties={"acl": "public-read"}),
            _pr("aws_s3_bucket_public_access_block", "b", properties={"bucket": "aws_s3_bucket.b"}),
        )
        assert _of(graph, "aws_s3_bucket.b")[0] == "internet"

    def test_a_block_flag_the_scan_cannot_read_is_not_a_block_and_not_an_answer(self) -> None:
        graph = _graph(
            _pr("aws_s3_bucket", "b", properties={"acl": "public-read"}),
            _pr(
                "aws_s3_bucket_public_access_block",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "block_public_acls": Unknown("var.x")},
            ),
        )
        # The block might be on, so the scan does not claim the bucket is public
        assert _of(graph, "aws_s3_bucket.b")[0] == "unknown"

    def test_an_acl_companion_resource_counts(self) -> None:
        graph = _graph(
            _pr("aws_s3_bucket", "b"),
            _pr(
                "aws_s3_bucket_acl",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "acl": "public-read"},
            ),
        )
        assert _of(graph, "aws_s3_bucket.b") == ("internet", "data")

    def test_a_policy_companion_resource_counts(self) -> None:
        policy = {
            "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}]
        }
        graph = _graph(
            _pr("aws_s3_bucket", "b"),
            _pr(
                "aws_s3_bucket_policy",
                "b",
                properties={"bucket": "aws_s3_bucket.b", "policy": policy},
            ),
        )
        assert _of(graph, "aws_s3_bucket.b")[0] == "internet"

    def test_an_acl_the_scan_cannot_read_is_unknown(self) -> None:
        assert _of(self._bucket(acl=Unknown("var.acl")), "aws_s3_bucket.b")[0] == "unknown"


class TestSecurityGroups:
    def _group(self, ingress: Any, **extra: Any) -> InfraGraph:
        return _graph(_pr("aws_security_group", "x", properties={"ingress": ingress, **extra}))

    @pytest.mark.parametrize(
        "rule",
        [
            {"cidr_blocks": ["0.0.0.0/0"], "from_port": 443, "to_port": 443, "protocol": "tcp"},
            {"cidr_blocks": ["10.0.0.0/8", "0.0.0.0/0"]},
            {"ipv6_cidr_blocks": ["::/0"]},
            {"cidr_blocks": [], "ipv6_cidr_blocks": ["::/0"]},
        ],
    )
    def test_world_open_ingress_exposes_the_group(self, rule: dict[str, Any]) -> None:
        assert _of(self._group([rule]), "aws_security_group.x")[0] == "internet"

    @pytest.mark.parametrize(
        "ingress",
        [
            [{"cidr_blocks": ["10.0.0.0/8"]}],
            [{"cidr_blocks": ["10.0.0.0/8"], "security_groups": ["sg-1"]}],
            [{"cidr_blocks": [Unknown("var.cidr")]}],
            [],
        ],
    )
    def test_anything_narrower_or_unreadable_does_not(self, ingress: list[Any]) -> None:
        assert _of(self._group(ingress), "aws_security_group.x")[0] == "unknown"

    def test_egress_is_not_ingress(self) -> None:
        graph = _graph(
            _pr(
                "aws_security_group",
                "x",
                properties={"ingress": [], "egress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
            )
        )
        assert _of(graph, "aws_security_group.x")[0] == "unknown"

    def test_a_standalone_ingress_rule_resource_exposes_its_group(self) -> None:
        graph = _graph(
            _pr("aws_security_group", "x"),
            _pr(
                "aws_security_group_rule",
                "open",
                properties={
                    "type": "ingress",
                    "security_group_id": "aws_security_group.x",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                },
            ),
        )
        assert _of(graph, "aws_security_group.x")[0] == "internet"

    def test_the_default_security_group_is_read_the_same_way(self) -> None:
        graph = _graph(
            _pr(
                "aws_default_security_group",
                "d",
                properties={"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]},
            )
        )
        assert _of(graph, "aws_default_security_group.d")[0] == "internet"


class TestAzureAndGoogleNetworkRules:
    @pytest.mark.parametrize(
        ("props", "expected"),
        [
            ({"direction": "Inbound", "access": "Allow", "source_address_prefix": "*"}, "internet"),
            (
                {"direction": "Inbound", "access": "Allow", "source_address_prefix": "Internet"},
                "internet",
            ),
            ({"direction": "Inbound", "access": "Deny", "source_address_prefix": "*"}, "unknown"),
            ({"direction": "Outbound", "access": "Allow", "source_address_prefix": "*"}, "unknown"),
            (
                {"direction": "Inbound", "access": "Allow", "source_address_prefix": "10.0.0.0/8"},
                "unknown",
            ),
            ({"direction": Unknown(), "access": "Allow", "source_address_prefix": "*"}, "unknown"),
        ],
    )
    def test_a_rule_is_internet_only_for_inbound_allow_from_the_world(
        self, props: dict[str, Any], expected: str
    ) -> None:
        assert _exposure("azurerm_network_security_rule", props) == expected

    def test_a_group_with_an_inline_world_rule_is_exposed(self) -> None:
        rule = {"direction": "Inbound", "access": "Allow", "source_address_prefix": "*"}
        assert _exposure("azurerm_network_security_group", {"security_rule": [rule]}) == "internet"
        denied = {**rule, "access": "Deny"}
        assert _exposure("azurerm_network_security_group", {"security_rule": [denied]}) == "unknown"

    @pytest.mark.parametrize(
        ("props", "expected"),
        [
            ({"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp"}]}, "internet"),
            (
                {
                    "direction": "INGRESS",
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [{"protocol": "tcp"}],
                },
                "internet",
            ),
            ({"source_ranges": ["10.0.0.0/8"], "allow": [{"protocol": "tcp"}]}, "unknown"),
            (
                {
                    "direction": "EGRESS",
                    "destination_ranges": ["0.0.0.0/0"],
                    "source_ranges": ["0.0.0.0/0"],
                    "allow": [{"protocol": "tcp"}],
                },
                "unknown",
            ),
            ({"source_ranges": ["0.0.0.0/0"], "deny": [{"protocol": "tcp"}]}, "unknown"),
            (
                {"source_ranges": ["0.0.0.0/0"], "allow": [{"protocol": "tcp"}], "disabled": True},
                "unknown",
            ),
        ],
    )
    def test_a_firewall_is_exposed_by_an_enabled_ingress_allow_from_the_world(
        self, props: dict[str, Any], expected: str
    ) -> None:
        assert _exposure("google_compute_firewall", props) == expected


class TestProviderDefaults:
    def test_the_documented_defaults(self) -> None:
        # The values the provider rule packages put in their enrichment DEFAULTS tables
        assert DEFAULTS["aws_eks_cluster"] == {"vpc_config.endpoint_public_access": True}
        assert DEFAULTS["azurerm_kubernetes_cluster"] == {"private_cluster_enabled": False}
        assert DEFAULTS["azurerm_storage_account"] == {
            "public_network_access_enabled": True,
            "allow_nested_items_to_be_public": True,
        }
        assert "azurerm_storage_account" in PUBLIC_NETWORK_TYPES

    def test_eks_with_a_public_endpoint(self) -> None:
        props = {"vpc_config": [{"endpoint_public_access": True}]}
        assert _exposure("aws_eks_cluster", props) == "internet"

    def test_eks_with_the_endpoint_off_or_unreadable(self) -> None:
        off = {"vpc_config": [{"endpoint_public_access": False}]}
        assert _exposure("aws_eks_cluster", off) == "unknown"
        unknown = {"vpc_config": [{"endpoint_public_access": Unknown()}]}
        assert _exposure("aws_eks_cluster", unknown) == "unknown"

    def test_eks_restricted_to_private_cidrs_is_not_exposed(self) -> None:
        props = {
            "vpc_config": [
                {"endpoint_public_access": True, "public_access_cidrs": ["203.0.113.0/24"]}
            ]
        }
        assert _exposure("aws_eks_cluster", props) == "unknown"

    def test_eks_open_to_the_world_cidr_is_exposed(self) -> None:
        props = {
            "vpc_config": [{"endpoint_public_access": True, "public_access_cidrs": ["0.0.0.0/0"]}]
        }
        assert _exposure("aws_eks_cluster", props) == "internet"

    def test_eks_without_the_attribute_uses_the_default_only_in_hcl_and_templates(self) -> None:
        assert _exposure("aws_eks_cluster", {"vpc_config": [{}]}, fmt=HCL) == "internet"
        assert _exposure("aws_eks_cluster", {"vpc_config": [{}]}, fmt=CFN) == "internet"
        assert _exposure("aws_eks_cluster", {"vpc_config": [{}]}, fmt=PLAN) == "unknown"

    def test_a_default_never_applies_to_a_design_input(self) -> None:
        graph = _graph(_pr("aws_eks_cluster", "x", evidence="design"), fmt=HCL)
        assert _of(graph, "aws_eks_cluster.x")[0] == "unknown"

    def test_aks_is_exposed_unless_the_cluster_is_private(self) -> None:
        assert _exposure("azurerm_kubernetes_cluster", {"private_cluster_enabled": False}) == (
            "internet"
        )
        assert _exposure("azurerm_kubernetes_cluster", {"private_cluster_enabled": True}) == (
            "unknown"
        )
        assert _exposure("azurerm_kubernetes_cluster", {}, fmt=HCL) == "internet"
        assert _exposure("azurerm_kubernetes_cluster", {}, fmt=PLAN) == "unknown"

    def test_an_azure_service_with_public_network_access(self) -> None:
        props = {"public_network_access_enabled": True}
        assert _exposure("azurerm_mssql_server", props) == "internet"
        assert _exposure("azurerm_mssql_server", {"public_network_access_enabled": False}) == (
            "unknown"
        )
        assert _exposure("azurerm_mssql_server", {}, fmt=HCL) == "internet"
        assert _exposure("azurerm_mssql_server", {}, fmt=PLAN) == "unknown"

    def test_a_service_firewall_that_denies_by_default_is_not_exposed(self) -> None:
        props = {
            "public_network_access_enabled": True,
            "network_acls": [{"default_action": "Deny"}],
        }
        assert _exposure("azurerm_key_vault", props) == "unknown"
        allow = {
            "public_network_access_enabled": True,
            "network_acls": [{"default_action": "Allow"}],
        }
        assert _exposure("azurerm_key_vault", allow) == "internet"

    def test_a_storage_account_needs_public_access_and_nested_public_items(self) -> None:
        both = {"public_network_access_enabled": True, "allow_nested_items_to_be_public": True}
        assert _exposure("azurerm_storage_account", both) == "internet"
        no_nested = {**both, "allow_nested_items_to_be_public": False}
        assert _exposure("azurerm_storage_account", no_nested) == "unknown"
        assert _exposure("azurerm_storage_account", {}, fmt=HCL) == "internet"

    def test_a_public_storage_account_keeps_the_data_zone(self) -> None:
        graph = _graph(_pr("azurerm_storage_account", "x"), fmt=HCL)
        assert _of(graph, "azurerm_storage_account.x") == ("internet", "data")


class TestKubernetes:
    @pytest.mark.parametrize(
        ("service_type", "expected"),
        [
            ("LoadBalancer", "internet"),
            ("NodePort", "internet"),
            ("ClusterIP", "unknown"),
            ("ExternalName", "unknown"),
            (Unknown(), "unknown"),
        ],
    )
    def test_a_service_is_exposed_by_its_type(self, service_type: Any, expected: str) -> None:
        assert _exposure("kubernetes_service", {"service_type": service_type}) == expected

    @pytest.mark.parametrize(("has_rules", "expected"), [(True, "internet"), (False, "unknown")])
    def test_an_ingress_is_exposed_when_it_has_rules(self, has_rules: bool, expected: str) -> None:
        assert _exposure("kubernetes_ingress", {"has_rules": has_rules}) == expected


class TestSubnets:
    def _network(self, *routes: ParsedResource, subnet: dict[str, Any] | None = None) -> InfraGraph:
        return _graph(
            _pr("aws_vpc", "main"),
            _pr("aws_internet_gateway", "gw", properties={"vpc_id": "aws_vpc.main"}),
            _pr("aws_nat_gateway", "nat"),
            _pr("aws_subnet", "s", properties=subnet or {}),
            _pr(
                "aws_route_table_association",
                "s",
                properties={"subnet_id": "aws_subnet.s", "route_table_id": "aws_route_table.rt"},
            ),
            *routes,
        )

    @staticmethod
    def _table(*routes: dict[str, Any]) -> ParsedResource:
        return _pr("aws_route_table", "rt", properties={"route": list(routes)})

    def test_a_default_route_to_an_internet_gateway_makes_the_subnet_public(self) -> None:
        graph = self._network(
            self._table({"cidr_block": "0.0.0.0/0", "gateway_id": "aws_internet_gateway.gw"})
        )
        assert _of(graph, "aws_subnet.s") == ("internet", "dmz")

    def test_an_ipv6_default_route_counts(self) -> None:
        graph = self._network(
            self._table({"ipv6_cidr_block": "::/0", "gateway_id": "aws_internet_gateway.gw"})
        )
        assert _of(graph, "aws_subnet.s")[0] == "internet"

    def test_a_standalone_route_resource_counts(self) -> None:
        graph = self._network(
            self._table(),
            _pr(
                "aws_route",
                "default",
                properties={
                    "route_table_id": "aws_route_table.rt",
                    "destination_cidr_block": "0.0.0.0/0",
                    "gateway_id": "aws_internet_gateway.gw",
                },
            ),
        )
        assert _of(graph, "aws_subnet.s") == ("internet", "dmz")

    def test_a_route_to_a_literal_internet_gateway_id_counts(self) -> None:
        graph = self._network(self._table({"cidr_block": "0.0.0.0/0", "gateway_id": "igw-0abc"}))
        assert _of(graph, "aws_subnet.s")[0] == "internet"

    def test_an_internet_gateway_on_the_vpc_does_not_make_a_private_subnet_public(self) -> None:
        # The gateway exists and is attached to the VPC; this subnet's table never routes to it
        graph = self._network(
            self._table({"cidr_block": "0.0.0.0/0", "nat_gateway_id": "aws_nat_gateway.nat"})
        )
        assert graph.get_node("aws_internet_gateway.gw") is not None
        assert _of(graph, "aws_subnet.s") == ("internal", "private")

    def test_a_table_with_only_local_routes_is_private(self) -> None:
        graph = self._network(self._table({"cidr_block": "10.0.0.0/16", "gateway_id": "local"}))
        assert _of(graph, "aws_subnet.s") == ("internal", "private")

    def test_a_non_default_route_to_the_gateway_does_not_make_it_public(self) -> None:
        graph = self._network(
            self._table({"cidr_block": "203.0.113.0/24", "gateway_id": "aws_internet_gateway.gw"})
        )
        assert _of(graph, "aws_subnet.s")[0] == "internal"

    def test_map_public_ip_on_launch_makes_the_subnet_public(self) -> None:
        graph = _graph(_pr("aws_subnet", "s", properties={"map_public_ip_on_launch": True}))
        assert _of(graph, "aws_subnet.s") == ("internet", "dmz")

    def test_a_subnet_with_no_route_table_in_the_graph_is_unknown(self) -> None:
        graph = _graph(_pr("aws_vpc", "main"), _pr("aws_subnet", "s"))
        assert _of(graph, "aws_subnet.s") == ("unknown", "private")

    def test_a_gateway_or_table_the_scan_cannot_read_is_unknown_not_private(self) -> None:
        graph = self._network(self._table({"cidr_block": "0.0.0.0/0", "gateway_id": Unknown()}))
        assert _of(graph, "aws_subnet.s")[0] == "unknown"

    def test_an_unreadable_public_flag_with_a_private_table_is_unknown(self) -> None:
        graph = self._network(
            self._table({"cidr_block": "10.0.0.0/16", "gateway_id": "local"}),
            subnet={"map_public_ip_on_launch": Unknown("var.public")},
        )
        assert _of(graph, "aws_subnet.s")[0] == "unknown"

    def test_a_declared_zone_is_never_moved(self) -> None:
        parsed = ParsedOutput(
            resources=[_pr("aws_subnet", "s", properties={"map_public_ip_on_launch": True})]
        )
        parsed.resources[0].trust_zone = "management"
        graph = InfraGraph.from_parsed(parsed)
        assert _of(graph, "aws_subnet.s") == ("internet", "management")


class TestInstances:
    def _public_subnet(self) -> list[ParsedResource]:
        return [_pr("aws_subnet", "pub", properties={"map_public_ip_on_launch": True})]

    def _open_group(self) -> ParsedResource:
        return _pr(
            "aws_security_group", "open", properties={"ingress": [{"cidr_blocks": ["0.0.0.0/0"]}]}
        )

    def _closed_group(self) -> ParsedResource:
        return _pr(
            "aws_security_group",
            "closed",
            properties={"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]},
        )

    def _instance(self, **props: Any) -> ParsedResource:
        return _pr(
            "aws_instance",
            "web",
            properties={
                "subnet_id": "aws_subnet.pub",
                "vpc_security_group_ids": ["aws_security_group.open"],
                **props,
            },
        )

    def test_a_public_ip_in_a_public_subnet_behind_an_open_group_is_exposed_in_the_dmz(
        self,
    ) -> None:
        graph = _graph(
            *self._public_subnet(),
            self._open_group(),
            self._instance(associate_public_ip_address=True),
        )
        assert _of(graph, "aws_instance.web") == ("internet", "dmz")

    def test_an_elastic_ip_is_a_public_address(self) -> None:
        graph = _graph(
            *self._public_subnet(),
            self._open_group(),
            self._instance(),
            _pr("aws_eip", "web", properties={"instance": "aws_instance.web"}),
        )
        assert _of(graph, "aws_instance.web") == ("internet", "dmz")

    def test_an_elastic_ip_association_is_a_public_address(self) -> None:
        graph = _graph(
            *self._public_subnet(),
            self._open_group(),
            self._instance(),
            _pr("aws_eip_association", "web", properties={"instance_id": "aws_instance.web"}),
        )
        assert _of(graph, "aws_instance.web")[0] == "internet"

    def test_no_public_address_means_no_exposure(self) -> None:
        graph = _graph(*self._public_subnet(), self._open_group(), self._instance())
        assert _of(graph, "aws_instance.web")[0] == "unknown"

    def test_a_private_subnet_means_no_exposure(self) -> None:
        graph = _graph(
            _pr("aws_subnet", "pub"),
            self._open_group(),
            self._instance(associate_public_ip_address=True),
        )
        # The flag puts it in the DMZ by the catalog, but the exposure analysis does not claim it
        assert _of(graph, "aws_instance.web") == ("unknown", "dmz")

    def test_a_closed_group_means_no_exposure(self) -> None:
        graph = _graph(
            *self._public_subnet(),
            self._closed_group(),
            self._instance(
                associate_public_ip_address=True,
                vpc_security_group_ids=["aws_security_group.closed"],
            ),
        )
        assert _of(graph, "aws_instance.web")[0] == "unknown"

    def test_an_unreadable_public_address_flag_means_no_exposure(self) -> None:
        graph = _graph(
            *self._public_subnet(),
            self._open_group(),
            self._instance(associate_public_ip_address=Unknown("var.public")),
        )
        assert _of(graph, "aws_instance.web") == ("unknown", "private")

    def test_a_launch_template_with_a_public_nic_is_read_too(self) -> None:
        graph = _graph(
            *self._public_subnet(),
            self._open_group(),
            _pr(
                "aws_launch_template",
                "lt",
                properties={
                    "network_interfaces": [
                        {
                            "associate_public_ip_address": True,
                            "subnet_id": "aws_subnet.pub",
                            "security_groups": ["aws_security_group.open"],
                        }
                    ]
                },
            ),
        )
        assert _of(graph, "aws_launch_template.lt") == ("internet", "dmz")


class TestScope:
    def test_data_sources_and_design_inputs_are_left_alone(self) -> None:
        graph = _graph(
            _pr("aws_lb", "d", properties={"internal": False}, mode="data"),
            _pr("aws_lb", "p", properties={"internal": False}, evidence="design"),
        )
        assert _of(graph, "aws_lb.d")[0] == "unknown"
        assert _of(graph, "aws_lb.p")[0] == "unknown"

    def test_a_graph_with_nothing_to_decide_is_untouched(self) -> None:
        graph = _graph(_pr("aws_iam_role", "r"), _pr("aws_vpc", "v"), _pr("aws_instance", "i"))
        assert {n.exposure for n in graph.nodes.values()} == {"unknown"}

    def test_the_exposure_is_in_the_serialised_node_only_when_decided(self) -> None:
        graph = _graph(_pr("aws_lb", "x", properties={"internal": False}), _pr("aws_vpc", "v"))
        nodes = graph.to_dict()["nodes"]
        assert nodes["aws_lb.x"]["exposure"] == "internet"
        assert "exposure" not in nodes["aws_vpc.v"]

    def test_the_trust_zone_enum_is_the_one_the_nodes_use(self) -> None:
        graph = _graph(_pr("aws_lb", "x", properties={"internal": True}))
        node = graph.get_node("aws_lb.x")
        assert node is not None and node.trust_zone is TrustZone.PRIVATE
