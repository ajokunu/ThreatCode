"""Graph-level assertions on real-shape CloudFormation and SAM templates.

``web_stack.yaml`` is written with short-form intrinsics (``!Ref``, ``!GetAtt``, ``!Sub``),
which is how almost every template in the wild is written. ``web_stack.json`` is the same
template in long form, so the long-form path stays testable apart from the short-form loader.

A CloudFormation resource is named after the Terraform type that models it, its properties
have the names and shapes the rules read, and every ``Ref``, ``Fn::GetAtt`` and ``Fn::Sub``
that names another resource is an edge.
What later packages deliver (zones, exposure and attack paths) is its own pending test.
"""

from __future__ import annotations

from tests.helpers.graph_assert import (
    assert_edge,
    assert_exposure,
    assert_nodes,
    assert_path,
    assert_zone,
)
from tests.helpers.pending import pending
from tests.helpers.scan import FIXTURES_DIR, scan_files, scan_real_shape
from tests.helpers.scan import REAL_SHAPES_DIR as REAL_SHAPES

CFN_FIXTURES = FIXTURES_DIR / "cloudformation"
WEB_YAML = "cloudformation/web_stack.yaml"
WEB_JSON = "cloudformation/web_stack.json"
SAM = "cloudformation/sam_api.yaml"
RESOURCES_ONLY = "cloudformation/resources_only.yaml"
NESTED_PARENT = "cloudformation/nested_parent.yaml"

WEB_NODES = {
    "Vpc",
    "InternetGateway",
    "GatewayAttachment",
    "PublicSubnet",
    "PrivateSubnet",
    "PrivateSubnetB",
    "PublicRouteTable",
    "PublicRoute",
    "PublicSubnetRouteTableAssociation",
    "LoadBalancerSecurityGroup",
    "AppSecurityGroup",
    "DatabaseSecurityGroup",
    "LoadBalancer",
    "TargetGroup",
    "Listener",
    "AppRole",
    "AppInstanceProfile",
    "AppInstance",
    "DbSubnetGroup",
    "Database",
    "UploadsBucket",
}


class TestLongFormTemplate:
    def test_every_logical_id_is_a_node(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_nodes(graph, WEB_NODES, exact=True)

    def test_logical_ids_map_to_the_resource_types_rules_match_on(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        types = {nid: graph.nodes[nid].resource_type for nid in WEB_NODES}
        assert types["UploadsBucket"] == "aws_s3_bucket"
        assert types["Database"] == "aws_db_instance"
        assert types["AppInstance"] == "aws_instance"
        assert types["LoadBalancer"] == "aws_lb"
        assert types["AppRole"] == "aws_iam_role"
        assert types["Vpc"] == "aws_vpc"

    def test_depends_on_is_a_dependency_edge(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "PublicRoute", "GatewayAttachment", type="dependency")

    def test_zones_follow_the_resource_type(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_zone(graph, "UploadsBucket", "data")
        assert_zone(graph, "LoadBalancer", "dmz")
        assert_zone(graph, "AppRole", "management")
        assert_zone(graph, "InternetGateway", "internet")


class TestLongFormReferences:
    """Ref, GetAtt and Sub in value positions are edges."""

    def test_subnets_are_contained_in_the_vpc(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        for node in ("PublicSubnet", "PrivateSubnet", "PrivateSubnetB"):
            assert_edge(graph, node, "Vpc", type="containment")

    def test_the_app_group_depends_on_the_load_balancer_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppSecurityGroup", "LoadBalancerSecurityGroup", type="dependency")

    def test_the_database_group_depends_on_the_app_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "DatabaseSecurityGroup", "AppSecurityGroup", type="dependency")

    def test_the_instance_is_contained_in_the_private_subnet(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "PrivateSubnet", type="containment")

    def test_the_instance_uses_the_app_security_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "AppSecurityGroup")

    def test_the_instance_uses_its_instance_profile(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "AppInstanceProfile", type="iam_binding")

    def test_the_database_uses_its_subnet_group_and_security_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "Database", "DbSubnetGroup")
        assert_edge(graph, "Database", "DatabaseSecurityGroup")

    def test_the_role_policy_depends_on_the_bucket_named_in_its_sub(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppRole", "UploadsBucket")

    def test_the_listener_chain_is_connected(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "Listener", "LoadBalancer")
        assert_edge(graph, "Listener", "TargetGroup")


class TestLongFormProperties:
    def test_the_database_has_the_snake_case_attributes(self) -> None:
        props = scan_real_shape(WEB_JSON).graph.nodes["Database"].properties
        assert props["publicly_accessible"] is False
        assert props["storage_encrypted"] is True

    def test_the_bucket_has_its_encryption_attribute(self) -> None:
        props = scan_real_shape(WEB_JSON).graph.nodes["UploadsBucket"].properties
        assert "server_side_encryption_configuration" in props

    def test_a_parameter_default_is_resolved(self) -> None:
        props = scan_real_shape(WEB_JSON).graph.nodes["Vpc"].properties
        assert props["cidr_block"] == "10.40.0.0/16"

    def test_an_unresolvable_intrinsic_is_unknown(self) -> None:
        from threatcode.values import is_unknown

        props = scan_real_shape(WEB_JSON).graph.nodes["Database"].properties
        assert is_unknown(props["master_user_password"])


class TestShortFormTemplate:
    def test_short_form_yaml_has_the_same_nodes_as_the_long_form(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        assert_nodes(graph, WEB_NODES, exact=True)

    def test_a_resources_only_template_is_read(self) -> None:
        graph = scan_real_shape(RESOURCES_ONLY).graph
        assert_nodes(graph, ["AuditBucket", "AuditTopic", "AuditQueue"], exact=True)

    def test_short_form_references_are_edges(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        assert_edge(graph, "AppInstance", "PrivateSubnet", type="containment")


class TestSam:
    def test_the_function_and_its_implicit_role_are_nodes(self) -> None:
        graph = scan_real_shape(SAM).graph
        types = {n.id: n.resource_type for n in graph.nodes.values()}
        assert types["OrdersFunction"] == "aws_lambda_function"
        assert types["OrdersTable"] == "aws_dynamodb_table"
        roles = [n for n in graph.nodes.values() if n.resource_type == "aws_iam_role"]
        assert len(roles) == 2

    def test_the_admin_function_is_bound_to_a_role(self) -> None:
        graph = scan_real_shape(SAM).graph
        edges = [e for e in graph.edges if e.source == "AdminFunction"]
        assert any(graph.nodes[e.target].resource_type == "aws_iam_role" for e in edges)


class TestNestedStacks:
    def test_the_nested_stack_is_reported_not_silently_flattened(self) -> None:
        result = scan_real_shape(NESTED_PARENT)
        assert "Network" in result.graph.nodes
        codes = {d.code for output in result.parsed for d in output.diagnostics}
        assert "cfn.nested_stack" in codes

    def test_the_instance_depends_on_the_nested_stack_that_supplies_its_subnet(self) -> None:
        graph = scan_real_shape(NESTED_PARENT).graph
        assert_edge(graph, "AppInstance", "Network")


class TestEdgesInTheShortFormTemplate:
    def test_both_forms_draw_the_same_edges(self) -> None:
        def edges(path: str) -> set[tuple[str, str, str]]:
            graph = scan_real_shape(path).graph
            return {(e.source, e.target, e.edge_type.value) for e in graph.edges}

        assert edges(WEB_YAML) == edges(WEB_JSON)

    def test_every_resource_that_names_another_has_an_edge_to_it(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        targets = {n: {e.target for e in graph.edges_from(n)} for n in WEB_NODES}
        assert targets["AppInstance"] >= {"PrivateSubnet", "AppSecurityGroup", "AppInstanceProfile"}
        assert targets["LoadBalancer"] >= {
            "LoadBalancerSecurityGroup",
            "PublicSubnet",
            "PrivateSubnetB",
        }
        assert targets["TargetGroup"] >= {"Vpc", "AppInstance"}
        assert targets["PublicRoute"] >= {
            "PublicRouteTable",
            "InternetGateway",
            "GatewayAttachment",
        }
        assert targets["GatewayAttachment"] >= {"Vpc", "InternetGateway"}

    def test_the_vpc_and_the_bucket_depend_on_nothing(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        assert graph.edges_from("Vpc") == []
        assert graph.edges_from("UploadsBucket") == []

    def test_parameters_and_pseudo_parameters_make_no_edge(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        assert not {e.target for e in graph.edges} - set(WEB_NODES)

    def test_the_typed_edges_have_their_relation(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "AppSecurityGroup", relation="security_group")
        assert_edge(graph, "AppInstanceProfile", "AppRole", type="iam_binding", relation="assumes")
        assert_edge(graph, "AppInstance", "AppInstanceProfile", relation="instance_profile")


class TestTypesZonesAndLines:
    def test_the_short_form_template_has_the_same_types(self) -> None:
        short = {n: node.resource_type for n, node in scan_real_shape(WEB_YAML).graph.nodes.items()}
        long = {n: node.resource_type for n, node in scan_real_shape(WEB_JSON).graph.nodes.items()}
        assert short == long
        assert short["Listener"] == "aws_lb_listener"
        assert short["TargetGroup"] == "aws_lb_target_group"
        assert short["PublicSubnetRouteTableAssociation"] == "aws_route_table_association"
        assert short["PublicRoute"] == "aws_route"
        assert short["DbSubnetGroup"] == "aws_db_subnet_group"
        assert short["AppInstanceProfile"] == "aws_iam_instance_profile"

    def test_a_public_subnet_is_in_the_dmz_and_a_private_one_is_not(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_zone(graph, "PublicSubnet", "dmz")
        assert_zone(graph, "PrivateSubnet", "private")

    def test_every_node_carries_the_lines_of_its_resource(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        lines = (REAL_SHAPES / "cloudformation" / "web_stack.yaml").read_text().splitlines()
        for name in WEB_NODES:
            node = graph.nodes[name]
            assert node.start_line is not None and node.end_line is not None
            assert lines[node.start_line - 1].strip() == f"{name}:"

    def test_the_implicit_api_is_an_api_gateway_type_and_policy_templates_are_reported(self) -> None:
        result = scan_files([CFN_FIXTURES / "sam_function.yaml"])
        assert result.graph.nodes["ServerlessRestApi"].resource_type == "aws_api_gateway_rest_api"
        codes = {d.code for d in result.graph.diagnostics}
        assert "cfn.sam_policy_template" in codes


class TestSamGraph:
    def test_the_api_reaches_the_function_and_the_function_its_role(self) -> None:
        graph = scan_files([CFN_FIXTURES / "sam_function.yaml"]).graph
        assert_edge(graph, "ServerlessRestApi", "AdminFunction", type="network_flow")
        assert_edge(graph, "AdminFunction", "AdminFunctionRole", type="iam_binding")
        assert_edge(graph, "ServerlessHttpApi", "ReaderFunction", type="network_flow")
        assert_edge(graph, "WorkQueue", "ReaderFunction", type="data_flow")

    def test_the_permission_depends_on_the_function_and_the_api(self) -> None:
        graph = scan_files([CFN_FIXTURES / "sam_function.yaml"]).graph
        assert_edge(graph, "AdminFunctionAdminPermission", "AdminFunction")
        assert_edge(graph, "AdminFunctionAdminPermission", "ServerlessRestApi")

    def test_a_function_with_its_own_role_has_no_role_node(self) -> None:
        graph = scan_files([CFN_FIXTURES / "sam_function.yaml"]).graph
        assert "PrivateFunctionRole" not in graph.nodes

    def test_the_policy_template_makes_the_role_depend_on_the_table(self) -> None:
        graph = scan_files([CFN_FIXTURES / "sam_function.yaml"]).graph
        assert_edge(graph, "ReaderFunctionRole", "ItemsTable")


class TestZonesExposureAndPaths:
    @pending("WP-3-1", "RDS types have an explicit DATABASE category, so zone data")
    def test_the_database_is_in_the_data_zone(self) -> None:
        assert_zone(scan_real_shape(WEB_JSON).graph, "Database", "data")

    @pending("WP-3-1", "a load balancer with Scheme internet-facing has exposure internet")
    def test_the_internet_facing_load_balancer_is_exposed(self) -> None:
        assert_exposure(scan_real_shape(WEB_JSON).graph, "LoadBalancer", "internet")

    @pending("WP-4-1", "reachability: internet to the load balancer, the instance and the database")
    def test_the_internet_reaches_the_database_through_the_app_tier(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        path = assert_path(graph, "internet", "Database", edge_types=["network_flow"])
        assert "LoadBalancer" in path
