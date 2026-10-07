"""Graph-level assertions on real-shape CloudFormation and SAM templates.

``web_stack.yaml`` is written with short-form intrinsics (``!Ref``, ``!GetAtt``, ``!Sub``),
which is how almost every template in the wild is written. ``web_stack.json`` is the same
template in long form, so the long-form path stays testable where the short-form loader is
missing and the work to read references can be told apart from the work to load the tags.

Today a CloudFormation resource keeps its properties exactly as written (PascalCase), no
intrinsic is read as a reference, and only ``DependsOn`` makes an edge. Assertions that hold
now run now; each one a later package delivers is its own pending test.
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
from tests.helpers.scan import scan_real_shape

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
    """Ref and GetAtt in value positions are edges once WP-2-3 reads them."""

    @pending("WP-2-3", "Ref and GetAtt of VpcId become containment edges")
    def test_subnets_are_contained_in_the_vpc(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        for node in ("PublicSubnet", "PrivateSubnet", "PrivateSubnetB"):
            assert_edge(graph, node, "Vpc", type="containment")

    @pending("WP-2-3", "SourceSecurityGroupId GetAtt becomes a dependency edge")
    def test_the_app_group_depends_on_the_load_balancer_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppSecurityGroup", "LoadBalancerSecurityGroup", type="dependency")

    @pending("WP-2-3", "SourceSecurityGroupId Ref becomes a dependency edge")
    def test_the_database_group_depends_on_the_app_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "DatabaseSecurityGroup", "AppSecurityGroup", type="dependency")

    @pending("WP-2-3", "SubnetId and SecurityGroupIds references become edges")
    def test_the_instance_is_contained_in_the_private_subnet(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "PrivateSubnet", type="containment")

    @pending("WP-2-3", "SecurityGroupIds GetAtt becomes an attachment")
    def test_the_instance_uses_the_app_security_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "AppSecurityGroup")

    @pending("WP-2-3", "IamInstanceProfile Ref becomes an iam_binding edge")
    def test_the_instance_uses_its_instance_profile(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppInstance", "AppInstanceProfile", type="iam_binding")

    @pending("WP-2-3", "DBSubnetGroupName and VPCSecurityGroups references become edges")
    def test_the_database_uses_its_subnet_group_and_security_group(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "Database", "DbSubnetGroup")
        assert_edge(graph, "Database", "DatabaseSecurityGroup")

    @pending("WP-2-3", "Sub variables such as ${UploadsBucket.Arn} count as references")
    def test_the_role_policy_depends_on_the_bucket_named_in_its_sub(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "AppRole", "UploadsBucket")

    @pending("WP-2-3", "load balancer, listener and target group references become edges")
    def test_the_listener_chain_is_connected(self) -> None:
        graph = scan_real_shape(WEB_JSON).graph
        assert_edge(graph, "Listener", "LoadBalancer")
        assert_edge(graph, "Listener", "TargetGroup")


class TestLongFormProperties:
    @pending("WP-2-3", "properties are translated to the attributes rules read")
    def test_the_database_has_the_snake_case_attributes(self) -> None:
        props = scan_real_shape(WEB_JSON).graph.nodes["Database"].properties
        assert props["publicly_accessible"] is False
        assert props["storage_encrypted"] is True

    @pending("WP-2-3", "BucketEncryption becomes server_side_encryption_configuration")
    def test_the_bucket_has_its_encryption_attribute(self) -> None:
        props = scan_real_shape(WEB_JSON).graph.nodes["UploadsBucket"].properties
        assert "server_side_encryption_configuration" in props

    @pending("WP-2-3", "a Ref to a Parameter with a Default resolves to the default")
    def test_a_parameter_default_is_resolved(self) -> None:
        props = scan_real_shape(WEB_JSON).graph.nodes["Vpc"].properties
        assert props["cidr_block"] == "10.40.0.0/16"

    @pending("WP-2-3", "an unresolved intrinsic becomes values.Unknown, not a dict")
    def test_an_unresolvable_intrinsic_is_unknown(self) -> None:
        from threatcode.values import is_unknown

        props = scan_real_shape(WEB_JSON).graph.nodes["Database"].properties
        assert is_unknown(props["master_user_password"])


class TestShortFormTemplate:
    @pending(
        "WP-2-3",
        "short-form tags load; the loader is WP-1-4, merged first, this package owns the inputs",
    )
    def test_short_form_yaml_has_the_same_nodes_as_the_long_form(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        assert_nodes(graph, WEB_NODES, exact=True)

    @pending("WP-2-3", "a Resources-only template is claimed; the detector is WP-1-4, merged first")
    def test_a_resources_only_template_is_read(self) -> None:
        graph = scan_real_shape(RESOURCES_ONLY).graph
        assert_nodes(graph, ["AuditBucket", "AuditTopic", "AuditQueue"], exact=True)

    @pending("WP-2-3", "short-form references become edges exactly as the long form does")
    def test_short_form_references_are_edges(self) -> None:
        graph = scan_real_shape(WEB_YAML).graph
        assert_edge(graph, "AppInstance", "PrivateSubnet", type="containment")


class TestSam:
    @pending("WP-2-3", "SAM Function expands to a Lambda function plus an implicit execution role")
    def test_the_function_and_its_implicit_role_are_nodes(self) -> None:
        graph = scan_real_shape(SAM).graph
        types = {n.id: n.resource_type for n in graph.nodes.values()}
        assert types["OrdersFunction"] == "aws_lambda_function"
        assert types["OrdersTable"] == "aws_dynamodb_table"
        roles = [n for n in graph.nodes.values() if n.resource_type == "aws_iam_role"]
        assert len(roles) == 2

    @pending("WP-2-3", "the function depends on its implicit role through the generated reference")
    def test_the_admin_function_is_bound_to_a_role(self) -> None:
        graph = scan_real_shape(SAM).graph
        edges = [e for e in graph.edges if e.source == "AdminFunction"]
        assert any(graph.nodes[e.target].resource_type == "aws_iam_role" for e in edges)


class TestNestedStacks:
    @pending("WP-2-3", "AWS::CloudFormation::Stack keeps a node plus a cfn.nested_stack diagnostic")
    def test_the_nested_stack_is_reported_not_silently_flattened(self) -> None:
        result = scan_real_shape(NESTED_PARENT)
        assert "Network" in result.graph.nodes
        codes = {d.code for output in result.parsed for d in output.diagnostics}
        assert "cfn.nested_stack" in codes

    @pending("WP-2-3", "GetAtt of a nested stack output is an edge to the nested stack node")
    def test_the_instance_depends_on_the_nested_stack_that_supplies_its_subnet(self) -> None:
        graph = scan_real_shape(NESTED_PARENT).graph
        assert_edge(graph, "AppInstance", "Network")


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
