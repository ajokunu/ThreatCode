"""Graph-level assertions on real-shape Terraform HCL.

``tests/fixtures/real_shapes/terraform/hcl/module_app`` is a multi-file module as a team
commits it: variables with defaults and tfvars overrides, locals in two files, data sources,
a ``dynamic`` block, a ``jsonencode`` policy, ``count`` driven by a variable, a literal
``count = 0``, a local module and a remote registry module.

Today a scan sees one ``.tf`` file at a time and treats ``count``, ``dynamic`` and every
reference as plain attribute text. Assertions that hold now run now; each one a later package
delivers is its own pending test.
"""

from __future__ import annotations

import pytest

from tests.helpers.graph_assert import (
    assert_edge,
    assert_exposure,
    assert_no_edge,
    assert_nodes,
    assert_path,
    assert_zone,
)
from tests.helpers.pending import pending
from tests.helpers.scan import real_shape, scan_real_shape

MODULE_DIR = "terraform/hcl/module_app"
TWO_VPCS = "terraform/hcl/two_vpcs.tf"
# Every .tf file of the module that declares resources, scanned together as one graph
MODULE_FILES = tuple(
    f"{MODULE_DIR}/{name}.tf" for name in ("network", "security", "compute", "iam", "storage")
)

# Resources the module declares with a non-literal or absent count, which stay nodes
MODULE_NODES = {
    "aws_vpc.main",
    "aws_internet_gateway.gw",
    "aws_subnet.public",
    "aws_subnet.private",
    "aws_route_table.public",
    "aws_route_table_association.public",
    "aws_security_group.lb",
    "aws_security_group.app",
    "aws_security_group.db",
    "aws_security_group.bastion",
    "aws_instance.app",
    "aws_lb.front",
    "aws_db_subnet_group.db",
    "aws_db_instance.orders",
    "aws_iam_role.app",
    "aws_iam_instance_profile.app",
    "aws_iam_role_policy.app_data",
    "aws_s3_bucket.uploads",
    "aws_s3_bucket_public_access_block.uploads",
}


class TestModuleAppFiles:
    def test_the_fixture_files_exist(self) -> None:
        for name in (
            "main",
            "variables",
            "network",
            "security",
            "compute",
            "iam",
            "storage",
            "modules",
            "outputs",
            "versions",
        ):
            assert real_shape(f"{MODULE_DIR}/{name}.tf").is_file()
        assert real_shape(f"{MODULE_DIR}/terraform.tfvars").is_file()
        assert real_shape(f"{MODULE_DIR}/modules/subnets/main.tf").is_file()

    def test_every_declared_resource_is_a_node(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_nodes(graph, MODULE_NODES)

    def test_subnets_and_gateways_are_contained_in_the_vpc(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        for node in ("aws_subnet.public", "aws_subnet.private", "aws_internet_gateway.gw"):
            assert_edge(graph, node, "aws_vpc.main", type="containment")

    def test_the_fixture_has_one_vpc_so_a_first_vpc_shortcut_is_correct_here(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        vpcs = [n for n in graph.nodes.values() if n.resource_type == "aws_vpc"]
        assert [v.id for v in vpcs] == ["aws_vpc.main"]

    def test_zones_of_the_bucket_load_balancer_and_role(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_zone(graph, "aws_s3_bucket.uploads", "data")
        assert_zone(graph, "aws_lb.front", "dmz")
        assert_zone(graph, "aws_iam_role.app", "management")


class TestModuleAppAsOneModule:
    """A directory of .tf files is one module, so variables and locals resolve across files."""

    @pending("WP-2-2", "a directory of .tf files parses as one Terraform module")
    def test_the_directory_is_one_graph_with_every_declared_resource(self) -> None:
        graph = scan_real_shape(MODULE_DIR).graph
        assert_nodes(graph, MODULE_NODES)

    @pending("WP-2-2", "a literal count = 0 resource is dropped with an hcl.count_zero diagnostic")
    def test_the_disabled_security_group_is_not_a_node(self) -> None:
        graph = scan_real_shape(MODULE_DIR).graph
        assert "aws_security_group.legacy" not in graph.nodes

    @pending("WP-2-2", "meta-arguments move out of properties, so count is not rule-visible")
    def test_count_and_dynamic_are_not_resource_properties(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        app = graph.nodes["aws_instance.app"]
        assert "count" not in app.properties
        assert "dynamic" not in graph.nodes["aws_security_group.app"].properties

    @pending("WP-2-2", "dynamic blocks become repeated blocks (ingress) with their content")
    def test_the_dynamic_ingress_block_becomes_an_ingress_list(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        ingress = graph.nodes["aws_security_group.app"].properties["ingress"]
        assert ingress[0]["protocol"] == "tcp"

    @pending("WP-2-2", "jsonencode policies become compact JSON text")
    def test_the_jsonencode_policy_is_json_text(self) -> None:
        import json

        graph = scan_real_shape(*MODULE_FILES).graph
        policy = graph.nodes["aws_iam_role_policy.app_data"].properties["policy"]
        assert json.loads(policy)["Statement"][0]["Effect"] == "Allow"

    @pending("WP-2-2", "a local module call is followed with addresses module.<name>.<type>.<name>")
    def test_the_local_module_resources_are_nodes(self) -> None:
        graph = scan_real_shape(MODULE_DIR).graph
        assert_nodes(graph, ["module.extra_subnets.aws_subnet.this"])

    @pending(
        "WP-2-2", "a module input resolves to the parent's reference (vpc_id = aws_vpc.main.id)"
    )
    def test_the_local_module_subnet_is_contained_in_the_vpc_it_was_given(self) -> None:
        graph = scan_real_shape(MODULE_DIR).graph
        assert_edge(
            graph, "module.extra_subnets.aws_subnet.this", "aws_vpc.main", type="containment"
        )

    @pending("WP-2-2", "a remote module call is reported as incomplete, never skipped silently")
    def test_the_remote_module_marks_the_parse_incomplete(self) -> None:
        result = scan_real_shape(MODULE_DIR)
        assert result.parsed[0].metadata.get("incomplete") is True


class TestModuleAppReferences:
    @pending("WP-2-2", "HCL traversals populate references, so attachments become edges")
    def test_the_app_group_depends_on_the_load_balancer_group_through_the_dynamic_block(
        self,
    ) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_edge(graph, "aws_security_group.app", "aws_security_group.lb", type="dependency")

    @pending("WP-2-2", "HCL traversals populate references, so attachments become edges")
    def test_the_database_group_depends_on_the_app_group(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_edge(graph, "aws_security_group.db", "aws_security_group.app", type="dependency")

    @pending("WP-2-2", "splat and indexed references resolve to every instance")
    def test_the_instances_are_contained_in_the_private_subnets(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_edge(graph, "aws_instance.app", "aws_subnet.private", type="containment")

    @pending("WP-2-2", "references inside function calls are tokenized, not skipped")
    def test_the_policy_depends_on_the_bucket_it_names(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_edge(graph, "aws_iam_role_policy.app_data", "aws_s3_bucket.uploads")

    @pending("WP-2-2", "iam_instance_profile references become an iam_binding edge")
    def test_the_instances_use_the_instance_profile(self) -> None:
        graph = scan_real_shape(*MODULE_FILES).graph
        assert_edge(graph, "aws_instance.app", "aws_iam_instance_profile.app", type="iam_binding")


class TestTwoVpcs:
    def test_the_first_vpc_is_the_control_for_the_heuristic(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        assert_edge(graph, "aws_subnet.prod", "aws_vpc.prod", type="containment")

    @pending("WP-2-2", "vpc_id references pick the referenced VPC, not the first VPC")
    def test_the_dev_subnet_is_contained_in_the_dev_vpc(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        assert_edge(graph, "aws_subnet.dev", "aws_vpc.dev", type="containment")

    @pending("WP-2-2", "vpc_id references pick the referenced VPC, not the first VPC")
    def test_nothing_in_the_dev_vpc_is_contained_in_the_prod_vpc(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        assert_edge(graph, "aws_security_group.dev", "aws_vpc.dev", type="containment")
        assert_no_edge(graph, "aws_subnet.dev", "aws_vpc.prod")
        assert_no_edge(graph, "aws_security_group.dev", "aws_vpc.prod")

    @pending("WP-2-2", "subnet_id references pick the referenced subnet")
    def test_the_dev_instance_is_contained_in_the_dev_subnet(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        assert_edge(graph, "aws_instance.dev", "aws_subnet.dev", type="containment")
        assert_no_edge(graph, "aws_instance.dev", "aws_subnet.prod")


class TestZonesExposureAndPaths:
    @pending("WP-3-1", "RDS types have an explicit DATABASE category, so zone data")
    def test_the_database_is_in_the_data_zone(self) -> None:
        assert_zone(scan_real_shape(*MODULE_FILES).graph, "aws_db_instance.orders", "data")

    @pending("WP-3-1", "an internet-facing load balancer has exposure internet")
    def test_the_load_balancer_is_exposed(self) -> None:
        assert_exposure(scan_real_shape(*MODULE_FILES).graph, "aws_lb.front", "internet")

    @pending("WP-4-1", "reachability: internet to the load balancer, app tier and database")
    def test_the_internet_reaches_the_database_through_the_app_tier(self) -> None:
        graph = scan_real_shape(MODULE_DIR).graph
        path = assert_path(graph, "internet", "aws_db_instance.orders", ["network_flow"])
        assert "aws_security_group.app" in path or "aws_instance.app" in path


@pytest.mark.parametrize("name", ["terraform.tfvars"])
def test_tfvars_overrides_exist_for_the_module_to_evaluate(name: str) -> None:
    text = real_shape(f"{MODULE_DIR}/{name}").read_text(encoding="utf-8")
    assert 'environment        = "prod"' in text
    assert "app_instance_count = 3" in text
