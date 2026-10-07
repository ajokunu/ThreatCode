"""Graph-level assertions on real-shape ``terraform show -json`` plans.

The fixtures under ``tests/fixtures/real_shapes/terraform/plan`` leave create-time ids unknown,
list them in ``after_unknown`` and put relationships in ``configuration.expressions.references``,
as real plans do. Hand-shaped plans store addresses as attribute values, which hides how rarely
containment and security-group inference fire on real input.

Assertions that hold on the current tree run now. Each assertion a later package delivers is its
own test marked ``pending(package, deliverable)``, so one switch turns one expectation on.
"""

from __future__ import annotations

import json

import pytest

from tests.helpers.graph_assert import (
    assert_edge,
    assert_exposure,
    assert_no_edge,
    assert_no_path,
    assert_nodes,
    assert_path,
    assert_zone,
)
from tests.helpers.pending import pending
from tests.helpers.plan_shape import plan_shape_problems
from tests.helpers.scan import REAL_SHAPES_DIR, scan_real_shape
from threatcode.ir.graph import InfraGraph
from threatcode.values import is_unknown

WEBAPP = "terraform/plan/webapp.plan.json"
MODULES = "terraform/plan/modules.plan.json"
TWO_VPCS = "terraform/plan/two_vpcs.plan.json"
MODULE_SCOPES = "terraform/plan/module_scopes.plan.json"
UNKNOWN_VALUES = "terraform/plan/unknown_values.plan.json"
AZURE_NETWORK = "terraform/plan/azure_network.plan.json"
GCP_NETWORK = "terraform/plan/gcp_network.plan.json"

PLAN_FIXTURES = sorted((REAL_SHAPES_DIR / "terraform" / "plan").glob("*.plan.json"))


# ---------------------------------------------------------------------------------------
# The corpus itself
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("path", PLAN_FIXTURES, ids=lambda p: p.name)
def test_every_plan_fixture_has_the_shape_terraform_emits(path: object) -> None:
    """A plan that claims a format_version needs resource_changes and configuration.

    Without them it is the hand-shaped kind that lets tests pass while real plans fail.
    """
    data = json.loads(path.read_text(encoding="utf-8"))  # type: ignore[attr-defined]
    assert plan_shape_problems(data) == []
    assert "resource_changes" in data
    assert "configuration" in data


# Plan fixtures that claim a format_version but are the hand-shaped kind: planned_values and
# configuration with attribute values that hold addresses, and no resource_changes. They stay as
# they are because golden recordings and older tests read them. The list is the explicit marker the
# next test demands: it may only shrink, and a fixture leaves it when it is rewritten to the shape
# `terraform show -json` prints.
LEGACY_HAND_SHAPED = frozenset(
    {
        "tests/fixtures/realistic/01_aws_ecommerce_platform.json",
        "tests/fixtures/realistic/04_aws_java_microservices.json",
        "tests/fixtures/realistic/08_aws_ml_training_platform.json",
        "tests/fixtures/realistic/10_aws_gaming_backend.json",
        "tests/fixtures/terraform/multi_service_insecure.plan.json",
        "tests/fixtures/terraform/multi_service_secure.plan.json",
        "tests/fixtures/terraform/simple_s3.plan.json",
    }
)


def _claimed_plans() -> dict[str, dict[str, object]]:
    """Every JSON fixture outside the corpus that claims to be a Terraform plan."""
    repo = REAL_SHAPES_DIR.parent.parent.parent
    found: dict[str, dict[str, object]] = {}
    patterns = (("tests/fixtures/terraform", "*.plan.json"), ("tests/fixtures/realistic", "*.json"))
    for directory, pattern in patterns:
        for path in sorted((repo / directory).glob(pattern)):
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "format_version" in data:
                found[str(path.relative_to(repo))] = data
    return found


def unlisted_hand_shaped(plans: dict[str, dict[str, object]], legacy: frozenset[str]) -> list[str]:
    """Plans that claim a format_version, lack resource_changes and are not marked legacy."""
    return sorted(
        name
        for name, data in plans.items()
        if "resource_changes" not in data and name not in legacy
    )


class TestNoUnrealisticPlanIsAddedSilently:
    def test_a_plan_without_resource_changes_must_be_listed_as_legacy(self) -> None:
        unlisted = unlisted_hand_shaped(_claimed_plans(), LEGACY_HAND_SHAPED)
        assert not unlisted, (
            f"{unlisted} claim a format_version but have no resource_changes block. Write them in "
            "the shape `terraform show -json` prints (see tests/fixtures/real_shapes/terraform/"
            "plan) or, for a deliberate hand-shaped fixture, list it in LEGACY_HAND_SHAPED."
        )

    def test_the_legacy_list_names_only_files_that_are_still_hand_shaped(self) -> None:
        plans = _claimed_plans()
        stale = sorted(
            name
            for name in LEGACY_HAND_SHAPED
            if name not in plans or "resource_changes" in plans[name]
        )
        assert not stale, f"remove {stale} from LEGACY_HAND_SHAPED: gone or now real-shaped"

    def test_a_new_hand_shaped_plan_would_be_caught_and_a_real_shaped_one_would_not(self) -> None:
        hand_shaped = {"format_version": "1.0", "planned_values": {"root_module": {}}}
        real = {**hand_shaped, "resource_changes": []}
        plans = {"new/hand.plan.json": hand_shaped, "new/real.plan.json": real}
        assert unlisted_hand_shaped(plans, frozenset()) == ["new/hand.plan.json"]
        assert unlisted_hand_shaped(plans, frozenset({"new/hand.plan.json"})) == []


def test_the_corpus_has_the_plan_fixtures() -> None:
    assert [p.name for p in PLAN_FIXTURES] == [
        "azure_network.plan.json",
        "gcp_network.plan.json",
        "module_scopes.plan.json",
        "modules.plan.json",
        "two_vpcs.plan.json",
        "unknown_values.plan.json",
        "webapp.plan.json",
    ]


def edge_set(graph: InfraGraph) -> set[tuple[str, str, str]]:
    """Every edge as (source, target, type), for asserting a whole graph at once."""
    return {(e.source, e.target, e.edge_type.value) for e in graph.edges}


# ---------------------------------------------------------------------------------------
# webapp.plan.json
# ---------------------------------------------------------------------------------------

WEBAPP_NODES = {
    "aws_vpc.main",
    "aws_internet_gateway.gw",
    "aws_subnet.public[0]",
    "aws_subnet.public[1]",
    "aws_subnet.private[0]",
    "aws_subnet.private[1]",
    "aws_route_table.public",
    "aws_route_table_association.public[0]",
    "aws_route_table_association.public[1]",
    "aws_security_group.alb",
    "aws_security_group.app",
    "aws_security_group.db",
    "aws_lb.front",
    "aws_lb_target_group.app",
    "aws_lb_listener.https",
    "aws_lb_target_group_attachment.app[0]",
    "aws_lb_target_group_attachment.app[1]",
    "aws_iam_role.app",
    "aws_iam_instance_profile.app",
    "aws_iam_role_policy.app_data",
    "aws_secretsmanager_secret.db",
    "aws_instance.app[0]",
    "aws_instance.app[1]",
    "aws_db_subnet_group.db",
    "aws_db_instance.orders",
    "aws_s3_bucket.data",
    "aws_s3_bucket_versioning.data",
    "aws_s3_bucket_server_side_encryption_configuration.data",
    "aws_s3_bucket_public_access_block.data",
    "aws_lambda_function.worker",
}


class TestWebappNodes:
    def test_every_planned_resource_is_a_node_one_per_counted_instance(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_nodes(graph, WEBAPP_NODES)

    def test_a_counted_resource_is_never_collapsed_into_one_node(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert "aws_instance.app" not in graph.nodes
        assert "aws_subnet.public" not in graph.nodes

    def test_the_split_s3_resources_stay_separate_nodes(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        types = {
            graph.nodes[n].resource_type
            for n in graph.nodes
            if n.startswith("aws_s3_bucket") and n.endswith(".data")
        }
        assert types == {
            "aws_s3_bucket",
            "aws_s3_bucket_versioning",
            "aws_s3_bucket_server_side_encryption_configuration",
            "aws_s3_bucket_public_access_block",
        }


class TestWebappTopLevelReferences:
    """References in top-level expressions already become dependency edges."""

    @pytest.mark.parametrize(
        ("src", "dst"),
        [
            ("aws_lb.front", "aws_security_group.alb"),
            ("aws_lb_listener.https", "aws_lb.front"),
            ("aws_iam_instance_profile.app", "aws_iam_role.app"),
            ("aws_iam_role_policy.app_data", "aws_iam_role.app"),
            ("aws_db_instance.orders", "aws_db_subnet_group.db"),
            ("aws_db_instance.orders", "aws_security_group.db"),
            ("aws_s3_bucket_versioning.data", "aws_s3_bucket.data"),
            ("aws_s3_bucket_public_access_block.data", "aws_s3_bucket.data"),
            ("aws_internet_gateway.gw", "aws_vpc.main"),
        ],
    )
    def test_dependency_edge(self, src: str, dst: str) -> None:
        assert_edge(scan_real_shape(WEBAPP).graph, src, dst, type="dependency")

    def test_references_never_run_backwards(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_no_edge(graph, "aws_vpc.main", "aws_internet_gateway.gw")
        assert_no_edge(graph, "aws_security_group.alb", "aws_lb.front")


class TestWebappZones:
    @pytest.mark.parametrize(
        ("node", "zone"),
        [
            ("aws_s3_bucket.data", "data"),
            ("aws_lb.front", "dmz"),
            ("aws_iam_role.app", "management"),
            ("aws_instance.app[0]", "private"),
            ("aws_internet_gateway.gw", "internet"),
        ],
    )
    def test_zone(self, node: str, zone: str) -> None:
        assert_zone(scan_real_shape(WEBAPP).graph, node, zone)

    @pending("WP-3-1", "RDS and Aurora types have an explicit DATABASE category, so zone data")
    def test_the_database_is_in_the_data_zone(self) -> None:
        assert_zone(scan_real_shape(WEBAPP).graph, "aws_db_instance.orders", "data")

    @pending("WP-3-1", "Secrets Manager secrets are the new SECRET category in the data zone")
    def test_the_secret_is_in_the_data_zone(self) -> None:
        assert_zone(scan_real_shape(WEBAPP).graph, "aws_secretsmanager_secret.db", "data")


class TestWebappExposure:
    @pending("WP-3-1", "an internet-facing load balancer has exposure internet")
    def test_the_internet_facing_load_balancer_is_exposed(self) -> None:
        assert_exposure(scan_real_shape(WEBAPP).graph, "aws_lb.front", "internet")

    @pending("WP-3-1", "a security group with world-open ingress has exposure internet")
    def test_the_world_open_security_group_is_exposed(self) -> None:
        assert_exposure(scan_real_shape(WEBAPP).graph, "aws_security_group.alb", "internet")


class TestWebappCountedInstancesInheritConfiguration:
    def test_every_app_instance_is_attached_to_the_app_security_group(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        for node in ("aws_instance.app[0]", "aws_instance.app[1]"):
            assert_edge(graph, node, "aws_security_group.app", type="dependency")

    def test_instances_are_contained_in_the_private_subnets(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_instance.app[0]", "aws_subnet.private[0]", type="containment")
        assert_edge(graph, "aws_instance.app[0]", "aws_subnet.private[1]", type="containment")

    def test_instances_reference_their_instance_profile(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(
            graph, "aws_instance.app[1]", "aws_iam_instance_profile.app", type="iam_binding"
        )

    def test_counted_subnets_are_contained_in_the_vpc(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        for node in ("aws_subnet.public[0]", "aws_subnet.private[1]"):
            assert_edge(graph, node, "aws_vpc.main", type="containment")

    def test_target_group_attachments_point_at_the_instances(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_lb_target_group_attachment.app[0]", "aws_instance.app[0]")


class TestWebappNestedBlockReferences:
    def test_the_app_group_depends_on_the_load_balancer_group(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_security_group.app", "aws_security_group.alb", type="dependency")

    def test_the_database_group_depends_on_the_app_group(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_security_group.db", "aws_security_group.app", type="dependency")

    def test_the_lambda_is_contained_in_the_private_subnets(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(
            graph, "aws_lambda_function.worker", "aws_subnet.private[0]", type="containment"
        )

    def test_the_lambda_uses_the_app_security_group(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_lambda_function.worker", "aws_security_group.app")


class TestWebappUnknownValues:
    def test_an_unknown_id_is_unknown_not_missing(self) -> None:
        node = scan_real_shape(WEBAPP).graph.nodes["aws_subnet.private[0]"]
        assert "vpc_id" in node.properties
        assert is_unknown(node.properties["vpc_id"])

    def test_the_data_source_is_graph_context_only(self) -> None:
        node = scan_real_shape(WEBAPP).graph.nodes["data.aws_iam_policy_document.assume"]
        assert getattr(node, "mode", "managed") == "data"

    def test_the_unknown_endpoint_of_the_database_is_unknown(self) -> None:
        node = scan_real_shape(WEBAPP).graph.nodes["aws_db_instance.orders"]
        assert is_unknown(node.properties.get("endpoint"))


class TestWebappAttackSurface:
    @pending("WP-3-1", "role resolution links an instance, its profile and its role by iam_binding")
    def test_the_instance_profile_is_bound_to_the_role(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_iam_instance_profile.app", "aws_iam_role.app", type="iam_binding")

    @pending("WP-4-1", "reachability: internet to the load balancer, app tier and database")
    def test_the_internet_reaches_the_database_through_the_app_tier(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        path = assert_path(
            graph, "internet", "aws_db_instance.orders", edge_types=["network_flow", "data_flow"]
        )
        assert "aws_lb.front" in path

    @pending("WP-4-1", "reachability follows security group references, so nothing runs backwards")
    def test_reachability_never_runs_from_the_database_back_to_the_internet(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        # Positive control: the walk reaches the app tier, so the absence below is meaningful
        assert_path(graph, "internet", "aws_instance.app[0]", edge_types=["network_flow"])
        assert_no_path(graph, "aws_security_group.db", "aws_lb.front", ["network_flow"])


# ---------------------------------------------------------------------------------------
# two_vpcs.plan.json
# ---------------------------------------------------------------------------------------


class TestTwoVpcs:
    @pytest.mark.parametrize("key", ["prod", "dev"])
    def test_each_vpc_keeps_its_own_dependency_edges(self, key: str) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        assert_edge(graph, f"aws_subnet.{key}", f"aws_vpc.{key}", type="dependency")
        assert_edge(graph, f"aws_security_group.{key}", f"aws_vpc.{key}", type="dependency")
        assert_edge(graph, f"aws_instance.{key}", f"aws_subnet.{key}", type="dependency")

    @pytest.mark.parametrize(("a", "b"), [("prod", "dev"), ("dev", "prod")])
    def test_nothing_in_one_vpc_attaches_to_the_other(self, a: str, b: str) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        for kind in ("subnet", "security_group", "instance"):
            assert_no_edge(graph, f"aws_{kind}.{a}", f"aws_vpc.{b}")
        assert_no_edge(graph, f"aws_instance.{a}", f"aws_subnet.{b}")

    def test_the_dev_subnet_is_contained_in_the_dev_vpc(self) -> None:
        assert_edge(scan_real_shape(TWO_VPCS).graph, "aws_subnet.dev", "aws_vpc.dev", "containment")

    def test_the_dev_instance_is_contained_in_the_dev_subnet(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        assert_edge(graph, "aws_instance.dev", "aws_subnet.dev", type="containment")

    @pending("WP-4-1", "attack paths never cross between two VPCs with no connection")
    def test_there_is_no_path_between_the_vpcs(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        # Positive control: each instance is wired into its own VPC, so the walk has edges
        assert_edge(graph, "aws_instance.prod", "aws_subnet.prod", type="containment")
        assert_edge(graph, "aws_instance.dev", "aws_subnet.dev", type="containment")
        assert_no_path(graph, "aws_instance.prod", "aws_instance.dev")
        assert_no_path(graph, "aws_instance.dev", "aws_instance.prod")


# ---------------------------------------------------------------------------------------
# modules.plan.json
# ---------------------------------------------------------------------------------------

MODULE_NODES = {
    "aws_vpc.main",
    "aws_security_group.internal",
    'aws_security_group_rule.ingress["https"]',
    'aws_security_group_rule.ingress["ssh"]',
    "aws_instance.worker",
    "aws_flow_log.main",
    "module.subnets[0].aws_subnet.this",
    "module.subnets[0].aws_network_acl.this",
    "module.subnets[1].aws_subnet.this",
    "module.subnets[1].aws_network_acl.this",
    "module.logging.aws_s3_bucket.this",
}


class TestModules:
    def test_module_resources_are_nodes_one_per_module_instance(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_nodes(graph, MODULE_NODES, exact=True)

    def test_for_each_instances_are_separate_nodes(self) -> None:
        graph = scan_real_shape(MODULES).graph
        https = graph.nodes['aws_security_group_rule.ingress["https"]']
        assert https.properties["from_port"] == 443
        assert graph.nodes['aws_security_group_rule.ingress["ssh"]'].properties["from_port"] == 22

    def test_root_references_to_root_resources_are_dependency_edges(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_edge(graph, "aws_security_group.internal", "aws_vpc.main", type="dependency")
        assert_edge(graph, "aws_instance.worker", "aws_security_group.internal", "dependency")

    def test_the_nacl_is_attached_to_the_subnet_of_its_own_module_instance(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_edge(
            graph,
            "module.subnets[1].aws_network_acl.this",
            "module.subnets[1].aws_subnet.this",
        )

    def test_a_module_subnet_is_contained_in_the_vpc_passed_as_input(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_edge(graph, "module.subnets[0].aws_subnet.this", "aws_vpc.main", type="containment")

    def test_the_worker_is_contained_in_the_subnet_its_module_output_names(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_edge(
            graph, "aws_instance.worker", "module.subnets[0].aws_subnet.this", type="containment"
        )
        assert_no_edge(graph, "aws_instance.worker", "module.subnets[1].aws_subnet.this")

    def test_the_flow_log_depends_on_the_logging_bucket(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_edge(graph, "aws_flow_log.main", "module.logging.aws_s3_bucket.this")

    def test_for_each_rules_are_attached_to_the_security_group(self) -> None:
        graph = scan_real_shape(MODULES).graph
        assert_edge(
            graph, 'aws_security_group_rule.ingress["https"]', "aws_security_group.internal"
        )


class TestModulesExactEdges:
    def test_the_whole_edge_set(self) -> None:
        graph = scan_real_shape(MODULES).graph
        subnet0, subnet1 = "module.subnets[0].aws_subnet.this", "module.subnets[1].aws_subnet.this"
        acl0, acl1 = (
            "module.subnets[0].aws_network_acl.this",
            "module.subnets[1].aws_network_acl.this",
        )
        rules = (
            'aws_security_group_rule.ingress["https"]',
            'aws_security_group_rule.ingress["ssh"]',
        )
        expected = {
            ("aws_flow_log.main", "aws_vpc.main", "containment"),
            ("aws_flow_log.main", "aws_vpc.main", "dependency"),
            ("aws_flow_log.main", "module.logging.aws_s3_bucket.this", "dependency"),
            ("aws_instance.worker", "aws_security_group.internal", "dependency"),
            ("aws_instance.worker", subnet0, "containment"),
            ("aws_instance.worker", subnet0, "dependency"),
            ("aws_security_group.internal", "aws_vpc.main", "containment"),
            ("aws_security_group.internal", "aws_vpc.main", "dependency"),
            (acl0, "aws_vpc.main", "containment"),
            (acl0, "aws_vpc.main", "dependency"),
            (acl0, subnet0, "containment"),
            (acl0, subnet0, "dependency"),
            (acl1, "aws_vpc.main", "containment"),
            (acl1, "aws_vpc.main", "dependency"),
            (acl1, subnet1, "containment"),
            (acl1, subnet1, "dependency"),
            (subnet0, "aws_vpc.main", "containment"),
            (subnet0, "aws_vpc.main", "dependency"),
            (subnet1, "aws_vpc.main", "containment"),
            (subnet1, "aws_vpc.main", "dependency"),
        }
        for rule in rules:
            expected |= {
                (rule, "aws_security_group.internal", "dependency"),
                (rule, "aws_vpc.main", "dependency"),
            }
        assert edge_set(graph) == expected


class TestTwoVpcsExactEdges:
    def test_the_whole_edge_set(self) -> None:
        graph = scan_real_shape(TWO_VPCS).graph
        expected: set[tuple[str, str, str]] = set()
        for key in ("prod", "dev"):
            vpc, subnet = f"aws_vpc.{key}", f"aws_subnet.{key}"
            expected |= {
                (f"aws_instance.{key}", f"aws_security_group.{key}", "dependency"),
                (f"aws_instance.{key}", subnet, "containment"),
                (f"aws_instance.{key}", subnet, "dependency"),
                (f"aws_security_group.{key}", vpc, "containment"),
                (f"aws_security_group.{key}", vpc, "dependency"),
                (subnet, vpc, "containment"),
                (subnet, vpc, "dependency"),
            }
        assert edge_set(graph) == expected


class TestModuleScopes:
    """Same-named resources in the root and in a module never bind to each other."""

    def test_the_module_subnet_binds_to_the_module_vpc_and_only_to_it(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        assert_edge(graph, "module.net.aws_subnet.a", "module.net.aws_vpc.main", "containment")
        assert_no_edge(graph, "module.net.aws_subnet.a", "aws_vpc.main")

    def test_the_root_group_binds_to_the_root_vpc_and_only_to_it(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        assert_edge(graph, "aws_security_group.shared", "aws_vpc.main", "containment")
        assert_no_edge(graph, "aws_security_group.shared", "module.net.aws_vpc.main")

    def test_a_variable_binds_to_the_parent_group_and_not_the_namesake_in_the_module(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        bastion = "module.net.aws_instance.bastion"
        assert_edge(graph, bastion, "aws_security_group.shared", type="dependency")
        assert_no_edge(graph, bastion, "module.net.aws_security_group.shared")

    def test_a_module_local_reference_binds_to_the_module_namesake(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        inner = "module.net.aws_instance.inner"
        assert_edge(graph, inner, "module.net.aws_security_group.shared", type="dependency")
        assert_no_edge(graph, inner, "aws_security_group.shared")

    def test_the_root_instance_is_contained_in_the_subnet_the_module_output_names(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        assert_edge(graph, "aws_instance.edge", "module.net.aws_subnet.a", type="containment")
        assert_edge(graph, "aws_instance.edge", "aws_security_group.shared", type="dependency")

    def test_a_pinned_module_key_reaches_one_tenant_subnet(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        assert_edge(
            graph, "aws_instance.pinned", 'module.tenant["a"].aws_subnet.this', "containment"
        )
        assert_no_edge(graph, "aws_instance.pinned", 'module.tenant["b"].aws_subnet.this')

    def test_every_tenant_subnet_is_contained_in_the_root_vpc(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        for key in ("a", "b"):
            assert_edge(
                graph, f'module.tenant["{key}"].aws_subnet.this', "aws_vpc.main", "containment"
            )

    def test_a_key_reaches_the_root_key_through_two_modules(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        sse = "module.net.module.leaf.aws_s3_bucket_server_side_encryption_configuration.logs"
        assert_edge(graph, sse, "aws_kms_key.main", type="dependency")
        assert_edge(graph, sse, "module.net.module.leaf.aws_s3_bucket.logs", type="dependency")

    def test_no_node_of_the_module_binds_to_a_root_resource_it_does_not_reference(self) -> None:
        graph = scan_real_shape(MODULE_SCOPES).graph
        allowed_root = {"aws_security_group.shared", "aws_kms_key.main", "aws_vpc.main"}
        for edge in graph.edges:
            if edge.source.startswith("module.net.") and not edge.target.startswith("module."):
                assert edge.target in allowed_root, edge


class TestUnknownValuesGraph:
    def test_the_whole_edge_set(self) -> None:
        graph = scan_real_shape(UNKNOWN_VALUES).graph
        assert edge_set(graph) == {
            ("aws_cloudtrail.encrypted", "aws_kms_key.trail", "dependency"),
            ("aws_cloudtrail.encrypted", "aws_s3_bucket.trail_logs", "dependency"),
            ("aws_cloudtrail.plain", "aws_s3_bucket.trail_logs", "dependency"),
            ("aws_sqs_queue.orders", "aws_kms_key.trail", "dependency"),
            ("module.audit.aws_cloudtrail.bare", "aws_s3_bucket.trail_logs", "dependency"),
            ("module.audit.aws_cloudtrail.this", "aws_kms_key.trail", "dependency"),
            ("module.audit.aws_cloudtrail.this", "aws_s3_bucket.trail_logs", "dependency"),
        }

    def test_the_module_trail_depends_on_the_key_the_root_passes_in(self) -> None:
        graph = scan_real_shape(UNKNOWN_VALUES).graph
        assert_edge(graph, "module.audit.aws_cloudtrail.this", "aws_kms_key.trail")
        assert_no_edge(graph, "module.audit.aws_cloudtrail.bare", "aws_kms_key.trail")


class TestUnknownIsNeverALiteral:
    """A value that is not known yet must not be mistaken for an id or a public address."""

    def test_an_unknown_vpc_id_with_no_reference_does_not_attach_to_the_first_vpc(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        # aws_lb.front has vpc_id in after_unknown but no vpc_id expression
        assert is_unknown(graph.nodes["aws_lb.front"].properties["vpc_id"])
        assert_no_edge(graph, "aws_lb.front", "aws_vpc.main")

    def test_an_unknown_public_ip_does_not_move_an_instance_into_the_dmz(self) -> None:
        node = scan_real_shape(WEBAPP).graph.nodes["aws_instance.app[0]"]
        assert is_unknown(node.properties["associate_public_ip_address"])
        assert node.trust_zone.value == "private"


class TestWebappDataSources:
    @pending("WP-2-7", "scanned_resources counts managed resources only, not mode data nodes")
    def test_a_data_source_is_not_counted_as_a_scanned_resource(self) -> None:
        result = scan_real_shape(WEBAPP)
        data_nodes = [n for n in result.graph.nodes.values() if n.mode == "data"]
        assert len(data_nodes) == 1
        assert result.report.scanned_resources == result.graph.node_count - len(data_nodes)

    def test_rules_never_report_a_data_source(self) -> None:
        result = scan_real_shape(WEBAPP)
        assert result.threats_for("data.aws_iam_policy_document.assume") == []

    def test_the_data_source_stays_a_node_that_the_role_depends_on(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        assert_edge(graph, "aws_iam_role.app", "data.aws_iam_policy_document.assume", "dependency")

    def test_the_parser_reports_the_data_source_and_the_unknowns(self) -> None:
        codes = {d.code for d in scan_real_shape(WEBAPP).parsed[0].diagnostics}
        assert {"plan.data_source", "plan.unknown_values"} <= codes
        assert "parse.zero_resources" not in codes


class TestCountedFanOut:
    def test_the_attachment_of_each_instance_reaches_every_app_instance(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        for attachment in (
            "aws_lb_target_group_attachment.app[0]",
            "aws_lb_target_group_attachment.app[1]",
        ):
            for instance in ("aws_instance.app[0]", "aws_instance.app[1]"):
                assert_edge(graph, attachment, instance)

    def test_no_edge_runs_from_a_resource_to_its_own_sibling_instance_of_itself(self) -> None:
        graph = scan_real_shape(WEBAPP).graph
        for edge in graph.edges:
            assert edge.source != edge.target


class TestOtherProviders:
    """References resolve the same way for the azurerm and google providers."""

    def test_the_azure_edge_set(self) -> None:
        graph = scan_real_shape(AZURE_NETWORK).graph
        group = "azurerm_resource_group.main"
        assert edge_set(graph) == {
            ("azurerm_virtual_network.main", group, "dependency"),
            ("azurerm_subnet.app", group, "dependency"),
            ("azurerm_subnet.app", "azurerm_virtual_network.main", "dependency"),
            ("azurerm_network_security_group.app", group, "dependency"),
            ("azurerm_network_security_rule.rdp", group, "dependency"),
            (
                "azurerm_network_security_rule.rdp",
                "azurerm_network_security_group.app",
                "dependency",
            ),
            ("azurerm_network_interface.app", group, "dependency"),
            ("azurerm_network_interface.app", "azurerm_subnet.app", "dependency"),
            ("azurerm_linux_virtual_machine.app", group, "dependency"),
            ("azurerm_linux_virtual_machine.app", "azurerm_network_interface.app", "dependency"),
            (
                "azurerm_subnet_network_security_group_association.app",
                "azurerm_network_security_group.app",
                "dependency",
            ),
            (
                "azurerm_subnet_network_security_group_association.app",
                "azurerm_subnet.app",
                "dependency",
            ),
            (
                "azurerm_subnet_network_security_group_association.app",
                "azurerm_subnet.app",
                "containment",
            ),
        }

    def test_a_nested_block_reference_reaches_the_subnet(self) -> None:
        graph = scan_real_shape(AZURE_NETWORK).graph
        assert_edge(graph, "azurerm_network_interface.app", "azurerm_subnet.app")
        ip_configuration = graph.nodes["azurerm_network_interface.app"].properties[
            "ip_configuration"
        ]
        assert is_unknown(ip_configuration[0]["subnet_id"])

    def test_the_gcp_edge_set(self) -> None:
        graph = scan_real_shape(GCP_NETWORK).graph
        network, subnet = "google_compute_network.vpc", "google_compute_subnetwork.app"
        assert edge_set(graph) == {
            (subnet, network, "dependency"),
            ("google_compute_firewall.ssh", network, "dependency"),
            ("google_compute_firewall.internal", network, "dependency"),
            ("google_compute_firewall.internal", subnet, "dependency"),
            ("google_compute_instance.vm", network, "dependency"),
            ("google_compute_instance.vm", subnet, "dependency"),
        }

    def test_the_gcp_network_interface_block_keeps_its_unknown_network(self) -> None:
        graph = scan_real_shape(GCP_NETWORK).graph
        (nic,) = graph.nodes["google_compute_instance.vm"].properties["network_interface"]
        assert is_unknown(nic["network"])
        assert nic["network"].reference == "google_compute_network.vpc.id"
