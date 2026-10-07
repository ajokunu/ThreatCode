"""Tests for threatcode.ir.nodes and the generic behaviour of threatcode.ir.catalog.

Tests of the entries of one provider family live in test_catalog_cloud.py,
test_catalog_kubernetes.py, test_catalog_docker.py and test_catalog_mcp.py.
"""

from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

import pytest

from threatcode.ir import catalog
from threatcode.ir.nodes import (
    CATEGORY_MAP,
    CONTAINER_TYPES,
    TRUST_ZONE_MAP,
    InfraNode,
    NodeCategory,
    TrustZone,
    _rebuild_category_prefixes,
    _rebuild_trust_zone_prefixes,
    categorize_resource,
    infer_trust_zone,
    register_category,
    register_trust_zone,
)
from threatcode.parsers import detect_and_parse

FIXTURES = Path(__file__).parent.parent / "fixtures"

# The resource type tables as they were in one module (ir/nodes.py at 0a3b0c3),
# before they were split into per-family catalog modules. The parity tests below
# hold the split to these literal values.
LEGACY_CATEGORIES: dict[str, str] = {
    "aws_instance": "compute",
    "aws_launch_template": "compute",
    "aws_autoscaling_group": "compute",
    "aws_ecs": "container",
    "aws_eks": "container",
    "aws_lambda": "serverless",
    "aws_s3": "storage",
    "aws_ebs": "storage",
    "aws_dynamodb": "database",
    "aws_rds": "database",
    "aws_db": "database",
    "aws_elasticache": "database",
    "aws_vpc": "network",
    "aws_subnet": "network",
    "aws_security_group": "network",
    "aws_lb": "network",
    "aws_alb": "network",
    "aws_nlb": "network",
    "aws_route": "network",
    "aws_internet_gateway": "network",
    "aws_nat_gateway": "network",
    "aws_eip": "network",
    "aws_iam": "iam",
    "aws_cloudfront": "cdn",
    "aws_route53": "dns",
    "aws_cloudwatch": "monitoring",
    "aws_sns": "messaging",
    "aws_sqs": "messaging",
    "azurerm_virtual_machine": "compute",
    "azurerm_linux_virtual_machine": "compute",
    "azurerm_windows_virtual_machine": "compute",
    "azurerm_storage": "storage",
    "azurerm_virtual_network": "network",
    "azurerm_subnet": "network",
    "azurerm_network_security_group": "network",
    "azurerm_sql": "database",
    "azurerm_cosmosdb": "database",
    "azurerm_function_app": "serverless",
    "azurerm_kubernetes_cluster": "container",
    "azurerm_network_security_rule": "network",
    "azurerm_sql_server": "database",
    "azurerm_sql_database": "database",
    "google_compute_instance": "compute",
    "google_storage_bucket": "storage",
    "google_sql_database": "database",
    "google_cloudfunctions": "serverless",
    "google_compute_network": "network",
    "google_compute_firewall": "network",
    "google_container_cluster": "container",
    "google_project_iam_member": "iam",
    "google_service_account_key": "iam",
    "google_storage_bucket_iam_member": "iam",
    "dockerfile_image": "container",
    "dockerfile_from": "container",
    "dockerfile_run": "compute",
    "dockerfile_expose": "network",
    "dockerfile_env": "container",
    "dockerfile_arg": "container",
    "dockerfile_copy": "storage",
    "dockerfile_add": "storage",
    "dockerfile_user": "iam",
    "dockerfile_healthcheck": "monitoring",
    "dockerfile_workdir": "container",
    "dockerfile_entrypoint": "container",
    "dockerfile_cmd": "container",
    "dockerfile_volume": "storage",
    "kubernetes_deployment": "container",
    "kubernetes_daemon_set": "container",
    "kubernetes_stateful_set": "container",
    "kubernetes_replica_set": "container",
    "kubernetes_pod": "container",
    "kubernetes_job": "container",
    "kubernetes_cron_job": "container",
    "kubernetes_service": "network",
    "kubernetes_ingress": "network",
    "kubernetes_config_map": "storage",
    "kubernetes_secret": "storage",
    "kubernetes_network_policy": "network",
    "kubernetes_service_account": "iam",
    "kubernetes_role": "iam",
    "kubernetes_cluster_role": "iam",
    "kubernetes_role_binding": "iam",
    "kubernetes_cluster_role_binding": "iam",
    "kubernetes_namespace": "container",
    "kubernetes_pvc": "storage",
    "mcp_server": "compute",
    "dependency_npm": "unknown",
    "dependency_pypi": "unknown",
    "dependency_go": "unknown",
    "dependency_crates.io": "unknown",
    "dependency_rubygems": "unknown",
    "dependency_packagist": "unknown",
}

LEGACY_ZONES: dict[str, str] = {
    "aws_internet_gateway": "internet",
    "aws_cloudfront": "dmz",
    "aws_lb": "dmz",
    "aws_alb": "dmz",
    "aws_nlb": "dmz",
    "aws_lambda": "private",
    "aws_ecs": "private",
    "aws_instance": "private",
    "aws_rds": "data",
    "aws_dynamodb": "data",
    "aws_s3": "data",
    "aws_elasticache": "data",
    "aws_iam": "management",
    "aws_cloudwatch": "management",
    "azurerm_kubernetes_cluster": "private",
    "azurerm_network_security_rule": "dmz",
    "azurerm_sql_server": "data",
    "azurerm_sql_database": "data",
    "google_container_cluster": "private",
    "google_project_iam_member": "management",
    "google_service_account_key": "management",
    "dockerfile_expose": "dmz",
    "dockerfile_image": "private",
    "dockerfile_user": "management",
    "kubernetes_ingress": "dmz",
    "kubernetes_service": "dmz",
    "kubernetes_deployment": "private",
    "kubernetes_pod": "private",
    "kubernetes_secret": "data",
    "kubernetes_config_map": "data",
    "kubernetes_service_account": "management",
    "kubernetes_role": "management",
    "kubernetes_cluster_role": "management",
    "kubernetes_network_policy": "private",
    "mcp_server": "private",
}


def _legacy_categorize(resource_type: str) -> str:
    if resource_type in LEGACY_CATEGORIES:
        return LEGACY_CATEGORIES[resource_type]
    for prefix, category in sorted(LEGACY_CATEGORIES.items(), key=lambda x: -len(x[0])):
        if resource_type.startswith(prefix):
            return category
    return "unknown"


def _legacy_zone(resource_type: str, properties: dict[str, Any]) -> str:
    if properties.get("map_public_ip_on_launch") or properties.get("associate_public_ip_address"):
        return "dmz"
    if properties.get("publicly_accessible"):
        return "dmz"
    if (
        resource_type == "mcp_server"
        and properties.get("is_remote")
        and not properties.get("is_loopback")
    ):
        return "internet"
    for prefix, zone in sorted(LEGACY_ZONES.items(), key=lambda x: -len(x[0])):
        if resource_type.startswith(prefix):
            return zone
    return "private"


def _fixture_resources() -> list[tuple[str, dict[str, Any]]]:
    """Every (resource type, properties) the fixture corpus parses to."""
    found: list[tuple[str, dict[str, Any]]] = []
    for path in sorted(FIXTURES.rglob("*")):
        if not path.is_file() or "golden" in path.parts or "secrets" in path.parts:
            continue
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                parsed = detect_and_parse(path)
        except Exception:  # noqa: BLE001 - not every fixture is a parseable input
            continue
        found.extend((r.resource_type, r.properties) for r in parsed.resources)
    return found


class TestCatalogParity:
    """Splitting the tables into family modules must not change any result."""

    def test_aggregate_tables_equal_the_legacy_tables(self) -> None:
        assert {k: v.value for k, v in catalog.CATEGORY_MAP.items()} == LEGACY_CATEGORIES
        assert {k: v.value for k, v in catalog.TRUST_ZONE_MAP.items()} == LEGACY_ZONES

    def test_nodes_reexports_the_catalog_tables_themselves(self) -> None:
        # Tests and plugins mutate these dicts, so they must be the same objects
        assert CATEGORY_MAP is catalog.CATEGORY_MAP
        assert TRUST_ZONE_MAP is catalog.TRUST_ZONE_MAP

    @pytest.mark.parametrize("resource_type", sorted(LEGACY_CATEGORIES))
    def test_every_legacy_category_entry_resolves_the_same(self, resource_type: str) -> None:
        legacy = LEGACY_CATEGORIES[resource_type]
        assert categorize_resource(resource_type).value == legacy
        # ... and so does a longer type that matches it as a prefix
        assert categorize_resource(resource_type + "_extra").value == _legacy_categorize(
            resource_type + "_extra"
        )

    @pytest.mark.parametrize("resource_type", sorted(LEGACY_ZONES))
    def test_every_legacy_zone_entry_resolves_the_same(self, resource_type: str) -> None:
        for candidate in (resource_type, resource_type + "_extra"):
            assert infer_trust_zone(candidate, {}).value == _legacy_zone(candidate, {})

    @pytest.mark.parametrize(
        "properties",
        [
            {},
            {"map_public_ip_on_launch": True},
            {"associate_public_ip_address": True},
            {"publicly_accessible": True},
            {"is_remote": True},
            {"is_remote": True, "is_loopback": True},
            {"is_remote": True, "is_loopback": False},
        ],
    )
    @pytest.mark.parametrize(
        "resource_type",
        [
            "aws_instance",
            "azurerm_sql_server",
            "google_compute_instance",
            "mcp_server",
            "x_unknown",
        ],
    )
    def test_property_heuristics_apply_to_every_type_as_before(
        self, resource_type: str, properties: dict[str, Any]
    ) -> None:
        assert infer_trust_zone(resource_type, properties).value == _legacy_zone(
            resource_type, properties
        )

    def test_every_type_in_the_fixture_corpus_resolves_the_same(self) -> None:
        resources = _fixture_resources()
        assert len({rtype for rtype, _ in resources}) > 40, "the fixture corpus did not parse"
        for rtype, props in resources:
            assert categorize_resource(rtype).value == _legacy_categorize(rtype), rtype
            assert infer_trust_zone(rtype, props).value == _legacy_zone(rtype, props), rtype

    def test_unknown_type_falls_back_as_before(self) -> None:
        assert categorize_resource("nothing_like_it") == NodeCategory.UNKNOWN
        assert infer_trust_zone("nothing_like_it", {}) == TrustZone.PRIVATE


class TestFamilies:
    def test_family_tables_do_not_overlap(self) -> None:
        seen: dict[str, str] = {}
        for family in catalog.FAMILIES:
            for key in (*family.CATEGORIES, *family.ZONES):
                owner = seen.setdefault(key, family.__name__)
                assert owner == family.__name__, f"{key} is in {owner} and {family.__name__}"

    def test_every_family_exports_both_tables(self) -> None:
        for family in catalog.FAMILIES:
            assert isinstance(family.CATEGORIES, dict), family.__name__
            assert isinstance(family.ZONES, dict), family.__name__

    def test_every_zone_prefix_has_a_category(self) -> None:
        # A zone entry for a type the catalog cannot categorize would be dead data
        for family in catalog.FAMILIES:
            for key in family.ZONES:
                assert categorize_resource(key) != NodeCategory.UNKNOWN, key


class TestRegisterCategory:
    def test_register_and_categorize(self) -> None:
        register_category("k8s_deployment", NodeCategory.CONTAINER)
        try:
            assert categorize_resource("k8s_deployment") == NodeCategory.CONTAINER
            assert categorize_resource("k8s_deployment_v1") == NodeCategory.CONTAINER
        finally:
            CATEGORY_MAP.pop("k8s_deployment", None)
            _rebuild_category_prefixes()
        assert categorize_resource("k8s_deployment") == NodeCategory.UNKNOWN

    def test_registered_entry_does_not_leak_into_family_tables(self) -> None:
        register_category("k8s_deployment", NodeCategory.CONTAINER)
        try:
            assert all("k8s_deployment" not in f.CATEGORIES for f in catalog.FAMILIES)
        finally:
            CATEGORY_MAP.pop("k8s_deployment", None)
            _rebuild_category_prefixes()

    def test_longer_registered_prefix_beats_a_family_entry(self) -> None:
        register_category("aws_s3_special", NodeCategory.NETWORK)
        try:
            assert categorize_resource("aws_s3_special_thing") == NodeCategory.NETWORK
            assert categorize_resource("aws_s3_bucket") == NodeCategory.STORAGE
        finally:
            CATEGORY_MAP.pop("aws_s3_special", None)
            _rebuild_category_prefixes()


class TestRegisterTrustZone:
    def test_register_and_infer(self) -> None:
        register_trust_zone("k8s_ingress", TrustZone.DMZ)
        try:
            zone = infer_trust_zone("k8s_ingress_controller", {})
            assert zone == TrustZone.DMZ
        finally:
            TRUST_ZONE_MAP.pop("k8s_ingress", None)
            _rebuild_trust_zone_prefixes()
        assert infer_trust_zone("k8s_ingress_controller", {}) == TrustZone.PRIVATE


class TestInfraNode:
    def _node(self, resource_type: str = "aws_s3_bucket", **kwargs: Any) -> InfraNode:
        return InfraNode(
            id="test",
            resource_type=resource_type,
            name="test",
            category=NodeCategory.STORAGE,
            trust_zone=TrustZone.DATA,
            **kwargs,
        )

    def test_stride_element(self) -> None:
        assert self._node().stride_element == "data_store"

    def test_new_fields_default_to_unknown_or_unset(self) -> None:
        node = self._node()
        assert node.source_file == ""
        assert node.start_line is None
        assert node.end_line is None
        assert node.mode == "managed"
        assert node.exposure == "unknown"

    def test_new_fields_can_be_set(self) -> None:
        node = self._node(
            source_file="infra/main.tf",
            start_line=4,
            end_line=9,
            mode="data",
            exposure="internet",
        )
        assert (node.source_file, node.start_line, node.end_line) == ("infra/main.tf", 4, 9)
        assert (node.mode, node.exposure) == ("data", "internet")

    @pytest.mark.parametrize(
        "resource_type",
        [
            "aws_vpc",
            "aws_subnet",
            "azurerm_virtual_network",
            "azurerm_subnet",
            "google_compute_network",
            "google_compute_subnetwork",
            "kubernetes_namespace",
        ],
    )
    def test_containers_are_containers(self, resource_type: str) -> None:
        assert self._node(resource_type).is_container is True

    @pytest.mark.parametrize(
        "resource_type",
        [
            "aws_instance",
            "aws_s3_bucket",
            "aws_security_group",
            "aws_route_table",
            "aws_vpc_endpoint",
            "aws_subnet_group",
            "kubernetes_deployment",
            "mcp_server",
        ],
    )
    def test_other_types_are_not_containers(self, resource_type: str) -> None:
        # Exact types only: aws_vpc_endpoint is not a VPC
        assert self._node(resource_type).is_container is False

    def test_container_types_are_exactly_the_specified_set(self) -> None:
        assert CONTAINER_TYPES == {
            "aws_vpc",
            "aws_subnet",
            "azurerm_virtual_network",
            "azurerm_subnet",
            "google_compute_network",
            "google_compute_subnetwork",
            "kubernetes_namespace",
        }
