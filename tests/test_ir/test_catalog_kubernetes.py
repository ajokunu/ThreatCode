"""Tests for the Kubernetes catalog family."""

from __future__ import annotations

import pytest

from threatcode.ir.catalog import kubernetes
from threatcode.ir.nodes import NodeCategory, TrustZone, categorize_resource, infer_trust_zone

CASES = [
    ("kubernetes_deployment", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("kubernetes_pod", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("kubernetes_daemon_set", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("kubernetes_stateful_set", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("kubernetes_job", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("kubernetes_cron_job", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("kubernetes_namespace", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    # With no properties a Service and an Ingress keep their static zone; the parser always
    # supplies service_type and has_rules, which TestZoneOverride covers
    ("kubernetes_service", NodeCategory.NETWORK, TrustZone.DMZ),
    ("kubernetes_ingress", NodeCategory.NETWORK, TrustZone.DMZ),
    ("kubernetes_network_policy", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("kubernetes_secret", NodeCategory.STORAGE, TrustZone.DATA),
    ("kubernetes_config_map", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("kubernetes_pvc", NodeCategory.STORAGE, TrustZone.DATA),
    ("kubernetes_service_account", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("kubernetes_role", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("kubernetes_cluster_role", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("kubernetes_role_binding", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("kubernetes_cluster_role_binding", NodeCategory.IAM, TrustZone.MANAGEMENT),
]


class TestKubernetesCatalog:
    @pytest.mark.parametrize(("rtype", "category", "zone"), CASES)
    def test_type_resolves_to_the_expected_category_and_zone(
        self, rtype: str, category: NodeCategory, zone: TrustZone
    ) -> None:
        assert categorize_resource(rtype) == category
        assert infer_trust_zone(rtype, {}) == zone

    def test_family_only_holds_kubernetes_types(self) -> None:
        keys = [*kubernetes.CATEGORIES, *kubernetes.ZONES]
        assert keys
        assert all(key.startswith("kubernetes_") for key in keys)

    def test_role_binding_is_not_swallowed_by_the_shorter_role_prefix(self) -> None:
        # Both are IAM, but longest-prefix lookup must find the binding entry itself
        assert "kubernetes_role_binding" in kubernetes.CATEGORIES
        assert "kubernetes_role" in kubernetes.CATEGORIES
        assert categorize_resource("kubernetes_role_binding") == NodeCategory.IAM

    def test_secret_is_data_but_a_deployment_is_not(self) -> None:
        assert infer_trust_zone("kubernetes_secret", {}) == TrustZone.DATA
        assert infer_trust_zone("kubernetes_deployment", {}) != TrustZone.DATA

    def test_public_flag_moves_a_workload_to_the_dmz(self) -> None:
        props = {"associate_public_ip_address": True}
        assert infer_trust_zone("kubernetes_pod", props) == TrustZone.DMZ

    def test_a_config_map_is_private_and_only_a_secret_is_data(self) -> None:
        assert infer_trust_zone("kubernetes_config_map", {}) == TrustZone.PRIVATE
        assert infer_trust_zone("kubernetes_secret", {}) == TrustZone.DATA

    def test_every_entry_resolves_through_the_aggregate_to_its_own_value(self) -> None:
        for key, category in kubernetes.CATEGORIES.items():
            assert categorize_resource(key) == category
        for key, zone in kubernetes.ZONES.items():
            assert infer_trust_zone(key, {}) == zone


class TestZoneOverride:
    @pytest.mark.parametrize(
        ("service_type", "zone"),
        [
            ("LoadBalancer", TrustZone.DMZ),
            ("NodePort", TrustZone.DMZ),
            ("ExternalName", TrustZone.INTERNET),
            ("ClusterIP", TrustZone.PRIVATE),
            ("loadbalancer", TrustZone.DMZ),
            ("Headless", TrustZone.PRIVATE),
        ],
    )
    def test_a_service_is_zoned_by_its_type(self, service_type: str, zone: TrustZone) -> None:
        assert infer_trust_zone("kubernetes_service", {"service_type": service_type}) == zone

    def test_a_service_without_a_type_keeps_the_static_zone(self) -> None:
        assert kubernetes.zone_override("kubernetes_service", {}) is None
        assert kubernetes.zone_override("kubernetes_service", {"service_type": None}) is None
        assert infer_trust_zone("kubernetes_service", {}) == TrustZone.DMZ

    def test_an_ingress_without_rules_is_private(self) -> None:
        assert infer_trust_zone("kubernetes_ingress", {"has_rules": False}) == TrustZone.PRIVATE

    def test_an_ingress_with_rules_is_in_the_dmz(self) -> None:
        assert infer_trust_zone("kubernetes_ingress", {"has_rules": True}) == TrustZone.DMZ

    def test_the_override_only_looks_at_its_own_types(self) -> None:
        assert kubernetes.zone_override("kubernetes_service_account", {"service_type": "x"}) is None
        assert kubernetes.zone_override("kubernetes_pod", {"has_rules": False}) is None
        assert kubernetes.zone_override("aws_lb", {"service_type": "ClusterIP"}) is None

    def test_a_public_ip_flag_still_wins_over_a_cluster_ip_service(self) -> None:
        zone = infer_trust_zone(
            "kubernetes_service", {"service_type": "ClusterIP", "associate_public_ip_address": True}
        )
        assert zone == TrustZone.DMZ
