"""Tests for threatcode.ir.nodes."""

from __future__ import annotations

from threatcode.ir.nodes import (
    CATEGORY_MAP,
    TRUST_ZONE_MAP,
    InfraNode,
    NodeCategory,
    TrustZone,
    categorize_resource,
    infer_trust_zone,
    register_category,
    register_trust_zone,
)


class TestCategorizeResource:
    def test_exact_match(self) -> None:
        assert categorize_resource("aws_s3") == NodeCategory.STORAGE

    def test_prefix_match(self) -> None:
        assert categorize_resource("aws_s3_bucket") == NodeCategory.STORAGE

    def test_unknown_type(self) -> None:
        assert categorize_resource("unknown_thing") == NodeCategory.UNKNOWN

    def test_azure_compute(self) -> None:
        assert categorize_resource("azurerm_virtual_machine") == NodeCategory.COMPUTE

    def test_gcp_storage(self) -> None:
        assert categorize_resource("google_storage_bucket") == NodeCategory.STORAGE

    def test_longest_prefix_wins(self) -> None:
        # aws_security_group should match NETWORK, not just aws_s*
        assert categorize_resource("aws_security_group_rule") == NodeCategory.NETWORK


class TestInferTrustZone:
    def test_public_ip_goes_to_dmz(self) -> None:
        props = {"associate_public_ip_address": True}
        assert infer_trust_zone("aws_instance", props) == TrustZone.DMZ

    def test_publicly_accessible_rds(self) -> None:
        assert infer_trust_zone("aws_rds_instance", {"publicly_accessible": True}) == TrustZone.DMZ

    def test_s3_goes_to_data(self) -> None:
        assert infer_trust_zone("aws_s3_bucket", {}) == TrustZone.DATA

    def test_iam_goes_to_management(self) -> None:
        assert infer_trust_zone("aws_iam_role", {}) == TrustZone.MANAGEMENT

    def test_unknown_defaults_to_private(self) -> None:
        assert infer_trust_zone("unknown_thing", {}) == TrustZone.PRIVATE


class TestRegisterCategory:
    def test_register_and_categorize(self) -> None:
        register_category("k8s_deployment", NodeCategory.CONTAINER)
        assert categorize_resource("k8s_deployment") == NodeCategory.CONTAINER
        assert categorize_resource("k8s_deployment_v1") == NodeCategory.CONTAINER
        # Clean up
        del CATEGORY_MAP["k8s_deployment"]


class TestRegisterTrustZone:
    def test_register_and_infer(self) -> None:
        register_trust_zone("k8s_ingress", TrustZone.DMZ)
        zone = infer_trust_zone("k8s_ingress_controller", {})
        assert zone == TrustZone.DMZ
        # Clean up
        del TRUST_ZONE_MAP["k8s_ingress"]


class TestInfraNode:
    def test_stride_element(self) -> None:
        node = InfraNode(
            id="test",
            resource_type="aws_s3_bucket",
            name="test",
            category=NodeCategory.STORAGE,
            trust_zone=TrustZone.DATA,
        )
        assert node.stride_element == "data_store"
