"""Tests for the AWS, Azure and GCP catalog families."""

from __future__ import annotations

import pytest

from threatcode.ir.catalog import aws, azure, gcp
from threatcode.ir.nodes import NodeCategory, TrustZone, categorize_resource, infer_trust_zone


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

    def test_longer_azure_prefix_beats_shorter(self) -> None:
        # azurerm_sql_server is DATABASE, as is the shorter azurerm_sql
        assert categorize_resource("azurerm_sql_server_firewall") == NodeCategory.DATABASE
        assert categorize_resource("azurerm_storage_account") == NodeCategory.STORAGE


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

    def test_public_ip_heuristic_applies_outside_aws(self) -> None:
        # The property checks are not an AWS rule: they apply to every resource type
        assert infer_trust_zone("azurerm_sql_server", {"publicly_accessible": True}) == (
            TrustZone.DMZ
        )
        assert infer_trust_zone("google_compute_instance", {"associate_public_ip_address": 1}) == (
            TrustZone.DMZ
        )

    def test_false_public_flags_do_not_move_a_resource(self) -> None:
        props = {"publicly_accessible": False, "associate_public_ip_address": False}
        assert infer_trust_zone("aws_instance", props) == TrustZone.PRIVATE


AWS_CASES = [
    # (type, category, zone)
    ("aws_instance", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("aws_lambda_function", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("aws_ecs_service", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("aws_eks_cluster", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("aws_s3_bucket_policy", NodeCategory.STORAGE, TrustZone.DATA),
    ("aws_db_instance", NodeCategory.DATABASE, TrustZone.PRIVATE),
    ("aws_rds_cluster", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_dynamodb_table", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_vpc", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_lb", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_alb_listener", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_internet_gateway", NodeCategory.NETWORK, TrustZone.INTERNET),
    ("aws_cloudfront_distribution", NodeCategory.CDN, TrustZone.DMZ),
    ("aws_route53_record", NodeCategory.DNS, TrustZone.PRIVATE),
    ("aws_cloudwatch_log_group", NodeCategory.MONITORING, TrustZone.MANAGEMENT),
    ("aws_iam_role_policy", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("aws_sns_topic", NodeCategory.MESSAGING, TrustZone.PRIVATE),
    ("aws_sqs_queue", NodeCategory.MESSAGING, TrustZone.PRIVATE),
]
AZURE_CASES = [
    ("azurerm_linux_virtual_machine", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("azurerm_storage_account", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("azurerm_virtual_network", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("azurerm_network_security_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("azurerm_network_security_rule", NodeCategory.NETWORK, TrustZone.DMZ),
    ("azurerm_sql_database", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_cosmosdb_account", NodeCategory.DATABASE, TrustZone.PRIVATE),
    ("azurerm_function_app", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("azurerm_kubernetes_cluster", NodeCategory.CONTAINER, TrustZone.PRIVATE),
]
GCP_CASES = [
    ("google_compute_instance", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("google_storage_bucket", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("google_storage_bucket_iam_member", NodeCategory.IAM, TrustZone.PRIVATE),
    ("google_sql_database_instance", NodeCategory.DATABASE, TrustZone.PRIVATE),
    ("google_cloudfunctions_function", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("google_compute_firewall", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("google_container_cluster", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("google_project_iam_member", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("google_service_account_key", NodeCategory.IAM, TrustZone.MANAGEMENT),
]


class TestFamilyEntries:
    @pytest.mark.parametrize(("rtype", "category", "zone"), AWS_CASES + AZURE_CASES + GCP_CASES)
    def test_type_resolves_to_the_expected_category_and_zone(
        self, rtype: str, category: NodeCategory, zone: TrustZone
    ) -> None:
        assert categorize_resource(rtype) == category
        assert infer_trust_zone(rtype, {}) == zone

    @pytest.mark.parametrize(
        ("family", "prefix"), [(aws, "aws_"), (azure, "azurerm_"), (gcp, "google_")]
    )
    def test_family_only_holds_its_own_prefix(self, family: object, prefix: str) -> None:
        keys = [*family.CATEGORIES, *family.ZONES]  # type: ignore[attr-defined]
        assert keys
        assert all(key.startswith(prefix) for key in keys)

    @pytest.mark.parametrize("family", [aws, azure, gcp])
    def test_cloud_families_have_no_zone_override(self, family: object) -> None:
        assert not hasattr(family, "zone_override")

    @pytest.mark.parametrize("family", [aws, azure, gcp])
    def test_every_entry_resolves_through_the_aggregate_to_its_own_value(
        self, family: object
    ) -> None:
        for key, category in family.CATEGORIES.items():  # type: ignore[attr-defined]
            assert categorize_resource(key) == category
        for key, zone in family.ZONES.items():  # type: ignore[attr-defined]
            assert infer_trust_zone(key, {}) == zone
