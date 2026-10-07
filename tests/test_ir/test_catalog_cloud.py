"""Tests for the AWS, Azure and GCP catalog families and the zone lookup order."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.engine.rules.loader import load_builtin_rules
from threatcode.ir import catalog
from threatcode.ir.catalog import aws, azure, gcp
from threatcode.ir.nodes import (
    CATEGORY_DEFAULT_ZONE,
    DATA_CATEGORIES,
    NodeCategory,
    TrustZone,
    categorize_resource,
    infer_trust_zone,
    tri_state,
)
from threatcode.parsers._cfn_types import CFN_TO_TERRAFORM
from threatcode.values import Unknown


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

    def test_an_exact_network_helper_beats_the_data_store_prefix(self) -> None:
        assert categorize_resource("aws_db_instance") == NodeCategory.DATABASE
        assert categorize_resource("aws_db_subnet_group") == NodeCategory.NETWORK

    def test_the_gcp_bucket_iam_member_beats_the_bucket_prefix(self) -> None:
        assert categorize_resource("google_storage_bucket") == NodeCategory.STORAGE
        assert categorize_resource("google_storage_bucket_iam_member") == NodeCategory.IAM


class TestTriState:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (True, "true"),
            (False, "false"),
            ("true", "true"),
            ("TRUE", "true"),
            ("  True ", "true"),
            ("false", "false"),
            ("False", "false"),
            (1, "true"),
            (0, "false"),
            (None, "false"),
            ("${var.public}", "unknown"),
            ("var.public", "unknown"),
            ("local.public", "unknown"),
            ("data.aws_x.y.public", "unknown"),
            ("module.net.public", "unknown"),
            ("!var.public", "unknown"),
            ("yes", "unknown"),
            ("", "unknown"),
            ("   ", "unknown"),
            (2, "unknown"),
            (1.5, "unknown"),
            ({"Ref": "Public"}, "unknown"),
            ({"Fn::If": ["P", True, False]}, "unknown"),
            ([True], "unknown"),
            (Unknown("var.public"), "unknown"),
            (Unknown(), "unknown"),
        ],
    )
    def test_config_evidence(self, value: Any, expected: str) -> None:
        assert tri_state(value) == expected

    def test_a_missing_value_is_a_fact_in_config_and_a_question_in_a_design(self) -> None:
        assert tri_state(None, "config") == "false"
        assert tri_state(None, "design") == "unknown"

    def test_a_given_value_reads_the_same_in_a_design(self) -> None:
        assert tri_state(True, "design") == "true"
        assert tri_state("false", "design") == "false"
        assert tri_state(Unknown(), "design") == "unknown"


class TestInferTrustZone:
    def test_public_ip_goes_to_dmz(self) -> None:
        props = {"associate_public_ip_address": True}
        assert infer_trust_zone("aws_instance", props) == TrustZone.DMZ

    def test_a_public_subnet_flag_goes_to_dmz(self) -> None:
        assert infer_trust_zone("aws_subnet", {"map_public_ip_on_launch": True}) == TrustZone.DMZ

    def test_a_publicly_accessible_database_stays_in_data(self) -> None:
        # It is exposed, which the exposure analysis records; it is still a data store
        assert infer_trust_zone("aws_db_instance", {"publicly_accessible": True}) == (
            TrustZone.DATA
        )
        assert infer_trust_zone("aws_rds_cluster", {"publicly_accessible": True}) == (
            TrustZone.DATA
        )

    def test_publicly_accessible_moves_a_resource_that_is_not_a_data_store(self) -> None:
        assert infer_trust_zone("aws_instance", {"publicly_accessible": True}) == TrustZone.DMZ

    def test_s3_goes_to_data(self) -> None:
        assert infer_trust_zone("aws_s3_bucket", {}) == TrustZone.DATA

    def test_iam_goes_to_management(self) -> None:
        assert infer_trust_zone("aws_iam_role", {}) == TrustZone.MANAGEMENT

    def test_unknown_defaults_to_private(self) -> None:
        assert infer_trust_zone("unknown_thing", {}) == TrustZone.PRIVATE

    def test_public_ip_heuristic_applies_outside_aws(self) -> None:
        # The address flags are not an AWS rule: they apply to every resource type
        assert infer_trust_zone("google_compute_instance", {"associate_public_ip_address": 1}) == (
            TrustZone.DMZ
        )
        assert infer_trust_zone("azurerm_linux_virtual_machine", {"publicly_accessible": True}) == (
            TrustZone.DMZ
        )

    def test_false_public_flags_do_not_move_a_resource(self) -> None:
        props = {"publicly_accessible": False, "associate_public_ip_address": False}
        assert infer_trust_zone("aws_instance", props) == TrustZone.PRIVATE


class TestUnresolvedFlagsNeverSelectTheDmz:
    FLAGS = ("map_public_ip_on_launch", "associate_public_ip_address", "publicly_accessible")

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize(
        "value",
        [
            "${var.public}",
            "var.public",
            "false",
            "False",
            Unknown("var.public"),
            Unknown(),
            {"Ref": "Public"},
            "!var.public",
            None,
        ],
    )
    def test_an_instance_with_an_unreadable_or_false_flag_stays_private(
        self, flag: str, value: Any
    ) -> None:
        assert infer_trust_zone("aws_instance", {flag: value}) == TrustZone.PRIVATE

    @pytest.mark.parametrize("flag", FLAGS)
    @pytest.mark.parametrize("value", [True, "true", "True", "TRUE"])
    def test_only_a_true_flag_selects_the_dmz(self, flag: str, value: Any) -> None:
        assert infer_trust_zone("aws_instance", {flag: value}) == TrustZone.DMZ

    def test_a_design_node_with_a_missing_flag_is_not_in_the_dmz(self) -> None:
        zone = infer_trust_zone("aws_instance", {}, evidence="design")
        assert zone == TrustZone.PRIVATE


class TestZoneLookupOrder:
    def test_a_property_override_beats_the_explicit_prefix(self) -> None:
        # aws_lb is DMZ by its prefix entry; internal true is a property that decides otherwise
        assert infer_trust_zone("aws_lb", {}) == TrustZone.DMZ
        assert infer_trust_zone("aws_lb", {"internal": True}) == TrustZone.PRIVATE

    def test_the_explicit_prefix_beats_the_category_default(self) -> None:
        # NETWORK defaults to PRIVATE, but the NAT gateway entry says DMZ
        assert categorize_resource("aws_nat_gateway") == NodeCategory.NETWORK
        assert infer_trust_zone("aws_nat_gateway", {}) == TrustZone.DMZ

    def test_the_category_default_decides_when_nothing_else_does(self) -> None:
        # No ZONES entry names aws_redshift_cluster: its DATABASE category puts it in DATA
        assert not any(
            "aws_redshift_cluster".startswith(prefix) for prefix in catalog.TRUST_ZONE_MAP
        )
        assert infer_trust_zone("aws_redshift_cluster", {}) == TrustZone.DATA

    def test_a_passed_category_replaces_the_computed_one(self) -> None:
        assert infer_trust_zone("custom_thing", {}) == TrustZone.PRIVATE
        assert infer_trust_zone("custom_thing", {}, NodeCategory.SECRET) == TrustZone.DATA
        assert infer_trust_zone("custom_thing", {}, NodeCategory.MONITORING) == TrustZone.MANAGEMENT

    def test_the_default_zone_of_each_category(self) -> None:
        assert CATEGORY_DEFAULT_ZONE == {
            NodeCategory.DATABASE: TrustZone.DATA,
            NodeCategory.STORAGE: TrustZone.DATA,
            NodeCategory.SECRET: TrustZone.DATA,
            NodeCategory.IAM: TrustZone.MANAGEMENT,
            NodeCategory.MONITORING: TrustZone.MANAGEMENT,
            NodeCategory.CDN: TrustZone.DMZ,
        }
        for category in NodeCategory:
            if category not in CATEGORY_DEFAULT_ZONE:
                assert infer_trust_zone("custom_thing", {}, category) == TrustZone.PRIVATE

    @pytest.mark.parametrize(
        ("rtype", "category"),
        [
            ("dockerfile_copy", NodeCategory.STORAGE),
            ("dockerfile_user", NodeCategory.IAM),
            ("dockerfile_healthcheck", NodeCategory.MONITORING),
            ("dependency_npm", NodeCategory.UNKNOWN),
        ],
    )
    def test_build_recipes_and_lockfiles_keep_the_private_default(
        self, rtype: str, category: NodeCategory
    ) -> None:
        # Their category would put a COPY in DATA and a USER line in MANAGEMENT
        assert categorize_resource(rtype) == category
        assert infer_trust_zone(rtype, {}) == TrustZone.PRIVATE

    def test_a_declared_prefix_entry_overrides_a_longer_default(self) -> None:
        catalog.register_trust_zone("aws_redshift_special", TrustZone.MANAGEMENT)
        try:
            assert infer_trust_zone("aws_redshift_special_thing", {}) == TrustZone.MANAGEMENT
            assert infer_trust_zone("aws_redshift_cluster", {}) == TrustZone.DATA
        finally:
            catalog.TRUST_ZONE_MAP.pop("aws_redshift_special", None)
            catalog._rebuild_trust_zone_prefixes()


AWS_CASES = [
    # (type, category, zone)
    ("aws_instance", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("aws_launch_template", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("aws_sagemaker_notebook_instance", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("aws_lambda_function", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("aws_lambda_function_url", NodeCategory.API, TrustZone.PRIVATE),
    ("aws_ecs_service", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("aws_eks_cluster", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("aws_ecr_repository", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("aws_s3_bucket", NodeCategory.STORAGE, TrustZone.DATA),
    ("aws_s3_bucket_policy", NodeCategory.STORAGE, TrustZone.DATA),
    ("aws_ebs_volume", NodeCategory.STORAGE, TrustZone.DATA),
    ("aws_efs_file_system", NodeCategory.STORAGE, TrustZone.DATA),
    ("aws_db_instance", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_rds_cluster", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_rds_cluster_instance", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_dynamodb_table", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_elasticache_replication_group", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_redshift_cluster", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_docdb_cluster", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_opensearch_domain", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_elasticsearch_domain", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_msk_cluster", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_kinesis_stream", NodeCategory.DATABASE, TrustZone.DATA),
    ("aws_kms_key", NodeCategory.SECRET, TrustZone.DATA),
    ("aws_secretsmanager_secret", NodeCategory.SECRET, TrustZone.DATA),
    ("aws_ssm_parameter", NodeCategory.SECRET, TrustZone.DATA),
    ("aws_api_gateway_rest_api", NodeCategory.API, TrustZone.DMZ),
    ("aws_apigatewayv2_api", NodeCategory.API, TrustZone.DMZ),
    ("aws_api_gateway_api_key", NodeCategory.SECRET, TrustZone.DATA),
    ("aws_cognito_user_pool", NodeCategory.IAM, TrustZone.DMZ),
    ("aws_wafv2_web_acl", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_vpc", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_vpc_endpoint", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_route_table", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_route_table_association", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_nat_gateway", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_vpn_gateway", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_lb", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_lb_target_group", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_lb_listener", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_alb_listener", NodeCategory.NETWORK, TrustZone.DMZ),
    ("aws_internet_gateway", NodeCategory.NETWORK, TrustZone.INTERNET),
    ("aws_cloudfront_distribution", NodeCategory.CDN, TrustZone.DMZ),
    ("aws_route53_record", NodeCategory.DNS, TrustZone.PRIVATE),
    ("aws_cloudwatch_log_group", NodeCategory.MONITORING, TrustZone.MANAGEMENT),
    ("aws_cloudtrail", NodeCategory.MONITORING, TrustZone.MANAGEMENT),
    ("aws_guardduty_detector", NodeCategory.MONITORING, TrustZone.MANAGEMENT),
    ("aws_config_configuration_recorder", NodeCategory.MONITORING, TrustZone.MANAGEMENT),
    ("aws_iam_role_policy", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("aws_sns_topic", NodeCategory.MESSAGING, TrustZone.PRIVATE),
    ("aws_sqs_queue", NodeCategory.MESSAGING, TrustZone.PRIVATE),
    # Network helpers under a data store prefix are exact NETWORK and PRIVATE entries
    ("aws_db_subnet_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_db_parameter_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_db_option_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_rds_cluster_parameter_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_elasticache_subnet_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("aws_redshift_subnet_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
]
AZURE_CASES = [
    ("azurerm_linux_virtual_machine", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("azurerm_linux_web_app", NodeCategory.COMPUTE, TrustZone.DMZ),
    ("azurerm_windows_web_app", NodeCategory.COMPUTE, TrustZone.DMZ),
    ("azurerm_service_plan", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("azurerm_storage_account", NodeCategory.STORAGE, TrustZone.DATA),
    ("azurerm_virtual_network", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("azurerm_network_security_group", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("azurerm_network_security_rule", NodeCategory.NETWORK, TrustZone.DMZ),
    ("azurerm_public_ip", NodeCategory.NETWORK, TrustZone.DMZ),
    ("azurerm_application_gateway", NodeCategory.NETWORK, TrustZone.DMZ),
    ("azurerm_lb", NodeCategory.NETWORK, TrustZone.DMZ),
    ("azurerm_frontdoor", NodeCategory.CDN, TrustZone.DMZ),
    ("azurerm_sql_database", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_mssql_server", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_mssql_database", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_postgresql_flexible_server", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_mysql_flexible_server", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_cosmosdb_account", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_redis_cache", NodeCategory.DATABASE, TrustZone.DATA),
    ("azurerm_key_vault", NodeCategory.SECRET, TrustZone.DATA),
    ("azurerm_key_vault_secret", NodeCategory.SECRET, TrustZone.DATA),
    ("azurerm_key_vault_access_policy", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("azurerm_container_registry", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("azurerm_function_app", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("azurerm_kubernetes_cluster", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("azurerm_monitor_diagnostic_setting", NodeCategory.MONITORING, TrustZone.MANAGEMENT),
    ("azurerm_role_assignment", NodeCategory.IAM, TrustZone.MANAGEMENT),
]
GCP_CASES = [
    ("google_compute_instance", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("google_storage_bucket", NodeCategory.STORAGE, TrustZone.DATA),
    ("google_storage_bucket_iam_member", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("google_sql_database_instance", NodeCategory.DATABASE, TrustZone.DATA),
    ("google_bigquery_dataset", NodeCategory.DATABASE, TrustZone.DATA),
    ("google_spanner_instance", NodeCategory.DATABASE, TrustZone.DATA),
    ("google_redis_instance", NodeCategory.DATABASE, TrustZone.DATA),
    ("google_kms_crypto_key", NodeCategory.SECRET, TrustZone.DATA),
    ("google_secret_manager_secret", NodeCategory.SECRET, TrustZone.DATA),
    ("google_cloud_run_service", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("google_cloud_run_v2_service", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("google_cloudfunctions_function", NodeCategory.SERVERLESS, TrustZone.PRIVATE),
    ("google_compute_firewall", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("google_compute_subnetwork", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("google_compute_forwarding_rule", NodeCategory.NETWORK, TrustZone.DMZ),
    ("google_compute_global_forwarding_rule", NodeCategory.NETWORK, TrustZone.DMZ),
    ("google_compute_backend_service", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("google_container_cluster", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("google_project_iam_member", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("google_service_account_key", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("google_pubsub_topic", NodeCategory.MESSAGING, TrustZone.PRIVATE),
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
    def test_cloud_families_export_a_zone_override(self, family: object) -> None:
        assert callable(family.zone_override)  # type: ignore[attr-defined]
        # An override must check the type itself: it has no opinion on a foreign type
        assert family.zone_override("kubernetes_pod", {"internal": True}) is None  # type: ignore[attr-defined]

    @pytest.mark.parametrize("family", [aws, azure, gcp])
    def test_every_entry_resolves_through_the_aggregate_to_its_own_value(
        self, family: object
    ) -> None:
        for key, category in family.CATEGORIES.items():  # type: ignore[attr-defined]
            assert categorize_resource(key) == category
        for key, zone in family.ZONES.items():  # type: ignore[attr-defined]
            assert infer_trust_zone(key, {}) == zone

    def test_every_data_store_type_is_in_the_data_zone(self) -> None:
        # The category decides: a database, storage or secret type never lands in PRIVATE
        mismatched = [
            key
            for family in (aws, azure, gcp)
            for key, category in family.CATEGORIES.items()
            if category in DATA_CATEGORIES
            and infer_trust_zone(key, {}) != TrustZone.DATA
            and key not in {"aws_db_subnet_group"}
        ]
        assert mismatched == []


def _rule_types() -> list[str]:
    types: set[str] = set()
    for rule in load_builtin_rules():
        types.update(t.rstrip("*") for t in rule.resource_types)
    return sorted(types)


class TestEveryBuiltinRuleTypeIsCatalogued:
    """The lint: a rule that targets a type must be able to place that type in the graph."""

    def test_the_corpus_has_rule_types(self) -> None:
        assert len(_rule_types()) > 60

    def test_every_rule_type_has_an_explicit_category(self) -> None:
        missing = [t for t in _rule_types() if categorize_resource(t) == NodeCategory.UNKNOWN]
        assert not missing, (
            "These rule resource types have no CATEGORY_MAP prefix; add them to their provider "
            f"family under src/threatcode/ir/catalog/: {missing}"
        )

    def test_every_rule_type_that_holds_data_is_in_the_data_zone(self) -> None:
        wrong = [
            t
            for t in _rule_types()
            if categorize_resource(t) in DATA_CATEGORIES
            and not t.startswith(catalog.PRIVATE_BY_DEFAULT_PREFIXES)
            and infer_trust_zone(t, {}) != TrustZone.DATA
        ]
        assert not wrong, f"data store types outside the DATA zone: {wrong}"

    def test_every_type_the_cloudformation_table_maps_to_is_catalogued(self) -> None:
        # Types that name a deployment unit, a pseudo resource or configuration with no
        # architectural role; each is listed with the reason it has no category
        uncategorized = {
            "aws_cloudformation_stack": "a nested stack is a deployment unit, not a resource",
            "aws_key_pair": "a public key, not a secret store",
            "aws_codedeploy_app": "deployment orchestration with no data or traffic",
        }
        missing = sorted(
            {
                t
                for t in CFN_TO_TERRAFORM.values()
                if categorize_resource(t) == NodeCategory.UNKNOWN and t not in uncategorized
            }
        )
        assert not missing, f"CloudFormation-mapped types with no category: {missing}"

    def test_an_aws_type_the_cloudformation_table_targets_matches_the_terraform_zone(self) -> None:
        # The CloudFormation path produces the Terraform names, so both inputs agree
        for terraform_type in ("aws_db_instance", "aws_db_subnet_group", "aws_kms_key"):
            assert terraform_type in set(CFN_TO_TERRAFORM.values())
        assert infer_trust_zone("aws_db_subnet_group", {}) == TrustZone.PRIVATE
        assert infer_trust_zone("aws_db_instance", {}) == TrustZone.DATA


class TestZoneOverrides:
    @pytest.mark.parametrize("rtype", ["aws_lb", "aws_alb", "aws_nlb", "aws_elb"])
    def test_an_internal_load_balancer_is_private_and_the_default_is_dmz(self, rtype: str) -> None:
        assert infer_trust_zone(rtype, {"internal": True}) == TrustZone.PRIVATE
        assert infer_trust_zone(rtype, {"internal": "true"}) == TrustZone.PRIVATE
        assert infer_trust_zone(rtype, {"internal": False}) == TrustZone.DMZ
        assert infer_trust_zone(rtype, {}) == TrustZone.DMZ

    def test_an_unreadable_internal_flag_keeps_the_type_default(self) -> None:
        for value in (Unknown("var.internal"), "${var.internal}", {"Ref": "Internal"}):
            assert infer_trust_zone("aws_lb", {"internal": value}) == TrustZone.DMZ

    @pytest.mark.parametrize(
        ("types", "zone"),
        [
            ([{"types": ["EDGE"]}], TrustZone.DMZ),
            ([{"types": ["REGIONAL"]}], TrustZone.DMZ),
            ([{"types": ["PRIVATE"]}], TrustZone.PRIVATE),
            ({"types": ["PRIVATE"]}, TrustZone.PRIVATE),
            ([{"types": ["PRIVATE", "REGIONAL"]}], TrustZone.DMZ),
            ([{"types": [Unknown()]}], TrustZone.DMZ),
            (None, TrustZone.DMZ),
        ],
    )
    def test_a_rest_api_is_private_only_when_its_endpoint_type_is_private(
        self, types: Any, zone: TrustZone
    ) -> None:
        props = {} if types is None else {"endpoint_configuration": types}
        assert infer_trust_zone("aws_api_gateway_rest_api", props) == zone

    @pytest.mark.parametrize(
        ("auth", "zone"),
        [
            ("NONE", TrustZone.DMZ),
            ("none", TrustZone.DMZ),
            ("AWS_IAM", TrustZone.PRIVATE),
            (Unknown(), TrustZone.PRIVATE),
            (None, TrustZone.PRIVATE),
        ],
    )
    def test_a_lambda_function_url_is_in_the_dmz_only_without_authorization(
        self, auth: Any, zone: TrustZone
    ) -> None:
        props = {} if auth is None else {"authorization_type": auth}
        assert infer_trust_zone("aws_lambda_function_url", props) == zone

    @pytest.mark.parametrize(
        ("props", "zone"),
        [
            (
                {"direction": "Inbound", "access": "Allow", "source_address_prefix": "*"},
                TrustZone.DMZ,
            ),
            (
                {"direction": "inbound", "access": "allow", "source_address_prefix": "Internet"},
                TrustZone.DMZ,
            ),
            (
                {"direction": "Inbound", "access": "Allow", "source_address_prefix": "0.0.0.0/0"},
                TrustZone.DMZ,
            ),
            (
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefixes": ["10.0.0.0/8", "*"],
                },
                TrustZone.DMZ,
            ),
            (
                {"direction": "Inbound", "access": "Deny", "source_address_prefix": "*"},
                TrustZone.PRIVATE,
            ),
            (
                {"direction": "Outbound", "access": "Allow", "source_address_prefix": "*"},
                TrustZone.PRIVATE,
            ),
            (
                {"direction": "Inbound", "access": "Allow", "source_address_prefix": "10.0.0.0/8"},
                TrustZone.PRIVATE,
            ),
            (
                {
                    "direction": "Inbound",
                    "access": "Allow",
                    "source_address_prefix": "VirtualNetwork",
                },
                TrustZone.PRIVATE,
            ),
            # What the scan cannot read keeps the type default
            ({"direction": Unknown(), "access": "Allow"}, TrustZone.DMZ),
            (
                {"direction": "Inbound", "access": "Allow", "source_address_prefix": Unknown()},
                TrustZone.DMZ,
            ),
            ({}, TrustZone.DMZ),
        ],
    )
    def test_an_azure_rule_is_in_the_dmz_only_for_inbound_allow_from_the_world(
        self, props: dict[str, Any], zone: TrustZone
    ) -> None:
        assert infer_trust_zone("azurerm_network_security_rule", props) == zone

    def test_the_azure_rule_check_ignores_other_azure_types(self) -> None:
        props = {"direction": "Outbound", "access": "Allow", "source_address_prefix": "*"}
        assert azure.zone_override("azurerm_virtual_network", props) is None

    @pytest.mark.parametrize(
        ("scheme", "zone"),
        [
            ("EXTERNAL", TrustZone.DMZ),
            ("EXTERNAL_MANAGED", TrustZone.DMZ),
            ("INTERNAL", TrustZone.PRIVATE),
            ("INTERNAL_MANAGED", TrustZone.PRIVATE),
            (None, TrustZone.DMZ),
        ],
    )
    def test_a_forwarding_rule_follows_its_load_balancing_scheme(
        self, scheme: str | None, zone: TrustZone
    ) -> None:
        props = {} if scheme is None else {"load_balancing_scheme": scheme}
        assert infer_trust_zone("google_compute_forwarding_rule", props) == zone
