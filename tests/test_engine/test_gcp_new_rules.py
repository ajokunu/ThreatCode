"""Tests for new GCP security rules."""

from __future__ import annotations

import pytest

from threatcode.engine.rules.loader import load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule


@pytest.fixture
def all_rules():
    return load_all_rules()


@pytest.fixture
def gcp_new_rule_ids():
    return {
        # Cloud SQL
        "CLOUDSQL_NO_SSL",
        "CLOUDSQL_PUBLIC_IP",
        "CLOUDSQL_NO_BACKUP",
        "CLOUDSQL_NO_ENCRYPTION",
        "CLOUDSQL_NO_MAINTENANCE_WINDOW",
        # Cloud Functions
        "GCFUNC_PUBLIC_INGRESS",
        "GCFUNC_NO_VPC_CONNECTOR",
        "GCFUNC_HTTP_NO_AUTH",
        "GCFUNC_NO_MAX_INSTANCES",
        # BigQuery
        "BQ_PUBLIC_ACCESS",
        "BQ_NO_ENCRYPTION",
        "BQ_NO_ACCESS_POLICY",
        "BQ_NO_LOCATION",
        # Pub/Sub
        "PUBSUB_NO_ENCRYPTION",
        "PUBSUB_NO_DEAD_LETTER",
        "PUBSUB_NO_RETENTION",
        # Cloud Run
        "CLOUDRUN_UNAUTHENTICATED",
        "CLOUDRUN_NO_VPC_CONNECTOR",
        "CLOUDRUN_NO_CPU_LIMIT",
        "CLOUDRUN_NO_MAX_INSTANCES",
    }


class TestGcpNewRulesExist:
    def test_all_new_rules_loaded(self, all_rules, gcp_new_rule_ids) -> None:
        loaded_ids = {r.id for r in all_rules}
        for rule_id in gcp_new_rule_ids:
            assert rule_id in loaded_ids, f"Rule {rule_id} not found"


class TestGcpNewRulesFire:
    def test_cloudsql_public_ip_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "CLOUDSQL_PUBLIC_IP")
        bad_props = {"settings": {"ip_configuration": {"ipv4_enabled": True}}}
        assert evaluate_rule(rule.condition, bad_props)

    def test_cloudsql_public_ip_passes(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "CLOUDSQL_PUBLIC_IP")
        good_props = {"settings": {"ip_configuration": {"ipv4_enabled": False}}}
        assert not evaluate_rule(rule.condition, good_props)

    def test_bq_public_access_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "BQ_PUBLIC_ACCESS")
        bad_props = {"has_public_access": True}
        assert evaluate_rule(rule.condition, bad_props)

    def test_cloudrun_unauthenticated_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "CLOUDRUN_UNAUTHENTICATED")
        bad_props = {"has_allow_unauthenticated": True}
        assert evaluate_rule(rule.condition, bad_props)

    def test_pubsub_no_encryption_fires(self, all_rules) -> None:
        rule = next(r for r in all_rules if r.id == "PUBSUB_NO_ENCRYPTION")
        bad_props = {"name": "test-topic"}
        assert evaluate_rule(rule.condition, bad_props)
