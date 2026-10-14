"""Google Cloud resource categories and trust zones.

A type without a `ZONES` entry gets the default zone of its category, so every database, bucket and
secret below is a DATA node without an entry of its own.
"""

from __future__ import annotations

from typing import Any

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    # Compute and serverless
    "google_compute_instance": NodeCategory.COMPUTE,
    "google_cloudfunctions": NodeCategory.SERVERLESS,
    "google_cloudfunctions2": NodeCategory.SERVERLESS,
    "google_cloud_run": NodeCategory.SERVERLESS,
    "google_dataproc": NodeCategory.COMPUTE,
    "google_app_engine": NodeCategory.SERVERLESS,
    # Containers
    "google_container": NodeCategory.CONTAINER,
    "google_artifact_registry": NodeCategory.CONTAINER,
    # Data stores
    "google_storage": NodeCategory.STORAGE,
    "google_filestore": NodeCategory.STORAGE,
    "google_compute_disk": NodeCategory.STORAGE,
    "google_compute_snapshot": NodeCategory.STORAGE,
    "google_sql": NodeCategory.DATABASE,
    "google_sql_database": NodeCategory.DATABASE,
    "google_bigquery": NodeCategory.DATABASE,
    "google_spanner": NodeCategory.DATABASE,
    "google_redis": NodeCategory.DATABASE,
    "google_memcache": NodeCategory.DATABASE,
    "google_bigtable": NodeCategory.DATABASE,
    "google_firestore": NodeCategory.DATABASE,
    "google_alloydb": NodeCategory.DATABASE,
    # Secret and key material
    "google_kms": NodeCategory.SECRET,
    "google_secret_manager": NodeCategory.SECRET,
    # Networks
    "google_compute_network": NodeCategory.NETWORK,
    "google_compute_subnetwork": NodeCategory.NETWORK,
    "google_compute_firewall": NodeCategory.NETWORK,
    "google_compute_forwarding_rule": NodeCategory.NETWORK,
    "google_compute_global_forwarding_rule": NodeCategory.NETWORK,
    "google_compute_backend_service": NodeCategory.NETWORK,
    "google_compute_region_backend_service": NodeCategory.NETWORK,
    "google_compute_url_map": NodeCategory.NETWORK,
    "google_compute_target": NodeCategory.NETWORK,
    "google_compute_router": NodeCategory.NETWORK,
    "google_compute_address": NodeCategory.NETWORK,
    "google_compute_global_address": NodeCategory.NETWORK,
    "google_compute_vpn": NodeCategory.NETWORK,
    "google_compute_security_policy": NodeCategory.NETWORK,
    "google_compute_ssl": NodeCategory.NETWORK,
    "google_vpc_access_connector": NodeCategory.NETWORK,
    # Identity
    "google_project_iam_member": NodeCategory.IAM,
    "google_project_iam": NodeCategory.IAM,
    "google_service_account": NodeCategory.IAM,
    "google_service_account_key": NodeCategory.IAM,
    "google_storage_bucket_iam": NodeCategory.IAM,
    "google_storage_bucket_iam_member": NodeCategory.IAM,
    "google_organization_iam": NodeCategory.IAM,
    "google_org_policy": NodeCategory.IAM,
    "google_folder_iam": NodeCategory.IAM,
    "google_compute_image_iam": NodeCategory.IAM,
    "google_sourcerepo_repository_iam": NodeCategory.IAM,
    # DNS, messaging and monitoring
    "google_dns": NodeCategory.DNS,
    "google_pubsub": NodeCategory.MESSAGING,
    "google_logging": NodeCategory.MONITORING,
    "google_monitoring": NodeCategory.MONITORING,
}

ZONES: dict[str, TrustZone] = {
    "google_container_cluster": TrustZone.PRIVATE,
    "google_project_iam_member": TrustZone.MANAGEMENT,
    "google_service_account_key": TrustZone.MANAGEMENT,
    # Forwarding rules are the public entry of a load balancer; zone_override moves an internal one
    "google_compute_forwarding_rule": TrustZone.DMZ,
    "google_compute_global_forwarding_rule": TrustZone.DMZ,
}

_FORWARDING_RULES = frozenset(
    {"google_compute_forwarding_rule", "google_compute_global_forwarding_rule"}
)


def zone_override(resource_type: str, properties: dict[str, Any]) -> TrustZone | None:
    """A forwarding rule with an INTERNAL load balancing scheme is private, else None."""
    if resource_type in _FORWARDING_RULES:
        scheme = properties.get("load_balancing_scheme")
        if isinstance(scheme, str) and scheme.strip().upper().startswith("INTERNAL"):
            return TrustZone.PRIVATE
    return None
