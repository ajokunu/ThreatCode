"""Google Cloud resource categories and trust zones."""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "google_compute_instance": NodeCategory.COMPUTE,
    "google_storage_bucket": NodeCategory.STORAGE,
    "google_sql_database": NodeCategory.DATABASE,
    "google_cloudfunctions": NodeCategory.SERVERLESS,
    "google_compute_network": NodeCategory.NETWORK,
    "google_compute_firewall": NodeCategory.NETWORK,
    "google_container_cluster": NodeCategory.CONTAINER,
    "google_project_iam_member": NodeCategory.IAM,
    "google_service_account_key": NodeCategory.IAM,
    "google_storage_bucket_iam_member": NodeCategory.IAM,
}

ZONES: dict[str, TrustZone] = {
    "google_container_cluster": TrustZone.PRIVATE,
    "google_project_iam_member": TrustZone.MANAGEMENT,
    "google_service_account_key": TrustZone.MANAGEMENT,
}
