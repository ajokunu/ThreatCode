"""Kubernetes resource categories and trust zones."""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "kubernetes_deployment": NodeCategory.CONTAINER,
    "kubernetes_daemon_set": NodeCategory.CONTAINER,
    "kubernetes_stateful_set": NodeCategory.CONTAINER,
    "kubernetes_replica_set": NodeCategory.CONTAINER,
    "kubernetes_pod": NodeCategory.CONTAINER,
    "kubernetes_job": NodeCategory.CONTAINER,
    "kubernetes_cron_job": NodeCategory.CONTAINER,
    "kubernetes_service": NodeCategory.NETWORK,
    "kubernetes_ingress": NodeCategory.NETWORK,
    "kubernetes_config_map": NodeCategory.STORAGE,
    "kubernetes_secret": NodeCategory.STORAGE,
    "kubernetes_network_policy": NodeCategory.NETWORK,
    "kubernetes_service_account": NodeCategory.IAM,
    "kubernetes_role": NodeCategory.IAM,
    "kubernetes_cluster_role": NodeCategory.IAM,
    "kubernetes_role_binding": NodeCategory.IAM,
    "kubernetes_cluster_role_binding": NodeCategory.IAM,
    "kubernetes_namespace": NodeCategory.CONTAINER,
    "kubernetes_pvc": NodeCategory.STORAGE,
}

ZONES: dict[str, TrustZone] = {
    "kubernetes_ingress": TrustZone.DMZ,
    "kubernetes_service": TrustZone.DMZ,
    "kubernetes_deployment": TrustZone.PRIVATE,
    "kubernetes_pod": TrustZone.PRIVATE,
    "kubernetes_secret": TrustZone.DATA,
    "kubernetes_config_map": TrustZone.DATA,
    "kubernetes_service_account": TrustZone.MANAGEMENT,
    "kubernetes_role": TrustZone.MANAGEMENT,
    "kubernetes_cluster_role": TrustZone.MANAGEMENT,
    "kubernetes_network_policy": TrustZone.PRIVATE,
}
