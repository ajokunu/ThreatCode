"""Kubernetes resource categories and trust zones."""

from __future__ import annotations

from typing import Any

from threatcode.ir.catalog.types import NodeCategory, TrustZone
from threatcode.values import is_unknown

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
    # A Secret holds secret material, so it is a secret store and not plain storage
    "kubernetes_secret": NodeCategory.SECRET,
    "kubernetes_network_policy": NodeCategory.NETWORK,
    "kubernetes_service_account": NodeCategory.IAM,
    "kubernetes_role": NodeCategory.IAM,
    "kubernetes_cluster_role": NodeCategory.IAM,
    "kubernetes_role_binding": NodeCategory.IAM,
    "kubernetes_cluster_role_binding": NodeCategory.IAM,
    "kubernetes_namespace": NodeCategory.CONTAINER,
    "kubernetes_pvc": NodeCategory.STORAGE,
    "kubernetes_persistent_volume": NodeCategory.STORAGE,
}

# The static zone of each type. A Service and an Ingress start in the DMZ and zone_override
# moves them when their properties say they are not reachable from outside the cluster.
# A ConfigMap holds configuration, not secrets, so it is private; the Secret is the data.
ZONES: dict[str, TrustZone] = {
    "kubernetes_ingress": TrustZone.DMZ,
    "kubernetes_service": TrustZone.DMZ,
    "kubernetes_deployment": TrustZone.PRIVATE,
    "kubernetes_pod": TrustZone.PRIVATE,
    "kubernetes_secret": TrustZone.DATA,
    "kubernetes_pvc": TrustZone.DATA,
    "kubernetes_persistent_volume": TrustZone.DATA,
    "kubernetes_config_map": TrustZone.PRIVATE,
    "kubernetes_service_account": TrustZone.MANAGEMENT,
    "kubernetes_role": TrustZone.MANAGEMENT,
    "kubernetes_cluster_role": TrustZone.MANAGEMENT,
    "kubernetes_network_policy": TrustZone.PRIVATE,
}

_EXPOSED_SERVICE_TYPES = frozenset({"loadbalancer", "nodeport"})


def zone_override(resource_type: str, properties: dict[str, Any]) -> TrustZone | None:
    """The zone a Service or an Ingress gets from its own properties, else None.

    A Service is exposed by its type: LoadBalancer and NodePort face the network (DMZ),
    ExternalName names something outside the cluster (INTERNET) and ClusterIP stays inside
    it (PRIVATE). An Ingress with no rule and no default backend routes nothing, so it is
    PRIVATE. A node that carries no ``service_type`` or ``has_rules``, or whose ``service_type``
    is not known, keeps the static zone.
    """
    if resource_type == "kubernetes_service":
        service_type = properties.get("service_type")
        # A type the scan cannot read keeps the static zone: an unresolved value selects nothing
        if not isinstance(service_type, str) or is_unknown(service_type):
            return None
        normalized = service_type.strip().lower()
        if normalized in _EXPOSED_SERVICE_TYPES:
            return TrustZone.DMZ
        if normalized == "externalname":
            return TrustZone.INTERNET
        return TrustZone.PRIVATE
    if resource_type == "kubernetes_ingress" and properties.get("has_rules") is False:
        return TrustZone.PRIVATE
    return None
