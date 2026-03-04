"""Infrastructure graph node types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class NodeCategory(str, Enum):
    COMPUTE = "compute"
    STORAGE = "storage"
    NETWORK = "network"
    DATABASE = "database"
    IAM = "iam"
    SERVERLESS = "serverless"
    CDN = "cdn"
    DNS = "dns"
    MONITORING = "monitoring"
    MESSAGING = "messaging"
    CONTAINER = "container"
    UNKNOWN = "unknown"

    @property
    def stride_element(self) -> str:
        """Map to STRIDE element type."""
        return _CATEGORY_TO_STRIDE.get(self, "process")


class TrustZone(str, Enum):
    INTERNET = "internet"
    DMZ = "dmz"
    PRIVATE = "private"
    DATA = "data"
    MANAGEMENT = "management"


# Map resource type prefixes to categories
CATEGORY_MAP: dict[str, NodeCategory] = {
    # AWS
    "aws_instance": NodeCategory.COMPUTE,
    "aws_launch_template": NodeCategory.COMPUTE,
    "aws_autoscaling_group": NodeCategory.COMPUTE,
    "aws_ecs": NodeCategory.CONTAINER,
    "aws_eks": NodeCategory.CONTAINER,
    "aws_lambda": NodeCategory.SERVERLESS,
    "aws_s3": NodeCategory.STORAGE,
    "aws_ebs": NodeCategory.STORAGE,
    "aws_dynamodb": NodeCategory.DATABASE,
    "aws_rds": NodeCategory.DATABASE,
    "aws_db": NodeCategory.DATABASE,
    "aws_elasticache": NodeCategory.DATABASE,
    "aws_vpc": NodeCategory.NETWORK,
    "aws_subnet": NodeCategory.NETWORK,
    "aws_security_group": NodeCategory.NETWORK,
    "aws_lb": NodeCategory.NETWORK,
    "aws_alb": NodeCategory.NETWORK,
    "aws_nlb": NodeCategory.NETWORK,
    "aws_route": NodeCategory.NETWORK,
    "aws_internet_gateway": NodeCategory.NETWORK,
    "aws_nat_gateway": NodeCategory.NETWORK,
    "aws_eip": NodeCategory.NETWORK,
    "aws_iam": NodeCategory.IAM,
    "aws_cloudfront": NodeCategory.CDN,
    "aws_route53": NodeCategory.DNS,
    "aws_cloudwatch": NodeCategory.MONITORING,
    "aws_sns": NodeCategory.MESSAGING,
    "aws_sqs": NodeCategory.MESSAGING,
    # Azure
    "azurerm_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_linux_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_windows_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_storage": NodeCategory.STORAGE,
    "azurerm_virtual_network": NodeCategory.NETWORK,
    "azurerm_subnet": NodeCategory.NETWORK,
    "azurerm_network_security_group": NodeCategory.NETWORK,
    "azurerm_sql": NodeCategory.DATABASE,
    "azurerm_cosmosdb": NodeCategory.DATABASE,
    "azurerm_function_app": NodeCategory.SERVERLESS,
    "azurerm_kubernetes_cluster": NodeCategory.CONTAINER,
    "azurerm_network_security_rule": NodeCategory.NETWORK,
    "azurerm_sql_server": NodeCategory.DATABASE,
    "azurerm_sql_database": NodeCategory.DATABASE,
    # GCP
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
    # Docker
    "dockerfile_image": NodeCategory.CONTAINER,
    "dockerfile_from": NodeCategory.CONTAINER,
    "dockerfile_run": NodeCategory.COMPUTE,
    "dockerfile_expose": NodeCategory.NETWORK,
    "dockerfile_env": NodeCategory.CONTAINER,
    "dockerfile_arg": NodeCategory.CONTAINER,
    "dockerfile_copy": NodeCategory.STORAGE,
    "dockerfile_add": NodeCategory.STORAGE,
    "dockerfile_user": NodeCategory.IAM,
    "dockerfile_healthcheck": NodeCategory.MONITORING,
    "dockerfile_workdir": NodeCategory.CONTAINER,
    "dockerfile_entrypoint": NodeCategory.CONTAINER,
    "dockerfile_cmd": NodeCategory.CONTAINER,
    "dockerfile_volume": NodeCategory.STORAGE,
    # Kubernetes
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
    # Dependencies
    "dependency_npm": NodeCategory.UNKNOWN,
    "dependency_pypi": NodeCategory.UNKNOWN,
    "dependency_go": NodeCategory.UNKNOWN,
    "dependency_crates.io": NodeCategory.UNKNOWN,
    "dependency_rubygems": NodeCategory.UNKNOWN,
    "dependency_packagist": NodeCategory.UNKNOWN,
}

_CATEGORY_TO_STRIDE: dict[NodeCategory, str] = {
    NodeCategory.COMPUTE: "process",
    NodeCategory.STORAGE: "data_store",
    NodeCategory.NETWORK: "data_flow",
    NodeCategory.DATABASE: "data_store",
    NodeCategory.IAM: "external_entity",
    NodeCategory.SERVERLESS: "process",
    NodeCategory.CDN: "data_flow",
    NodeCategory.DNS: "data_flow",
    NodeCategory.MONITORING: "process",
    NodeCategory.MESSAGING: "data_flow",
    NodeCategory.CONTAINER: "process",
    NodeCategory.UNKNOWN: "process",
}

# Trust zone inference based on resource type
TRUST_ZONE_MAP: dict[str, TrustZone] = {
    "aws_internet_gateway": TrustZone.INTERNET,
    "aws_cloudfront": TrustZone.DMZ,
    "aws_lb": TrustZone.DMZ,
    "aws_alb": TrustZone.DMZ,
    "aws_nlb": TrustZone.DMZ,
    "aws_lambda": TrustZone.PRIVATE,
    "aws_ecs": TrustZone.PRIVATE,
    "aws_instance": TrustZone.PRIVATE,
    "aws_rds": TrustZone.DATA,
    "aws_dynamodb": TrustZone.DATA,
    "aws_s3": TrustZone.DATA,
    "aws_elasticache": TrustZone.DATA,
    "aws_iam": TrustZone.MANAGEMENT,
    "aws_cloudwatch": TrustZone.MANAGEMENT,
    # Azure
    "azurerm_kubernetes_cluster": TrustZone.PRIVATE,
    "azurerm_network_security_rule": TrustZone.DMZ,
    "azurerm_sql_server": TrustZone.DATA,
    "azurerm_sql_database": TrustZone.DATA,
    # GCP
    "google_container_cluster": TrustZone.PRIVATE,
    "google_project_iam_member": TrustZone.MANAGEMENT,
    "google_service_account_key": TrustZone.MANAGEMENT,
    # Docker
    "dockerfile_expose": TrustZone.DMZ,
    "dockerfile_image": TrustZone.PRIVATE,
    "dockerfile_user": TrustZone.MANAGEMENT,
    # Kubernetes
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

# Pre-sorted prefix lists (longest prefix first) — rebuilt on registration
_CATEGORY_PREFIXES: list[tuple[str, NodeCategory]] = sorted(
    CATEGORY_MAP.items(), key=lambda x: -len(x[0])
)
_TRUST_ZONE_PREFIXES: list[tuple[str, TrustZone]] = sorted(
    TRUST_ZONE_MAP.items(), key=lambda x: -len(x[0])
)


def _rebuild_category_prefixes() -> None:
    """Rebuild pre-sorted category prefix list after registration."""
    global _CATEGORY_PREFIXES
    _CATEGORY_PREFIXES = sorted(CATEGORY_MAP.items(), key=lambda x: -len(x[0]))


def _rebuild_trust_zone_prefixes() -> None:
    """Rebuild pre-sorted trust zone prefix list after registration."""
    global _TRUST_ZONE_PREFIXES
    _TRUST_ZONE_PREFIXES = sorted(TRUST_ZONE_MAP.items(), key=lambda x: -len(x[0]))


def register_category(prefix: str, category: NodeCategory) -> None:
    """Register a custom resource type prefix → NodeCategory mapping.

    Use this to extend ThreatCode for non-cloud resource types (K8s, Docker, etc.).
    """
    CATEGORY_MAP[prefix] = category
    _rebuild_category_prefixes()


def register_trust_zone(prefix: str, zone: TrustZone) -> None:
    """Register a custom resource type prefix → TrustZone mapping.

    Use this to extend ThreatCode for non-cloud resource types (K8s, Docker, etc.).
    """
    TRUST_ZONE_MAP[prefix] = zone
    _rebuild_trust_zone_prefixes()


def categorize_resource(resource_type: str) -> NodeCategory:
    """Determine node category from resource type using prefix matching."""
    # Exact match first
    if resource_type in CATEGORY_MAP:
        return CATEGORY_MAP[resource_type]
    # Prefix match (e.g., aws_s3_bucket matches aws_s3)
    for prefix, category in _CATEGORY_PREFIXES:
        if resource_type.startswith(prefix):
            return category
    return NodeCategory.UNKNOWN


def infer_trust_zone(resource_type: str, properties: dict[str, Any]) -> TrustZone:
    """Infer trust zone from resource type and properties."""
    # Heuristic: public subnet or public IP → DMZ (check before static map)
    if properties.get("map_public_ip_on_launch") or properties.get("associate_public_ip_address"):
        return TrustZone.DMZ

    # Public RDS → DMZ
    if properties.get("publicly_accessible"):
        return TrustZone.DMZ

    for prefix, zone in _TRUST_ZONE_PREFIXES:
        if resource_type.startswith(prefix):
            return zone

    return TrustZone.PRIVATE


@dataclass
class InfraNode:
    id: str
    resource_type: str
    name: str
    category: NodeCategory
    trust_zone: TrustZone
    properties: dict[str, Any] = field(default_factory=dict)
    provider: str = ""
    module: str = ""

    @property
    def stride_element(self) -> str:
        return self.category.stride_element
