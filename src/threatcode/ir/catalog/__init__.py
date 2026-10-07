"""Resource type catalog: the node category and trust zone of each resource type.

Each family module (`aws`, `azure`, `gcp`, `docker`, `kubernetes`, `mcp` and
`dependency`) owns the entries for its own resource types and exports

- `CATEGORIES`: resource type prefix to `NodeCategory`,
- `ZONES`: resource type prefix to `TrustZone`,
- optionally `zone_override(resource_type, properties)`, which returns a
  `TrustZone` when a property of the resource decides the zone, else `None`.

This module merges the families into one lookup.
A type matches the longest registered prefix, so `aws_s3_bucket` finds
`aws_s3` and `aws_security_group_rule` finds `aws_security_group`, not a
shorter prefix.
The merged lookup does not dispatch on the prefix, and two prefixes that both
match one type cannot have the same length, so the order of the families never
changes a result.

Before the static tables, `infer_trust_zone` applies the public-exposure
properties that mean the same on any resource type (`publicly_accessible`,
`associate_public_ip_address`, `map_public_ip_on_launch`), then every family's
`zone_override`, in family order.
An override must check the resource type itself.

`register_category` and `register_trust_zone` add entries at run time.
"""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from typing import Any

from threatcode.ir.catalog import aws, azure, dependency, docker, gcp, kubernetes, mcp
from threatcode.ir.catalog.types import NodeCategory, TrustZone

ZoneOverride = Callable[[str, dict[str, Any]], TrustZone | None]

# Order is the order the entries had in one table, which keeps dict order stable
FAMILIES: tuple[ModuleType, ...] = (aws, azure, gcp, docker, kubernetes, mcp, dependency)

CATEGORY_MAP: dict[str, NodeCategory] = {}
TRUST_ZONE_MAP: dict[str, TrustZone] = {}
for _family in FAMILIES:
    CATEGORY_MAP.update(_family.CATEGORIES)
    TRUST_ZONE_MAP.update(_family.ZONES)

_ZONE_OVERRIDES: tuple[ZoneOverride, ...] = tuple(
    override for override in (getattr(f, "zone_override", None) for f in FAMILIES) if override
)

# Pre-sorted prefix lists (longest prefix first), rebuilt on registration
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

    for zone_override in _ZONE_OVERRIDES:
        zone = zone_override(resource_type, properties)
        if zone is not None:
            return zone

    for prefix, zone in _TRUST_ZONE_PREFIXES:
        if resource_type.startswith(prefix):
            return zone

    return TrustZone.PRIVATE
