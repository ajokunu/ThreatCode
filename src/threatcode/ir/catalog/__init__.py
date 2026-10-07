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
An exact entry is the longest prefix a type can match, so it beats any prefix: that is how
`aws_db_subnet_group` is a NETWORK type under the `aws_db` database prefix.
The merged lookup does not dispatch on the prefix, and two prefixes that both
match one type cannot have the same length, so the order of the families never
changes a result.

Zone lookup order
-----------------

`infer_trust_zone` decides a zone in three tiers, and the first tier that has an answer wins:

1. A property override.
   The public-exposure flags that mean the same on any resource type
   (`associate_public_ip_address`, `map_public_ip_on_launch` and, for a type that is not a data
   store, `publicly_accessible`), then every family's `zone_override`, in family order.
   An override must check the resource type itself.
2. An explicit prefix entry in a family's `ZONES`.
3. The default zone of the resource's category (`CATEGORY_DEFAULT_ZONE`): DATABASE, STORAGE and
   SECRET are DATA, IAM and MONITORING are MANAGEMENT, CDN is DMZ and everything else is PRIVATE.
   Dockerfile, lockfile and MCP types are not cloud resources and stay PRIVATE
   (`PRIVATE_BY_DEFAULT_PREFIXES`).

A data store (DATABASE, STORAGE or SECRET) never moves to the DMZ because it is public.
It stays in DATA and `threatcode.ir.exposure` marks it as exposed to the internet instead, so
an attack path can still end at it.

Exposure flags are tri-state (`tri_state`): only a value that is known to be true selects an
exposure.
An `Unknown`, an unresolved expression such as `"${var.public}"`, a CloudFormation intrinsic and
any string that is not a boolean spelling never select the DMZ.

`register_category` and `register_trust_zone` add entries at run time.
"""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from typing import Any, Literal

from threatcode.ir.catalog import aws, azure, dependency, docker, gcp, kubernetes, mcp
from threatcode.ir.catalog.types import NodeCategory, TrustZone
from threatcode.values import is_unknown

ZoneOverride = Callable[[str, dict[str, Any]], TrustZone | None]
TriState = Literal["true", "false", "unknown"]

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

# The zone a type gets when neither a property override nor an explicit prefix decides it
CATEGORY_DEFAULT_ZONE: dict[NodeCategory, TrustZone] = {
    NodeCategory.DATABASE: TrustZone.DATA,
    NodeCategory.STORAGE: TrustZone.DATA,
    NodeCategory.SECRET: TrustZone.DATA,
    NodeCategory.IAM: TrustZone.MANAGEMENT,
    NodeCategory.MONITORING: TrustZone.MANAGEMENT,
    NodeCategory.CDN: TrustZone.DMZ,
}

# Families whose types are not cloud resources: a Dockerfile `COPY` is not a data store and a
# `USER` line is not an administrative target, so these keep the PRIVATE default whatever their
# category. Their family modules say so in their docstrings
PRIVATE_BY_DEFAULT_PREFIXES: tuple[str, ...] = ("dockerfile_", "dependency_", "mcp_")

# Categories whose nodes hold data: public exposure is recorded on them, not a move to the DMZ
DATA_CATEGORIES: frozenset[NodeCategory] = frozenset(
    {NodeCategory.DATABASE, NodeCategory.STORAGE, NodeCategory.SECRET}
)

# Properties that put a node in the DMZ when they are true, on any resource type
_PUBLIC_ADDRESS_FLAGS: tuple[str, ...] = ("map_public_ip_on_launch", "associate_public_ip_address")

# Pre-sorted prefix lists (longest prefix first), rebuilt on registration
_CATEGORY_PREFIXES: list[tuple[str, NodeCategory]] = sorted(
    CATEGORY_MAP.items(), key=lambda x: -len(x[0])
)
_TRUST_ZONE_PREFIXES: list[tuple[str, TrustZone]] = sorted(
    TRUST_ZONE_MAP.items(), key=lambda x: -len(x[0])
)

_TRUE_NUMBERS = (1,)
_FALSE_NUMBERS = (0,)
_EXPRESSION_ROOTS = ("var.", "local.", "data.", "module.", "each.", "count.", "self.", "path.")


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


def tri_state(value: Any, evidence: str = "config") -> TriState:
    """Read an exposure flag as ``"true"``, ``"false"`` or ``"unknown"``.

    ======================================  =========
    value                                   result
    ======================================  =========
    ``True`` / ``False``                    true / false
    ``1`` / ``0``                           true / false
    ``"true"`` / ``"false"`` (any case)     true / false
    an `Unknown`                            unknown
    a string with ``${`` or a ``var.``,     unknown
    ``local.``, ``data.`` ... root
    any other string, number, list          unknown
    a mapping (``{"Ref": ...}``)            unknown
    ``None`` (the property is absent)       false for ``config`` evidence, because a missing
                                            property is a fact there; unknown for ``design``,
                                            where a missing property is a question
    ======================================  =========

    Only ``"true"`` selects an exposure.
    """
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "unknown" if evidence == "design" else "false"
    if is_unknown(value):
        return "unknown"
    if isinstance(value, str):
        text = value.strip().lower()
        if "${" in text or text.startswith(_EXPRESSION_ROOTS):
            return "unknown"
        if text == "true":
            return "true"
        if text == "false":
            return "false"
        return "unknown"
    if isinstance(value, int):
        if value in _TRUE_NUMBERS:
            return "true"
        if value in _FALSE_NUMBERS:
            return "false"
    return "unknown"


def infer_trust_zone(
    resource_type: str,
    properties: dict[str, Any],
    category: NodeCategory | None = None,
    evidence: str = "config",
) -> TrustZone:
    """Infer trust zone from resource type and properties; see the module docstring."""
    if category is None:
        category = categorize_resource(resource_type)

    # Tier 1: property overrides. A public address puts a node in the DMZ before any table
    for flag in _PUBLIC_ADDRESS_FLAGS:
        if tri_state(properties.get(flag), evidence) == "true":
            return TrustZone.DMZ

    # A public database or bucket stays a data node; its exposure is recorded separately
    if (
        category not in DATA_CATEGORIES
        and tri_state(properties.get("publicly_accessible"), evidence) == "true"
    ):
        return TrustZone.DMZ

    for zone_override in _ZONE_OVERRIDES:
        zone = zone_override(resource_type, properties)
        if zone is not None:
            return zone

    # Tier 2: an explicit prefix entry
    for prefix, zone in _TRUST_ZONE_PREFIXES:
        if resource_type.startswith(prefix):
            return zone

    # Tier 3: the default zone of the category
    if resource_type.startswith(PRIVATE_BY_DEFAULT_PREFIXES):
        return TrustZone.PRIVATE
    return CATEGORY_DEFAULT_ZONE.get(category, TrustZone.PRIVATE)
