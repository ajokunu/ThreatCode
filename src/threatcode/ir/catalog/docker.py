"""Dockerfile resource categories and trust zones."""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
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
}

ZONES: dict[str, TrustZone] = {
    "dockerfile_expose": TrustZone.DMZ,
    "dockerfile_image": TrustZone.PRIVATE,
    "dockerfile_user": TrustZone.MANAGEMENT,
}
