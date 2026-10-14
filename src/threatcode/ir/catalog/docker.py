"""Dockerfile resource categories and trust zones.

A Dockerfile is a build recipe, not a deployed endpoint, so every Dockerfile type is in the
private zone, which is also the default for a type with no entry.
``EXPOSE`` declares the ports a process listens on, not that anything reaches them, and
``USER`` names the identity the container runs as, not an administrative target.
Whether a port is reachable is decided by the Kubernetes, Compose or cloud definition that
runs the image.
"""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "dockerfile_image": NodeCategory.CONTAINER,
    "dockerfile_stage": NodeCategory.CONTAINER,
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
    "dockerfile_image": TrustZone.PRIVATE,
    "dockerfile_stage": TrustZone.PRIVATE,
}
