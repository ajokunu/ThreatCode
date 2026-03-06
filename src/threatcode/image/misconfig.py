"""Image configuration misconfiguration checks."""

from __future__ import annotations

import re
from typing import Any

_SECRET_ENV_PATTERN = re.compile(
    r"(?i)(password|secret|api_key|apikey|token|private_key|access_key|"
    r"secret_key|credentials|auth_token|db_pass|database_password)="
)


def _has_secret_env(config: dict[str, Any]) -> list[str]:
    """Return env var names that look like they contain secrets."""
    hits: list[str] = []
    for env_str in config.get("config", {}).get("Env", []):
        if _SECRET_ENV_PATTERN.search(env_str):
            key = env_str.split("=", 1)[0]
            hits.append(key)
    return hits


def _get_privileged_ports(config: dict[str, Any]) -> list[str]:
    """Return exposed ports below 1024."""
    exposed = config.get("config", {}).get("ExposedPorts", {})
    hits: list[str] = []
    for port_proto in exposed:
        port_str = port_proto.split("/")[0]
        try:
            if int(port_str) < 1024:
                hits.append(port_proto)
        except (ValueError, TypeError):
            pass
    return hits


def check_image_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    """Run misconfiguration checks against an OCI image config.

    Returns a list of finding dicts, each with id, title, severity, description.
    """
    findings: list[dict[str, Any]] = []
    img_config = config.get("config", {})

    # Running as root
    user = img_config.get("User", "")
    if not user or user in ("0", "root"):
        findings.append(
            {
                "id": "IMG_ROOT_USER",
                "title": "Container runs as root",
                "severity": "high",
                "description": (
                    "The image does not set a non-root USER. Containers running as root "
                    "increase the blast radius of a container breakout."
                ),
            }
        )

    # No healthcheck
    if not img_config.get("Healthcheck"):
        findings.append(
            {
                "id": "IMG_NO_HEALTHCHECK",
                "title": "No HEALTHCHECK defined",
                "severity": "medium",
                "description": (
                    "The image does not define a HEALTHCHECK instruction. "
                    "Orchestrators cannot detect unhealthy containers without one."
                ),
            }
        )

    # Secrets in environment variables
    secret_vars = _has_secret_env(config)
    if secret_vars:
        findings.append(
            {
                "id": "IMG_SECRET_IN_ENV",
                "title": "Possible secret in environment variable",
                "severity": "critical",
                "description": (
                    f"Environment variables with secret-like names found: "
                    f"{', '.join(secret_vars)}. Environment variables are visible "
                    f"via docker inspect and should not contain secrets."
                ),
            }
        )

    # Privileged ports
    priv_ports = _get_privileged_ports(config)
    if priv_ports:
        findings.append(
            {
                "id": "IMG_PRIVILEGED_PORT",
                "title": "Privileged port exposed",
                "severity": "low",
                "description": (
                    f"The image exposes privileged port(s) (<1024): "
                    f"{', '.join(priv_ports)}. Binding to privileged ports may "
                    f"require elevated capabilities."
                ),
            }
        )

    # Missing standard labels
    labels = img_config.get("Labels", {}) or {}
    if not labels.get("maintainer") and not labels.get("org.opencontainers.image.authors"):
        findings.append(
            {
                "id": "IMG_NO_MAINTAINER",
                "title": "No maintainer label",
                "severity": "info",
                "description": (
                    "The image has no maintainer or org.opencontainers.image.authors label. "
                    "Consider adding metadata labels for provenance."
                ),
            }
        )

    return findings
