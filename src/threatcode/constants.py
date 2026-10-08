"""Single source of truth for validation constants."""

from __future__ import annotations

VALID_STRIDE_CATEGORIES: frozenset[str] = frozenset(
    {
        "spoofing",
        "tampering",
        "repudiation",
        "information_disclosure",
        "denial_of_service",
        "elevation_of_privilege",
    }
)

VALID_SEVERITIES: frozenset[str] = frozenset(
    {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
)


# File names (lower-cased) that hold a Dockerfile, and the prefixes and suffixes of the
# variants: Dockerfile.dev, Dockerfile-dev, Dockerfile_api, app.dockerfile. Podman and
# Buildah call the same file a Containerfile.
_DOCKERFILE_NAMES = frozenset({"dockerfile", "containerfile"})
_DOCKERFILE_PREFIXES = (
    "dockerfile.",
    "dockerfile-",
    "dockerfile_",
    "containerfile.",
    "containerfile-",
    "containerfile_",
)
_DOCKERFILE_SUFFIXES = (".dockerfile", ".containerfile")


def is_dockerfile_name(name: str) -> bool:
    """Return True if a file name (not a path) names a Dockerfile or Containerfile."""
    lowered = name.lower()
    return (
        lowered in _DOCKERFILE_NAMES
        or lowered.startswith(_DOCKERFILE_PREFIXES)
        or lowered.endswith(_DOCKERFILE_SUFFIXES)
    )


# Terraform and OpenTofu source files. ``.tf.json`` is Terraform's JSON syntax, which CDK
# for Terraform writes as ``cdk.tf.json``.
TERRAFORM_JSON_SUFFIX = ".tf.json"
_TERRAFORM_SUFFIXES = (".tf", ".tofu", TERRAFORM_JSON_SUFFIX)


def is_terraform_name(name: str) -> bool:
    """Return True for a file name Terraform or OpenTofu reads (case-insensitive)."""
    return name.lower().endswith(_TERRAFORM_SUFFIXES)


def is_terraform_json_name(name: str) -> bool:
    """Return True for a file in Terraform's JSON syntax (``*.tf.json``)."""
    return name.lower().endswith(TERRAFORM_JSON_SUFFIX)
