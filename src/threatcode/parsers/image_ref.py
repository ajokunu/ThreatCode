"""Container image reference parsing shared by the Dockerfile, Kubernetes and MCP parsers.

One parser for ``[registry[:port]/]repository[:tag][@digest]`` means every package that
reads an image name (rules about floating tags, ingestion of scanner results that name an
image) agrees on what the name means.
"""

from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from typing import Literal

ImageRefKind = Literal["registry", "stage", "scratch", "variable"]

DOCKER_HUB = "docker.io"

# Hosts that all name Docker Hub.
_DOCKER_HUB_HOSTS = frozenset(
    {"docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com"}
)

# Tags that move: a build today and a build next month can pull different images.
FLOATING_TAGS = frozenset(
    {
        "latest",
        "stable",
        "main",
        "master",
        "edge",
        "nightly",
        "dev",
        "develop",
        "canary",
        "beta",
        "alpha",
        "rolling",
        "current",
    }
)

_VARIABLE_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
_MASK_RE = re.compile(r"\x00(\d+)\x00")


@dataclass(frozen=True)
class ImageRef:
    """A parsed image reference.

    ``tag`` is empty when the reference has none, which Docker resolves to ``latest``.
    ``registry`` is ``docker.io`` for Docker Hub names, with ``library/`` added to
    single-component repositories, and empty when a variable hides it. ``kind`` is
    ``stage`` for a reference to an earlier build stage, ``scratch`` for the empty base
    image and ``variable`` when the text contains ``${VAR}`` or ``$VAR``, where the image
    that is really used is unknown.
    """

    registry: str
    repository: str
    tag: str
    digest: str
    kind: ImageRefKind
    raw: str

    @property
    def name(self) -> str:
        """Registry and repository, without tag or digest."""
        return f"{self.registry}/{self.repository}" if self.registry else self.repository

    @property
    def normalized(self) -> str:
        """The full normalized reference: name, then ``:tag`` and ``@digest`` if present."""
        text = self.name
        if self.tag:
            text += f":{self.tag}"
        if self.digest:
            text += f"@{self.digest}"
        return text


def is_floating_tag(tag: str) -> bool:
    """Return True for an empty tag and for tags that name a moving target."""
    cleaned = tag.strip().lower()
    return not cleaned or cleaned in FLOATING_TAGS


def parse_image_ref(text: str, stages: Collection[str] = ()) -> ImageRef:
    """Parse an image reference.

    Args:
        text: The reference as written, for example ``nginx``, ``ghcr.io/org/app:1.2``,
            ``localhost:5000/app@sha256:...`` or ``${REGISTRY}/app:${TAG}``.
        stages: Names of the build stages declared earlier in the same Dockerfile. A
            reference equal to one of them (case-insensitive) has kind ``stage``.

    An empty reference returns an ``ImageRef`` with an empty repository rather than
    raising, so a manifest with a missing ``image`` still parses.
    """
    raw = text.strip()
    if not raw:
        return ImageRef("", "", "", "", "registry", raw)
    if raw.lower() == "scratch":
        return ImageRef("", "scratch", "", "", "scratch", raw)
    if raw.lower() in {stage.lower() for stage in stages}:
        return ImageRef("", raw, "", "", "stage", raw)

    # Hide variables so a ':' inside ${TAG:-latest} or a '/' inside a default cannot be
    # mistaken for a separator; the original text is restored in every field below.
    variables: list[str] = []

    def mask(match: re.Match[str]) -> str:
        variables.append(match.group(0))
        return f"\x00{len(variables) - 1}\x00"

    def restore(value: str) -> str:
        return _MASK_RE.sub(lambda m: variables[int(m.group(1))], value)

    masked = _VARIABLE_RE.sub(mask, raw)
    name, _, digest = masked.partition("@")

    parts = name.split("/")
    registry = ""
    if len(parts) > 1:
        head = parts[0]
        if "." in head or ":" in head or head == "localhost" or "\x00" in head:
            registry = head
            parts = parts[1:]
    repository = "/".join(parts)

    tag = ""
    if ":" in repository:
        repository, _, tag = repository.rpartition(":")

    only_a_variable = not registry and bool(_MASK_RE.fullmatch(repository))
    if not only_a_variable:
        if not registry or registry.lower() in _DOCKER_HUB_HOSTS:
            registry = DOCKER_HUB
        if registry == DOCKER_HUB and "/" not in repository:
            repository = f"library/{repository}"
    registry = registry.lower() if "\x00" not in registry else registry

    return ImageRef(
        registry=restore(registry),
        repository=restore(repository),
        tag=restore(tag),
        digest=restore(digest),
        kind="variable" if variables else "registry",
        raw=raw,
    )


def same_image(a: ImageRef | str, b: ImageRef | str) -> bool:
    """Return True when two references name the same image.

    References are compared after normalization, so ``nginx`` equals
    ``docker.io/library/nginx:latest``. A digest wins over names: two references with the
    same digest are the same image whatever they are called, and two different digests
    never are. A tag cannot be proven equal to a digest, so a digest-only reference
    matches a tag reference only when both carry the same tag. A reference that contains
    a variable matches nothing, because the image it resolves to is unknown.
    """
    left = parse_image_ref(a) if isinstance(a, str) else a
    right = parse_image_ref(b) if isinstance(b, str) else b
    if left.kind != right.kind:
        return False
    if left.kind == "scratch":
        return True
    if left.kind == "stage":
        return left.raw.lower() == right.raw.lower()
    if left.kind == "variable":
        return False
    if left.digest and right.digest:
        return left.digest == right.digest
    if left.name != right.name:
        return False
    if left.digest or right.digest:
        return bool(left.tag) and left.tag == right.tag
    return (left.tag or "latest") == (right.tag or "latest")
