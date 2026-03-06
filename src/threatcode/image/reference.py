"""Docker/OCI image reference parsing."""

from __future__ import annotations

from dataclasses import dataclass

from threatcode.exceptions import ThreatCodeError

_DOCKER_HUB_REGISTRY = "registry-1.docker.io"
_DEFAULT_TAG = "latest"


def _is_registry_hostname(component: str) -> bool:
    """Return True if the first path component looks like a registry hostname."""
    return "." in component or ":" in component or component == "localhost"


@dataclass
class ImageReference:
    """Parsed Docker/OCI image reference."""

    registry: str  # e.g. "registry-1.docker.io"
    repository: str  # e.g. "library/nginx"
    tag: str  # e.g. "latest" or ""
    digest: str  # e.g. "sha256:abc..." or ""

    @classmethod
    def parse(cls, raw: str) -> ImageReference:
        """Parse an image reference string into its components.

        Handles all standard Docker reference formats:
        - nginx                                → docker.io library/nginx:latest
        - nginx:1.25                           → docker.io library/nginx:1.25
        - myuser/myapp                         → docker.io myuser/myapp:latest
        - ghcr.io/owner/repo:v1               → ghcr.io owner/repo:v1
        - localhost:5000/img:dev              → localhost:5000 img:dev
        - nginx@sha256:abc                    → docker.io library/nginx @sha256:abc
        - gcr.io/project/img@sha256:abc       → gcr.io project/img @sha256:abc
        """
        if not raw:
            raise ThreatCodeError("Image reference cannot be empty")

        # Split off digest (@sha256:...)
        digest = ""
        name_part = raw
        if "@" in raw:
            at_idx = raw.rindex("@")
            name_part = raw[:at_idx]
            digest = raw[at_idx + 1 :]
            if not digest.startswith("sha256:") and not digest.startswith("sha512:"):
                raise ThreatCodeError(f"Invalid digest format: {digest!r}")

        # Split off tag (:tag) — but only after the last slash to avoid
        # catching the port number in registry:port/repo
        tag = ""
        if not digest:
            # Find the last component and check for a colon in it
            last_slash = name_part.rfind("/")
            last_component = name_part[last_slash + 1 :]
            if ":" in last_component:
                colon_idx = name_part.rfind(":")
                tag = name_part[colon_idx + 1 :]
                name_part = name_part[:colon_idx]

        # Parse registry and repository from name_part
        parts = name_part.split("/")

        if len(parts) == 1:
            # e.g. "nginx" → docker hub, library namespace
            registry = _DOCKER_HUB_REGISTRY
            repository = "library/" + parts[0]
        elif _is_registry_hostname(parts[0]):
            # e.g. "ghcr.io/owner/repo" or "localhost:5000/img"
            registry = parts[0]
            repository = "/".join(parts[1:])
        else:
            # e.g. "myuser/myapp" → docker hub, user namespace
            registry = _DOCKER_HUB_REGISTRY
            repository = "/".join(parts)

        # Normalise docker.io → registry-1.docker.io
        if registry == "docker.io":
            registry = _DOCKER_HUB_REGISTRY

        if not repository:
            raise ThreatCodeError(f"Could not determine repository from reference: {raw!r}")

        # Default tag
        if not tag and not digest:
            tag = _DEFAULT_TAG

        return cls(registry=registry, repository=repository, tag=tag, digest=digest)

    @property
    def full_name(self) -> str:
        """Full canonical reference string."""
        base = f"{self.registry}/{self.repository}"
        if self.digest:
            return f"{base}@{self.digest}"
        return f"{base}:{self.tag}"

    @property
    def api_base(self) -> str:
        """Base URL for registry API calls."""
        return f"https://{self.registry}"

    @property
    def manifest_ref(self) -> str:
        """The reference to use when fetching the manifest (digest or tag)."""
        return self.digest or self.tag

    def __str__(self) -> str:
        return self.full_name
