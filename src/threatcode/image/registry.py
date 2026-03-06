"""Docker Registry HTTP API V2 client."""

from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import httpx

from threatcode.exceptions import ThreatCodeError
from threatcode.image.auth import CredentialStore, TokenProvider
from threatcode.image.reference import ImageReference

logger = logging.getLogger(__name__)

_MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
    ]
)

_MANIFEST_LIST_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}


class RegistryClient:
    """Pull manifests, blobs, and configs from container registries."""

    def __init__(
        self,
        credential_store: CredentialStore | None = None,
        *,
        insecure: bool = False,
        timeout: float = 120.0,
        platform_os: str = "linux",
        platform_arch: str = "amd64",
    ) -> None:
        self._creds = credential_store or CredentialStore()
        self._insecure = insecure
        self._timeout = timeout
        self._platform_os = platform_os
        self._platform_arch = platform_arch
        self._token_cache: dict[str, str] = {}
        self._client = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
        )

    def pull_manifest(self, ref: ImageReference) -> tuple[dict[str, Any], str]:
        """Pull the image manifest.

        Handles manifest lists by selecting the correct platform entry
        and re-fetching the platform-specific manifest.

        Returns (manifest_dict, content_type).
        """
        url = f"{ref.api_base}/v2/{ref.repository}/manifests/{ref.manifest_ref}"
        resp = self._request("GET", url, ref, headers={"Accept": _MANIFEST_ACCEPT})

        content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()
        manifest: dict[str, Any] = resp.json()

        # If we got a manifest list / OCI index, drill down to the platform
        if content_type in _MANIFEST_LIST_TYPES or "manifests" in manifest:
            platform_digest = self._select_platform(ref, manifest)
            platform_url = f"{ref.api_base}/v2/{ref.repository}/manifests/{platform_digest}"
            resp = self._request("GET", platform_url, ref, headers={"Accept": _MANIFEST_ACCEPT})
            content_type = resp.headers.get("Content-Type", "").split(";")[0].strip()
            manifest = resp.json()

        return manifest, content_type

    def pull_blob(self, ref: ImageReference, digest: str) -> bytes:
        """Download a blob by digest and verify its SHA-256.

        Follows redirects automatically (common for CDN-backed registries).
        """
        url = f"{ref.api_base}/v2/{ref.repository}/blobs/{digest}"
        resp = self._request("GET", url, ref)
        data = resp.content
        self._verify_digest(data, digest)
        return data

    def pull_config(self, ref: ImageReference, manifest: dict[str, Any]) -> dict[str, Any]:
        """Download and parse the image config JSON."""
        config_descriptor = manifest.get("config", {})
        digest = config_descriptor.get("digest", "")
        if not digest:
            raise ThreatCodeError("Manifest has no config digest")
        blob = self.pull_blob(ref, digest)
        try:
            result: dict[str, Any] = json.loads(blob)
            return result
        except json.JSONDecodeError as e:
            raise ThreatCodeError(f"Image config is not valid JSON: {e}") from e

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> RegistryClient:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    # ──────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────

    def _select_platform(self, ref: ImageReference, manifest_list: dict[str, Any]) -> str:
        """Return the digest of the manifest matching our target platform."""
        entries: list[dict[str, Any]] = manifest_list.get("manifests", [])
        for entry in entries:
            platform = entry.get("platform", {})
            if (
                platform.get("os") == self._platform_os
                and platform.get("architecture") == self._platform_arch
            ):
                return str(entry["digest"])

        # Fallback: first linux entry if exact arch not found
        for entry in entries:
            platform = entry.get("platform", {})
            if platform.get("os") == self._platform_os:
                logger.warning(
                    "Exact platform %s/%s not found; using %s/%s",
                    self._platform_os,
                    self._platform_arch,
                    platform.get("os"),
                    platform.get("architecture"),
                )
                return str(entry["digest"])

        raise ThreatCodeError(
            f"No manifest found for platform {self._platform_os}/{self._platform_arch}"
        )

    def _get_auth_header(self, ref: ImageReference) -> dict[str, str]:
        """Return Authorization header dict for the registry."""
        cache_key = f"{ref.registry}/{ref.repository}"
        token = self._token_cache.get(cache_key)
        if token is None:
            cred = self._creds.get(ref.registry)
            provider = TokenProvider(self._client, credential=cred)
            token = provider.get_token(ref.registry, ref.repository)
            if token is not None:
                self._token_cache[cache_key] = token

        if token:
            return {"Authorization": f"Bearer {token}"}
        return {}

    def _request(
        self,
        method: str,
        url: str,
        ref: ImageReference,
        **kwargs: Any,
    ) -> httpx.Response:
        """Make an authenticated request, raising on HTTP errors."""
        headers = kwargs.pop("headers", {})
        headers.update(self._get_auth_header(ref))
        try:
            resp = self._client.request(method, url, headers=headers, **kwargs)
            resp.raise_for_status()
            return resp
        except httpx.HTTPStatusError as e:
            raise ThreatCodeError(f"Registry request failed: {e.response.status_code} {url}") from e
        except httpx.RequestError as e:
            raise ThreatCodeError(f"Registry connection error: {e}") from e

    @staticmethod
    def _verify_digest(data: bytes, expected_digest: str) -> None:
        """Verify SHA-256 digest of downloaded data."""
        algo, _, expected_hash = expected_digest.partition(":")
        if algo != "sha256":
            raise ThreatCodeError(f"Unsupported digest algorithm: {algo!r}")
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected_hash:
            raise ThreatCodeError(
                f"Digest mismatch: expected sha256:{expected_hash[:16]}..., "
                f"got sha256:{actual[:16]}..."
            )
