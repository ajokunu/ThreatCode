"""Tests for the OCI registry client."""

from __future__ import annotations

import hashlib

import pytest

from threatcode.exceptions import ThreatCodeError
from threatcode.image.registry import RegistryClient


class TestRegistryContextManager:
    def test_context_manager_closes_client(self) -> None:
        client = RegistryClient()
        with client:
            assert client._client is not None
        # After exit, close() was called — httpx client is closed
        assert client._client.is_closed


class TestSelectPlatform:
    def test_exact_platform_match(self) -> None:
        from threatcode.image.reference import ImageReference

        client = RegistryClient(platform_os="linux", platform_arch="arm64")
        ref = ImageReference.parse("nginx:latest")
        manifest_list = {
            "manifests": [
                {
                    "digest": "sha256:amd64digest",
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
                {
                    "digest": "sha256:arm64digest",
                    "platform": {"os": "linux", "architecture": "arm64"},
                },
            ]
        }
        digest = client._select_platform(ref, manifest_list)
        assert digest == "sha256:arm64digest"

    def test_missing_digest_skipped(self) -> None:
        from threatcode.image.reference import ImageReference

        client = RegistryClient(platform_os="linux", platform_arch="amd64")
        ref = ImageReference.parse("nginx:latest")
        manifest_list = {
            "manifests": [
                {
                    "digest": "",
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ]
        }
        with pytest.raises(ThreatCodeError, match="No manifest found"):
            client._select_platform(ref, manifest_list)

    def test_fallback_to_same_os(self) -> None:
        from threatcode.image.reference import ImageReference

        client = RegistryClient(platform_os="linux", platform_arch="s390x")
        ref = ImageReference.parse("nginx:latest")
        manifest_list = {
            "manifests": [
                {
                    "digest": "sha256:amd64digest",
                    "platform": {"os": "linux", "architecture": "amd64"},
                },
            ]
        }
        digest = client._select_platform(ref, manifest_list)
        assert digest == "sha256:amd64digest"


class TestVerifyDigest:
    def test_valid_digest(self) -> None:
        data = b"hello world"
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        RegistryClient._verify_digest(data, digest)

    def test_invalid_digest_raises(self) -> None:
        with pytest.raises(ThreatCodeError, match="Digest mismatch"):
            RegistryClient._verify_digest(b"data", "sha256:0000000000000000")

    def test_unsupported_algorithm_raises(self) -> None:
        with pytest.raises(ThreatCodeError, match="Unsupported digest"):
            RegistryClient._verify_digest(b"data", "md5:abc123")
