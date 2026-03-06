"""Tests for image reference parsing."""

from __future__ import annotations

import pytest

from threatcode.exceptions import ThreatCodeError
from threatcode.image.reference import ImageReference


class TestImageReferenceParse:
    def test_bare_name_defaults_to_docker_hub_library(self) -> None:
        ref = ImageReference.parse("nginx")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"
        assert ref.tag == "latest"
        assert ref.digest == ""

    def test_name_with_tag(self) -> None:
        ref = ImageReference.parse("nginx:1.25")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"
        assert ref.tag == "1.25"

    def test_user_scoped_name(self) -> None:
        ref = ImageReference.parse("myuser/myapp")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "myuser/myapp"
        assert ref.tag == "latest"

    def test_ghcr_with_tag(self) -> None:
        ref = ImageReference.parse("ghcr.io/owner/repo:v1")
        assert ref.registry == "ghcr.io"
        assert ref.repository == "owner/repo"
        assert ref.tag == "v1"

    def test_localhost_with_port(self) -> None:
        ref = ImageReference.parse("localhost:5000/img:dev")
        assert ref.registry == "localhost:5000"
        assert ref.repository == "img"
        assert ref.tag == "dev"

    def test_digest_only(self) -> None:
        ref = ImageReference.parse("nginx@sha256:abc123def456")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"
        assert ref.tag == ""
        assert ref.digest == "sha256:abc123def456"

    def test_nested_path_with_digest(self) -> None:
        ref = ImageReference.parse("gcr.io/project/img@sha256:abc123")
        assert ref.registry == "gcr.io"
        assert ref.repository == "project/img"
        assert ref.digest == "sha256:abc123"
        assert ref.tag == ""

    def test_docker_io_normalised(self) -> None:
        ref = ImageReference.parse("docker.io/library/nginx:latest")
        assert ref.registry == "registry-1.docker.io"
        assert ref.repository == "library/nginx"
        assert ref.tag == "latest"

    def test_custom_registry_with_port(self) -> None:
        ref = ImageReference.parse("registry.example.com:8443/team/app:v2.1")
        assert ref.registry == "registry.example.com:8443"
        assert ref.repository == "team/app"
        assert ref.tag == "v2.1"

    def test_deep_repository_path(self) -> None:
        ref = ImageReference.parse("us-docker.pkg.dev/project/repo/image:tag")
        assert ref.registry == "us-docker.pkg.dev"
        assert ref.repository == "project/repo/image"
        assert ref.tag == "tag"

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ThreatCodeError):
            ImageReference.parse("")

    def test_invalid_digest_raises(self) -> None:
        with pytest.raises(ThreatCodeError):
            ImageReference.parse("nginx@md5:abc123")


class TestImageReferenceProperties:
    def test_full_name_with_tag(self) -> None:
        ref = ImageReference.parse("nginx:latest")
        assert ref.full_name == "registry-1.docker.io/library/nginx:latest"

    def test_full_name_with_digest(self) -> None:
        ref = ImageReference.parse("nginx@sha256:abc")
        assert ref.full_name == "registry-1.docker.io/library/nginx@sha256:abc"

    def test_api_base(self) -> None:
        ref = ImageReference.parse("ghcr.io/owner/repo:v1")
        assert ref.api_base == "https://ghcr.io"

    def test_manifest_ref_prefers_digest(self) -> None:
        ref = ImageReference.parse("nginx@sha256:abc")
        assert ref.manifest_ref == "sha256:abc"

    def test_manifest_ref_uses_tag(self) -> None:
        ref = ImageReference.parse("nginx:1.25")
        assert ref.manifest_ref == "1.25"

    def test_str_returns_full_name(self) -> None:
        ref = ImageReference.parse("nginx:latest")
        assert str(ref) == ref.full_name
