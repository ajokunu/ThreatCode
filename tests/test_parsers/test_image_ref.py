"""Tests for threatcode.parsers.image_ref."""

from __future__ import annotations

import pytest

from threatcode.parsers.image_ref import (
    FLOATING_TAGS,
    ImageRef,
    is_floating_tag,
    parse_image_ref,
    same_image,
)

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


class TestParse:
    def test_bare_name_is_normalized_to_docker_hub(self) -> None:
        ref = parse_image_ref("nginx")
        assert ref == ImageRef("docker.io", "library/nginx", "", "", "registry", "nginx")

    def test_tag(self) -> None:
        ref = parse_image_ref("nginx:1.25")
        assert (ref.registry, ref.repository, ref.tag) == ("docker.io", "library/nginx", "1.25")

    def test_user_repository_on_docker_hub(self) -> None:
        ref = parse_image_ref("bitnami/redis:7.2")
        assert (ref.registry, ref.repository, ref.tag) == ("docker.io", "bitnami/redis", "7.2")

    @pytest.mark.parametrize(
        "text",
        [
            "docker.io/nginx",
            "index.docker.io/library/nginx",
            "registry-1.docker.io/library/nginx",
            "DOCKER.IO/library/nginx",
        ],
    )
    def test_docker_hub_hosts_normalize_to_one_name(self, text: str) -> None:
        ref = parse_image_ref(text)
        assert (ref.registry, ref.repository) == ("docker.io", "library/nginx")

    def test_registry_host(self) -> None:
        ref = parse_image_ref("ghcr.io/org/app:1.2.3")
        assert (ref.registry, ref.repository, ref.tag) == ("ghcr.io", "org/app", "1.2.3")

    def test_registry_with_port_and_no_tag(self) -> None:
        ref = parse_image_ref("registry.example.com:5000/team/app")
        assert ref.registry == "registry.example.com:5000"
        assert ref.repository == "team/app"
        assert ref.tag == ""

    def test_registry_with_port_and_tag(self) -> None:
        ref = parse_image_ref("registry.example.com:5000/team/app:2.1")
        assert (ref.registry, ref.repository, ref.tag) == (
            "registry.example.com:5000",
            "team/app",
            "2.1",
        )

    def test_localhost_registry_with_port(self) -> None:
        ref = parse_image_ref("localhost:5000/app")
        assert (ref.registry, ref.repository, ref.tag) == ("localhost:5000", "app", "")

    def test_localhost_without_port_is_a_registry(self) -> None:
        ref = parse_image_ref("localhost/app:dev")
        assert (ref.registry, ref.repository, ref.tag) == ("localhost", "app", "dev")

    def test_digest_only(self) -> None:
        ref = parse_image_ref(f"nginx@{DIGEST}")
        assert (ref.repository, ref.tag, ref.digest) == ("library/nginx", "", DIGEST)

    def test_tag_and_digest(self) -> None:
        ref = parse_image_ref(f"ghcr.io/org/app:1.2@{DIGEST}")
        assert (ref.registry, ref.repository, ref.tag, ref.digest) == (
            "ghcr.io",
            "org/app",
            "1.2",
            DIGEST,
        )

    def test_whitespace_is_trimmed_and_raw_is_kept(self) -> None:
        ref = parse_image_ref("  nginx:1.25 \n")
        assert ref.raw == "nginx:1.25"
        assert ref.tag == "1.25"

    def test_empty_reference_does_not_raise(self) -> None:
        ref = parse_image_ref("")
        assert ref.repository == ""
        assert ref.kind == "registry"

    def test_name_and_normalized(self) -> None:
        ref = parse_image_ref(f"quay.io/org/app:v1@{DIGEST}")
        assert ref.name == "quay.io/org/app"
        assert ref.normalized == f"quay.io/org/app:v1@{DIGEST}"
        assert parse_image_ref("nginx").normalized == "docker.io/library/nginx"


class TestKinds:
    def test_scratch(self) -> None:
        for text in ("scratch", "SCRATCH"):
            assert parse_image_ref(text).kind == "scratch"

    def test_stage_reference_is_case_insensitive(self) -> None:
        ref = parse_image_ref("Builder", stages=["builder"])
        assert ref.kind == "stage"
        assert ref.raw == "Builder"

    def test_stage_name_only_applies_to_declared_stages(self) -> None:
        assert parse_image_ref("builder").kind == "registry"
        assert parse_image_ref("builder", stages=["other"]).kind == "registry"

    def test_braced_variable(self) -> None:
        ref = parse_image_ref("${REGISTRY}/app:${TAG}")
        assert ref.kind == "variable"
        assert ref.registry == "${REGISTRY}"
        assert ref.repository == "app"
        assert ref.tag == "${TAG}"

    def test_bare_variable(self) -> None:
        ref = parse_image_ref("$BASE_IMAGE")
        assert ref.kind == "variable"
        assert ref.repository == "$BASE_IMAGE"
        assert ref.registry == ""

    def test_variable_with_default_containing_a_colon(self) -> None:
        ref = parse_image_ref("app:${TAG:-latest}")
        assert ref.kind == "variable"
        assert ref.repository == "library/app"
        assert ref.tag == "${TAG:-latest}"

    def test_plain_reference_is_not_a_variable(self) -> None:
        assert parse_image_ref("nginx:1.25").kind == "registry"


class TestFloatingTags:
    @pytest.mark.parametrize("tag", sorted(FLOATING_TAGS))
    def test_floating(self, tag: str) -> None:
        assert is_floating_tag(tag)
        assert is_floating_tag(tag.upper())

    def test_expected_floating_set(self) -> None:
        assert FLOATING_TAGS == {
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

    @pytest.mark.parametrize("tag", ["", "  "])
    def test_empty_tag_is_floating(self, tag: str) -> None:
        assert is_floating_tag(tag)

    @pytest.mark.parametrize("tag", ["1.25", "v2", "3.12-slim", "sha256-abc", "${TAG}"])
    def test_pinned_tags_are_not_floating(self, tag: str) -> None:
        assert not is_floating_tag(tag)


class TestSameImage:
    def test_default_registry_and_tag_are_normalized(self) -> None:
        assert same_image("nginx", "docker.io/library/nginx:latest")
        assert same_image("library/nginx:1.25", "index.docker.io/library/nginx:1.25")

    def test_accepts_parsed_references(self) -> None:
        assert same_image(parse_image_ref("nginx"), "nginx:latest")

    def test_different_tag_is_a_different_image(self) -> None:
        assert not same_image("nginx:1.25", "nginx:1.26")

    def test_different_registry_is_a_different_image(self) -> None:
        assert not same_image("ghcr.io/org/app:1", "docker.io/org/app:1")

    def test_equal_digests_win_over_names(self) -> None:
        assert same_image(f"ghcr.io/org/app@{DIGEST}", f"mirror.example.com/copy@{DIGEST}")

    def test_different_digests_win_over_names(self) -> None:
        assert not same_image(f"app:1@{DIGEST}", f"app:1@{OTHER_DIGEST}")

    def test_digest_matches_a_tag_only_when_the_tags_agree(self) -> None:
        assert same_image(f"app:1.2@{DIGEST}", "app:1.2")
        assert not same_image(f"app:1.2@{DIGEST}", "app:1.3")
        assert not same_image(f"app@{DIGEST}", "app:1.2")

    def test_variables_match_nothing(self) -> None:
        assert not same_image("${IMAGE}", "${IMAGE}")
        assert not same_image("app:${TAG}", "app:${TAG}")

    def test_stage_and_scratch(self) -> None:
        build = parse_image_ref("build", stages=["build"])
        assert same_image(build, parse_image_ref("BUILD", stages=["build"]))
        assert not same_image(build, "build")
        assert same_image("scratch", "scratch")
