"""Tests for the Dockerfile catalog family."""

from __future__ import annotations

import pytest

from threatcode.ir.catalog import docker
from threatcode.ir.nodes import NodeCategory, TrustZone, categorize_resource, infer_trust_zone

CASES = [
    ("dockerfile_image", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_from", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_run", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("dockerfile_expose", NodeCategory.NETWORK, TrustZone.DMZ),
    ("dockerfile_env", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_arg", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_copy", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("dockerfile_add", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("dockerfile_user", NodeCategory.IAM, TrustZone.MANAGEMENT),
    ("dockerfile_healthcheck", NodeCategory.MONITORING, TrustZone.PRIVATE),
    ("dockerfile_workdir", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_entrypoint", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_cmd", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_volume", NodeCategory.STORAGE, TrustZone.PRIVATE),
]


class TestDockerCatalog:
    @pytest.mark.parametrize(("rtype", "category", "zone"), CASES)
    def test_type_resolves_to_the_expected_category_and_zone(
        self, rtype: str, category: NodeCategory, zone: TrustZone
    ) -> None:
        assert categorize_resource(rtype) == category
        assert infer_trust_zone(rtype, {}) == zone

    def test_every_dockerfile_instruction_the_catalog_names_is_covered_by_a_case(self) -> None:
        assert set(docker.CATEGORIES) == {rtype for rtype, _, _ in CASES}

    def test_family_only_holds_dockerfile_types(self) -> None:
        keys = [*docker.CATEGORIES, *docker.ZONES]
        assert keys
        assert all(key.startswith("dockerfile_") for key in keys)

    def test_only_expose_is_public(self) -> None:
        public = [rtype for rtype, _, zone in CASES if zone == TrustZone.DMZ]
        assert public == ["dockerfile_expose"]

    def test_user_instruction_is_in_the_management_zone(self) -> None:
        # A USER instruction decides which identity the container runs as
        assert infer_trust_zone("dockerfile_user", {}) == TrustZone.MANAGEMENT

    def test_has_no_zone_override(self) -> None:
        assert not hasattr(docker, "zone_override")

    def test_every_entry_resolves_through_the_aggregate_to_its_own_value(self) -> None:
        for key, category in docker.CATEGORIES.items():
            assert categorize_resource(key) == category
        for key, zone in docker.ZONES.items():
            assert infer_trust_zone(key, {}) == zone
