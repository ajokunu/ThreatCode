"""Tests for the Dockerfile catalog family."""

from __future__ import annotations

import pytest

from threatcode.ir.catalog import docker
from threatcode.ir.nodes import NodeCategory, TrustZone, categorize_resource, infer_trust_zone

CASES = [
    ("dockerfile_image", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_stage", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_from", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_run", NodeCategory.COMPUTE, TrustZone.PRIVATE),
    ("dockerfile_expose", NodeCategory.NETWORK, TrustZone.PRIVATE),
    ("dockerfile_env", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_arg", NodeCategory.CONTAINER, TrustZone.PRIVATE),
    ("dockerfile_copy", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("dockerfile_add", NodeCategory.STORAGE, TrustZone.PRIVATE),
    ("dockerfile_user", NodeCategory.IAM, TrustZone.PRIVATE),
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

    def test_every_case_is_in_the_catalog(self) -> None:
        assert {rtype for rtype, _, _ in CASES} <= set(docker.CATEGORIES)

    def test_family_only_holds_dockerfile_types(self) -> None:
        keys = [*docker.CATEGORIES, *docker.ZONES]
        assert keys
        assert all(key.startswith("dockerfile_") for key in keys)

    def test_no_dockerfile_type_is_outside_the_private_zone(self) -> None:
        # A Dockerfile is a build recipe, not a deployed endpoint
        assert {zone for _rtype, _category, zone in CASES} == {TrustZone.PRIVATE}

    def test_a_declared_port_is_not_internet_exposure(self) -> None:
        assert infer_trust_zone("dockerfile_expose", {"ports": [22, 80]}) == TrustZone.PRIVATE

    def test_a_user_instruction_is_not_an_administrative_target(self) -> None:
        assert infer_trust_zone("dockerfile_user", {"user": "root"}) == TrustZone.PRIVATE
        assert infer_trust_zone("dockerfile_user", {}) != TrustZone.MANAGEMENT

    def test_the_stage_node_is_a_container_in_the_private_zone(self) -> None:
        assert docker.CATEGORIES["dockerfile_stage"] == NodeCategory.CONTAINER
        assert docker.ZONES["dockerfile_stage"] == TrustZone.PRIVATE

    def test_has_no_zone_override(self) -> None:
        assert not hasattr(docker, "zone_override")

    def test_every_entry_resolves_through_the_aggregate_to_its_own_value(self) -> None:
        for key, category in docker.CATEGORIES.items():
            assert categorize_resource(key) == category
        for key, zone in docker.ZONES.items():
            assert infer_trust_zone(key, {}) == zone
