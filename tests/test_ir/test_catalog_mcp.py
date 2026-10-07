"""Tests for the MCP client configuration catalog family."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.ir.catalog import dependency, mcp
from threatcode.ir.nodes import NodeCategory, TrustZone, categorize_resource, infer_trust_zone


class TestMcpCatalog:
    def test_server_is_compute(self) -> None:
        assert categorize_resource("mcp_server") == NodeCategory.COMPUTE

    def test_local_server_is_private(self) -> None:
        assert infer_trust_zone("mcp_server", {}) == TrustZone.PRIVATE

    def test_remote_server_is_in_the_internet_zone(self) -> None:
        assert infer_trust_zone("mcp_server", {"is_remote": True}) == TrustZone.INTERNET

    def test_remote_server_on_loopback_stays_private(self) -> None:
        props = {"is_remote": True, "is_loopback": True}
        assert infer_trust_zone("mcp_server", props) == TrustZone.PRIVATE

    def test_loopback_flag_alone_does_not_make_a_server_remote(self) -> None:
        assert infer_trust_zone("mcp_server", {"is_loopback": False}) == TrustZone.PRIVATE

    def test_family_only_holds_mcp_types(self) -> None:
        assert set(mcp.CATEGORIES) == {"mcp_server"}
        assert set(mcp.ZONES) == {"mcp_server"}


class TestZoneOverride:
    @pytest.mark.parametrize(
        ("properties", "expected"),
        [
            ({"is_remote": True}, TrustZone.INTERNET),
            ({"is_remote": True, "is_loopback": False}, TrustZone.INTERNET),
            ({"is_remote": True, "is_loopback": True}, None),
            ({"is_remote": False}, None),
            ({}, None),
        ],
    )
    def test_remote_non_loopback_servers_override_the_zone(
        self, properties: dict[str, Any], expected: TrustZone | None
    ) -> None:
        assert mcp.zone_override("mcp_server", properties) == expected

    def test_other_resource_types_are_never_overridden(self) -> None:
        # The override looks at the type itself, because every family's override runs
        assert mcp.zone_override("aws_instance", {"is_remote": True}) is None

    def test_a_remote_flag_on_another_type_does_not_reach_the_internet_zone(self) -> None:
        assert infer_trust_zone("aws_instance", {"is_remote": True}) == TrustZone.PRIVATE

    def test_override_wins_over_the_static_zone_but_not_over_a_public_flag(self) -> None:
        # The generic public-exposure properties run before any family override
        props = {"is_remote": True, "publicly_accessible": True}
        assert infer_trust_zone("mcp_server", props) == TrustZone.DMZ


class TestDependencyCatalog:
    """Lockfile dependencies have no zone and no useful category yet."""

    @pytest.mark.parametrize(
        "ecosystem", ["npm", "pypi", "go", "crates.io", "rubygems", "packagist"]
    )
    def test_dependencies_are_unknown_in_the_default_zone(self, ecosystem: str) -> None:
        rtype = f"dependency_{ecosystem}"
        assert categorize_resource(rtype) == NodeCategory.UNKNOWN
        assert infer_trust_zone(rtype, {}) == TrustZone.PRIVATE

    def test_family_only_holds_dependency_types(self) -> None:
        assert dependency.CATEGORIES
        assert all(key.startswith("dependency_") for key in dependency.CATEGORIES)
        assert dependency.ZONES == {}
