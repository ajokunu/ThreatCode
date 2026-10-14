"""MCP client configuration resource categories and trust zones."""

from __future__ import annotations

from typing import Any

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "mcp_server": NodeCategory.COMPUTE,
    # The synthetic node for the AI agent a config scope starts. The agent runs on the
    # user's machine, so it is private whatever its servers are
    "mcp_agent": NodeCategory.COMPUTE,
}

ZONES: dict[str, TrustZone] = {
    "mcp_server": TrustZone.PRIVATE,
    "mcp_agent": TrustZone.PRIVATE,
}


def zone_override(resource_type: str, properties: dict[str, Any]) -> TrustZone | None:
    """A remote MCP server is a third-party endpoint outside the local machine."""
    if (
        resource_type == "mcp_server"
        and properties.get("is_remote")
        and not properties.get("is_loopback")
    ):
        return TrustZone.INTERNET
    return None
