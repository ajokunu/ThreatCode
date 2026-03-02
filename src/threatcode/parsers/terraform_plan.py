"""Terraform plan JSON parser (primary input format).

Security: recursion depth is capped to prevent stack overflow from
deeply nested Terraform modules in malicious plan files.
"""

from __future__ import annotations

import logging
from typing import Any

from threatcode.exceptions import ParseError
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)

# Max nesting depth for Terraform module recursion
MAX_MODULE_DEPTH = 50


class TerraformPlanParser(BaseParser):
    """Parse output of `terraform show -json <planfile>`."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if not isinstance(data, dict):
            raise ParseError("Terraform plan JSON must be an object")

        resources: list[ParsedResource] = []
        dep_map = self._build_dependency_map(data)

        # Walk planned_values for resolved attribute values
        planned = data.get("planned_values", {})
        root_module = planned.get("root_module", {})
        self._walk_module(root_module, resources, dep_map, module_prefix="", depth=0)

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="terraform_plan",
            metadata={
                "format_version": data.get("format_version", ""),
                "terraform_version": data.get("terraform_version", ""),
            },
        )

    def _walk_module(
        self,
        module: dict[str, Any],
        resources: list[ParsedResource],
        dep_map: dict[str, list[str]],
        module_prefix: str,
        depth: int = 0,
    ) -> None:
        if depth > MAX_MODULE_DEPTH:
            logger.warning(
                "Module nesting depth %d exceeds limit %d — skipping",
                depth,
                MAX_MODULE_DEPTH,
            )
            return
        for res in module.get("resources", []):
            address = res.get("address", "")
            rtype = res.get("type", "")
            name = res.get("name", "")
            provider = res.get("provider_name", "")
            values = res.get("values", {}) or {}

            resources.append(
                ParsedResource(
                    resource_type=rtype,
                    address=address,
                    name=name,
                    provider=provider,
                    properties=values,
                    dependencies=dep_map.get(address, []),
                    module=module_prefix,
                )
            )

        # Recurse into child modules
        for child in module.get("child_modules", []):
            child_addr = child.get("address", "")
            self._walk_module(child, resources, dep_map, module_prefix=child_addr, depth=depth + 1)

    def _build_dependency_map(self, data: dict[str, Any]) -> dict[str, list[str]]:
        """Extract dependency info from the configuration block."""
        dep_map: dict[str, list[str]] = {}
        config = data.get("configuration", {})
        root = config.get("root_module", {})
        self._walk_config_module(root, dep_map, prefix="", depth=0)
        return dep_map

    def _walk_config_module(
        self,
        module: dict[str, Any],
        dep_map: dict[str, list[str]],
        prefix: str,
        depth: int = 0,
    ) -> None:
        if depth > MAX_MODULE_DEPTH:
            logger.warning("Config module nesting depth %d exceeds limit — skipping", depth)
            return
        for res in module.get("resources", []):
            rtype = res.get("type", "")
            name = res.get("name", "")
            address = f"{prefix}{rtype}.{name}" if not prefix else f"{prefix}.{rtype}.{name}"
            deps = res.get("depends_on", [])
            if deps:
                dep_map[address] = [f"{prefix}.{d}" if prefix else d for d in deps]
            # Also extract implicit dependencies from expressions
            expressions = res.get("expressions", {})
            implicit = self._extract_references(expressions)
            if implicit:
                existing = dep_map.get(address, [])
                dep_map[address] = list(set(existing + implicit))

        for call_key, call_val in module.get("module_calls", {}).items():
            child_module = call_val.get("module", {})
            child_prefix = f"module.{call_key}"
            if prefix:
                child_prefix = f"{prefix}.module.{call_key}"
            self._walk_config_module(child_module, dep_map, prefix=child_prefix, depth=depth + 1)

    def _extract_references(self, expressions: dict[str, Any]) -> list[str]:
        """Extract resource references from HCL expressions."""
        refs: list[str] = []
        for _key, val in expressions.items():
            if isinstance(val, dict):
                for ref in val.get("references", []):
                    if isinstance(ref, str) and not ref.startswith("var."):
                        refs.append(ref)
        return refs
