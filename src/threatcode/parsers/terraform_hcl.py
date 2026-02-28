"""Terraform HCL fallback parser for raw .tf files."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from threatcode.exceptions import ParseError
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource


class TerraformHCLParser(BaseParser):
    """Parse raw .tf files via python-hcl2 (fallback when plan JSON unavailable)."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if not isinstance(data, dict):
            raise ParseError("HCL parse result must be a dict")
        return self._extract_resources(data, source_path)

    def parse_file(self, path: Path) -> ParsedOutput:
        try:
            import hcl2
        except ImportError as e:
            raise ParseError("python-hcl2 required: pip install python-hcl2") from e

        try:
            with open(path, encoding="utf-8") as f:
                data = hcl2.load(f)
        except Exception as e:
            raise ParseError(f"Failed to parse HCL file {path}: {e}") from e

        return self._extract_resources(data, str(path))

    def _extract_resources(self, data: dict[str, Any], source_path: str) -> ParsedOutput:
        resources: list[ParsedResource] = []

        for block in data.get("resource", []):
            if not isinstance(block, dict):
                continue
            for rtype, instances in block.items():
                if not isinstance(instances, dict):
                    continue
                for name, config in instances.items():
                    props = config if isinstance(config, dict) else {}
                    resources.append(
                        ParsedResource(
                            resource_type=rtype,
                            address=f"{rtype}.{name}",
                            name=name,
                            provider=_infer_provider(rtype),
                            properties=props,
                            source_location=source_path,
                        )
                    )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="terraform_hcl",
        )


def _infer_provider(resource_type: str) -> str:
    prefix = resource_type.split("_")[0]
    return {
        "aws": "hashicorp/aws",
        "azurerm": "hashicorp/azurerm",
        "google": "hashicorp/google",
    }.get(prefix, prefix)
