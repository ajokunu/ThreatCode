"""Parser auto-detection and dispatch."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from threatcode.exceptions import UnsupportedFormatError

if TYPE_CHECKING:
    from threatcode.parsers.base import ParsedOutput


def detect_and_parse(path: str | Path) -> ParsedOutput:
    """Auto-detect input format and parse it."""
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    content = path.read_text(encoding="utf-8")

    # Try terraform plan JSON first
    if path.suffix == ".json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise UnsupportedFormatError(f"Invalid JSON: {e}") from e

        if "planned_values" in data or "format_version" in data:
            from threatcode.parsers.terraform_plan import TerraformPlanParser

            return TerraformPlanParser().parse(data, source_path=str(path))

        # CloudFormation JSON
        if "AWSTemplateFormatVersion" in data or "Resources" in data:
            from threatcode.parsers.cloudformation import CloudFormationParser

            return CloudFormationParser().parse(data, source_path=str(path))

    # CloudFormation YAML
    if path.suffix in (".yml", ".yaml"):
        import yaml

        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise UnsupportedFormatError(f"Invalid YAML: {e}") from e
        if isinstance(data, dict) and ("AWSTemplateFormatVersion" in data or "Resources" in data):
            from threatcode.parsers.cloudformation import CloudFormationParser

            return CloudFormationParser().parse(data, source_path=str(path))

    # Terraform HCL fallback
    if path.suffix == ".tf":
        from threatcode.parsers.terraform_hcl import TerraformHCLParser

        return TerraformHCLParser().parse_file(path)

    raise UnsupportedFormatError(
        f"Cannot detect format for {path.name}. "
        "Supported: terraform plan JSON, .tf files, CloudFormation YAML/JSON"
    )
