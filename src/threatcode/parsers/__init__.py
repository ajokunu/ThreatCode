"""Parser auto-detection and dispatch via pluggable registry."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from threatcode.exceptions import ParseError, UnsupportedFormatError

if TYPE_CHECKING:
    from threatcode.parsers.base import BaseParser, ParsedOutput

# Reject plan files larger than 50 MB to prevent resource exhaustion
MAX_INPUT_SIZE_BYTES = 50 * 1024 * 1024


@dataclass
class ParserEntry:
    """Registry entry for a parser."""

    name: str
    detector: Callable[[Path, str, Any | None], bool]
    factory: Callable[[], BaseParser]
    extensions: frozenset[str] = field(default_factory=frozenset)
    priority: int = 100


_REGISTRY: list[ParserEntry] = []


def register_parser(
    name: str,
    detector: Callable[[Path, str, Any | None], bool],
    factory: Callable[[], BaseParser],
    extensions: frozenset[str] | set[str] | None = None,
    priority: int = 100,
) -> None:
    """Register a custom parser.

    Args:
        name: Human-readable parser name.
        detector: Function(path, content, parsed_data) → bool. Called to check if this
            parser handles the given file. `parsed_data` is the JSON/YAML-parsed dict
            if available, else None.
        factory: Callable that returns a BaseParser instance.
        extensions: File extensions this parser handles (e.g., {".yaml", ".yml"}).
        priority: Lower number = checked first. Built-in parsers use 10-30.
    """
    entry = ParserEntry(
        name=name,
        detector=detector,
        factory=factory,
        extensions=frozenset(extensions or set()),
        priority=priority,
    )
    _REGISTRY.append(entry)
    _REGISTRY.sort(key=lambda e: e.priority)


def detect_and_parse(path: str | Path) -> ParsedOutput:
    """Auto-detect input format and parse it."""
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

    file_size = path.stat().st_size
    if file_size > MAX_INPUT_SIZE_BYTES:
        raise ParseError(
            f"Input file {path.name} is {file_size / 1024 / 1024:.1f} MB, "
            f"exceeding the {MAX_INPUT_SIZE_BYTES // 1024 // 1024} MB limit."
        )

    content = path.read_text(encoding="utf-8")

    # Pre-parse structured data if possible
    parsed_data: Any = None
    if path.suffix == ".json":
        try:
            parsed_data = json.loads(content)
        except json.JSONDecodeError as e:
            raise UnsupportedFormatError(f"Invalid JSON: {e}") from e
    elif path.suffix in (".yml", ".yaml"):
        import yaml

        try:
            parsed_data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            raise UnsupportedFormatError(f"Invalid YAML: {e}") from e

    # Check registered parsers in priority order
    for entry in _REGISTRY:
        if entry.extensions and path.suffix not in entry.extensions:
            continue
        try:
            if entry.detector(path, content, parsed_data):
                parser = entry.factory()
                if hasattr(parser, "parse_file") and parsed_data is None:
                    return parser.parse_file(path)  # type: ignore[union-attr]
                return parser.parse(parsed_data or content, source_path=str(path))
        except (ParseError, UnsupportedFormatError):
            raise
        except Exception:
            continue

    raise UnsupportedFormatError(
        f"Cannot detect format for {path.name}. "
        "Supported: terraform plan JSON, .tf files, CloudFormation YAML/JSON"
    )


# ── Built-in parser registration ──────────────────────────────────────


def _detect_terraform_plan(path: Path, content: str, data: Any) -> bool:
    return (
        path.suffix == ".json"
        and isinstance(data, dict)
        and ("planned_values" in data or "format_version" in data)
    )


def _detect_cloudformation(path: Path, content: str, data: Any) -> bool:
    return isinstance(data, dict) and (
        "AWSTemplateFormatVersion" in data or "Resources" in data
    )


def _detect_terraform_hcl(path: Path, content: str, data: Any) -> bool:
    return path.suffix == ".tf"


def _factory_terraform_plan() -> BaseParser:  # type: ignore[type-arg]
    from threatcode.parsers.terraform_plan import TerraformPlanParser

    return TerraformPlanParser()


def _factory_cloudformation() -> BaseParser:  # type: ignore[type-arg]
    from threatcode.parsers.cloudformation import CloudFormationParser

    return CloudFormationParser()


def _factory_terraform_hcl() -> BaseParser:  # type: ignore[type-arg]
    from threatcode.parsers.terraform_hcl import TerraformHCLParser

    return TerraformHCLParser()


register_parser(
    name="terraform_plan",
    detector=_detect_terraform_plan,
    factory=_factory_terraform_plan,
    extensions=frozenset({".json"}),
    priority=10,
)

register_parser(
    name="cloudformation",
    detector=_detect_cloudformation,
    factory=_factory_cloudformation,
    extensions=frozenset({".json", ".yml", ".yaml"}),
    priority=20,
)

register_parser(
    name="terraform_hcl",
    detector=_detect_terraform_hcl,
    factory=_factory_terraform_hcl,
    extensions=frozenset({".tf"}),
    priority=30,
)
