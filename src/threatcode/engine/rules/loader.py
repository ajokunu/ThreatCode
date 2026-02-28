"""YAML rule file loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from threatcode.exceptions import RuleLoadError


@dataclass
class Rule:
    id: str
    title: str
    description: str
    stride_category: str
    severity: str
    resource_type: str
    condition: dict[str, Any]
    mitigation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def load_rules_from_file(path: Path) -> list[Rule]:
    """Load rules from a single YAML file."""
    try:
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except (OSError, yaml.YAMLError) as e:
        raise RuleLoadError(f"Failed to load rule file {path}: {e}") from e

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoadError(f"Rule file {path} must contain a 'rules' key")

    rules: list[Rule] = []
    for raw in data["rules"]:
        try:
            rules.append(
                Rule(
                    id=raw["id"],
                    title=raw["title"],
                    description=raw["description"],
                    stride_category=raw["stride_category"],
                    severity=raw["severity"],
                    resource_type=raw["resource_type"],
                    condition=raw["condition"],
                    mitigation=raw.get("mitigation", ""),
                    metadata=raw.get("metadata", {}),
                )
            )
        except KeyError as e:
            raise RuleLoadError(f"Rule in {path} missing required field: {e}") from e

    return rules


def load_builtin_rules() -> list[Rule]:
    """Load all built-in rule files from the builtin/ directory."""
    builtin_dir = Path(__file__).parent / "builtin"
    rules: list[Rule] = []
    if builtin_dir.exists():
        for path in sorted(builtin_dir.glob("*.yml")):
            rules.extend(load_rules_from_file(path))
    return rules


def load_all_rules(extra_paths: list[Path] | None = None) -> list[Rule]:
    """Load built-in rules plus any additional rule files."""
    rules = load_builtin_rules()
    for path in extra_paths or []:
        rules.extend(load_rules_from_file(path))
    return rules
