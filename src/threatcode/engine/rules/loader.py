"""YAML rule file loader."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from threatcode.exceptions import RuleLoadError

# Security limits
MAX_RULES_PER_FILE = 100
MAX_TOTAL_RULES = 500

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STRIDE_CATEGORIES = {
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
}


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

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise RuleLoadError(f"Rule file {path}: 'rules' must be a list")

    if len(raw_rules) > MAX_RULES_PER_FILE:
        raise RuleLoadError(
            f"Rule file {path} has {len(raw_rules)} rules, exceeding limit of {MAX_RULES_PER_FILE}"
        )

    rules: list[Rule] = []
    for raw in raw_rules:
        if not isinstance(raw, dict):
            raise RuleLoadError(f"Rule in {path} must be a mapping, got {type(raw).__name__}")
        try:
            rule = Rule(
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
        except KeyError as e:
            raise RuleLoadError(f"Rule in {path} missing required field: {e}") from e

        # Validate schema
        if rule.severity not in VALID_SEVERITIES:
            raise RuleLoadError(
                f"Rule {rule.id} in {path}: invalid severity '{rule.severity}'"
            )
        if rule.stride_category not in VALID_STRIDE_CATEGORIES:
            raise RuleLoadError(
                f"Rule {rule.id} in {path}: invalid stride_category '{rule.stride_category}'"
            )
        if not isinstance(rule.condition, dict) or not rule.condition:
            raise RuleLoadError(f"Rule {rule.id} in {path}: condition must be a non-empty mapping")

        rules.append(rule)

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
    if len(rules) > MAX_TOTAL_RULES:
        raise RuleLoadError(
            f"Total rule count {len(rules)} exceeds limit of {MAX_TOTAL_RULES}"
        )
    return rules
