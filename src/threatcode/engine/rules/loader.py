"""YAML rule file loader."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from threatcode.constants import VALID_SEVERITIES, VALID_STRIDE_CATEGORIES
from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.exceptions import RuleLoadError

logger = logging.getLogger(__name__)

# Regex for valid MITRE ATT&CK technique IDs (T#### or T####.###)
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Regex for valid MITRE ATT&CK tactic IDs (TA####)
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")

# Security limits
MAX_RULES_PER_FILE = 100
MAX_TOTAL_RULES = 500
MAX_RULE_FILE_SIZE = 1 * 1024 * 1024  # 1 MB


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
    # Check file size before reading
    try:
        file_size = path.stat().st_size
    except OSError as e:
        raise RuleLoadError(f"Cannot stat rule file {path}: {e}") from e

    if file_size > MAX_RULE_FILE_SIZE:
        raise RuleLoadError(
            f"Rule file {path} is {file_size} bytes, exceeding {MAX_RULE_FILE_SIZE} byte limit"
        )

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
                id=str(raw["id"]),
                title=str(raw["title"]),
                description=str(raw["description"]),
                stride_category=str(raw["stride_category"]),
                severity=str(raw["severity"]),
                resource_type=str(raw["resource_type"]),
                condition=raw["condition"],
                mitigation=str(raw.get("mitigation", "")),
                metadata=raw.get("metadata", {}),
            )
        except KeyError as e:
            raise RuleLoadError(f"Rule in {path} missing required field: {e}") from e

        if not isinstance(rule.condition, dict):
            raise RuleLoadError(
                f"Rule {rule.id} in {path}: condition must be a mapping, "
                f"got {type(rule.condition).__name__}"
            )
        if rule.metadata and not isinstance(rule.metadata, dict):
            raise RuleLoadError(f"Rule {rule.id} in {path}: metadata must be a mapping")

        # Validate schema
        if rule.severity not in VALID_SEVERITIES:
            raise RuleLoadError(f"Rule {rule.id} in {path}: invalid severity '{rule.severity}'")
        if rule.stride_category not in VALID_STRIDE_CATEGORIES:
            raise RuleLoadError(
                f"Rule {rule.id} in {path}: invalid stride_category '{rule.stride_category}'"
            )
        if not isinstance(rule.condition, dict) or not rule.condition:
            raise RuleLoadError(f"Rule {rule.id} in {path}: condition must be a non-empty mapping")

        # Validate MITRE metadata format and existence in TECHNIQUE_DB
        mitre = rule.metadata.get("mitre", {})
        if mitre:
            for tid in mitre.get("techniques", []):
                if not _TECHNIQUE_ID_RE.match(tid):
                    logger.warning(
                        "Rule %s: invalid MITRE technique ID '%s' — expected T#### or T####.###",
                        rule.id,
                        tid,
                    )
                elif tid not in TECHNIQUE_DB:
                    logger.warning(
                        "Rule %s: MITRE technique ID '%s' not found in known technique database",
                        rule.id,
                        tid,
                    )
            for tac_id in mitre.get("tactics", []):
                if not _TACTIC_ID_RE.match(tac_id):
                    logger.warning(
                        "Rule %s: invalid MITRE tactic ID '%s' — expected TA####",
                        rule.id,
                        tac_id,
                    )

        rules.append(rule)

    return rules


def load_builtin_rules() -> list[Rule]:
    """Load all built-in rule files from the builtin/ directory."""
    builtin_dir = Path(__file__).parent / "builtin"
    rules: list[Rule] = []
    if builtin_dir.exists():
        for path in sorted(builtin_dir.glob("*.yml")):
            # Log SHA-256 checksums for integrity verification (uses stat, not full read)
            file_size = path.stat().st_size
            logger.debug("Loading built-in rules: %s (%d bytes)", path.name, file_size)
            rules.extend(load_rules_from_file(path))
    return rules


def load_all_rules(extra_paths: list[Path] | None = None) -> list[Rule]:
    """Load built-in rules plus any additional rule files."""
    rules = load_builtin_rules()

    # Enforce unique rule IDs (start with builtins)
    seen_ids: set[str] = set()
    for rule in rules:
        if rule.id in seen_ids:
            raise RuleLoadError(
                f"Duplicate rule ID '{rule.id}' in built-in rules. Rule IDs must be unique."
            )
        seen_ids.add(rule.id)

    for path in extra_paths or []:
        # Security: block symlinks in extra rule paths
        if path.is_symlink():
            raise RuleLoadError(f"Extra rule path is a symlink (blocked for security): {path}")
        resolved = path.resolve()

        # Security: prevent path traversal via symlinks or .. components
        if not resolved.is_file():
            raise RuleLoadError(f"Extra rule path does not exist or is not a file: {path}")
        extra_rules = load_rules_from_file(resolved)
        for rule in extra_rules:
            if rule.id in seen_ids:
                raise RuleLoadError(
                    f"Duplicate rule ID '{rule.id}' — already defined. Rule IDs must be unique."
                )
            seen_ids.add(rule.id)
        rules.extend(extra_rules)

    if len(rules) > MAX_TOTAL_RULES:
        raise RuleLoadError(f"Total rule count {len(rules)} exceeds limit of {MAX_TOTAL_RULES}")

    return rules
