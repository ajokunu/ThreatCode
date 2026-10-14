"""Secret scanner configuration.

A scanned repository is untrusted input, so the ``secrets`` section of a configuration file is read
only from a file the user named with ``--config``.
A ``.threatcode.yml`` found inside the scanned tree must never be able to switch off the secret
detectors that protect the tree, which is why ``SecretScanConfig.from_mapping`` exists as a separate
step the caller applies to an explicit configuration only.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, cast

logger = logging.getLogger(__name__)

# Longest user supplied pattern, to keep a hostile configuration from compiling a ReDoS bomb
MAX_PATTERN_LENGTH = 500

DEFAULT_MAX_FILE_SIZE = 5 * 1024 * 1024
DEFAULT_MAX_FINDINGS_PER_FILE = 100
DEFAULT_MAX_FINDINGS_PER_RULE = 25

_SEVERITIES = ("critical", "high", "medium", "low")


@dataclass
class ExtraRule:
    """A user supplied detection rule: an id, a regex with an optional ``secret`` group."""

    id: str
    regex: str
    keywords: Sequence[str] = ()
    severity: str = "high"
    title: str = ""


@dataclass
class SecretScanConfig:
    """Configuration for secret scanning."""

    # Files larger than this are not scanned and are reported as a coverage gap
    max_file_size: int = DEFAULT_MAX_FILE_SIZE

    # Regexes searched in the captured secret value; a match suppresses the finding
    allow_patterns: list[str] = field(default_factory=list)

    # Ids of built-in rules to switch off
    disabled_rules: list[str] = field(default_factory=list)

    # Additional rules
    extra_rules: list[ExtraRule] = field(default_factory=list)

    # Findings kept per file and per rule; the rest are dropped and the file is marked truncated
    max_findings_per_file: int = DEFAULT_MAX_FINDINGS_PER_FILE
    max_findings_per_rule: int = DEFAULT_MAX_FINDINGS_PER_RULE

    # Turns on the high-entropy fallback rule when set (bits per character, for example 3.5)
    entropy_threshold: float | None = None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> SecretScanConfig:
        """Build a config from the ``secrets`` section of a configuration file.

        Unknown keys and malformed entries are logged and ignored, never raised, so one typo does
        not turn the secret scan off.
        """
        config = cls()
        if not data:
            return config
        if not isinstance(data, Mapping):
            logger.warning("The 'secrets' configuration section must be a mapping; ignored")
            return config
        known = {
            "max_file_size",
            "allow_patterns",
            "disabled_rules",
            "extra_rules",
            "max_findings_per_file",
            "max_findings_per_rule",
            "entropy_threshold",
        }
        for key in data:
            if key not in known:
                logger.warning("Unknown 'secrets' configuration key '%s' ignored", key)
        config.max_file_size = _positive_int(data, "max_file_size", config.max_file_size)
        config.max_findings_per_file = _positive_int(
            data, "max_findings_per_file", config.max_findings_per_file
        )
        config.max_findings_per_rule = _positive_int(
            data, "max_findings_per_rule", config.max_findings_per_rule
        )
        config.allow_patterns = _string_list(data, "allow_patterns")
        config.disabled_rules = _string_list(data, "disabled_rules")
        threshold = data.get("entropy_threshold")
        if (
            isinstance(threshold, (int, float))
            and not isinstance(threshold, bool)
            and threshold > 0
        ):
            config.entropy_threshold = float(threshold)
        elif threshold is not None:
            logger.warning("'secrets.entropy_threshold' must be a positive number; ignored")
        for entry in data.get("extra_rules") or []:
            rule = _extra_rule(entry)
            if rule is not None:
                config.extra_rules.append(rule)
        return config


def _positive_int(data: Mapping[str, Any], key: str, default: int) -> int:
    value = data.get(key)
    if value is None:
        return default
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    logger.warning("'secrets.%s' must be a positive integer; using %d", key, default)
    return default


def _string_list(data: Mapping[str, Any], key: str) -> list[str]:
    value = data.get(key)
    if value is None:
        return []
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(cast("list[str]", value))
    logger.warning("'secrets.%s' must be a list of strings; ignored", key)
    return []


def _extra_rule(entry: Any) -> ExtraRule | None:
    if not isinstance(entry, Mapping):
        logger.warning("A 'secrets.extra_rules' entry must be a mapping; ignored")
        return None
    rule_id = entry.get("id")
    regex = entry.get("regex")
    if not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{2,63}", rule_id):
        logger.warning("A 'secrets.extra_rules' entry needs an 'id' such as MY_TOKEN; ignored")
        return None
    if not isinstance(regex, str) or not regex or len(regex) > MAX_PATTERN_LENGTH:
        logger.warning("Extra secret rule '%s' needs a 'regex' of at most 500 characters", rule_id)
        return None
    try:
        re.compile(regex)
    except re.error:
        logger.warning("Extra secret rule '%s' has an invalid regex; ignored", rule_id)
        return None
    keywords = entry.get("keywords") or []
    severity = entry.get("severity", "high")
    if severity not in _SEVERITIES:
        logger.warning("Extra secret rule '%s' has an unknown severity; using high", rule_id)
        severity = "high"
    return ExtraRule(
        id=rule_id,
        regex=regex,
        keywords=[k for k in keywords if isinstance(k, str)] if isinstance(keywords, list) else [],
        severity=str(severity),
        title=str(entry.get("title") or rule_id),
    )
