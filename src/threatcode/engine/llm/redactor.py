"""ARN/account/tag/IP redaction before LLM calls.

Security: recursion depth is capped to prevent stack overflow on deeply nested data.
Mapping size is capped to prevent memory exhaustion.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Max recursion depth for nested data structures
MAX_REDACT_DEPTH = 50

# Max unique values tracked in the redaction mapping
MAX_REDACTION_MAPPINGS = 10_000

# Patterns to redact — aws_account_id requires word-boundary context to reduce
# false positives on arbitrary 12-digit numbers
_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_account_id": re.compile(
        r"(?:account[_-]?id|arn:aws)[:\s\"'=]*(\d{12})\b"
    ),
    "aws_arn": re.compile(r"arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:\S+"),
    "ip_v4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "ip_v6": re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
}


_SENSITIVE_KEYS = frozenset({
    "arn",
    "account_id",
    "tags",
    "tag",
    "ip_address",
    "private_ip",
    "public_ip",
    "owner_id",
    "caller_reference",
    "secret",
    "password",
    "token",
    "api_key",
    "access_key",
    "secret_key",
    "connection_string",
    "credentials",
    "private_key",
    "certificate",
    "name",
    "module",
    "provider",
    "source_location",
})


class Redactor:
    """Redacts sensitive values from data before sending to LLM."""

    def __init__(
        self,
        strategy: str = "placeholder",
        extra_fields: list[str] | None = None,
    ) -> None:
        self._strategy = strategy
        self._mapping: dict[str, str] = {}  # original -> redacted
        self._reverse: dict[str, str] = {}  # redacted -> original
        self._counter = 0
        self._sensitive_keys = _SENSITIVE_KEYS | set(extra_fields or [])

    def redact(self, data: Any, _depth: int = 0) -> Any:
        """Recursively redact sensitive values in a data structure."""
        if _depth > MAX_REDACT_DEPTH:
            return "[REDACTED_DEPTH_LIMIT]"

        if isinstance(data, dict):
            return {k: self._redact_field(k, v, _depth) for k, v in data.items()}
        if isinstance(data, list):
            return [self.redact(item, _depth + 1) for item in data]
        if isinstance(data, str):
            return self._redact_string(data)
        return data

    def unredact_string(self, text: str) -> str:
        """Reverse redaction on a string."""
        result = text
        # Sort by longest placeholder first to avoid prefix collisions
        # (e.g. REDACTED_x_10 must be replaced before REDACTED_x_1)
        for redacted, original in sorted(
            self._reverse.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            result = result.replace(redacted, original)
        return result

    def _redact_field(self, key: str, value: Any, depth: int = 0) -> Any:
        """Redact a dict field based on key name."""
        if key.lower() in self._sensitive_keys:
            return self._redact_sensitive_value(value, key, depth)
        return self.redact(value, depth + 1)

    def _redact_sensitive_value(self, value: Any, label: str, depth: int = 0) -> Any:
        """Recursively redact all leaf values under a sensitive key."""
        if depth > MAX_REDACT_DEPTH:
            return "[REDACTED_DEPTH_LIMIT]"
        if isinstance(value, str):
            return self._get_placeholder(value, label)
        if isinstance(value, dict):
            return {
                k: self._redact_sensitive_value(v, f"{label}.{k}", depth + 1)
                for k, v in value.items()
            }
        if isinstance(value, list):
            return [
                self._redact_sensitive_value(item, f"{label}[]", depth + 1)
                for item in value
            ]
        # Non-string primitives (int, float, bool) — redact as string
        if value is not None:
            return self._get_placeholder(str(value), label)
        return value

    def _redact_string(self, text: str) -> str:
        """Apply regex-based redaction to a string."""
        result = text
        for pattern_name, pattern in _PATTERNS.items():
            # Collect all matches from current result (not original text),
            # so each pattern sees the output of previous patterns
            matches: list[str] = []
            for match in pattern.finditer(result):
                if pattern_name == "aws_account_id" and match.lastindex:
                    matches.append(match.group(1))
                else:
                    matches.append(match.group())
            # Deduplicate while preserving order, then replace
            seen: set[str] = set()
            for original in matches:
                if original in seen:
                    continue
                seen.add(original)
                placeholder = self._get_placeholder(original, pattern_name)
                result = result.replace(original, placeholder)
        return result

    def _get_placeholder(self, original: str, label: str) -> str:
        if original in self._mapping:
            return self._mapping[original]

        # Cap mapping size to prevent memory exhaustion
        if len(self._mapping) >= MAX_REDACTION_MAPPINGS:
            logger.warning(
                "Redaction mapping limit reached (%d entries) — using generic placeholder",
                MAX_REDACTION_MAPPINGS,
            )
            placeholder = f"REDACTED_{label}_overflow"
            # Don't grow _mapping, but still allow reverse lookup
            self._reverse[placeholder] = original
            return placeholder

        if self._strategy == "hash":
            h = hashlib.sha256(original.encode()).hexdigest()[:8]
            placeholder = f"REDACTED_{label}_{h}"
        else:
            self._counter += 1
            placeholder = f"REDACTED_{label}_{self._counter}"

        self._mapping[original] = placeholder
        self._reverse[placeholder] = original
        return placeholder
