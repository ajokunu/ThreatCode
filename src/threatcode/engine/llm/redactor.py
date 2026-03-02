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
        self._extra_fields = set(extra_fields or [])

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
        for redacted, original in self._reverse.items():
            result = result.replace(redacted, original)
        return result

    def _redact_field(self, key: str, value: Any, depth: int = 0) -> Any:
        """Redact a dict field based on key name."""
        sensitive_keys = {
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
        }
        sensitive_keys.update(self._extra_fields)

        if key.lower() in sensitive_keys:
            if isinstance(value, str):
                return self._get_placeholder(value, key)
            if isinstance(value, dict):
                return {k: self._get_placeholder(str(v), f"{key}.{k}") for k, v in value.items()}
        return self.redact(value, depth + 1)

    def _redact_string(self, text: str) -> str:
        """Apply regex-based redaction to a string."""
        result = text
        for pattern_name, pattern in _PATTERNS.items():
            for match in pattern.finditer(result):
                # For aws_account_id, redact only the captured group (the 12-digit number)
                if pattern_name == "aws_account_id" and match.lastindex:
                    original = match.group(1)
                else:
                    original = match.group()
                if original not in self._mapping:
                    placeholder = self._get_placeholder(original, pattern_name)
                    self._mapping[original] = placeholder
                result = result.replace(original, self._mapping[original])
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
            return f"REDACTED_{label}_overflow"

        if self._strategy == "hash":
            h = hashlib.sha256(original.encode()).hexdigest()[:8]
            placeholder = f"REDACTED_{label}_{h}"
        else:
            self._counter += 1
            placeholder = f"REDACTED_{label}_{self._counter}"

        self._mapping[original] = placeholder
        self._reverse[placeholder] = original
        return placeholder
