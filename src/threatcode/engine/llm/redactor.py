"""Redaction before LLM calls: sensitive keys, secret-shaped values, ARNs, accounts and addresses.

Security:
- Keys are matched by substring (``db_password``, ``aws_secret_access_key``, ``user_data``), not
  by exact name, so a variant spelling is still caught.
- Values are scanned for secret shapes (cloud keys, tokens, JWTs, PEM blocks, webhook URLs, URL
  userinfo) with the secret scanner's own patterns, whatever key they sit under.
- ``redact_allowlisted`` is deny by default: only the paths it is given survive.
- The mapping is capped; past the cap redaction fails closed with ``LLMError`` instead of sharing
  one placeholder between different values.
- The ``hash`` strategy is an HMAC keyed with a random per-run key held in memory only, so the
  provider cannot confirm a guessed value by hashing it.
- Recursion depth is capped to prevent stack overflow on deeply nested data.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import os
import re
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from threatcode.exceptions import LLMError

logger = logging.getLogger(__name__)

# Max recursion depth for nested data structures
MAX_REDACT_DEPTH = 50

# Max unique values tracked in the redaction mapping
MAX_REDACTION_MAPPINGS = 10_000

# Hex characters of the keyed digest kept by the ``hash`` strategy (64 bits).
HASH_HEX_LENGTH = 16

# A key containing any of these is sensitive, wherever it sits.
SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "key",
    "credential",
    "authorization",
    "user_data",
    "connection",
    "private",
    "certificate",
    "cookie",
)

# Exact (case-insensitive) key names that are sensitive too.
_SENSITIVE_KEYS = frozenset(
    {
        "arn",
        "account_id",
        "owner_id",
        "tags",
        "tag",
        "ip_address",
        "private_ip",
        "public_ip",
        "caller_reference",
        "pwd",
        "auth",
        "name",
        "module",
        "provider",
        "source_location",
        "source_file",
        "start_line",
        "end_line",
    }
)

# Placeholders for these labels name a resource or a network location, not a secret, so they may
# be written back into a finding about that same resource.
RESTORABLE_LABELS = frozenset({"aws_arn", "ip_v4", "ip_v6", "aws_account_id", "arn", "boundary"})

# Values that name no one in particular and matter to the analysis: "any address".
_KEEP_IPV4 = frozenset({"0.0.0.0", "127.0.0.1"})
_KEEP_IPV6 = frozenset({"::", "::1"})

_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]+-----.*?(?:-----END [A-Z0-9 ]+-----|\Z)", re.DOTALL)

# Secret shapes found without a keyword, in the order they are tried.
_SECRET_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\b[rp]k_live_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"\bxox[abprso]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]*"),
    re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+"),
    re.compile(r"https://discord(?:app)?\.com/api/webhooks/[A-Za-z0-9/_\-]+"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
)

_URL_USERINFO = re.compile(
    r"(?P<scheme>\b[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<auth>[^/\s@\"'<>]+@[^/\s?#\"'<>]+)"
)
_AWS_ARN = re.compile(r"arn:aws[a-zA-Z-]*:[a-zA-Z0-9-]+:[^\s\"'<>,]+")
# 12 digits count as an account id only next to a word that says so.
_ACCOUNT_CONTEXT = re.compile(
    r"(?i)(?:account[_-]?id|source[_-]?account|principal[_-]?account|source[_-]?owner"
    r"|\baws[\"']?\s*:\s*\[?)[:\s\"'=]*(\d{12})\b"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:.])")

# Kept for the documentation and tests: every pattern name a placeholder can carry.
PATTERN_LABELS: tuple[str, ...] = (
    "secret",
    "pem",
    "url_userinfo",
    "aws_arn",
    "aws_account_id",
    "email",
    "ip_v4",
    "ip_v6",
)


def _label_of(key: str) -> str:
    """A placeholder label from a key: lowercase, with anything odd replaced."""
    return re.sub(r"[^a-z0-9_]", "_", key.lower()) or "value"


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
        self._labels: dict[str, str] = {}  # redacted -> label
        self._counter = 0
        self._extra_keys = frozenset(f.lower() for f in extra_fields or [])
        # Per-run key for the hash strategy; never written anywhere.
        self._hmac_key = os.urandom(32)
        self._scope: str | None = None
        self._scoped: dict[str, set[str]] = {}
        self._secret_rules = _load_secret_rules()

    @property
    def strategy(self) -> str:
        return self._strategy

    @property
    def mapping_size(self) -> int:
        return len(self._mapping)

    # ------------------------------------------------------------------ redaction

    def redact(self, data: Any, _depth: int = 0) -> Any:
        """Recursively redact sensitive values in a data structure."""
        if _depth > MAX_REDACT_DEPTH:
            return "[REDACTED_DEPTH_LIMIT]"

        if isinstance(data, dict):
            return {k: self._redact_field(str(k), v, _depth) for k, v in data.items()}
        if isinstance(data, list | tuple):
            return [self.redact(item, _depth + 1) for item in data]
        if isinstance(data, str):
            return self._redact_string(data)
        return data

    def redact_text(self, text: str) -> str:
        """Redact the secret-shaped and address-shaped parts of one string."""
        return self._redact_string(text)

    def placeholder_for(self, value: str, label: str) -> str:
        """The placeholder that stands for ``value`` (made on first use)."""
        return self._get_placeholder(value, _label_of(label))

    def redact_allowlisted(self, data: Any, allowed: Mapping[str, Any], _depth: int = 0) -> Any:
        """Keep only the keys ``allowed`` names and scrub what is kept (deny by default).

        ``allowed`` maps a key (case-insensitive) to ``True``, which keeps the whole value, or to
        a mapping of the same shape for the keys inside it.
        A list is walked element by element with the same allowlist.
        Kept strings are scrubbed for secret-shaped and address-shaped content, and the values
        below a ``True`` entry go through ``redact`` in full, so a secret nested under an allowed
        key is still caught.
        Anything not named is dropped.
        """
        if _depth > MAX_REDACT_DEPTH:
            return "[REDACTED_DEPTH_LIMIT]"
        if isinstance(data, list | tuple):
            return [
                kept
                for item in data
                if (kept := self.redact_allowlisted(item, allowed, _depth + 1)) is not _DROPPED
            ]
        if not isinstance(data, dict):
            # A scalar where the allowlist expects keys names nothing it allows.
            return _DROPPED
        lowered = {str(k).lower(): v for k, v in allowed.items()}
        result: dict[str, Any] = {}
        for key, value in data.items():
            rule = lowered.get(str(key).lower())
            if rule is None:
                continue
            if str(key).lower() in self._extra_keys:
                # The user named this field as sensitive; that wins over the allowlist.
                result[key] = self._redact_sensitive_value(value, _label_of(str(key)), _depth + 1)
                continue
            if rule is True:
                result[key] = self._keep(value, _depth + 1)
                continue
            if isinstance(rule, Mapping):
                kept = self.redact_allowlisted(value, rule, _depth + 1)
                if kept is not _DROPPED:
                    result[key] = kept
        return result

    def _keep(self, value: Any, depth: int) -> Any:
        """An explicitly allowed value: scalars are scrubbed, containers redacted in full."""
        if isinstance(value, str):
            return self._redact_string(value)
        if isinstance(value, dict | list | tuple):
            return self.redact(value, depth)
        return value

    # ------------------------------------------------------------------ restoring

    @contextmanager
    def scope(self, name: str) -> Iterator[None]:
        """Remember which placeholders are issued while this block runs, under ``name``."""
        previous = self._scope
        self._scope = name
        self._scoped.setdefault(name, set())
        try:
            yield
        finally:
            self._scope = previous

    def unredact_string(
        self,
        text: str,
        *,
        scope: str | None = None,
        labels: frozenset[str] | None = None,
    ) -> str:
        """Reverse redaction on a string.

        With no arguments every placeholder is restored.
        ``scope`` limits restoring to placeholders issued inside ``scope(name)``, and ``labels``
        to placeholders of those labels, so text written by a model can name the one resource it
        is about without echoing an unrelated secret back into a report.
        """
        allowed: set[str] | None = None
        if scope is not None:
            allowed = self._scoped.get(scope, set())
        result = text
        # Sort by longest placeholder first to avoid prefix collisions
        # (e.g. REDACTED_x_10 must be replaced before REDACTED_x_1)
        for redacted, original in sorted(
            self._reverse.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            if allowed is not None and redacted not in allowed:
                continue
            if labels is not None and self._labels.get(redacted) not in labels:
                continue
            result = result.replace(redacted, original)
        return result

    # ------------------------------------------------------------------ internals

    def _is_sensitive_key(self, key: str) -> bool:
        lowered = key.lower()
        if lowered in _SENSITIVE_KEYS or lowered in self._extra_keys:
            return True
        return any(part in lowered for part in SENSITIVE_KEY_PARTS)

    def _redact_field(self, key: str, value: Any, depth: int = 0) -> Any:
        """Redact a dict field based on key name."""
        if self._is_sensitive_key(key):
            return self._redact_sensitive_value(value, _label_of(key), depth)
        return self.redact(value, depth + 1)

    def _redact_sensitive_value(self, value: Any, label: str, depth: int = 0) -> Any:
        """Recursively redact all leaf values under a sensitive key."""
        if depth > MAX_REDACT_DEPTH:
            return "[REDACTED_DEPTH_LIMIT]"
        if isinstance(value, str):
            return self._get_placeholder(value, label)
        if isinstance(value, dict):
            return {k: self._redact_sensitive_value(v, label, depth + 1) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [self._redact_sensitive_value(item, label, depth + 1) for item in value]
        # A flag says nothing secret ("enable_key_rotation": true); other primitives are redacted
        if isinstance(value, bool) or value is None:
            return value
        return self._get_placeholder(str(value), label)

    def _redact_string(self, text: str) -> str:
        """Redact secret shapes, URL credentials, ARNs, accounts, emails and addresses."""
        if not text:
            return text
        result = text
        result = _PEM_BLOCK.sub(self._replacer("pem"), result)
        # Credential URLs go whole (userinfo and host) before the secret rules, which would
        # otherwise redact only the password and leave the user name and host behind
        result = _URL_USERINFO.sub(self._userinfo_replacer, result)
        lowered = result.lower()
        for rule_regex, keywords in self._secret_rules:
            if keywords and not any(k in lowered for k in keywords):
                continue
            result = rule_regex.sub(self._group_replacer("secret"), result)
        for pattern in _SECRET_PATTERNS:
            result = pattern.sub(self._replacer("secret"), result)
        result = _AWS_ARN.sub(self._replacer("aws_arn"), result)
        result = _ACCOUNT_CONTEXT.sub(self._group_replacer("aws_account_id"), result)
        result = _EMAIL.sub(self._replacer("email"), result)
        result = _IPV4.sub(self._ipv4_replacer, result)
        result = _IPV6.sub(self._ipv6_replacer, result)
        return result

    def _replacer(self, label: str) -> Callable[[re.Match[str]], str]:
        def replace(match: re.Match[str]) -> str:
            text = match.group()
            if "REDACTED_" in text:
                return text
            return self._get_placeholder(text, label)

        return replace

    def _group_replacer(self, label: str) -> Callable[[re.Match[str]], str]:
        """Replace the ``secret`` group of a match, else its last group (else the whole match)."""

        def replace(match: re.Match[str]) -> str:
            if not match.re.groups:
                text = match.group()
                return text if "REDACTED_" in text else self._get_placeholder(text, label)
            # Rules with a named ``secret`` group (credential URLs and connection strings also
            # capture the host after it) must redact that group, not whichever group matched last
            group = match.re.groupindex.get("secret") or match.lastindex or 1
            secret = match.group(group)
            if not secret or "REDACTED_" in secret:
                return match.group()
            start, end = match.span(group)
            offset = match.start()
            whole = match.group()
            return (
                whole[: start - offset]
                + self._get_placeholder(secret, label)
                + whole[end - offset :]
            )

        return replace

    def _userinfo_replacer(self, match: re.Match[str]) -> str:
        auth = match.group("auth")
        if "REDACTED_" in auth:
            return match.group()
        return match.group("scheme") + self._get_placeholder(auth, "url_userinfo")

    def _ipv4_replacer(self, match: re.Match[str]) -> str:
        address = match.group()
        if address in _KEEP_IPV4:
            return address
        return self._get_placeholder(address, "ip_v4")

    def _ipv6_replacer(self, match: re.Match[str]) -> str:
        candidate = match.group()
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            return candidate
        if candidate in _KEEP_IPV6:
            return candidate
        return self._get_placeholder(candidate, "ip_v6")

    def _digest(self, original: str) -> str:
        return hmac.new(self._hmac_key, original.encode(), hashlib.sha256).hexdigest()[
            :HASH_HEX_LENGTH
        ]

    def _get_placeholder(self, original: str, label: str) -> str:
        existing = self._mapping.get(original)
        if existing is not None:
            self._note_issued(existing)
            return existing

        # Fail closed: sharing one placeholder between different values would let the model's
        # answer be restored to the wrong value, and dropping values silently would hide gaps.
        if len(self._mapping) >= MAX_REDACTION_MAPPINGS:
            raise LLMError(
                f"Redaction mapping limit reached ({MAX_REDACTION_MAPPINGS} distinct values); "
                "nothing is sent to the model"
            )

        if self._strategy == "hash":
            placeholder = f"REDACTED_{label}_{self._digest(original)}"
        else:
            self._counter += 1
            placeholder = f"REDACTED_{label}_{self._counter}"

        self._mapping[original] = placeholder
        self._reverse[placeholder] = original
        self._labels[placeholder] = label
        self._note_issued(placeholder)
        return placeholder

    def _note_issued(self, placeholder: str) -> None:
        if self._scope is not None:
            self._scoped[self._scope].add(placeholder)


class _Dropped:
    """Marks a value the allowlist removed (None is a real value)."""


_DROPPED: Any = _Dropped()


def _load_secret_rules() -> list[tuple[re.Pattern[str], tuple[str, ...]]]:
    """The secret scanner's patterns with their keyword prefilters, allow rules ignored.

    Allow rules exist to quiet false positives in a report; for redaction an over-match costs
    nothing and a miss leaks, so they are not applied.
    """
    from threatcode.engine.secrets.builtin import get_builtin_rules

    rules: list[tuple[re.Pattern[str], tuple[str, ...]]] = []
    for rule in get_builtin_rules():
        rules.append((rule.regex, tuple(k.lower() for k in rule.keywords)))
    return rules
