"""Secret detection rule definitions and the value checks every detector shares.

A rule's regex captures the secret itself in a named group ``secret``.
Everything that decides whether a match is real (allow-lists, placeholders, templates, length and
character mix) looks at that captured value and never at the surrounding text, so a key name such
as ``TestPassword`` or a host such as ``db.latest-prod.internal`` cannot suppress a real secret.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final, Literal

__all__ = [
    "SecretRule",
    "char_classes",
    "has_template_marker",
    "is_env_var_name",
    "is_placeholder",
    "is_reference",
    "shannon_entropy",
]

RuleKind = Literal["provider", "structure", "generic"]
"""``provider``: a token with a distinctive shape.
``structure``: a credential in a recognisable syntax (URL userinfo, an Authorization header).
``generic``: a literal value under a credential-like key, which needs the length and character
mix checks because the key name is the only evidence.
"""

KIND_PRIORITY: Final[dict[str, int]] = {"provider": 0, "structure": 1, "generic": 2}

# Markers of a value that is computed or substituted at deploy time, not a literal.
TEMPLATE_MARKERS: Final[tuple[str, ...]] = ("{{", "{%", "${", "$(", "<%", "#{", "%{", "{$")

_PLACEHOLDER: Final = re.compile(
    r"(?is)^(?:"
    r"example|sample|dummy|fake|placeholder|test|todo|tbd|null|none|nil|undefined|"
    r"redacted|secret|password|passwd|token|api[_-]?key|"
    r"change[-_ ]?me(?:[-_ ].*)?|replace[-_ ]?me(?:[-_ ].*)?|replace[-_]with.*|insert[-_ ].*|"
    r"your[-_ ].*|.*[-_ ]here|"
    r"x{3,}|\*{3,}|\.{3,}|-{3,}|0{6,}|"
    r"<[^<>]*>|\[[^\[\]]*\]|"
    # How a Terraform plan masks a sensitive or not yet known value
    r"\([^()]{0,40}\)|sensitive(?:[ _]value)?|known[ _]after[ _]apply"
    r")$"
)
_ENV_VAR_NAME: Final = re.compile(r"^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$")
# A dotted identifier chain such as var.db_password, data.x.y.result or each.value
_REFERENCE: Final = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\s]{0,64}\])?"
    r"(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]\s]{0,64}\])?)+$"
)
_SYMBOL_FREE: Final = frozenset("_-.")
# A file path or a URL names where a credential lives, it is not the credential
_PATH_OR_URL: Final = re.compile(
    r"^(?:[/~]|\.{1,2}/|[A-Za-z]:[\\/]|\\\\|[A-Za-z][A-Za-z0-9+.\-]*://)"
)


def has_template_marker(value: str) -> bool:
    """True when the value holds a template or substitution marker such as ``{{ }}`` or ``${X}``."""
    return any(marker in value for marker in TEMPLATE_MARKERS)


def is_placeholder(value: str) -> bool:
    """True when the whole value is a placeholder word, mask or ``<angle bracket>`` stand-in."""
    return bool(_PLACEHOLDER.match(value.strip()))


def is_env_var_name(value: str) -> bool:
    """True for an ALL_CAPS_WITH_UNDERSCORES name such as ``ANTHROPIC_AUTH_TOKEN``."""
    return bool(_ENV_VAR_NAME.match(value))


def is_reference(value: str) -> bool:
    """True for a dotted identifier chain, the shape of a Terraform or template reference."""
    return bool(_REFERENCE.match(value))


def char_classes(value: str) -> int:
    """How many of lower case, upper case, digit and symbol the value uses.

    ``_``, ``-`` and ``.`` do not count as symbols, so ``my_secret_value`` has one class.
    """
    lower = upper = digit = symbol = False
    for ch in value:
        if ch.islower():
            lower = True
        elif ch.isupper():
            upper = True
        elif ch.isdigit():
            digit = True
        elif not ch.isspace() and ch not in _SYMBOL_FREE:
            symbol = True
    return lower + upper + digit + symbol


def _has_digit_or_symbol(value: str) -> bool:
    return any(
        ch.isdigit() or not (ch.isalpha() or ch.isspace() or ch in _SYMBOL_FREE) for ch in value
    )


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


@dataclass
class SecretRule:
    """A single secret detection pattern.

    ``keywords`` are lower-cased at construction and compared with the lower-cased text, so the
    prefilter is as case-insensitive as the ``(?i)`` regexes behind it.
    ``allow_values`` are searched in the captured value only.
    ``allow_hosts`` are searched in the ``host`` group, so ``localhost`` allow-lists a local
    database URL without letting the word excuse a URL that mentions it elsewhere.
    ``requires`` must match somewhere in the file for the rule to run at all.
    """

    id: str
    category: str
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    regex: re.Pattern[str]
    keywords: Sequence[str] = ()
    kind: RuleKind = "provider"
    path_filter: re.Pattern[str] | None = None
    allow_values: Sequence[re.Pattern[str]] = ()
    allow_hosts: Sequence[re.Pattern[str]] = ()
    requires: re.Pattern[str] | None = None
    min_length: int = 0
    min_classes: int = 0
    # The value needs a digit or a symbol, so a plain word is never taken for a password.
    needs_non_alpha: bool = False
    min_entropy: float = 0.0
    # Whether the text before the secret names a key worth reporting as the attribute
    keyed: bool = True
    description: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        self.keywords = tuple(dict.fromkeys(kw.lower() for kw in self.keywords))

    def matches_path(self, file_path: str) -> bool:
        """Check if this rule applies to the given file path."""
        return not (self.path_filter and not self.path_filter.search(file_path))

    @staticmethod
    def secret_of(match: re.Match[str]) -> tuple[str, int, int]:
        """The secret value of a match and its span; the whole match when no group captures."""
        if "secret" in match.re.groupindex and match.group("secret") is not None:
            return match.group("secret"), match.start("secret"), match.end("secret")
        return match.group(0), match.start(), match.end()

    def is_allowed(self, value: str) -> bool:
        """True when the captured value is excluded: a placeholder, a template or allow-listed."""
        if is_placeholder(value) or has_template_marker(value):
            return True
        return any(allow.search(value) for allow in self.allow_values)

    def accepts(self, value: str, *, quoted: bool = True, host: str = "") -> bool:
        """Whether a captured value is a real secret for this rule."""
        if not value or self.is_allowed(value):
            return False
        if host and any(allow.search(host) for allow in self.allow_hosts):
            return False
        if len(value) < self.min_length:
            return False
        if self.kind == "generic":
            if is_env_var_name(value) or _PATH_OR_URL.match(value):
                return False
            if not quoted and is_reference(value):
                return False
        if self.min_classes and char_classes(value) < self.min_classes:
            return False
        if self.needs_non_alpha and not _has_digit_or_symbol(value):
            return False
        return not (self.min_entropy and shannon_entropy(value) < self.min_entropy)
