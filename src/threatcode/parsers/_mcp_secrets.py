"""Literal credential detection for MCP server entries.

This is the only MCP module that imports ``threatcode.engine.secrets``.
It scans every place a config can hold a credential: ``env`` values, ``headers``, the URL
(userinfo password, query parameters and, with lower confidence, a long token in the path)
and the effective launch arguments (``-e KEY=VALUE``, ``--flag=value``, ``--flag value``,
``--header 'Authorization: Bearer ...'`` and ``Bearer ...`` strings).

A value counts as a placeholder only when the whole value is a reference or template:
``${VAR}``, ``${env:VAR}``, ``${input:id}``, ``$VAR``, ``%VAR%``, ``$env:VAR``,
``{{ var }}``, ``<token>``, ``YOUR_*``, ``your-*-here``, ``changeme``, ``xxx`` and
ellipsis shapes.
``${VAR:-literal}`` is expanded and the default is tested, so a literal default is a
literal credential.
A literal next to a reference (``sk-live-abc${SUFFIX}``) is tested as the literal part.
Each client writes references its own way (Claude Code ``${VAR}`` and ``${VAR:-default}``,
Cursor and Windsurf ``${env:VAR}``, VS Code ``${input:id}``) and all of them are accepted.

Confidence has two levels.
High: a known provider pattern from the secret scanner matches, the value has the shape of
a random token under a credential-like key, the value sits in a credential header, or a URL
carries a userinfo password.
Medium: only the key name says it is a credential (``PASSWORD=abc123``), or a long
token-like path segment.

Only ``kind:key`` labels and argument indexes are returned, never a value.
``redact_args`` returns the argument list with each secret replaced by ``[REDACTED]`` so no
value reaches a report, SARIF or an LLM prompt.
"""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Final, Literal
from urllib.parse import parse_qsl, urlsplit

from threatcode.engine.secrets.builtin import get_builtin_rules
from threatcode.engine.secrets.rules import SecretRule
from threatcode.parsers._mcp_launch import EffectiveLaunch, Token

Confidence = Literal["high", "medium"]

REDACTED: Final = "[REDACTED]"

# ---------------------------------------------------------------------------
# Placeholders
# ---------------------------------------------------------------------------

# Longest value judged; the rest of a longer value is ignored
_MAX_VALUE_CHARS: Final = 16384
_DEFAULT_REF: Final = re.compile(r"\$\{(?:env:)?[A-Za-z_][A-Za-z0-9_]*(?::-|:=|-|=)([^}]{0,256})\}")
_ANY_REF: Final = re.compile(
    r"\$\{[^}]{0,256}\}|\$env:[A-Za-z_]\w*|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%"
    r"|\{\{[^}]{0,256}\}\}|<[^<>]{1,256}>"
)
_PLACEHOLDER_WORD: Final = re.compile(
    r"(?ix)^(?:"
    r"changeme|change[-_ ]?me|replace[-_ ]?me|insert[-_ ].*|todo|tbd|"
    r"x{3,}|\*{3,}|\.{3,}|…|-{3,}|"
    r"your[-_].*|.*[-_]here|"
    r"\[?redacted\]?|<[^<>]{0,256}>|"
    r"example(?:[-_].*)?|placeholder.*|dummy|fake|sample"
    r")$"
)
_BEARER_PREFIX: Final = re.compile(r"(?i)^(?:bearer|basic|token)\s+")
_BOOLEAN_WORDS: Final = frozenset(
    {"true", "false", "yes", "no", "on", "off", "none", "null", "nil", "enabled", "disabled"}
)
_PATH_LIKE: Final = re.compile(r"^(?:/|~|\./|\.\./|[A-Za-z]:[\\/]|\\\\)")
_URL_LIKE: Final = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def literal_text(value: str) -> str:
    """The part of a value that is not a reference.

    ``${VAR:-default}`` becomes ``default``; any other reference becomes nothing.
    An empty result means the whole value is a reference or template.
    """
    # A bounded prefix keeps the scan linear on hostile input; a real secret fits well inside it
    text = value.strip()[:_MAX_VALUE_CHARS]
    for _ in range(3):
        expanded = _DEFAULT_REF.sub(lambda m: m.group(1), text)
        if expanded == text:
            break
        text = expanded
    text = _ANY_REF.sub("", text).strip()
    if _PLACEHOLDER_WORD.match(text):
        return ""
    return text


def is_placeholder(value: str) -> bool:
    """True when the whole value is a reference or template, so it holds no literal secret."""
    return not literal_text(value)


# ---------------------------------------------------------------------------
# Key names
# ---------------------------------------------------------------------------

_STRONG_TOKENS: Final = frozenset({"password", "passwd", "pwd", "passphrase", "secret", "token"})
_WEAK_TOKENS: Final = frozenset({"apikey", "credential", "credentials", "bearer", "pat"})
_KEY_QUALIFIERS: Final = frozenset({"api", "secret", "private", "access"})
# A key whose last token says the value is something other than the credential itself
_EXCLUDED_SUFFIXES: Final = frozenset(
    {
        "url", "uri", "name", "type", "id", "path", "file", "dir", "endpoint", "host", "arn",
        "region", "mode", "ttl", "expiry", "expiration", "timeout", "length", "prefix", "header",
        "scope", "scopes", "env", "var", "ref", "label",
    }
)  # fmt: skip
_AUTH_HEADER: Final = re.compile(
    r"(?i)^(?:authorization|proxy-authorization|x-api-key|api-key|apikey|x-auth-token"
    r"|x-access-token|.*token.*|.*secret.*)$"
)


def key_tokens(key: str) -> list[str]:
    """Split a key on ``_``, ``-``, ``.`` and camelCase; ``apiKey`` gives ``['api', 'key']``."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(key))
    spaced = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", spaced)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def key_strength(key: str) -> Literal["strong", "weak"] | None:
    """How credential-like a key name is.

    Strong: a whole token is password, passwd, pwd, passphrase, secret or token.
    Weak: apikey, credential, bearer, pat, or ``key`` together with api, secret, private or
    access.
    None: not credential-like, or the last token says it is a URL, name, type, id, path or
    file rather than the credential itself.
    """
    tokens = key_tokens(key)
    if not tokens:
        return None
    if tokens[-1] in _EXCLUDED_SUFFIXES:
        return None
    if any(t in _STRONG_TOKENS for t in tokens):
        return "strong"
    if any(t in _WEAK_TOKENS for t in tokens):
        return "weak"
    if "key" in tokens and any(t in _KEY_QUALIFIERS for t in tokens):
        return "weak"
    return None


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


def shannon_entropy(text: str) -> float:
    """Shannon entropy of ``text`` in bits per character."""
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = len(text)
    return -sum(n / total * math.log2(n / total) for n in counts.values())


def looks_random(text: str) -> bool:
    """A long value with letters and digits and the spread of characters of a random token."""
    return (
        len(text) >= 16
        and bool(re.search(r"[A-Za-z]", text))
        and bool(re.search(r"\d", text))
        and shannon_entropy(text) >= 3.5
    )


@lru_cache(maxsize=1)
def _provider_rules() -> tuple[SecretRule, ...]:
    # Only rules for a distinctive provider token run here. URLs are judged by their userinfo
    # password and query parameters, headers by their own scoring, and generic key = value
    # assignments by ``key_strength`` and ``looks_random``, so the structural and generic rules of
    # the scanner are left out.
    return tuple(r for r in get_builtin_rules() if r.kind == "provider")


def provider_pattern_hit(key: str, value: str) -> bool:
    """True when a known-provider pattern of the secret scanner matches ``key=value``."""
    line = f"{key}={value}"
    lowered = line.lower()
    for rule in _provider_rules():
        if rule.keywords and not any(kw in lowered for kw in rule.keywords):
            continue
        match = rule.regex.search(line)
        if match and rule.accepts(rule.secret_of(match)[0]):
            return True
    return False


def _plain_non_secret(text: str, strength: str) -> bool:
    """Values that are not a credential whatever the key says."""
    low = text.lower()
    if low in _BOOLEAN_WORDS or _URL_LIKE.match(text) or _PATH_LIKE.match(text):
        return True
    if strength == "weak":
        if len(text) < 8 or text.isdigit():
            return True
        # A plain lower-case phrase such as "service-account" is an enumeration
        if re.fullmatch(r"[a-z][a-z_.-]*", text) and len(text) < 40:
            return True
    return False


# ---------------------------------------------------------------------------
# Hits
# ---------------------------------------------------------------------------


@dataclass
class SecretHit:
    """One literal credential found: where it is, never what it is."""

    label: str  # kind:key, for example env:GITHUB_TOKEN or arg:--api-key
    confidence: Confidence
    origin: int | None = None  # index into the entry's original args, when it came from args
    value: str = field(default="", repr=False, compare=False)
    redact: Callable[[str], str] | None = field(default=None, repr=False, compare=False)


def score_value(key: str, raw: Any, *, header: bool = False) -> Confidence | None:
    """Judge one ``key``/``value`` pair; None means it is not a literal credential."""
    if isinstance(raw, bool) or not isinstance(raw, str | int | float):
        return None
    value = _BEARER_PREFIX.sub("", str(raw).strip())
    literal = literal_text(value)
    if not literal:
        return None
    if header:
        token = literal
        if not token or is_placeholder(token):
            return None
        auth_like = bool(re.match(r"(?i)^(authorization|proxy-authorization)$", str(key)))
        if auth_like or key_strength(key) is not None:
            if provider_pattern_hit(key, token) or looks_random(token) or len(token) >= 8:
                return "high"
            return "medium"
    token = literal
    if _URL_LIKE.match(token):
        return None  # judged by its userinfo and query parameters instead
    if key.lower() == token.lower():
        return None  # KEY=KEY names the variable instead of holding a value
    if provider_pattern_hit(key, token):
        return "high"
    strength = key_strength(key)
    if strength is None or _plain_non_secret(token, strength):
        return None
    return "high" if looks_random(token) else "medium"


def _scan_mapping(values: Mapping[Any, Any], kind: str, *, header: bool = False) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for key, raw in values.items():
        label = f"{kind}:{key}"
        confidence = score_value(str(key), raw, header=header)
        if confidence is not None:
            hits.append(SecretHit(label, confidence, value=str(raw)))
        elif isinstance(raw, str) and _URL_LIKE.match(raw.strip()):
            # A URL value (a connection string): its parts are judged, the label is the key
            hits.extend(_scan_url(raw.strip(), label, path_tokens=False, suffix=False)[0])
    return hits


def scan_env(env: Mapping[Any, Any]) -> list[SecretHit]:
    """Literal credentials among ``env`` values."""
    return _scan_mapping(env, "env")


def scan_headers(headers: Mapping[Any, Any]) -> list[SecretHit]:
    """Literal credentials among ``headers`` values."""
    return _scan_mapping(headers, "header", header=True)


def _redact_in_text(text: str, secret: str) -> str:
    return text.replace(secret, REDACTED) if secret and secret in text else text


def _value_redactor(secret: str) -> Callable[[str], str]:
    def redact(text: str) -> str:
        return _redact_in_text(text, secret)

    return redact


def _redact_markers(text: str, markers: list[str]) -> str:
    """Replace each marker (``:pw@``, ``//user@``, ``/token`` or ``name=value``) in a URL text."""
    for marker in markers:
        if marker.startswith(":"):
            text = text.replace(marker, f":{REDACTED}@")
        elif marker.startswith("//"):
            text = text.replace(marker, f"//{REDACTED}@")
        elif marker.startswith("/"):
            text = text.replace(marker, f"/{REDACTED}")
        else:
            name = marker.split("=", 1)[0]
            text = text.replace(marker, f"{name}={REDACTED}")
    return text


def _scan_url(
    url: str, label: str, *, path_tokens: bool, suffix: bool = True
) -> tuple[list[SecretHit], bool, Callable[[str], str] | None]:
    """Hits in one URL, whether it carries query credentials, and a redactor for its text.

    The redactor replaces each secret part inside the URL text, so the host and the rest of
    the URL stay readable.
    """
    try:
        parts = urlsplit(url)
        username, password = parts.username, parts.password
        query = parse_qsl(parts.query, keep_blank_values=False)
        segments = [s for s in parts.path.split("/") if s]
    except ValueError:
        return [], False, None

    def name_of(part: str) -> str:
        return f"{label}:{part}" if suffix else label

    hits: list[SecretHit] = []
    secrets: list[str] = []
    query_credential = False
    if password and not is_placeholder(password):
        hits.append(SecretHit(name_of("userinfo"), "high", value=password))
        secrets.append(f":{password}@")
    elif username and not is_placeholder(username):
        token = username
        if provider_pattern_hit("", token) or looks_random(token):
            hits.append(SecretHit(name_of("userinfo"), "high", value=username))
            secrets.append(f"//{username}@")
    for name, value in query:
        if key_strength(name) is not None or _AUTH_HEADER.match(name):
            query_credential = True
        confidence = score_value(name, value)
        if confidence is not None:
            hits.append(SecretHit(name_of(name), confidence, value=value))
            secrets.append(f"{name}={value}")
    if path_tokens:
        for segment in segments:
            if (
                len(segment) >= 20
                and re.fullmatch(r"[A-Za-z0-9_-]+", segment)
                and looks_random(segment)
                and not is_placeholder(segment)
            ):
                hits.append(SecretHit(name_of("path"), "medium", value=segment))
                secrets.append(f"/{segment}")

    def redact(text: str) -> str:
        return _redact_markers(text, secrets)

    return hits, query_credential, redact if secrets else None


@dataclass
class UrlScan:
    """What a remote URL holds: credential hits, and whether it carries auth at all."""

    hits: list[SecretHit]
    has_userinfo: bool
    has_query_credential: bool


def scan_url(url: str) -> UrlScan:
    """Scan a server URL: userinfo, query parameters and (medium) a token in the path."""
    hits, query_credential, _redact = _scan_url(url, "url", path_tokens=True)
    try:
        has_userinfo = bool(urlsplit(url).username)
    except ValueError:
        has_userinfo = False
    return UrlScan(hits, has_userinfo, query_credential)


def redact_url(url: str) -> str:
    """The URL with its userinfo password, credential parameters and path token replaced."""
    _hits, _query, redact = _scan_url(url, "url", path_tokens=True)
    return redact(url) if redact else url


# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------

_HEADER_FLAGS: Final = frozenset({"--header", "-H", "--headers"})
_AUTH_STRING: Final = re.compile(
    r"(?i)^\s*(authorization|proxy-authorization|x-api-key|api-key)\s*:\s*(.+)$"
)
_BEARER_STRING: Final = re.compile(r"(?i)^(?:bearer|basic)\s+(\S+)$")


def _arg_hit(
    label: str, confidence: Confidence, token: Token, value: str, redact: Callable[[str], str]
) -> SecretHit:
    return SecretHit(label, confidence, origin=token.origin, value=value, redact=redact)


def _after_equals(text: str) -> str:
    key, sep, _value = text.partition("=")
    return f"{key}{sep}{REDACTED}"


def _scan_env_overrides(launch: EffectiveLaunch) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for key, value in launch.env_overrides.items():
        confidence = score_value(key, value)
        if confidence is not None:
            hits.append(
                SecretHit(
                    f"arg:{key}",
                    confidence,
                    origin=launch.env_origins.get(key),
                    value=value,
                    redact=_value_redactor(value),
                )
            )
    return hits


def _scan_env_flag(tok: Token, nxt: Token | None) -> tuple[list[SecretHit], int] | None:
    """A docker style ``-e KEY=VALUE`` argument: its hits and the tokens it used, else None."""
    env_item: Token | None = None
    consumed = 1
    text = tok.text
    if text in ("-e", "--env") and nxt is not None:
        env_item, consumed = nxt, 2
    elif text.startswith("--env="):
        env_item = Token(text.split("=", 1)[1], tok.origin)
    elif re.match(r"^-e[A-Za-z_]\w*=", text):
        env_item = Token(text[2:], tok.origin)
    if env_item is None:
        return None
    key, sep, value = env_item.text.partition("=")
    if sep:
        confidence = score_value(key, value)
        if confidence is not None:
            return [_arg_hit(f"arg:{key}", confidence, env_item, value, _after_equals)], consumed
    return [], consumed


def _scan_option_value(tok: Token, nxt: Token | None) -> tuple[list[SecretHit], int] | None:
    """A ``--name value`` or ``--name=value`` option that holds a credential, else None."""
    text = tok.text
    if not (text.startswith("--") and len(text) > 2):
        return None
    name, eq, inline = text[2:].partition("=")
    value_token: Token | None
    consumed = 1
    if eq:
        value_token = Token(inline, tok.origin)
    elif nxt is not None and not nxt.text.startswith("-"):
        value_token, consumed = nxt, 2
    else:
        value_token = None
    if value_token is None or key_strength(name) is None:
        return None
    confidence = score_value(name, value_token.text)
    if confidence is None:
        return None
    redact = _after_equals if eq else _whole_value
    hit = _arg_hit(f"arg:--{name}", confidence, value_token, value_token.text, redact)
    return [hit], consumed


def _scan_arg(launch: EffectiveLaunch, tokens: list[Token], i: int) -> tuple[list[SecretHit], int]:
    """The hits in ``tokens[i]`` and how many tokens it used."""
    tok = tokens[i]
    text = tok.text
    nxt = tokens[i + 1] if i + 1 < len(tokens) else None

    env_result = _scan_env_flag(tok, nxt)
    if env_result is not None:
        return env_result

    if text in _HEADER_FLAGS and nxt is not None:
        return _scan_header_arg(nxt), 2
    if text.startswith(("--header=", "--headers=")):
        return _scan_header_arg(Token(text.split("=", 1)[1], tok.origin)), 1

    option_result = _scan_option_value(tok, nxt)
    if option_result is not None:
        return option_result

    if launch.bridge and tok.origin == launch.remote_url_origin and text == launch.remote_url:
        return [], 1  # the bridge URL is scanned as the server URL, with its path token
    direct = _scan_auth_string(tok)
    if direct:
        return direct, 1
    hits: list[SecretHit] = []
    if _URL_LIKE.match(text):
        url_hits, _query, redact_url_text = _scan_url(
            text, "arg:url", path_tokens=False, suffix=False
        )
        for hit in url_hits:
            hit.origin = tok.origin
            hit.redact = redact_url_text
            hits.append(hit)
    return hits, 1


def scan_args(launch: EffectiveLaunch) -> list[SecretHit]:
    """Literal credentials in the effective launch arguments.

    Docker ``-e KEY`` with no value is a reference to the environment, not a credential.
    """
    tokens = launch.inner_argv[1:]
    hits = _scan_env_overrides(launch)
    i = 0
    while i < len(tokens):
        found, used = _scan_arg(launch, tokens, i)
        hits.extend(found)
        i += used
    return _dedupe(hits)


def _whole_value(_text: str) -> str:
    return REDACTED


def _scan_header_arg(token: Token) -> list[SecretHit]:
    name, sep, value = token.text.partition(":")
    if not sep:
        return []
    name, value = name.strip(), value.strip()
    confidence = score_value(name, value, header=True)
    if confidence is None:
        return []

    return [_arg_hit(f"arg:{name}", confidence, token, value, _value_redactor(value))]


def _scan_auth_string(token: Token) -> list[SecretHit]:
    match = _AUTH_STRING.match(token.text)
    if match:
        return _scan_header_arg(token)
    bearer = _BEARER_STRING.match(token.text.strip())
    if bearer and not is_placeholder(bearer.group(1)):
        value = bearer.group(1)
        return [_arg_hit("arg:Authorization", "high", token, value, _value_redactor(value))]
    return []


def _dedupe(hits: list[SecretHit]) -> list[SecretHit]:
    seen: set[tuple[str, int | None, str]] = set()
    unique: list[SecretHit] = []
    for hit in hits:
        key = (hit.label, hit.origin, hit.value)
        if key not in seen:
            seen.add(key)
            unique.append(hit)
    return unique


def redact_args(args: list[str], hits: list[SecretHit], split_origins: set[int]) -> list[str]:
    """Return ``args`` with every secret replaced by ``[REDACTED]``.

    A secret in an argument is replaced in place (the part after ``=``, the next word, the
    password of a URL), so the rest of the argument stays readable.
    A secret that came out of a shell string is replaced inside that string.
    """
    result = list(args)
    for hit in hits:
        index = hit.origin
        if index is None or not 0 <= index < len(result):
            continue
        text = result[index]
        if index in split_origins or hit.redact is None:
            replaced = _redact_in_text(text, hit.value)
            result[index] = replaced if replaced != text else (REDACTED if hit.value else text)
        else:
            result[index] = hit.redact(text)
    return result


def summarize(hits: list[SecretHit]) -> tuple[list[str], list[int], Confidence | None]:
    """Unique labels, the argument indexes and the highest confidence of ``hits``."""
    labels = list(dict.fromkeys(h.label for h in hits))
    indexes = sorted({h.origin for h in hits if h.origin is not None and h.origin >= 0})
    if any(h.confidence == "high" for h in hits):
        return labels, indexes, "high"
    return labels, indexes, "medium" if hits else None
