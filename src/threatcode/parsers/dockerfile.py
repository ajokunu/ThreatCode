"""Dockerfile parser for ThreatCode.

The parser reads a Dockerfile as a list of build stages, because the image that runs is the
last stage and a ``USER``, ``HEALTHCHECK`` or ``WORKDIR`` in an earlier build stage says
nothing about it.

What it emits:

* One resource per instruction (``dockerfile_<instruction>``) at the address
  ``dockerfile.<instruction>.<position>``, where the position counts instructions from zero.
  Every instruction resource has the properties ``stage`` and ``onbuild``.
  ``ONBUILD <INSTRUCTION>`` is unwrapped into the inner instruction with ``onbuild`` set, so
  command-level checks (curl piped to a shell, ``sudo``) run on the trigger while the image
  summary ignores it: a trigger runs in a child build, not in this image.
* One synthetic ``dockerfile_stage`` resource per ``FROM`` at ``dockerfile.stage.<name or
  index>``, with a containment edge from each instruction to its stage and dependency edges
  between stages for ``FROM <stage>`` (relation ``base``) and ``COPY --from=<stage>``
  (relation ``copy_from``). The edges are inferred, so they are never ``declared``.
* One ``dockerfile_image`` summary at ``dockerfile.image.summary``, computed from the final
  stage. A stage that starts ``FROM <earlier stage>`` inherits that stage's ``USER``,
  ``HEALTHCHECK``, ``WORKDIR`` and ``EXPOSE`` until it overrides them. ``uses_latest_tag`` is
  true when any stage uses a floating tag; ``final_stage_uses_latest_tag`` looks at the image
  that ships.

A value that depends on a variable with no known default (``FROM base:${TAG}``,
``USER ${APP_USER}``) is a :class:`threatcode.values.Unknown`, so rules neither pass nor fail
on it. ``ARG`` defaults declared before the first ``FROM`` are substituted into ``FROM``
lines; ``ARG`` and ``ENV`` values inside a stage are substituted into ``USER`` and ``EXPOSE``.

Properties never carry a secret value: ``ENV`` and ``ARG`` resources list key names, and the
value of a key that looks like a secret is masked in ``arguments``.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from threatcode.diagnostics import Diagnostic, Level, register_code
from threatcode.parsers._dockerfile_lexer import (
    HEREDOC_INSTRUCTIONS,
    KEYWORDS,
    Instruction,
    command_name,
    has_variable,
    lex,
    parse_json_array,
    shell_pipelines,
    split_options,
    split_words,
    split_words_raw,
    substitute,
    unquote,
)
from threatcode.parsers.base import BaseParser, ParsedEdge, ParsedOutput, ParsedResource
from threatcode.parsers.image_ref import ImageRef, is_floating_tag, parse_image_ref
from threatcode.values import Unknown, is_unknown

register_code("dockerfile.skipped_line", "A Dockerfile line is not an instruction and was skipped")
register_code(
    "dockerfile.unresolved_variable",
    "A Dockerfile value uses a variable with no known default, so it is not judged",
)

# ---------------------------------------------------------------------------
# What the parser produces
# ---------------------------------------------------------------------------

# Every property a Dockerfile resource can carry, by resource type.
# A rule may read a property of a ``dockerfile_*`` resource only if it is listed here: the
# provenance gate (tests/test_engine/test_rule_property_provenance.py) fails a rule that reads
# anything else, because such a rule can never fire, and it fails when the parser emits a
# property this table does not list or this table lists one the parser never emits.
_INSTRUCTION_PROPERTIES = frozenset(
    {"arguments", "instruction", "line_number", "onbuild", "stage", "stage_index"}
)
_INSTRUCTION_EXTRAS: dict[str, frozenset[str]] = {
    "ADD": frozenset(
        {
            "destination",
            "has_checksum",
            "has_chown",
            "has_sensitive_file",
            "is_local_add",
            "is_url_add",
            "sources",
        }
    ),
    "ARG": frozenset(
        {"has_secret_pattern", "key", "keys", "pairs", "secret_keys", "secret_keys_without_default"}
    ),
    "COPY": frozenset(
        {
            "chown_missing",
            "destination",
            "from_stage",
            "has_chown",
            "has_sensitive_file",
            "sources",
        }
    ),
    "ENV": frozenset({"has_secret_pattern", "key", "keys", "pairs", "secret_keys"}),
    "EXPOSE": frozenset({"port_ranges", "ports", "unknown_ports"}),
    "FROM": frozenset(
        {
            "digest",
            "digest_pinned",
            "image",
            "kind",
            "parent_stage",
            "platform",
            "stage_name",
            "tag",
            "uses_latest_tag",
        }
    ),
    "HEALTHCHECK": frozenset({"disabled"}),
    "RUN": frozenset({"has_apt_no_clean", "has_apt_no_recommends", "has_curl_pipe", "has_sudo"}),
    "USER": frozenset({"is_root", "user"}),
}
PRODUCED: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        **{
            f"dockerfile_{name.lower()}": _INSTRUCTION_PROPERTIES
            | _INSTRUCTION_EXTRAS.get(name, frozenset())
            | (frozenset({"heredoc_body"}) if name in HEREDOC_INSTRUCTIONS else frozenset())
            for name in sorted(KEYWORDS)
        },
        # The summary of the final stage: what runs is the last stage
        "dockerfile_image": frozenset(
            {
                "add_count",
                "base_image",
                "base_kind",
                "copy_without_chown",
                "entrypoint_count",
                "exposed_port_ranges",
                "exposed_ports",
                "final_stage_uses_latest_tag",
                "has_digest_pin",
                "has_healthcheck",
                "has_privileged_port",
                "has_ssh_exposed",
                "has_user",
                "has_workdir",
                "is_non_minimal",
                "is_root_user",
                "stage_count",
                "unknown_exposed_ports",
                "user_value",
                "uses_latest_tag",
            }
        ),
        # One synthetic resource per FROM
        "dockerfile_stage": frozenset(
            {
                "base_image",
                "base_ref",
                "digest_pinned",
                "exposed_port_ranges",
                "exposed_ports",
                "has_healthcheck",
                "has_user",
                "has_workdir",
                "instruction_count",
                "is_final",
                "kind",
                "parent_stage",
                "stage_index",
                "stage_name",
                "tag",
                "user_value",
            }
        ),
    }
)

# ---------------------------------------------------------------------------
# Heuristic tables
# ---------------------------------------------------------------------------

# Programs that execute what they read: a download piped into one runs unverified code.
_INTERPRETER_RE = re.compile(r"^(sh|bash|zsh|dash|ash|ksh|perl|ruby|node|python[0-9]*(\.[0-9]+)*)$")
_FETCHERS = frozenset({"curl", "wget"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ash", "ksh"})
_APT_PROGRAMS = frozenset({"apt-get", "apt", "aptitude"})
_APT_LISTS = "/var/lib/apt/lists"

# Files that hold secrets, matched against real ADD and COPY sources.
_SENSITIVE_FILE_RE = re.compile(r"\.(key|pem|p12|pfx)$|id_rsa(?!\.pub)|(^|/)\.env$")

# Archive suffixes: ADD of a local archive extracts it, which is what ADD is for.
_ARCHIVE_SUFFIXES = (
    ".tar",
    ".tar.gz",
    ".tgz",
    ".tar.bz2",
    ".tbz",
    ".tbz2",
    ".tar.xz",
    ".txz",
    ".tar.zst",
    ".tzst",
    ".tar.lz",
    ".tar.lzma",
    ".tar.z",
)
_URL_PREFIXES = ("http://", "https://", "ftp://", "git://", "git@", "ssh://")

# Image families that ship a full operating system. Matched on the last path component of the
# repository. Language runtimes (python, node) are not listed: their size depends on the tag.
FULL_OS_FAMILIES: frozenset[str] = frozenset(
    {
        "ubuntu",
        "debian",
        "centos",
        "fedora",
        "amazonlinux",
        "rockylinux",
        "almalinux",
        "oraclelinux",
        "sles",
    }
)
# Markers in the tag that name a stripped-down variant of the family.
_MINIMAL_TAG_RE = re.compile(r"(^|[-_.])(slim|minimal|micro|alpine|distroless|busybox)($|[-_.])")
_MINIMAL_REPO_MARKERS = ("distroless", "alpine", "busybox", "wolfi", "chainguard", "minimal")

# Words of an environment variable name that make it look like it holds a secret.
_SECRET_WORDS = frozenset(
    {"password", "passwd", "secret", "token", "apikey", "credential", "credentials", "pwd"}
)
# Pairs of adjacent words that do the same (API_KEY, PRIVATE_KEY, AUTH_TOKEN).
_SECRET_BIGRAMS = frozenset({("api", "key"), ("private", "key"), ("auth", "token")})
# "key" alone proves nothing (KEYBOARD, PUBLIC_KEY_PATH); it counts with one of these.
_KEY_COMPANIONS = frozenset({"api", "secret", "private", "access"})
# A name that ends in one of these holds a location or a label, not the secret itself.
_NON_SECRET_SUFFIXES = frozenset(
    {
        "path",
        "file",
        "url",
        "uri",
        "name",
        "id",
        "dir",
        "directory",
        "version",
        "length",
        "ttl",
        "expiry",
        "endpoint",
        "header",
    }
)
_PLACEHOLDER_RE = re.compile(
    r"^(<.*>|\{\{.*\}\}|x{3,}|\*{3,}|\.{3,}|change[-_ ]?me|replace[-_ ]?me|todo|tbd|"
    r"placeholder|dummy|example|redacted|none|null|undefined)$",
    re.IGNORECASE,
)
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_RE = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")

_PORT_RE = re.compile(r"^(\d{1,5})(?:-(\d{1,5}))?(?:/[A-Za-z]+)?$")
_REDACTED = "<redacted>"

# Option values: the mount that keeps apt state out of the layer.
_APT_CACHE_TARGETS = ("/var/lib/apt", "/var/cache/apt")


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def name_words(key: str) -> list[str]:
    """Split an environment variable name into lower-case words (``_``, ``-``, camelCase)."""
    words: list[str] = []
    for chunk in _WORD_SPLIT_RE.split(key):
        words.extend(match.lower() for match in _CAMEL_RE.findall(chunk))
    return words


def looks_secret_name(key: str) -> bool:
    """True when an environment variable name looks like it holds a secret."""
    words = name_words(key)
    if not words or words[-1] in _NON_SECRET_SUFFIXES:
        return False
    if any(word in _SECRET_WORDS or word.endswith(("password", "passwd")) for word in words):
        return True
    if any(pair in _SECRET_BIGRAMS for pair in zip(words, words[1:], strict=False)):
        return True
    return "key" in words and any(word in _KEY_COMPANIONS for word in words)


def _classify_value(value: str) -> str:
    """How an ENV or ARG value looks: empty, variable, path, placeholder or literal."""
    stripped = value.strip()
    if not stripped:
        return "empty"
    if has_variable(stripped):
        return "variable"
    if stripped.startswith(("/", "./", "../", "~/")):
        return "path"
    if _PLACEHOLDER_RE.match(stripped):
        return "placeholder"
    return "literal"


def _root_state(user: str | Unknown) -> bool | Unknown:
    """Whether a USER value is root: ``root`` or uid 0 (before any ``:group``)."""
    if is_unknown(user):
        return user
    part = str(user).split(":", 1)[0].strip().lower()
    return part == "root" or (part.isdigit() and int(part) == 0)


def _is_archive(source: str) -> bool:
    return source.lower().endswith(_ARCHIVE_SUFFIXES)


def _is_url(source: str) -> bool:
    return source.lower().startswith(_URL_PREFIXES)


def _port_in(port: int, ports: list[int], ranges: list[tuple[int, int]]) -> bool:
    return port in ports or any(lo <= port <= hi for lo, hi in ranges)


def _unique(items: list[Any]) -> list[Any]:
    return list(dict.fromkeys(items))


# ---------------------------------------------------------------------------
# Stage model
# ---------------------------------------------------------------------------


@dataclass
class _Stage:
    """One build stage while the parser walks the instructions."""

    index: int
    name: str  # lower-case name from AS, or ""
    ident: str  # the address suffix: the name, or the index when the name is missing or reused
    from_line: int | None
    image_text: str = ""  # the image reference after ARG substitution
    kind: str = "registry"  # registry | stage | scratch | variable | none
    tag: str | Unknown = ""
    digest_pinned: bool = False
    uses_latest_tag: bool = False
    ref: ImageRef | None = None
    platform: str = ""
    parent: _Stage | None = None
    last_line: int | None = None
    # State a child stage inherits when it starts FROM this stage
    user: str | Unknown | None = None
    healthcheck: bool | None = None
    has_workdir: bool = False
    ports: list[int] = field(default_factory=list)
    port_ranges: list[tuple[int, int]] = field(default_factory=list)
    unknown_ports: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    # Not inherited
    args: dict[str, str] = field(default_factory=dict)
    entrypoint_count: int = 0
    instruction_count: int = 0

    def inherit_from(self, parent: _Stage) -> None:
        self.user = parent.user
        self.healthcheck = parent.healthcheck
        self.has_workdir = parent.has_workdir
        self.ports = list(parent.ports)
        self.port_ranges = list(parent.port_ranges)
        self.unknown_ports = list(parent.unknown_ports)
        self.env = dict(parent.env)

    def base(self) -> _Stage:
        """The stage whose FROM names a real image: follow FROM <stage> to its root."""
        stage = self
        seen = {id(stage)}
        while stage.parent is not None and id(stage.parent) not in seen:
            stage = stage.parent
            seen.add(id(stage))
        return stage


@dataclass(frozen=True)
class _Pair:
    """One ``KEY=value`` of an ENV or ARG line; ``value`` is None for ``ARG KEY``."""

    key: str
    value: str | None
    raw: str
    legacy: bool


@dataclass
class _Copy:
    """What the final-stage ownership check needs to know about one COPY instruction."""

    stage: _Stage | None
    from_stage: bool
    has_chown: bool
    onbuild: bool


class _Builder:
    def __init__(self, source_path: str) -> None:
        self.source_path = source_path
        self.resources: list[ParsedResource] = []
        self.edges: list[ParsedEdge] = []
        self.diagnostics: list[Diagnostic] = []
        self.global_args: dict[str, str] = {}
        self.stages: list[_Stage] = []
        self.stage_by_name: dict[str, _Stage] = {}
        self.idents: set[str] = set()
        self.stage: _Stage | None = None
        self.copies: list[_Copy] = []
        self.add_count = 0
        self.instruction_addresses: dict[int, list[str]] = {}

    # -- variables ----------------------------------------------------------

    def _lookup(self, name: str) -> str | None:
        if self.stage is None:
            return self.global_args.get(name)
        if name in self.stage.env:
            return self.stage.env[name]
        return self.stage.args.get(name)

    def _diagnose(self, code: str, message: str, line: int | None, level: Level = "info") -> None:
        self.diagnostics.append(Diagnostic(level, code, message, self.source_path, line))

    # -- instructions -------------------------------------------------------

    def add(self, ins: Instruction) -> None:
        if ins.name == "FROM" and not ins.onbuild:
            props: dict[str, Any] = self._from_properties(self._open_stage(ins))
        else:
            if self.stage is None and ins.name != "ARG":
                self._open_implicit_stage()
            props = {}
        stage = self.stage
        position = len(self.resources)
        ident = stage.ident if stage is not None else ""
        base_props: dict[str, Any] = {
            "instruction": ins.name,
            "arguments": ins.args,
            "line_number": ins.start_line,
            "stage": ident,
            "onbuild": ins.onbuild,
        }
        if ins.heredoc_body:
            base_props["heredoc_body"] = ins.heredoc_body
        if stage is not None:
            base_props["stage_index"] = stage.index
        handler = getattr(self, f"_do_{ins.name.lower()}", None)
        extra: dict[str, Any] = handler(ins) if handler is not None and ins.name != "FROM" else {}
        properties = {**base_props, **props, **extra}
        address = f"dockerfile.{ins.name.lower()}.{position}"
        if stage is not None:
            stage.instruction_count += 1
            stage.last_line = max(stage.last_line or 0, ins.end_line)
            self.instruction_addresses.setdefault(stage.index, []).append(address)
        display = str(properties["arguments"])
        self.resources.append(
            ParsedResource(
                resource_type=f"dockerfile_{ins.name.lower()}",
                address=address,
                name=f"{ins.name} {display[:50]}",
                provider="docker",
                properties=properties,
                source_location=self.source_path,
                start_line=ins.start_line,
                end_line=ins.end_line,
            )
        )

    def _open_implicit_stage(self) -> None:
        stage = _Stage(index=len(self.stages), name="", ident=str(len(self.stages)), from_line=None)
        stage.kind = "none"
        self.stages.append(stage)
        self.idents.add(stage.ident)
        self.stage = stage

    def _open_stage(self, ins: Instruction) -> _Stage:
        options, rest = split_options(ins.args)
        words = split_words_raw(rest)
        image_text = unquote(words[0]) if words else ""
        name = ""
        if len(words) >= 3 and words[1].lower() == "as":
            name = unquote(words[2]).lower()
        substituted, unresolved = substitute(image_text, self.global_args.get)
        # Look the name up here: handing every stage name to parse_image_ref would cost a
        # set build per FROM, which is quadratic in the number of stages
        named = self.stage_by_name.get(substituted.strip().lower())
        ref = parse_image_ref(substituted, (named.name,) if named else ())
        index = len(self.stages)
        ident = name if name and name not in self.idents else str(index)
        stage = _Stage(index=index, name=name, ident=ident, from_line=ins.start_line)
        stage.image_text = substituted
        stage.ref = ref
        stage.kind = ref.kind
        stage.digest_pinned = bool(ref.digest)
        if ref.kind == "stage" and named is not None:
            stage.parent = named
            stage.inherit_from(named)
        elif ref.kind == "registry":
            stage.tag = ref.tag if (ref.tag or ref.digest) else "latest"
            stage.uses_latest_tag = (
                bool(ref.repository) and not ref.digest and is_floating_tag(ref.tag)
            )
        elif ref.kind == "variable":
            if ref.tag and not has_variable(ref.tag):
                stage.tag = ref.tag
            elif ref.tag or not ref.digest:
                stage.tag = Unknown(ref.tag or substituted)
        if ref.kind == "variable" or unresolved:
            self._diagnose(
                "dockerfile.unresolved_variable",
                f"FROM {image_text} uses a variable with no default, so its tag is not judged",
                ins.start_line,
            )
        stage.platform = options.get("platform", "")
        self.stages.append(stage)
        self.idents.add(ident)
        if name:
            self.stage_by_name.setdefault(name, stage)
        self.stage = stage
        if stage.parent is not None:
            self._edge(stage, stage.parent, "base")
        return stage

    def _from_properties(self, stage: _Stage) -> dict[str, Any]:
        ref = stage.ref
        props: dict[str, Any] = {
            "image": stage.image_text,
            "tag": stage.tag,
            "digest": ref.digest if ref else "",
            "digest_pinned": stage.digest_pinned,
            "kind": stage.kind,
            "stage_name": stage.name,
            "uses_latest_tag": stage.uses_latest_tag,
            "parent_stage": stage.parent.ident if stage.parent else "",
        }
        if stage.platform:
            props["platform"] = stage.platform
        return props

    def _edge(self, source: _Stage, target: _Stage, relation: str) -> None:
        self.edges.append(
            ParsedEdge(
                source=f"dockerfile.stage.{source.ident}",
                target=f"dockerfile.stage.{target.ident}",
                edge_type="dependency",
                metadata={"relation": relation},
                declared=False,
            )
        )

    def _in_image(self, ins: Instruction) -> bool:
        """Whether the instruction shapes this image (an ONBUILD trigger does not)."""
        return not ins.onbuild and self.stage is not None

    # -- per-instruction handlers --------------------------------------------

    def _do_user(self, ins: Instruction) -> dict[str, Any]:
        value = ins.args.strip()
        substituted, unresolved = substitute(value, self._lookup)
        user: str | Unknown = Unknown(value) if unresolved else substituted
        if self._in_image(ins) and self.stage is not None:
            self.stage.user = user
        if unresolved:
            self._diagnose(
                "dockerfile.unresolved_variable",
                f"USER {value} uses a variable with no default, so the user is not judged",
                ins.start_line,
            )
        return {"user": user, "is_root": _root_state(user)}

    def _do_healthcheck(self, ins: Instruction) -> dict[str, Any]:
        _options, rest = split_options(ins.args)
        disabled = rest.strip().upper() == "NONE"
        if self._in_image(ins) and self.stage is not None and rest.strip():
            self.stage.healthcheck = not disabled
        return {"disabled": disabled}

    def _do_workdir(self, ins: Instruction) -> dict[str, Any]:
        if self._in_image(ins) and self.stage is not None:
            self.stage.has_workdir = True
        return {}

    def _do_entrypoint(self, ins: Instruction) -> dict[str, Any]:
        if self._in_image(ins) and self.stage is not None:
            self.stage.entrypoint_count += 1
        return {}

    def _do_expose(self, ins: Instruction) -> dict[str, Any]:
        ports: list[int] = []
        ranges: list[tuple[int, int]] = []
        unknown: list[str] = []
        for token in split_words(ins.args):
            text, unresolved = substitute(token, self._lookup)
            if unresolved:
                unknown.append(token)
                continue
            match = _PORT_RE.match(text)
            if match is None:
                continue
            low = int(match.group(1))
            high = int(match.group(2)) if match.group(2) else None
            if low > 65535 or (high is not None and high > 65535):
                continue
            if high is None:
                ports.append(low)
            else:
                ranges.append((min(low, high), max(low, high)))
        if self._in_image(ins) and self.stage is not None:
            self.stage.ports.extend(ports)
            self.stage.port_ranges.extend(ranges)
            self.stage.unknown_ports.extend(unknown)
        if unknown:
            self._diagnose(
                "dockerfile.unresolved_variable",
                f"EXPOSE {ins.args} uses a variable with no default, so that port is not judged",
                ins.start_line,
            )
        return {
            "ports": ports,
            "port_ranges": [[lo, hi] for lo, hi in ranges],
            "unknown_ports": unknown,
        }

    def _do_env(self, ins: Instruction) -> dict[str, Any]:
        return self._env_or_arg(ins, is_arg=False)

    def _do_arg(self, ins: Instruction) -> dict[str, Any]:
        return self._env_or_arg(ins, is_arg=True)

    def _pairs(self, ins: Instruction, is_arg: bool) -> list[_Pair]:
        """Every key of an ENV or ARG line, with its value (None for an ARG without default)."""
        words = split_words_raw(ins.args)
        if not words:
            return []
        if not is_arg and "=" not in words[0]:
            # The legacy form: ENV KEY value with spaces
            rest = ins.args.strip()[len(words[0]) :].strip()
            return [_Pair(unquote(words[0]), unquote(rest) if rest else "", ins.args.strip(), True)]
        pairs: list[_Pair] = []
        for word in words:
            key, equals, value = word.partition("=")
            key = unquote(key)
            if key:
                pairs.append(_Pair(key, unquote(value) if equals else None, word, False))
        return pairs

    def _env_or_arg(self, ins: Instruction, is_arg: bool) -> dict[str, Any]:
        pairs = self._pairs(ins, is_arg)
        info: list[dict[str, Any]] = []
        secret_keys: list[str] = []
        informational: list[str] = []
        shown: list[str] = []
        for pair in pairs:
            key, value = pair.key, pair.value
            kind = "none" if value is None else _classify_value(value)
            info.append({"key": key, "value_kind": kind})
            flagged = looks_secret_name(key)
            if flagged and kind == "literal":
                secret_keys.append(key)
                shown.append(f"{key} {_REDACTED}" if pair.legacy else f"{key}={_REDACTED}")
            else:
                shown.append(pair.raw)
                if flagged and kind == "none" and is_arg:
                    informational.append(key)
            self._remember(key, value, is_arg, ins)
        props: dict[str, Any] = {
            "key": pairs[0].key if pairs else "",
            "keys": [pair.key for pair in pairs],
            "pairs": info,
            "has_secret_pattern": bool(secret_keys),
            "secret_keys": secret_keys,
        }
        if is_arg:
            props["secret_keys_without_default"] = informational
        if secret_keys:
            props["arguments"] = " ".join(shown)
        return props

    def _remember(self, key: str, value: str | None, is_arg: bool, ins: Instruction) -> None:
        """Record a value so later USER and EXPOSE lines can use it."""
        if ins.onbuild:
            return
        if self.stage is None:
            if is_arg and value is not None:
                self.global_args[key] = substitute(value, self.global_args.get)[0]
            return
        if is_arg:
            if value is not None:
                text, unresolved = substitute(value, self._lookup)
                if not unresolved:
                    self.stage.args[key] = text
            elif key in self.global_args:
                self.stage.args[key] = self.global_args[key]
        elif value is not None:
            text, unresolved = substitute(value, self._lookup)
            if not unresolved:
                self.stage.env[key] = text
            else:
                self.stage.env.pop(key, None)

    def _do_run(self, ins: Instruction) -> dict[str, Any]:
        options, rest = split_options(ins.args)
        exec_form = parse_json_array(rest)
        text = rest
        if exec_form is not None:
            if len(exec_form) >= 3 and exec_form[0].rsplit("/", 1)[-1] in _SHELLS:
                text = exec_form[2] if exec_form[1] == "-c" else " ".join(exec_form)
            else:
                text = " ".join(exec_form)
        if ins.heredoc_body:
            text = f"{text}\n{ins.heredoc_body}"
        has_sudo = False
        has_curl_pipe = False
        apt_install = False
        apt_recommends = False
        apt_clean = False
        for pipeline in shell_pipelines(text):
            fetched = False
            for raw_words in pipeline:
                wrappers, program, words = command_name(raw_words)
                if "sudo" in wrappers or program == "sudo":
                    has_sudo = True
                if fetched and _INTERPRETER_RE.match(program):
                    has_curl_pipe = True
                if program in _FETCHERS:
                    fetched = True
                if program in _APT_PROGRAMS:
                    positional = [w for w in words if not w.startswith("-")]
                    if positional and positional[0] == "install":
                        apt_install = True
                        if "--no-install-recommends" in words:
                            apt_recommends = True
                    elif positional and positional[0] in ("clean", "autoclean"):
                        apt_clean = True
                elif program in ("rm", "find") and any(_APT_LISTS in word for word in words):
                    apt_clean = True
        mount = options.get("mount", "")
        cache_mounted = any(target in mount for target in _APT_CACHE_TARGETS)
        return {
            "has_sudo": has_sudo,
            "has_curl_pipe": has_curl_pipe,
            "has_apt_no_recommends": apt_install and not apt_recommends,
            "has_apt_no_clean": apt_install and not apt_clean and not cache_mounted,
        }

    def _split_sources(self, rest: str) -> list[str]:
        words = parse_json_array(rest)
        if words is None:
            words = split_words(rest)
        # A heredoc source (<<EOF) is inline text, not a file
        return [w for w in words if not w.startswith("<<")]

    def _do_add(self, ins: Instruction) -> dict[str, Any]:
        options, rest = split_options(ins.args)
        items = self._split_sources(rest)
        sources = items[:-1] if len(items) >= 2 else []
        is_url = any(_is_url(s) for s in sources)
        local = [s for s in sources if not _is_url(s)]
        local_files = [s for s in local if not _is_archive(s)]
        if any(has_variable(s) for s in local_files) and not any(
            not has_variable(s) for s in local_files
        ):
            is_local: bool | Unknown = Unknown(" ".join(local_files))
        else:
            is_local = bool(local_files)
        if self._in_image(ins):
            self.add_count += 1
        return {
            "sources": sources,
            "destination": items[-1] if len(items) >= 2 else "",
            "is_url_add": is_url,
            "is_local_add": is_local,
            "has_checksum": "checksum" in options,
            "has_sensitive_file": any(_SENSITIVE_FILE_RE.search(s) for s in local),
            "has_chown": "chown" in options,
        }

    def _do_copy(self, ins: Instruction) -> dict[str, Any]:
        options, rest = split_options(ins.args)
        items = self._split_sources(rest)
        sources = items[:-1] if len(items) >= 2 else []
        from_ref = options.get("from", "")
        has_chown = "chown" in options
        if from_ref:
            self._copy_from_edge(from_ref)
        self.copies.append(
            _Copy(
                stage=self.stage,
                from_stage=bool(from_ref),
                has_chown=has_chown,
                onbuild=ins.onbuild,
            )
        )
        return {
            "sources": sources,
            "destination": items[-1] if len(items) >= 2 else "",
            "has_sensitive_file": any(_SENSITIVE_FILE_RE.search(s) for s in sources),
            "has_chown": has_chown,
            "from_stage": from_ref,
            "chown_missing": False,
        }

    def _copy_from_edge(self, from_ref: str) -> None:
        stage = self.stage
        if stage is None:
            return
        source = from_ref.lower()
        target: _Stage | None = None
        if source.isdigit():
            index = int(source)
            target = self.stages[index] if index < len(self.stages) else None
        else:
            target = self.stage_by_name.get(source)
        if target is not None and target is not stage:
            self._edge(stage, target, "copy_from")

    # -- finishing ------------------------------------------------------------

    def finish(self, escape: str, syntax: str) -> ParsedOutput:
        final = self.stages[-1] if self.stages else None
        self._resolve_copy_ownership(final)
        resources = list(self.resources)
        for stage in self.stages:
            resources.append(self._stage_resource(stage, final))
            for address in self.instruction_addresses.get(stage.index, []):
                self.edges.append(
                    ParsedEdge(
                        source=address,
                        target=f"dockerfile.stage.{stage.ident}",
                        edge_type="containment",
                        declared=False,
                    )
                )
        summary = self._summary(final)
        resources.append(
            ParsedResource(
                resource_type="dockerfile_image",
                address="dockerfile.image.summary",
                name=f"Dockerfile ({summary['base_image'] or 'unknown'})",
                provider="docker",
                properties=summary,
                source_location=self.source_path,
            )
        )
        metadata: dict[str, Any] = {"escape": escape}
        if syntax:
            metadata["syntax"] = syntax
        return ParsedOutput(
            resources=resources,
            source_path=self.source_path,
            format_type="dockerfile",
            metadata=metadata,
            edges=self.edges,
            diagnostics=self.diagnostics,
        )

    def _resolve_copy_ownership(self, final: _Stage | None) -> None:
        """Mark COPY lines that leave root-owned files in an image that runs as someone else.

        Only the final stage counts: earlier stages are build scratch space. A COPY from
        another stage is excluded, and so is any COPY when the image runs as root or the user
        is not known.
        """
        user = final.user if final is not None else None
        non_root = user is not None and _root_state(user) is False
        for copy, resource in self._copy_resources():
            missing = (
                non_root
                and copy.stage is final
                and not copy.onbuild
                and not copy.from_stage
                and not copy.has_chown
            )
            resource.properties["chown_missing"] = bool(missing)

    def _copy_resources(self) -> list[tuple[_Copy, ParsedResource]]:
        copy_resources = [r for r in self.resources if r.resource_type == "dockerfile_copy"]
        return list(zip(self.copies, copy_resources, strict=True))

    def _stage_resource(self, stage: _Stage, final: _Stage | None) -> ParsedResource:
        base = stage.base()
        props: dict[str, Any] = {
            "stage_name": stage.name,
            "stage_index": stage.index,
            "base_image": base.image_text,
            "base_ref": stage.image_text,
            "kind": stage.kind,
            "tag": stage.tag,
            "digest_pinned": base.digest_pinned,
            "parent_stage": stage.parent.ident if stage.parent else "",
            "is_final": stage is final,
            "has_user": stage.user is not None,
            "user_value": stage.user if stage.user is not None else "",
            "has_healthcheck": bool(stage.healthcheck),
            "has_workdir": stage.has_workdir,
            "exposed_ports": _unique(stage.ports),
            "exposed_port_ranges": [[lo, hi] for lo, hi in stage.port_ranges],
            "instruction_count": stage.instruction_count,
        }
        return ParsedResource(
            resource_type="dockerfile_stage",
            address=f"dockerfile.stage.{stage.ident}",
            name=f"Stage {stage.ident} ({stage.image_text or 'no base image'})",
            provider="docker",
            properties=props,
            source_location=self.source_path,
            start_line=stage.from_line,
            end_line=stage.last_line,
        )

    def _summary(self, final: _Stage | None) -> dict[str, Any]:
        ports: list[int] = []
        ranges: list[tuple[int, int]] = []
        unknown_ports: list[str] = []
        user: str | Unknown | None = None
        base_text = ""
        base_kind = "none"
        digest_pin: bool | Unknown = False
        non_minimal: bool | Unknown = False
        latest_final = False
        healthcheck = False
        workdir = False
        entrypoints = 0
        if final is not None:
            base = final.base()
            ports, ranges = final.ports, final.port_ranges
            unknown_ports = final.unknown_ports
            user, healthcheck = final.user, bool(final.healthcheck)
            workdir, entrypoints = final.has_workdir, final.entrypoint_count
            base_text, base_kind = base.image_text, base.kind
            latest_final = base.uses_latest_tag
            if base.kind == "registry" and base.ref is not None:
                digest_pin = base.digest_pinned
                non_minimal = _is_non_minimal(base.ref)
            elif base.kind == "variable":
                digest_pin = non_minimal = Unknown(base.image_text)
        user_set = user is not None
        flat_ports = _unique(ports)
        return {
            "has_user": user_set,
            "user_value": user if user is not None else "",
            "is_root_user": _root_state(user) if user is not None else False,
            "has_healthcheck": healthcheck,
            "has_workdir": workdir,
            "exposed_ports": flat_ports,
            "exposed_port_ranges": [[lo, hi] for lo, hi in ranges],
            "unknown_exposed_ports": list(unknown_ports),
            "has_ssh_exposed": _port_in(22, flat_ports, ranges),
            "has_privileged_port": any(p < 1024 for p in flat_ports)
            or any(lo < 1024 for lo, _hi in ranges),
            "base_image": base_text,
            "base_kind": base_kind,
            "has_digest_pin": digest_pin,
            "is_non_minimal": non_minimal,
            "uses_latest_tag": any(s.uses_latest_tag for s in self.stages),
            "final_stage_uses_latest_tag": latest_final,
            "stage_count": len([s for s in self.stages if s.from_line is not None]),
            "entrypoint_count": entrypoints,
            "add_count": self.add_count,
            "copy_without_chown": sum(
                1
                for r in self.resources
                if r.resource_type == "dockerfile_copy" and r.properties.get("chown_missing")
            ),
        }


def _is_non_minimal(ref: ImageRef) -> bool:
    """A full operating system image: a known distro family without a minimal variant."""
    repository = ref.repository.lower()
    family = repository.rsplit("/", 1)[-1]
    if family not in FULL_OS_FAMILIES:
        return False
    if any(marker in repository for marker in _MINIMAL_REPO_MARKERS):
        return False
    return _MINIMAL_TAG_RE.search(ref.tag.lower()) is None


class DockerfileParser(BaseParser):
    """Parse a Dockerfile (or Containerfile) into instruction, stage and summary resources."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if not isinstance(data, str):
            data = str(data)
        lexed = lex(data)
        builder = _Builder(source_path)
        for skipped in lexed.skipped:
            builder.diagnostics.append(
                Diagnostic(
                    "warning",
                    "dockerfile.skipped_line",
                    f"Skipped '{skipped.text}': {skipped.reason}",
                    source_path,
                    skipped.line,
                )
            )
        for instruction in lexed.instructions:
            builder.add(instruction)
        return builder.finish(lexed.escape, lexed.syntax)
