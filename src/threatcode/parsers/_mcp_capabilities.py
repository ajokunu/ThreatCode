"""What an AI agent can do through its MCP servers: the capability model.

The "lethal trifecta" is an agent that can read private data, ingest content an attacker
can write, and send data out or act on the outside world.
Any prompt injection in the untrusted content can then steer the agent to read the private
data and exfiltrate it.
No single server shows this; the combination of the servers one client config starts does.

This module holds the one reviewed table that gives a server its capability tags.
A server gets tags only from

- the table of known packages and images below (matched on the package or image name,
  never on a path or a config key), and
- facts the parser already proved about this very entry: a shell-exec server can read and
  act, a filesystem server rooted at the home directory can read private data, and a
  remote server receives whatever the agent sends it.

A server the table does not know contributes no tags and is reported as unknown capability,
so a missing entry never turns into a guessed finding.

Capability tags
---------------
``reads_private_data``
    Reads files, databases, repositories, messages or documents the user owns.
``ingests_untrusted_content``
    Returns content that a third party can write: web pages, search results, issues and
    pull requests, chat messages, shared documents.
``can_exfiltrate_or_act``
    Can send data to a host the user does not control or change the outside world: HTTP
    requests, a browser, a shell, posting messages, creating issues, any remote server.

The entries were reviewed on 2026-10-07 from each package's documented purpose.
They were not checked against the registries, so an entry says what the package is for, not
what a fork or a renamed release does.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Final

READS_PRIVATE_DATA: Final = "reads_private_data"
INGESTS_UNTRUSTED_CONTENT: Final = "ingests_untrusted_content"
CAN_EXFILTRATE_OR_ACT: Final = "can_exfiltrate_or_act"

CAPABILITY_TAGS: Final = (READS_PRIVATE_DATA, INGESTS_UNTRUSTED_CONTENT, CAN_EXFILTRATE_OR_ACT)

_R: Final = frozenset({READS_PRIVATE_DATA})
_U: Final = frozenset({INGESTS_UNTRUSTED_CONTENT})
_A: Final = frozenset({CAN_EXFILTRATE_OR_ACT})
_RU: Final = _R | _U
_RA: Final = _R | _A
_UA: Final = _U | _A
_RUA: Final = _R | _U | _A
_NONE: Final = frozenset[str]()


@dataclass(frozen=True)
class KnownServer:
    """One reviewed table entry."""

    tags: frozenset[str]
    note: str


# Package names are lower-case; PyPI names use hyphens (``mcp_server_fetch`` is looked up as
# ``mcp-server-fetch``).
PACKAGES: Final[dict[str, KnownServer]] = {
    # --- Reference servers (modelcontextprotocol/servers) ---
    "@modelcontextprotocol/server-filesystem": KnownServer(_R, "reads and writes local files"),
    "@modelcontextprotocol/server-memory": KnownServer(_NONE, "a local knowledge graph"),
    "@modelcontextprotocol/server-everything": KnownServer(_NONE, "the protocol test server"),
    "@modelcontextprotocol/server-sequential-thinking": KnownServer(_NONE, "reasoning scratchpad"),
    "@modelcontextprotocol/server-postgres": KnownServer(_R, "read-only SQL on a database"),
    "@modelcontextprotocol/server-sqlite": KnownServer(_R, "SQL on a local database"),
    "@modelcontextprotocol/server-redis": KnownServer(_R, "reads and writes a Redis store"),
    "@modelcontextprotocol/server-github": KnownServer(
        _RUA, "private repositories; issues and pull requests by outsiders; can comment and push"
    ),
    "@modelcontextprotocol/server-gitlab": KnownServer(
        _RUA, "private projects; issues and merge requests by outsiders; can comment and push"
    ),
    "@modelcontextprotocol/server-brave-search": KnownServer(_U, "web search results"),
    "@modelcontextprotocol/server-puppeteer": KnownServer(_UA, "a browser that opens any URL"),
    "@modelcontextprotocol/server-slack": KnownServer(
        _RUA, "workspace messages written by others; can post messages"
    ),
    "@modelcontextprotocol/server-gdrive": KnownServer(_RU, "files others can share into a drive"),
    "mcp-server-fetch": KnownServer(_UA, "fetches any URL and returns its content"),
    "mcp-server-git": KnownServer(_R, "reads a local git repository"),
    "mcp-server-time": KnownServer(_NONE, "time and time zones"),
    "mcp-server-sqlite": KnownServer(_R, "SQL on a local database"),
    # --- Browser automation ---
    "@playwright/mcp": KnownServer(_UA, "a browser that opens any URL"),
    "@executeautomation/playwright-mcp-server": KnownServer(_UA, "a browser that opens any URL"),
    # --- Shell and terminal servers: can read anything the user can and run commands ---
    "@wonderwhy-er/desktop-commander": KnownServer(_RA, "terminal and file operations"),
    "mcp-server-commands": KnownServer(_RA, "runs arbitrary commands"),
    "super-shell-mcp": KnownServer(_RA, "runs shell commands"),
    "mcp-shell-server": KnownServer(_RA, "runs shell commands"),
    "mcp-server-shell": KnownServer(_RA, "runs shell commands"),
    "iterm-mcp": KnownServer(_RA, "types commands into iTerm sessions"),
    "ssh-mcp": KnownServer(_RA, "runs commands over SSH"),
    "mcp-server-ssh": KnownServer(_RA, "runs commands over SSH"),
    # --- Hosted services with a local wrapper ---
    "@notionhq/notion-mcp-server": KnownServer(_RUA, "workspace pages others can edit; can write"),
    "@upstash/context7-mcp": KnownServer(_U, "library documentation from the web"),
    "duckduckgo-mcp-server": KnownServer(_U, "web search and page fetch"),
}

# Container images, keyed by the normalized name (registry and repository, no tag).
IMAGES: Final[dict[str, KnownServer]] = {
    "ghcr.io/github/github-mcp-server": PACKAGES["@modelcontextprotocol/server-github"],
    "docker.io/mcp/github-mcp-server": PACKAGES["@modelcontextprotocol/server-github"],
    "docker.io/mcp/fetch": PACKAGES["mcp-server-fetch"],
    "docker.io/mcp/filesystem": PACKAGES["@modelcontextprotocol/server-filesystem"],
    "docker.io/mcp/postgres": PACKAGES["@modelcontextprotocol/server-postgres"],
    "docker.io/mcp/sqlite": PACKAGES["mcp-server-sqlite"],
    "docker.io/mcp/git": PACKAGES["mcp-server-git"],
    "docker.io/mcp/memory": PACKAGES["@modelcontextprotocol/server-memory"],
    "docker.io/mcp/time": PACKAGES["mcp-server-time"],
    "docker.io/mcp/puppeteer": PACKAGES["@modelcontextprotocol/server-puppeteer"],
    "docker.io/mcp/playwright": PACKAGES["@playwright/mcp"],
}


def _words(basename: str) -> set[str]:
    return {w for w in re.split(r"[-_.]", basename) if w}


# Name patterns for servers the table does not list one by one. Each tests the words of the
# package basename (the part after a scope slash), never a path or the config key.
COMMAND_PATTERNS: Final[tuple[tuple[Callable[[set[str]], bool], KnownServer], ...]] = (
    (
        lambda w: "mcp" in w and bool(w & {"shell", "terminal"}),
        KnownServer(_RA, "a shell or terminal server by name"),
    ),
    (
        lambda w: bool(w & {"playwright", "puppeteer"}),
        KnownServer(_UA, "browser automation by name"),
    ),
)


def normalize_name(package_name: str) -> str:
    """Lower-case a package name; a scoped npm name keeps its scope, others use hyphens."""
    name = package_name.strip().lower()
    return name if name.startswith("@") else name.replace("_", "-")


def basename_of(package_name: str) -> str:
    """The part of a package or image name after the last slash."""
    return normalize_name(package_name).rsplit("/", 1)[-1]


@dataclass(frozen=True)
class ServerCapability:
    """The capabilities of one server and how they were learned."""

    tags: frozenset[str]
    # True when the table (or a name pattern) knows the server; False means unknown
    known: bool
    # package, image, pattern, structure or unknown
    source: str


def lookup(package_name: str, *, container: bool = False) -> tuple[KnownServer, str] | None:
    """Find a table entry for a package or image name; return it with how it matched."""
    if not package_name:
        return None
    name = normalize_name(package_name)
    entry = (IMAGES if container else PACKAGES).get(name)
    if entry is not None:
        return entry, "image" if container else "package"
    words = _words(basename_of(name))
    for predicate, pattern_entry in COMMAND_PATTERNS:
        if predicate(words):
            return pattern_entry, "pattern"
    return None


def server_capability(
    package_name: str,
    *,
    container: bool = False,
    exposes_shell_exec: bool = False,
    reaches_private_files: bool = False,
    remote_server: bool = False,
) -> ServerCapability:
    """Capabilities of one server from the table plus facts proved about its entry.

    ``known`` is True only when the table knows the server; structural facts add tags but
    never make an unknown server known.
    """
    tags: set[str] = set()
    found = lookup(package_name, container=container)
    if found is not None:
        tags |= found[0].tags
    if exposes_shell_exec:
        tags |= _RA
    if reaches_private_files:
        tags.add(READS_PRIVATE_DATA)
    if remote_server:
        tags.add(CAN_EXFILTRATE_OR_ACT)
    if found is not None:
        return ServerCapability(frozenset(tags), True, found[1])
    source = "structure" if tags else "unknown"
    return ServerCapability(frozenset(tags), False, source)


@dataclass(frozen=True)
class AgentCapabilities:
    """The union over the enabled servers of one config scope."""

    tags: frozenset[str]
    unknown_servers: tuple[str, ...]

    @property
    def lethal_trifecta(self) -> bool:
        return all(tag in self.tags for tag in CAPABILITY_TAGS)


def aggregate(servers: Iterable[tuple[str, ServerCapability]]) -> AgentCapabilities:
    """Union the definite capabilities of ``(server name, capability)`` pairs.

    Servers the table does not know add only the tags their entry proves and are listed in
    ``unknown_servers``.
    """
    tags: set[str] = set()
    unknown: list[str] = []
    for name, capability in servers:
        tags |= capability.tags
        if not capability.known:
            unknown.append(name)
    return AgentCapabilities(frozenset(tags), tuple(unknown))
