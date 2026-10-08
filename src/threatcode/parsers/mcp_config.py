"""MCP client configuration parser for ThreatCode.

Turns each server entry in an MCP client config file into an ``mcp_server`` resource, and
each config scope into one synthetic ``mcp_agent`` resource that holds the union of what its
servers let the agent do. Supported shapes, checked against each client's documentation on
2026-10-01:

- ``mcpServers`` object: Claude Desktop (``claude_desktop_config.json``),
  Claude Code (``.mcp.json``, and ``~/.claude.json`` including the
  per-project ``projects.<path>.mcpServers`` entries), Cursor
  (``.cursor/mcp.json``), Windsurf/Devin (``mcp_config.json``, remote servers
  use ``serverUrl``), Gemini CLI (``settings.json``, remote servers use ``httpUrl``) and the
  portable format VS Code and Copilot read (``.mcp.json``, ``~/.copilot/mcp-config.json``).
- ``servers`` object in VS Code's own ``.vscode/mcp.json``, which may contain
  comments (JSONC).

OpenCode (``mcp`` object with ``type: local|remote``) and Zed (``context_servers``) use other
top-level keys and are not read: such a file is not claimed as an MCP config.
A server entry with none of ``command``, ``url``, ``serverUrl`` or ``httpUrl`` gets transport
``unknown`` and an ``mcp.unknown_entry`` diagnostic instead of a benign-looking record.

The parser never connects to a server. It resolves each entry's effective launch
(``_mcp_launch``), derives the boolean properties that the YAML rules in
``engine/rules/builtin/mcp/`` match on, and stores only the names of environment variables
and headers, never their values. Secret-bearing arguments are redacted in ``properties["args"]``.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final
from urllib.parse import urlsplit

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import ParseError
from threatcode.parsers._json_lines import json_line_index
from threatcode.parsers._mcp_capabilities import (
    CAN_EXFILTRATE_OR_ACT,
    CAPABILITY_TAGS,
    INGESTS_UNTRUSTED_CONTENT,
    READS_PRIVATE_DATA,
    ServerCapability,
    aggregate,
    basename_of,
    normalize_name,
    server_capability,
)
from threatcode.parsers._mcp_launch import (
    EffectiveLaunch,
    bind_mount_sources,
    container_flags,
    lacks_no_new_privileges,
    resolve_launch,
    unpinned_packages,
)
from threatcode.parsers._mcp_secrets import (
    SecretHit,
    redact_args,
    redact_url,
    scan_args,
    scan_env,
    scan_headers,
    scan_url,
    summarize,
)
from threatcode.parsers._text import decode_input
from threatcode.parsers.base import BaseParser, ParsedEdge, ParsedOutput, ParsedResource

# File names whose JSON may carry comments or trailing commas (VS Code JSONC).
MCP_CONFIG_FILENAMES: frozenset[str] = frozenset(
    {
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "mcp_config.json",
        "mcp-config.json",
    }
)

# Keys that say how a server is reached; an entry with none of them is of unknown shape.
_LAUNCH_KEYS: Final = ("command", "url", "serverUrl", "httpUrl")

_AUTH_HEADER_RE: Final = re.compile(
    r"(?i)^(authorization|proxy-authorization|x-api-key|api-key|.*token.*)$"
)

# Published MCP servers whose purpose is running commands for the agent. The first five were
# verified against the npm and PyPI registries on 2026-10-01; the SSH and iTerm entries were
# added on 2026-10-07 from the packages' documented purpose and were not registry-checked.
_SHELL_EXEC_PACKAGES: Final = frozenset(
    {
        "@wonderwhy-er/desktop-commander",  # "MCP server for terminal operations"
        "mcp-server-commands",  # "An MCP server to run arbitrary commands"
        "super-shell-mcp",  # "MCP server for executing shell commands"
        "mcp-shell-server",  # PyPI: "Execute shell commands via MCP protocol"
        "mcp-server-shell",  # PyPI: "shell command execution capabilities for LLMs"
        "iterm-mcp",  # types commands into iTerm sessions
        "ssh-mcp",  # runs commands over SSH
        "mcp-server-ssh",  # runs commands over SSH
    }
)
_SHELL_NAME_WORDS: Final = frozenset({"shell", "terminal"})


# ── JSONC ────────────────────────────────────────────────────────────


def strip_jsonc(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas outside JSON strings.

    A comma outside a string is dropped only when the next character that is neither
    whitespace nor part of a comment is ``}`` or ``]``, so a value such as ``"abc,}"`` is
    left alone.
    Newlines inside block comments are kept, so line numbers still match the original text.
    A leading byte order mark is dropped.
    """
    if text.startswith("\ufeff"):
        text = text[1:]
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
    pending_comma: int | None = None  # index in out of a comma that may turn out trailing
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            pending_comma = None
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            stop = n if end == -1 else end + 2
            out.append("\n" * text.count("\n", i, stop))
            i = stop
        elif ch == ",":
            pending_comma = len(out)
            out.append(ch)
            i += 1
        elif ch in "}]":
            if pending_comma is not None:
                out[pending_comma] = ""
                pending_comma = None
            out.append(ch)
            i += 1
        else:
            if not ch.isspace():
                pending_comma = None
            out.append(ch)
            i += 1
    return "".join(out)


# ── Detection ────────────────────────────────────────────────────────


def is_mcp_config(path: Path, data: Any) -> bool:
    """Return True if parsed JSON data has an MCP client config shape."""
    if not isinstance(data, dict):
        return False
    if isinstance(data.get("mcpServers"), dict):
        return True
    if path.name == "mcp.json" and isinstance(data.get("servers"), dict):
        return all(_looks_like_server(v) for v in data["servers"].values())
    projects = data.get("projects")
    if path.name == ".claude.json" and isinstance(projects, dict):
        return any(
            isinstance(p, dict) and isinstance(p.get("mcpServers"), dict) for p in projects.values()
        )
    return False


def _looks_like_server(entry: Any) -> bool:
    return isinstance(entry, dict) and any(k in entry for k in (*_LAUNCH_KEYS, "type"))


# ── Parser ───────────────────────────────────────────────────────────


@dataclass
class _Scope:
    """One place a config holds servers: the file itself, or one project of ``~/.claude.json``."""

    client_format: str
    servers: dict[str, Any]
    pointer: str  # JSON pointer of the servers object
    disabled: frozenset[str] = frozenset()
    project_path: str = ""

    @property
    def label(self) -> str:
        """The readable project name, or empty for the file's own scope."""
        return Path(self.project_path).name or "project" if self.project_path else ""

    @property
    def project_hash(self) -> str:
        """A stable short hash of the full project path, so equal basenames never collide."""
        if not self.project_path:
            return ""
        return hashlib.sha256(self.project_path.encode("utf-8")).hexdigest()[:8]

    @property
    def slug(self) -> str:
        if not self.project_path:
            return ""
        base = re.sub(r"[^A-Za-z0-9_-]+", "_", self.label).strip("_") or "project"
        return f"{base}-{self.project_hash}"


@dataclass
class _Built:
    resource: ParsedResource
    capability: ServerCapability
    disabled: bool
    line: int | None
    unknown_entry: bool


class MCPConfigParser(BaseParser):
    """Parse MCP client configuration files into ``mcp_server`` resources."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if isinstance(data, str):
            data = json.loads(strip_jsonc(data))
        if not isinstance(data, dict):
            return ParsedOutput(source_path=source_path, format_type="mcp_config")

        content = _read_text(source_path)
        line_index = json_line_index(strip_jsonc(content)) if content else {}

        resources: list[ParsedResource] = []
        edges: list[ParsedEdge] = []
        diagnostics: list[Diagnostic] = []

        for scope in _scopes(data):
            built = [
                self._build_server(str(name), entry, scope, data, source_path, line_index)
                for name, entry in scope.servers.items()
                if isinstance(entry, dict)
            ]
            for item in built:
                resources.append(item.resource)
                diagnostics.extend(_server_diagnostics(item, source_path))
            agent = _agent_for(scope, built, source_path, line_index)
            if agent is not None:
                resources.append(agent[0])
                edges.extend(agent[1])

        return ParsedOutput(
            resources=resources,
            edges=edges,
            diagnostics=diagnostics,
            source_path=source_path,
            format_type="mcp_config",
        )

    def _build_server(
        self,
        name: str,
        entry: dict[str, Any],
        scope: _Scope,
        root: dict[str, Any],
        source_path: str,
        line_index: dict[str, int],
    ) -> _Built:
        address = f"mcp_server.{scope.slug}.{name}" if scope.slug else f"mcp_server.{name}"
        properties, capability, unknown_entry = _server_properties(name, entry, scope, root)
        line = line_index.get(f"{scope.pointer}/{_escape_pointer(name)}")
        resource = ParsedResource(
            resource_type="mcp_server",
            address=address,
            name=name,
            provider="mcp",
            properties=properties,
            source_location=source_path,
            start_line=line,
        )
        return _Built(resource, capability, bool(properties["disabled"]), line, unknown_entry)


def _escape_pointer(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _string_list(value: Any) -> frozenset[str]:
    if isinstance(value, list):
        return frozenset(v for v in value if isinstance(v, str))
    return frozenset()


def _scopes(data: dict[str, Any]) -> list[_Scope]:
    """The scopes found in the config: the file's own, then each project of ``~/.claude.json``."""
    scopes: list[_Scope] = []
    own_disabled = _string_list(data.get("disabledMcpServers")) | _string_list(
        data.get("disabledMcpjsonServers")
    )
    if isinstance(data.get("mcpServers"), dict):
        scopes.append(_Scope("mcpServers", data["mcpServers"], "/mcpServers", own_disabled))
    elif isinstance(data.get("servers"), dict):
        scopes.append(_Scope("vscode", data["servers"], "/servers", own_disabled))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            if isinstance(project, dict) and isinstance(project.get("mcpServers"), dict):
                disabled = _string_list(project.get("disabledMcpServers")) | _string_list(
                    project.get("disabledMcpjsonServers")
                )
                scopes.append(
                    _Scope(
                        "mcpServers",
                        project["mcpServers"],
                        f"/projects/{_escape_pointer(str(project_path))}/mcpServers",
                        disabled,
                        str(project_path),
                    )
                )
    return scopes


# ── Server properties ────────────────────────────────────────────────


def _mapping(value: Any) -> dict[Any, Any]:
    return value if isinstance(value, dict) else {}


def _scalar_args(values: Any) -> list[str]:
    return [
        str(a) for a in values or [] if isinstance(a, str | int | float) and not isinstance(a, bool)
    ]


def _command_and_args(entry: dict[str, Any]) -> tuple[str, list[str]]:
    """``command`` and ``args``, also reading a list command and Zed-style ``{path, args}``."""
    raw = entry.get("command")
    args = _scalar_args(entry.get("args"))
    if isinstance(raw, list):
        words = _scalar_args(raw)
        return (words[0] if words else ""), words[1:] + args
    if isinstance(raw, dict):
        return str(raw.get("path") or ""), _scalar_args(raw.get("args")) + args
    return (str(raw) if isinstance(raw, str) else ""), args


def is_loopback_host(host: str) -> bool:
    """True for ``localhost``, ``*.localhost`` and loopback IP literals; nothing else.

    ``127.attacker.com`` and ``127.0.0.1.nip.io`` are ordinary names, so they are not loopback.
    """
    name = host.strip().strip("[]").lower().rstrip(".")
    if not name:
        return False
    if name == "localhost" or name.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def _url_parts(url: str) -> tuple[str, str]:
    """Scheme and lower-cased host of a URL; empty strings for text that is not a URL."""
    try:
        parts = urlsplit(url)
        return parts.scheme.lower(), (parts.hostname or "").lower()
    except ValueError:
        return "", ""


# Every property an MCP resource can carry, by resource type.
# A rule may read a property of an ``mcp_*`` resource only if it is listed here: the provenance
# gate (tests/test_engine/test_rule_property_provenance.py) fails a rule that reads anything
# else, because such a rule can never fire, and it fails when the parser emits a property this
# table does not list or this table lists one the parser never emits.
PRODUCED: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "mcp_server": frozenset(
            {
                "args",
                "bridge",
                "bridge_allow_http",
                "broad_filesystem_access",
                "broad_filesystem_paths",
                "capability_known",
                "capability_tags",
                "client_format",
                "command",
                "container_flags",
                "container_lacks_no_new_privileges",
                "container_privileged",
                "disabled",
                "env_keys",
                "exposes_sensitive_paths",
                "exposes_shell_exec",
                "has_configured_auth",
                "has_high_confidence_secret",
                "has_literal_secret",
                "has_possible_secret",
                "header_keys",
                "is_loopback",
                "is_remote",
                "launch_wrappers",
                "literal_secret_arg_indexes",
                "literal_secret_keys",
                "package_name",
                "package_unpinned",
                "project_hash",
                "remote_without_configured_auth",
                "runner",
                "sandbox_enabled",
                "scope",
                "secret_confidence",
                "sensitive_filesystem_paths",
                "server_name",
                "transport",
                "unpinned_packages",
                "unpinned_reasons",
                "url_host",
                "url_scheme",
                "uses_plaintext_transport",
            }
        ),
        "mcp_agent": frozenset(
            {
                CAN_EXFILTRATE_OR_ACT,
                INGESTS_UNTRUSTED_CONTENT,
                READS_PRIVATE_DATA,
                "capabilities",
                "client_format",
                "enabled_server_count",
                "project_hash",
                "scope",
                "server_count",
                "unknown_capability_servers",
            }
        ),
    }
)


def _server_properties(
    name: str, entry: dict[str, Any], scope: _Scope, root: dict[str, Any]
) -> tuple[dict[str, Any], ServerCapability, bool]:
    command, args = _command_and_args(entry)
    launch = resolve_launch(command, args)
    env = _mapping(entry.get("env"))
    headers = _mapping(entry.get("headers"))
    url_value = next(
        (entry[k] for k in ("url", "serverUrl", "httpUrl") if isinstance(entry.get(k), str)), ""
    )
    native_url = str(url_value)
    bridged = bool(launch.bridge and launch.remote_url)
    url = native_url or (launch.remote_url if bridged else "")

    no_launch_key = not any(entry.get(k) for k in _LAUNCH_KEYS)
    transport = str(entry.get("type") or entry.get("transport") or "")
    if bridged and transport in ("", "stdio"):
        transport = "stdio-bridge"
    elif not transport:
        transport = "stdio" if command else ("http" if native_url else "unknown")
    if no_launch_key:
        transport = "unknown"
    is_remote = bool(url) and transport != "stdio"

    scheme, host = _url_parts(url) if url else ("", "")
    is_loopback = is_loopback_host(host) if host else False
    uses_plaintext = scheme in ("http", "ws") and not is_loopback and is_remote

    # ── Secrets: env, headers, URL and arguments
    hits: list[SecretHit] = scan_env(env) + scan_headers(headers)
    url_has_auth = False
    if url:
        url_scan = scan_url(url)
        for hit in url_scan.hits:
            if bridged and not native_url:
                hit.origin = launch.remote_url_origin
                hit.redact = _redact_url_text
        hits += url_scan.hits
        url_has_auth = url_scan.has_userinfo or url_scan.has_query_credential
        url_has_auth = url_has_auth or any(h.label.endswith(":path") for h in url_scan.hits)
    hits += scan_args(launch)
    labels, arg_indexes, confidence = summarize(hits)
    redacted_args = redact_args(args, hits, launch.split_origins)

    all_header_names = [str(k) for k in headers] + list(launch.extra_headers)
    has_auth = (
        any(_AUTH_HEADER_RE.match(h) for h in all_header_names)
        or any(k in entry for k in ("oauth", "auth", "headersHelper"))
        or url_has_auth
    )

    # ── Pinning
    unpinned = unpinned_packages(launch)

    # ── Container and filesystem exposure
    flags = container_flags(launch)
    broad: list[str] = []
    sensitive: list[str] = []
    for source in bind_mount_sources(launch):
        normalized = normalize_path(source)
        if is_system_mount(normalized):
            flags.append(f"-v {source}")
        if is_broad_path(normalized):
            broad.append(source)
        if is_sensitive_path(normalized):
            sensitive.append(source)
    for path in _filesystem_candidates(launch):
        normalized = normalize_path(path)
        if is_broad_path(normalized):
            broad.append(path)
        if is_sensitive_path(normalized):
            sensitive.append(path)
    broad = list(dict.fromkeys(broad))
    sensitive = list(dict.fromkeys(sensitive))

    shell_exec = _exposes_shell_exec(launch)
    disabled = (
        entry.get("disabled") is True or entry.get("enabled") is False or name in scope.disabled
    )
    sandbox = entry.get("sandbox") if scope.client_format == "vscode" else None

    capability = server_capability(
        launch.package_name,
        container=bool(launch.container_runtime),
        exposes_shell_exec=shell_exec,
        reaches_private_files=bool(broad or sensitive),
        remote_server=is_remote and not is_loopback,
    )

    properties: dict[str, Any] = {
        "server_name": name,
        "client_format": scope.client_format,
        "scope": scope.label,
        "transport": transport,
        "command": launch.inner_argv[0].text if -1 in launch.split_origins else command,
        "args": redacted_args,
        "env_keys": sorted(str(k) for k in env),
        "header_keys": sorted(set(all_header_names)),
        "url_scheme": scheme,
        "url_host": host,
        "is_remote": is_remote,
        "is_loopback": is_loopback,
        "uses_plaintext_transport": uses_plaintext,
        "bridge": launch.bridge,
        "bridge_allow_http": launch.allow_http,
        "has_configured_auth": has_auth,
        "remote_without_configured_auth": is_remote and not is_loopback and not has_auth,
        "has_literal_secret": bool(hits),
        "has_high_confidence_secret": confidence == "high",
        "has_possible_secret": confidence == "medium",
        "secret_confidence": confidence or "",
        "literal_secret_keys": labels,
        "literal_secret_arg_indexes": arg_indexes,
        "runner": launch.runner,
        "package_name": launch.package_name,
        "launch_wrappers": list(launch.wrappers),
        "package_unpinned": bool(unpinned),
        "unpinned_packages": [spec for spec, _reason in unpinned],
        "unpinned_reasons": [f"{spec}: {reason}" for spec, reason in unpinned],
        "broad_filesystem_access": bool(broad),
        "broad_filesystem_paths": broad,
        "exposes_sensitive_paths": bool(sensitive),
        "sensitive_filesystem_paths": sensitive,
        "exposes_shell_exec": shell_exec,
        "container_privileged": bool(flags),
        "container_flags": flags,
        "container_lacks_no_new_privileges": lacks_no_new_privileges(launch),
        "sandbox_enabled": bool(sandbox) or _vscode_sandbox_enabled(root),
        "disabled": disabled,
        "capability_tags": sorted(capability.tags),
        "capability_known": capability.known,
    }
    if scope.project_path:
        properties["project_hash"] = scope.project_hash
    return properties, capability, no_launch_key


def _redact_url_text(text: str) -> str:
    return redact_url(text)


def _vscode_sandbox_enabled(root: dict[str, Any]) -> bool:
    sandbox = root.get("sandbox")
    return isinstance(sandbox, dict) and bool(sandbox)


# ── Filesystem paths ─────────────────────────────────────────────────

_HOME_RE: Final = re.compile(
    r"^(?:~|\$\{(?:env:)?(?:HOME|USERPROFILE|userHome)\}|\$env:(?:HOME|USERPROFILE)"
    r"|\$(?:HOME|USERPROFILE)|%(?:USERPROFILE|HOMEPATH|HOME)%)(?=/|$)",
    re.IGNORECASE,
)
_DRIVE_RE: Final = re.compile(r"^[A-Za-z]:(?:/|$)")
_BROAD_PATH_RE: Final = re.compile(
    r"""^(?:
        /                                  # filesystem root
      | ~ | ~/\.\.                         # the home directory and its parent
      | /(?:Users|home)                    # the parent of every home directory
      | /(?:Users|home)/[^/]+              # a home directory
      | /root
      | /(?:mnt|Volumes|media)             # mount points
      | /mnt/[a-z]                         # a Windows drive under WSL
      | [A-Za-z]:/?                        # a whole Windows drive
      | [A-Za-z]:/Users(?:/[^/]+)?         # C:\\Users and a Windows home directory
    )$""",
    re.VERBOSE,
)
_CREDENTIAL_DIRS: Final = frozenset(
    {".ssh", ".aws", ".gnupg", ".kube", ".config", ".azure", ".docker", ".netrc", ".npmrc"}
)
_SYSTEM_DIRS: Final = ("/etc", "/var/run", "/run", "/proc", "/sys", "/dev", "/boot", "/private/etc")
# Path-taking flags of any server: --allowed-directories=/, --root /home, --workspace ~
_PATH_FLAG_RE: Final = re.compile(
    r"(?i)^--?(?:[a-z0-9]+-)*(?:dirs?|directory|directories|paths?|roots?|folders?|workspaces?"
    r"|repos?|repository|files?)$"
)
_FILESYSTEM_WORDS: Final = frozenset({"filesystem", "fs"})


def normalize_path(raw: str) -> str:
    """Normalize a path argument for classification.

    Home variables of every client (``~``, ``$HOME``, ``${HOME}``, ``${env:HOME}``,
    ``${userHome}``, ``%USERPROFILE%``, ``$env:USERPROFILE``) become ``~``, backslashes become
    slashes, ``.`` and ``..`` are resolved lexically and trailing slashes are dropped.
    """
    text = raw.strip().strip("\"'").replace("\\", "/")
    text = _HOME_RE.sub("~", text)
    text = re.sub(r"/{2,}", "/", text)
    drive = _DRIVE_RE.match(text)
    if drive:
        letter, rest = text[0].upper(), text[2:]
        normalized = posixpath.normpath("/" + rest.lstrip("/")) if rest.strip("/") else "/"
        return f"{letter}:{normalized}" if normalized != "/" else f"{letter}:/"
    if text.startswith("~"):
        tail = text[1:].lstrip("/")
        if not tail:
            return "~"
        resolved = posixpath.normpath("/home_/" + tail)
        if resolved == "/home_":
            return "~"
        if resolved == "/":
            return "~/.."
        return "~" + resolved[len("/home_") :]
    if not text:
        return ""
    normalized = posixpath.normpath(text)
    return "/" if normalized in ("//", "/") else normalized


def _is_pathlike(text: str) -> bool:
    s = text.strip().strip("\"'")
    return bool(
        s.startswith(("/", "~", "./", "../", "\\\\"))
        or _HOME_RE.match(s.replace("\\", "/"))
        or re.match(r"^[A-Za-z]:[\\/]", s)
    )


def is_broad_path(normalized: str) -> bool:
    """A filesystem or drive root, a mount point, or a home directory or its parent."""
    return bool(_BROAD_PATH_RE.match(normalized))


def is_system_mount(normalized: str) -> bool:
    """The root, the container runtime socket or a system directory (``/etc``, ``/proc``...)."""
    if normalized == "/" or normalized.endswith("docker.sock"):
        return True
    return any(normalized == d or normalized.startswith(d + "/") for d in _SYSTEM_DIRS)


def is_sensitive_path(normalized: str) -> bool:
    """A credential directory, the keychain, the runtime socket or a system directory."""
    if not normalized:
        return False
    parts = [p for p in normalized.split("/") if p]
    if any(p in _CREDENTIAL_DIRS for p in parts):
        return True
    if "Library/Keychains" in normalized or normalized.endswith("docker.sock"):
        return True
    if re.match(r"^[A-Za-z]:/Windows(?:/|$)", normalized):
        return True
    return any(normalized == d or normalized.startswith(d + "/") for d in _SYSTEM_DIRS)


def _is_filesystem_server(launch: EffectiveLaunch) -> bool:
    name = launch.package_name
    if not name:
        return False
    words = {w for w in re.split(r"[-_.]", basename_of(name)) if w}
    return bool(words & _FILESYSTEM_WORDS)


def _filesystem_candidates(launch: EffectiveLaunch) -> list[str]:
    """Path arguments of the server program worth classifying.

    A path given to a named path flag counts on any server.
    A bare positional path counts for a filesystem server, where it is an allowed root.
    A server that takes some other positional path (``node server.js /home/me``) is not
    guessed at.
    """
    fs_server = _is_filesystem_server(launch)
    found: list[str] = []
    tokens = [t.text for t in launch.server_args]
    previous_flag = ""
    for text in tokens:
        if text.startswith("-"):
            flag, eq, value = text.partition("=")
            previous_flag = flag
            if eq and _is_pathlike(value) and (_PATH_FLAG_RE.match(flag) or fs_server):
                found.append(value)
            continue
        if _is_pathlike(text) and (fs_server or _PATH_FLAG_RE.match(previous_flag)):
            found.append(text)
        previous_flag = ""
    return found


# ── Shell exposure ───────────────────────────────────────────────────


def _exposes_shell_exec(launch: EffectiveLaunch) -> bool:
    """True when the launched package is a known shell server or is named as one.

    Only the package position of the effective launch is read: the package (or the
    ``--from`` value), the module of ``python -m`` and the image repository.
    A directory in an argument path such as ``/home/me/mcp-shell-docs/server.js`` is never a
    package, so it cannot match.
    """
    name = normalize_name(launch.package_name)
    if not name:
        return False
    if name in _SHELL_EXEC_PACKAGES or basename_of(name) in _SHELL_EXEC_PACKAGES:
        return True
    words = {w for w in re.split(r"[-_.]", basename_of(name)) if w}
    return "mcp" in words and bool(words & _SHELL_NAME_WORDS)


# ── Agent node ───────────────────────────────────────────────────────


def _agent_for(
    scope: _Scope,
    built: list[_Built],
    source_path: str,
    line_index: dict[str, int],
) -> tuple[ParsedResource, list[ParsedEdge]] | None:
    """The synthetic ``mcp_agent`` of one scope, wired to its enabled servers."""
    enabled = [b for b in built if not b.disabled]
    if not enabled:
        return None
    capabilities = aggregate((b.resource.name, b.capability) for b in enabled)
    address = f"mcp_agent.{scope.slug}" if scope.slug else "mcp_agent.config"
    name = scope.label or (Path(source_path).name if source_path else "config")
    tags = capabilities.tags
    properties: dict[str, Any] = {
        "client_format": scope.client_format,
        "scope": scope.label,
        "server_count": len(built),
        "enabled_server_count": len(enabled),
        "capabilities": [t for t in CAPABILITY_TAGS if t in tags],
        READS_PRIVATE_DATA: READS_PRIVATE_DATA in tags,
        INGESTS_UNTRUSTED_CONTENT: INGESTS_UNTRUSTED_CONTENT in tags,
        CAN_EXFILTRATE_OR_ACT: CAN_EXFILTRATE_OR_ACT in tags,
        "unknown_capability_servers": list(capabilities.unknown_servers),
    }
    if scope.project_path:
        properties["project_hash"] = scope.project_hash
    start = line_index.get(scope.pointer)
    agent = ParsedResource(
        resource_type="mcp_agent",
        address=address,
        name=name,
        provider="mcp",
        properties=properties,
        source_location=source_path,
        start_line=start,
    )
    edges: list[ParsedEdge] = []
    for item in enabled:
        server = item.resource.address
        props = item.resource.properties
        # What the edge carries, for the boundary analysis that will read it
        carried = {
            "protocol": props["url_scheme"] or "stdio",
            "authenticated": bool(props["has_configured_auth"]),
        }
        # The agent calls the server, and the server's content comes back into the agent
        edges.append(
            ParsedEdge(
                address,
                server,
                "iam_binding",
                {"relation": "invokes", **carried},
                declared=False,
            )
        )
        edges.append(
            ParsedEdge(
                server,
                address,
                "data_flow",
                {"relation": "returns_content", **carried},
                declared=False,
            )
        )
    return agent, edges


def _server_diagnostics(item: _Built, source_path: str) -> list[Diagnostic]:
    name = item.resource.name
    found: list[Diagnostic] = []
    if item.unknown_entry:
        found.append(
            Diagnostic(
                "warning",
                "mcp.unknown_entry",
                f"MCP server '{name}' has none of command, url, serverUrl or httpUrl, so how it "
                "is launched is unknown and it was not analysed",
                source_path,
                item.line,
            )
        )
    if not item.disabled and not item.capability.known:
        found.append(
            Diagnostic(
                "info",
                "mcp.unknown_capability",
                f"MCP server '{name}' is not in the capability table, so it adds no capability "
                "to the agent beyond what its own entry proves",
                source_path,
                item.line,
            )
        )
    return found


# ── Source text ──────────────────────────────────────────────────────


def _read_text(source_path: str) -> str:
    if not source_path:
        return ""
    try:
        return decode_input(Path(source_path), allow_empty=True)
    except (OSError, ParseError):
        return ""  # unreadable text only loses line numbers


__all__ = [
    "MCP_CONFIG_FILENAMES",
    "MCPConfigParser",
    "is_broad_path",
    "is_loopback_host",
    "is_mcp_config",
    "is_sensitive_path",
    "is_system_mount",
    "normalize_path",
    "strip_jsonc",
]
