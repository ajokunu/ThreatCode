"""MCP client configuration parser for ThreatCode.

Turns each server entry in an MCP client config file into an ``mcp_server``
resource. Supported shapes, checked against each client's documentation on
2026-10-01:

- ``mcpServers`` object: Claude Desktop (``claude_desktop_config.json``),
  Claude Code (``.mcp.json``, and ``~/.claude.json`` including the
  per-project ``projects.<path>.mcpServers`` entries), Cursor
  (``.cursor/mcp.json``), Windsurf/Devin (``mcp_config.json``, remote servers
  use ``serverUrl``) and the portable format VS Code and Copilot read
  (``.mcp.json``, ``~/.copilot/mcp-config.json``).
- ``servers`` object in VS Code's own ``.vscode/mcp.json``, which may contain
  comments (JSONC).

The parser never connects to a server. It derives boolean properties that the
YAML rules in ``engine/rules/builtin/mcp/`` match on, and it stores only the
names of environment variables and headers, never their values.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

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

_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"})

# Package runners that download and execute a package by name at launch.
_NODE_RUNNERS = frozenset({"npx", "bunx"})
_NODE_SUBCOMMAND_RUNNERS = frozenset({"pnpm", "yarn"})  # pnpm dlx, yarn dlx
_PY_RUNNERS = frozenset({"uvx"})
_CONTAINER_RUNTIMES = frozenset({"docker", "podman"})

# Runner flags that take a value as the next argument.
_NPX_FLAGS_WITH_VALUE = frozenset({"-p", "--package", "-c", "--call"})
_UVX_FLAGS_WITH_VALUE = frozenset(
    {"--from", "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url"}
)

# Published MCP servers whose purpose is running commands for the agent,
# verified against the npm and PyPI registries on 2026-10-01.
_SHELL_EXEC_PACKAGES = frozenset(
    {
        "@wonderwhy-er/desktop-commander",  # "MCP server for terminal operations"
        "mcp-server-commands",  # "An MCP server to run arbitrary commands"
        "super-shell-mcp",  # "MCP server for executing shell commands"
        "mcp-shell-server",  # PyPI: "Execute shell commands via MCP protocol"
        "mcp-server-shell",  # PyPI: "shell command execution capabilities for LLMs"
    }
)
_SHELL_NAME_TOKENS = frozenset({"shell", "terminal"})

# Arguments that grant a filesystem server the whole disk or home directory.
_BROAD_PATH_RE = re.compile(
    r"""^(
        /                               # filesystem root
      | ~/?                             # home directory
      | \$HOME/?  | \$\{HOME\}/?        # home via environment
      | \$\{userHome\}/?                # Cursor/VS Code home variable
      | /Users/[^/]+/?                  # macOS home directory
      | /home/[^/]+/?                   # Linux home directory
      | /root/?
      | [A-Za-z]:[\\/]*                 # whole Windows drive
      | [A-Za-z]:[\\/]+Users[\\/]+[^\\/]+[\\/]*  # Windows home directory
    )$""",
    re.VERBOSE,
)

_SECRET_KEY_RE = re.compile(
    r"(?i)(token|secret|passw|api[_-]?key|apikey|auth(?!ors?(?:_|\b))|credential|private[_-]?key"
    r"|access[_-]?key)"
)
_PATH_LIKE_RE = re.compile(r"^(/|~|\./|\.\./|[A-Za-z]:[\\/])")
_AUTH_HEADER_RE = re.compile(
    r"(?i)^(authorization|proxy-authorization|x-api-key|api-key|.*token.*)$"
)


def strip_jsonc(text: str) -> str:
    """Remove // and /* */ comments and trailing commas outside JSON strings."""
    out: list[str] = []
    i = 0
    n = len(text)
    in_string = False
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
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


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
    return isinstance(entry, dict) and any(k in entry for k in ("command", "url", "type"))


class MCPConfigParser(BaseParser):
    """Parse MCP client configuration files into ``mcp_server`` resources."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        if isinstance(data, str):
            data = json.loads(strip_jsonc(data))
        if not isinstance(data, dict):
            return ParsedOutput(source_path=source_path, format_type="mcp_config")

        content = _read_text(source_path)
        resources: list[ParsedResource] = []

        for scope, client_format, servers in _server_groups(data):
            for name, entry in servers.items():
                if not isinstance(entry, dict):
                    continue
                address = f"mcp_server.{name}" if not scope else f"mcp_server.{scope}.{name}"
                resources.append(
                    ParsedResource(
                        resource_type="mcp_server",
                        address=address,
                        name=str(name),
                        provider="mcp",
                        properties=_server_properties(str(name), entry, client_format, data),
                        source_location=_locate(source_path, content, str(name)),
                    )
                )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="mcp_config",
        )


def _server_groups(data: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Return (scope, client_format, servers) groups found in the config."""
    groups: list[tuple[str, str, dict[str, Any]]] = []
    if isinstance(data.get("mcpServers"), dict):
        groups.append(("", "mcpServers", data["mcpServers"]))
    if isinstance(data.get("servers"), dict) and "mcpServers" not in data:
        groups.append(("", "vscode", data["servers"]))
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project_path, project in projects.items():
            if isinstance(project, dict) and isinstance(project.get("mcpServers"), dict):
                scope = Path(str(project_path)).name or "project"
                groups.append((scope, "mcpServers", project["mcpServers"]))
    return groups


def _server_properties(
    name: str, entry: dict[str, Any], client_format: str, root: dict[str, Any]
) -> dict[str, Any]:
    command = str(entry.get("command") or "")
    args = [str(a) for a in entry.get("args") or [] if isinstance(a, str | int | float)]
    env = _mapping(entry.get("env"))
    headers = _mapping(entry.get("headers"))
    url = str(entry.get("url") or entry.get("serverUrl") or "")

    transport = str(entry.get("type") or entry.get("transport") or "")
    if not transport:
        transport = "stdio" if command else ("http" if url else "unknown")
    is_remote = bool(url) and transport != "stdio"

    parsed_url = urlparse(url) if url else None
    host = (parsed_url.hostname or "").lower() if parsed_url else ""
    is_loopback = host in _LOOPBACK_HOSTS or host.startswith("127.")
    scheme = parsed_url.scheme if parsed_url else ""
    uses_plaintext = scheme in ("http", "ws") and not is_loopback

    secret_keys = _literal_secret_keys(env, "env") + _literal_secret_keys(headers, "header")
    if parsed_url:
        query = dict(parse_qsl(parsed_url.query))
        secret_keys += _literal_secret_keys(query, "url")

    has_auth = (
        any(_AUTH_HEADER_RE.match(str(k)) for k in headers)
        or any(k in entry for k in ("oauth", "auth", "headersHelper"))
        or bool(parsed_url and parsed_url.username)
    )

    unpinned = _unpinned_packages(command, args)
    container_flags = _container_flags(command, args)
    broad_paths = _broad_filesystem_paths(name, command, args)
    shell_exec = _exposes_shell_exec(name, command, args)
    sandbox = entry.get("sandbox") if client_format == "vscode" else None

    return {
        "server_name": name,
        "client_format": client_format,
        "transport": transport,
        "command": command,
        "args": args,
        "env_keys": sorted(str(k) for k in env),
        "header_keys": sorted(str(k) for k in headers),
        "url_scheme": scheme,
        "url_host": host,
        "is_remote": is_remote,
        "is_loopback": is_loopback,
        "uses_plaintext_transport": uses_plaintext and is_remote,
        "has_configured_auth": has_auth,
        "remote_without_configured_auth": is_remote and not has_auth,
        "has_literal_secret": bool(secret_keys),
        "literal_secret_keys": secret_keys,
        "package_unpinned": bool(unpinned),
        "unpinned_packages": unpinned,
        "broad_filesystem_access": bool(broad_paths),
        "broad_filesystem_paths": broad_paths,
        "exposes_shell_exec": shell_exec,
        "container_privileged": bool(container_flags),
        "container_flags": container_flags,
        "sandbox_enabled": bool(sandbox) or _vscode_sandbox_enabled(root),
    }


def _mapping(value: Any) -> dict[Any, Any]:
    return value if isinstance(value, dict) else {}


def _vscode_sandbox_enabled(root: dict[str, Any]) -> bool:
    sandbox = root.get("sandbox")
    return isinstance(sandbox, dict) and bool(sandbox)


# ── Secret detection ─────────────────────────────────────────────────


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    return (
        not v
        or "${" in v
        or bool(re.fullmatch(r"<[^<>]+>", v))
        or bool(re.fullmatch(r"\$[A-Za-z_][A-Za-z0-9_]*", v))
    )


def _literal_secret_keys(values: dict[Any, Any], kind: str) -> list[str]:
    """Return ``kind:key`` labels for entries that hold a literal credential."""
    from threatcode.engine.secrets.builtin import get_builtin_rules

    found: list[str] = []
    rules = get_builtin_rules()
    for key, raw in values.items():
        if not isinstance(raw, str | int | float) or isinstance(raw, bool):
            continue
        value = str(raw)
        if _is_placeholder(value):
            continue
        # A bearer value is a literal secret unless the token part is a placeholder.
        token = re.sub(r"(?i)^(bearer|basic|token)\s+", "", value)
        if _is_placeholder(token):
            continue
        line = f"{key}={value}"
        pattern_hit = any(
            r.regex.search(line) and not r.is_allowed(line)
            for r in rules
            if not r.keywords or any(kw.lower() in line.lower() for kw in r.keywords)
        )
        key_hit = (
            bool(_SECRET_KEY_RE.search(str(key)))
            and len(token) >= 8
            and not _PATH_LIKE_RE.match(token)
        )
        if pattern_hit or key_hit:
            found.append(f"{kind}:{key}")
    return found


# ── Supply chain pinning ─────────────────────────────────────────────


def _basename(command: str) -> str:
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    return name[:-4] if name.endswith((".exe", ".cmd")) else name


def _first_positional(args: list[str], flags_with_value: frozenset[str]) -> tuple[str, str]:
    """Return (package, --from/--package value) from a runner's argument list."""
    from_value = ""
    skip = False
    for i, arg in enumerate(args):
        if skip:
            skip = False
            continue
        if arg in flags_with_value:
            if arg in ("--from", "-p", "--package") and i + 1 < len(args):
                from_value = from_value or args[i + 1]
            skip = True
            continue
        if arg.startswith("--from=") or arg.startswith("--package="):
            from_value = from_value or arg.split("=", 1)[1]
            continue
        if arg.startswith("-"):
            continue
        return arg, from_value
    return "", from_value


def _npm_spec_pinned(spec: str) -> bool:
    body = spec[1:] if spec.startswith("@") else spec
    if "@" not in body:
        return False
    version = body.rsplit("@", 1)[1]
    return bool(version) and version.lower() not in ("latest", "next", "*", "x")


def _py_spec_pinned(spec: str) -> bool:
    if "==" in spec:
        return True
    # For VCS URLs (git+ssh://git@host/repo@tag) only the last path segment can pin.
    tail = spec.rsplit("/", 1)[-1] if "://" in spec else spec
    if "@" in tail:
        version = tail.rsplit("@", 1)[1]
        return bool(version) and version.lower() != "latest"
    return False


def _image_pinned(image: str) -> bool:
    if "@sha256:" in image:
        return True
    last = image.rsplit("/", 1)[-1]
    if ":" not in last:
        return False
    return last.rsplit(":", 1)[1].lower() != "latest"


def _unpinned_packages(command: str, args: list[str]) -> list[str]:
    runner = _basename(command)
    if runner in _NODE_SUBCOMMAND_RUNNERS:
        if not args or args[0] != "dlx":
            return []
        runner, args = "npx", args[1:]
    if runner in _NODE_RUNNERS:
        package, from_value = _first_positional(args, _NPX_FLAGS_WITH_VALUE)
        spec = from_value or package
        return [spec] if spec and not _npm_spec_pinned(spec) else []
    if runner in _PY_RUNNERS:
        package, from_value = _first_positional(args, _UVX_FLAGS_WITH_VALUE)
        spec = from_value or package
        return [spec] if spec and not _py_spec_pinned(spec) else []
    if runner in _CONTAINER_RUNTIMES:
        image = _container_image(args)
        return [image] if image and not _image_pinned(image) else []
    return []


# ── Container launch flags ───────────────────────────────────────────

_DOCKER_FLAGS_WITH_VALUE = frozenset(
    {
        "-e",
        "--env",
        "--env-file",
        "-v",
        "--volume",
        "--mount",
        "--network",
        "--net",
        "--name",
        "-p",
        "--publish",
        "-u",
        "--user",
        "-w",
        "--workdir",
        "--cap-add",
        "--cap-drop",
        "--pid",
        "--ipc",
        "--entrypoint",
        "--platform",
        "-l",
        "--label",
        "--security-opt",
    }
)


def _docker_run_args(command: str, args: list[str]) -> list[str] | None:
    if _basename(command) not in _CONTAINER_RUNTIMES:
        return None
    if args[:1] == ["run"]:
        return args[1:]
    if args[:2] == ["container", "run"]:
        return args[2:]
    return None


def _container_image(args: list[str]) -> str:
    run_args = _docker_run_args("docker", args)
    if run_args is None:
        return ""
    skip = False
    for arg in run_args:
        if skip:
            skip = False
            continue
        if arg in _DOCKER_FLAGS_WITH_VALUE:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return ""


def _option_values(run_args: list[str], names: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for i, arg in enumerate(run_args):
        for name in names:
            if arg == name and i + 1 < len(run_args):
                values.append(run_args[i + 1])
            elif arg.startswith(name + "="):
                values.append(arg.split("=", 1)[1])
    return values


def _container_flags(command: str, args: list[str]) -> list[str]:
    run_args = _docker_run_args(command, args)
    if run_args is None:
        return []
    flags: list[str] = []
    if "--privileged" in run_args:
        flags.append("--privileged")
    for net in _option_values(run_args, ("--network", "--net")):
        if net == "host":
            flags.append("--network=host")
    for mode in _option_values(run_args, ("--pid", "--ipc", "--uts", "--userns")):
        if mode == "host":
            flags.append("host namespace")
    for cap in _option_values(run_args, ("--cap-add",)):
        if cap.upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE"):
            flags.append(f"--cap-add={cap}")
    for opt in _option_values(run_args, ("--security-opt",)):
        if opt.replace(":", "=") in ("seccomp=unconfined", "apparmor=unconfined"):
            flags.append(f"--security-opt={opt}")
    for vol in _option_values(run_args, ("-v", "--volume")):
        source = vol.split(":", 1)[0]
        if source == "/" or source.endswith("docker.sock"):
            flags.append(f"-v {source}")
    for mount in _option_values(run_args, ("--mount",)):
        parts = dict(p.split("=", 1) for p in mount.split(",") if "=" in p)
        source = parts.get("source") or parts.get("src") or ""
        if source == "/" or source.endswith("docker.sock"):
            flags.append(f"--mount {source}")
    return flags


# ── Filesystem and shell exposure ────────────────────────────────────


def _broad_filesystem_paths(name: str, command: str, args: list[str]) -> list[str]:
    haystack = " ".join([name, command, *args]).lower()
    if "filesystem" not in haystack:
        return []
    return [a for a in args if _BROAD_PATH_RE.match(a.strip())]


def _package_names(command: str, args: list[str]) -> list[str]:
    names = [_basename(command)]
    for arg in args:
        if arg.startswith("-"):
            continue
        spec = arg[1:] if arg.startswith("@") else arg
        base = re.split(r"==|@", spec, maxsplit=1)[0]
        names.append(("@" + base) if arg.startswith("@") else base)
    return names


def _exposes_shell_exec(name: str, command: str, args: list[str]) -> bool:
    candidates = [n.lower() for n in _package_names(command, args)]
    if any(c in _SHELL_EXEC_PACKAGES for c in candidates):
        return True
    for candidate in candidates:
        if "mcp" not in candidate:
            continue
        tokens = set(re.split(r"[-_/@.]", candidate))
        if tokens & _SHELL_NAME_TOKENS:
            return True
    return False


# ── Source locations ─────────────────────────────────────────────────


def _read_text(source_path: str) -> str:
    if not source_path:
        return ""
    try:
        return Path(source_path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def _locate(source_path: str, content: str, name: str) -> str:
    """Return ``path:line`` for the first ``"name":`` key in the file."""
    if not content:
        return source_path
    match = re.search(r'"' + re.escape(name) + r'"\s*:', content)
    if not match:
        return source_path
    return f"{source_path}:{content.count(chr(10), 0, match.start()) + 1}"
