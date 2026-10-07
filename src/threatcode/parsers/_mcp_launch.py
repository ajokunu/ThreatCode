"""Effective launch of an MCP server entry.

A server entry says how a client starts the server: a ``command`` and its ``args``.
Real configs wrap that in launchers (``cmd /c npx``, ``bash -c '...'``, ``env FOO=1 npx``,
``sudo``), in package runners that download code (``npx``, ``uvx``, ``pipx run``,
``deno run npm:``), in bridges that turn a remote URL into a stdio server (``mcp-remote``,
``supergateway``, ``mcp-proxy``) and in ``docker run`` with dozens of options.
``resolve_launch`` computes one ``EffectiveLaunch`` per entry before any analysis, so
pinning, secrets, filesystem exposure, container privileges and the shell-exec check all
read the same unwrapped command and a wrapped launch is analysed like a direct one.

Unwrapping repeats until nothing changes, at most ``MAX_UNWRAP_DEPTH`` times.
A launcher nested deeper than that stays opaque: its own name becomes the runner and
nothing behind it is analysed.

Splitting a shell string is an approximation.
``bash -c`` strings use POSIX rules and keep the last simple command after ``&&``, ``||``
and ``;``.
``cmd /c`` and ``powershell -Command`` strings use a Windows-style split that keeps
backslashes.
Neither is a full shell parser, so a string built with command substitution or ``eval``
is left as it is.

The docker option tables were generated from ``docker run --help`` and ``docker --help``
(Docker 29.8.0) with two hidden aliases added (``--net``, ``--net-alias``).
The podman additions are written by hand from the podman-run documentation.
An option that is in neither set is treated as a boolean flag, so an unknown
``--flag value`` is never read as taking a value.
"""

from __future__ import annotations

import base64
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

from threatcode.parsers.image_ref import FLOATING_TAGS, parse_image_ref
from threatcode.vocab import DANGEROUS_CAPABILITIES, normalize_capability

MAX_UNWRAP_DEPTH: Final = 4

# ---------------------------------------------------------------------------
# Tokens and the launch record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Token:
    """One word of the effective command and the config argument it came from.

    ``origin`` is the index into the entry's original ``args`` (``-1`` for the ``command``
    itself).
    Words that came out of splitting a shell string share the index of that string.
    """

    text: str
    origin: int


@dataclass(frozen=True)
class ContainerOption:
    """A ``docker run`` option as written: canonical long name, value and origin."""

    name: str
    value: str | None
    origin: int

    @property
    def enabled(self) -> bool:
        """For a boolean flag: true unless it was written ``=false`` (or ``=0``)."""
        return self.value is None or self.value.strip().lower() not in _FALSE_WORDS


@dataclass
class EffectiveLaunch:
    """The command a client really runs, after launchers and runners are unwrapped."""

    # npx, bunx, pnpm dlx, pnpm exec, yarn dlx, bun x, npm exec, uvx, pipx run, uv run,
    # deno, docker, podman, or the command name for anything else
    runner: str = ""
    # The package (or image) the runner fetches, as written, with its version
    package_spec: str = ""
    # The package or image name without version or tag, lower-cased
    package_name: str = ""
    # A --from / --package / --spec value (the package when the positional is a binary name)
    from_spec: str = ""
    # Specs to check for pinning: the package, all -p values, all --with values
    pin_specs: list[str] = field(default_factory=list)
    # The command word and every argument after unwrapping
    inner_argv: list[Token] = field(default_factory=list)
    # The arguments that go to the server program itself
    server_args: list[Token] = field(default_factory=list)
    # Original arg indexes that held a shell string that was split
    split_origins: set[int] = field(default_factory=set)
    wrappers: list[str] = field(default_factory=list)
    # mcp-remote, supergateway or mcp-proxy when the server only bridges a remote URL
    bridge: str = ""
    remote_url: str = ""
    remote_url_origin: int = -1
    extra_headers: dict[str, str] = field(default_factory=dict)
    header_origins: dict[str, int] = field(default_factory=dict)
    allow_http: bool = False
    env_overrides: dict[str, str] = field(default_factory=dict)
    env_origins: dict[str, int] = field(default_factory=dict)
    container_runtime: str = ""
    container_subcommand: str = ""
    container_options: list[ContainerOption] = field(default_factory=list)
    image: str = ""
    # Package specs that are a local path or file: target, never a pinning finding
    local_target: bool = False


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

_FALSE_WORDS: Final = frozenset({"false", "0", "f", "no", "off", "n"})
_ASSIGN_RE: Final = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)
_URL_RE: Final = re.compile(r"^(?:https?|wss?)://", re.IGNORECASE)
_EXE_SUFFIXES: Final = (".exe", ".cmd", ".bat", ".ps1")


def basename(command: str) -> str:
    """Lower-cased file name of a command, without ``.exe``, ``.cmd``, ``.bat`` or ``.ps1``."""
    name = re.split(r"[\\/]", command.strip())[-1].lower()
    for suffix in _EXE_SUFFIXES:
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _strip_quotes(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def _split_windows(text: str) -> list[str]:
    """Split a Windows command line: quotes group words, backslashes stay."""
    try:
        parts = shlex.split(text, posix=False)
    except ValueError:
        parts = text.split()
    return [_strip_quotes(p) for p in parts]


_SHELL_OPERATORS: Final = frozenset({"&&", "||", ";", "|", "&", "\n"})


def _split_posix(text: str) -> list[str]:
    """Split a ``sh -c`` string and keep the last simple command.

    ``cd /x && npx -y pkg 2>&1`` gives ``npx -y pkg``.
    A pipeline keeps the part before the first pipe.
    """
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = list(lexer)
    except ValueError:
        return text.split()
    commands: list[list[str]] = [[]]
    for word in words:
        if word in ("&&", "||", ";", "&"):
            commands.append([])
        else:
            commands[-1].append(word)
    chosen = next((c for c in reversed(commands) if c), [])
    if "|" in chosen:
        chosen = chosen[: chosen.index("|")]
    cleaned: list[str] = []
    skip_next = False
    for word in chosen:
        if skip_next:
            skip_next = False
            continue
        if re.fullmatch(r"\d*[<>]+&?\d*", word):
            # A redirection: the word after it is the target, unless it is "&1" style
            skip_next = not re.fullmatch(r"\d*[<>]+&\d*", word)
            continue
        if re.fullmatch(r"[<>()&|;]+", word):
            continue
        cleaned.append(word)
    return cleaned


def _tokens(words: list[str], origin: int) -> list[Token]:
    return [Token(w, origin) for w in words]


# ---------------------------------------------------------------------------
# Launchers (wrappers that run another command)
# ---------------------------------------------------------------------------

_SHELLS: Final = frozenset({"bash", "sh", "zsh", "dash", "ash", "ksh", "fish"})
_PWSH: Final = frozenset({"powershell", "pwsh"})
_SUDO_VALUE_FLAGS: Final = frozenset(
    {"-u", "-g", "-C", "-D", "-h", "-p", "-R", "-T", "-U", "--user", "--group", "--host"}
)
_ENV_VALUE_FLAGS: Final = frozenset({"-u", "--unset", "-C", "--chdir"})
_WSL_VALUE_FLAGS: Final = frozenset(
    {"-d", "--distribution", "-u", "--user", "--cd", "--distribution-id"}
)


@dataclass
class _Unwrapped:
    argv: list[Token]
    wrapper: str
    env: dict[str, tuple[str, int]] = field(default_factory=dict)
    split_origin: int | None = None


def _take_assignments(argv: list[Token]) -> tuple[list[Token], dict[str, tuple[str, int]]]:
    env: dict[str, tuple[str, int]] = {}
    index = 0
    while index < len(argv):
        match = _ASSIGN_RE.match(argv[index].text)
        if not match:
            break
        env[match.group(1)] = (match.group(2), argv[index].origin)
        index += 1
    return argv[index:], env


def _unwrap_once(argv: list[Token]) -> _Unwrapped | None:
    """Remove one launcher layer from ``argv``, or return None when none applies."""
    if not argv:
        return None
    cmd = basename(argv[0].text)
    args = argv[1:]

    stripped, assigned = _take_assignments(argv)
    if assigned and stripped:
        return _Unwrapped(stripped, "env", assigned)

    if cmd == "cmd":
        for i, tok in enumerate(args):
            if tok.text.lower() in ("/c", "/k", "/r"):
                rest = args[i + 1 :]
                if len(rest) == 1 and re.search(r"\s", rest[0].text):
                    words = _split_windows(rest[0].text)
                    return _Unwrapped(
                        _tokens(words, rest[0].origin), "cmd", split_origin=rest[0].origin
                    )
                return _Unwrapped(rest, "cmd") if rest else None
        return None

    if cmd in _PWSH:
        return _unwrap_powershell(args)

    if cmd in _SHELLS:
        for i, tok in enumerate(args):
            text = tok.text
            if text.startswith("-") and not text.startswith("--") and "c" in text[1:]:
                if i + 1 < len(args):
                    command = args[i + 1]
                    words = _split_posix(command.text)
                    return _Unwrapped(
                        _tokens(words, command.origin), cmd, split_origin=command.origin
                    )
                return None
        return None

    if cmd == "env":
        return _unwrap_env(args)

    if cmd == "sudo" or cmd == "doas":
        return _unwrap_sudo(args)

    if cmd in ("nohup", "time", "setsid", "winpty"):
        return _Unwrapped(args, cmd) if args else None

    if cmd in ("exec", "command"):
        first = next((i for i, t in enumerate(args) if not t.text.startswith("-")), None)
        return _Unwrapped(args[first:], cmd) if first is not None else None

    if cmd == "nice":
        i = 0
        while i < len(args) and args[i].text.startswith("-"):
            i += 2 if args[i].text in ("-n", "--adjustment") else 1
        return _Unwrapped(args[i:], cmd) if args[i:] else None

    if cmd == "timeout":
        i = 0
        while i < len(args) and args[i].text.startswith("-"):
            i += 2 if args[i].text in ("-s", "--signal", "-k", "--kill-after") else 1
        i += 1  # the duration
        return _Unwrapped(args[i:], cmd) if args[i:] else None

    if cmd == "wsl":
        i = 0
        while i < len(args):
            text = args[i].text
            if text == "--":
                i += 1
                break
            if text in ("-e", "--exec"):
                i += 1
                break
            if text in _WSL_VALUE_FLAGS:
                i += 2
            elif text.startswith("-"):
                i += 1
            else:
                break
        return _Unwrapped(args[i:], cmd) if args[i:] else None

    return None


def _unwrap_env(args: list[Token]) -> _Unwrapped | None:
    i = 0
    env: dict[str, tuple[str, int]] = {}
    while i < len(args):
        text = args[i].text
        if text == "--":
            i += 1
            break
        if text in ("-S", "--split-string") and i + 1 < len(args):
            words = _split_posix(args[i + 1].text)
            return _Unwrapped(
                _tokens(words, args[i + 1].origin),
                "env",
                env,
                split_origin=args[i + 1].origin,
            )
        if text in _ENV_VALUE_FLAGS:
            i += 2
        elif text.startswith("-"):
            i += 1
        else:
            match = _ASSIGN_RE.match(text)
            if not match:
                break
            env[match.group(1)] = (match.group(2), args[i].origin)
            i += 1
    rest = args[i:]
    rest, more = _take_assignments(rest)
    env.update(more)
    return _Unwrapped(rest, "env", env) if rest else None


def _unwrap_sudo(args: list[Token]) -> _Unwrapped | None:
    i = 0
    while i < len(args):
        text = args[i].text
        if text == "--":
            i += 1
            break
        if text in _SUDO_VALUE_FLAGS:
            i += 2
        elif text.startswith("-"):
            i += 1
        else:
            break
    rest, env = _take_assignments(args[i:])
    return _Unwrapped(rest, "sudo", env) if rest else None


def _unwrap_powershell(args: list[Token]) -> _Unwrapped | None:
    for i, tok in enumerate(args):
        flag = tok.text.lower()
        if flag in ("-command", "-c", "-commandwithargs"):
            rest = args[i + 1 :]
            if not rest:
                return None
            text = " ".join(t.text for t in rest)
            words = _split_windows(text)
            if words and words[0] == "&":
                words = words[1:]
            return _Unwrapped(
                _tokens(words, rest[0].origin), "powershell", split_origin=rest[0].origin
            )
        if flag in ("-encodedcommand", "-e", "-ec", "-enc") and i + 1 < len(args):
            try:
                decoded = base64.b64decode(args[i + 1].text, validate=True).decode("utf-16-le")
            except (ValueError, UnicodeDecodeError):
                return None
            words = _split_windows(decoded)
            return _Unwrapped(
                _tokens(words, args[i + 1].origin), "powershell", split_origin=args[i + 1].origin
            )
    return None


# ---------------------------------------------------------------------------
# Package runners
# ---------------------------------------------------------------------------

_NPX_VALUE_FLAGS: Final = frozenset(
    {"-p", "--package", "-c", "--call", "--prefix", "--registry", "--cache", "--userconfig"}
)
_UVX_VALUE_FLAGS: Final = frozenset(
    {
        "--from",
        "--with",
        "--with-editable",
        "--with-requirements",
        "--python",
        "-p",
        "--index",
        "--index-url",
        "-i",
        "--extra-index-url",
        "--default-index",
        "--find-links",
        "-f",
        "--constraint",
        "-c",
        "--override",
        "--env-file",
        "--directory",
        "--project",
        "--config-file",
        "--python-preference",
        "--index-strategy",
        "--resolution",
        "--prerelease",
        "--refresh-package",
        "--reinstall-package",
        "--upgrade-package",
        "-P",
        "--exclude-newer",
        "--link-mode",
        "--keyring-provider",
    }
)
_PIPX_VALUE_FLAGS: Final = frozenset(
    {"--spec", "--python", "--pip-args", "--index-url", "--path", "--verbose-config"}
)
_UV_RUN_VALUE_FLAGS: Final = _UVX_VALUE_FLAGS | frozenset({"--package", "--module"})
_DENO_VALUE_FLAGS: Final = frozenset({"--config", "-c", "--import-map", "--lock", "--reload"})

_NODE_RUNNERS: Final = {
    "npx": "npx",
    "bunx": "bunx",
    "pnpx": "pnpx",
}
_BRIDGES: Final = frozenset({"mcp-remote", "supergateway", "mcp-proxy"})
_INTERPRETERS: Final = frozenset(
    {"node", "python", "python3", "python2", "ruby", "php", "java", "dotnet", "bun", "go", "perl"}
)

_NPM_FAMILY = frozenset(
    {"npx", "bunx", "pnpx", "npm exec", "pnpm exec", "pnpm dlx", "yarn dlx", "bun x"}
)
_PY_FAMILY = frozenset({"uvx", "uv tool run", "pipx run", "uv run"})


def _is_local_spec(spec: str) -> bool:
    s = spec.strip()
    return (
        s in (".", "..")
        or s.startswith(("./", "../", "/", "~", "file:", "link:", "\\", ".\\", "..\\"))
        or bool(re.match(r"^[A-Za-z]:[\\/]", s))
    )


def _scan_flags(
    args: list[Token], value_flags: frozenset[str]
) -> tuple[Token | None, int, dict[str, list[str]]]:
    """Find the first positional word and collect the values of repeatable flags.

    Returns the positional token, its index in ``args`` and a mapping from flag name to
    every value it was given (``--with a --with b`` gives ``{"--with": ["a", "b"]}``).
    """
    flags: dict[str, list[str]] = {}
    i = 0
    while i < len(args):
        text = args[i].text
        if text == "--":
            i += 1
            if i < len(args):
                return args[i], i, flags
            return None, len(args), flags
        if text.startswith("--") and "=" in text:
            name, _, value = text.partition("=")
            flags.setdefault(name, []).append(value)
            i += 1
        elif text in value_flags:
            if i + 1 < len(args):
                flags.setdefault(text, []).append(args[i + 1].text)
            i += 2
        elif text.startswith("-") and len(text) > 1:
            i += 1
        else:
            return args[i], i, flags
    return None, len(args), flags


def _resolve_runner(launch: EffectiveLaunch, argv: list[Token]) -> None:
    """Fill the runner, package and server arguments from the unwrapped ``argv``."""
    cmd = basename(argv[0].text)
    args = argv[1:]
    launch.inner_argv = list(argv)
    launch.runner = cmd

    if cmd in _NODE_RUNNERS or (cmd == "bun" and args[:1] and args[0].text == "x"):
        runner = "bun x" if cmd == "bun" else _NODE_RUNNERS[cmd]
        _resolve_npm(launch, runner, args[1:] if cmd == "bun" else args)
        return
    if cmd == "npm" and args[:1] and args[0].text in ("exec", "x"):
        _resolve_npm(launch, "npm exec", args[1:])
        return
    if cmd == "pnpm" and args[:1] and args[0].text in ("exec", "dlx", "x"):
        _resolve_npm(launch, f"pnpm {'exec' if args[0].text == 'exec' else 'dlx'}", args[1:])
        return
    if cmd == "yarn" and args[:1] and args[0].text in ("dlx", "exec"):
        _resolve_npm(launch, f"yarn {args[0].text}", args[1:])
        return
    if cmd == "uvx":
        _resolve_uvx(launch, "uvx", args)
        return
    if cmd == "uv" and args[:2] and [t.text for t in args[:2]] == ["tool", "run"]:
        _resolve_uvx(launch, "uv tool run", args[2:])
        return
    if cmd == "uv" and args[:1] and args[0].text == "run":
        _resolve_uv_run(launch, args[1:])
        return
    if cmd == "pipx" and args[:1] and args[0].text == "run":
        _resolve_pipx(launch, args[1:])
        return
    if cmd == "deno" and args[:1] and args[0].text == "run":
        _resolve_deno(launch, args[1:])
        return
    if cmd in ("docker", "podman"):
        _resolve_container(launch, cmd, args)
        return

    # A command run directly: an installed binary, an interpreter and a script, a module
    launch.server_args = list(args)
    if cmd in _INTERPRETERS:
        module = _module_name(args)
        launch.package_name = module
        if module:
            launch.server_args = [t for t in args if t.text != module and t.text != "-m"]
    else:
        launch.package_name = cmd
    if cmd in _BRIDGES:
        launch.package_name = cmd


def _module_name(args: list[Token]) -> str:
    for i, tok in enumerate(args):
        if tok.text == "-m" and i + 1 < len(args):
            return args[i + 1].text.lower()
    return ""


def _name_of(spec: str) -> str:
    """The package name of a spec: version, tag, extras and VCS parts removed, lower-cased."""
    s = spec.strip()
    if _is_local_spec(s):
        return ""
    s = re.sub(r"^(?:npm|jsr):", "", s)
    if "://" in s or s.startswith(("git+", "github:", "gitlab:", "git@")):
        tail = re.split(r"[#?]", s)[0].rstrip("/")
        return re.sub(r"\.git$", "", tail.rsplit("/", 1)[-1]).split("@")[0].lower()
    body = s[1:] if s.startswith("@") else s
    body = re.split(r"[=<>!~;\[ ]", body, maxsplit=1)[0]
    body = body.split("@", 1)[0]
    name = ("@" + body) if s.startswith("@") else body
    return name.lower().replace("_", "-") if not name.startswith("@") else name.lower()


def _resolve_npm(launch: EffectiveLaunch, runner: str, args: list[Token]) -> None:
    launch.runner = runner
    positional, index, flags = _scan_flags(args, _NPX_VALUE_FLAGS)
    packages = flags.get("-p", []) + flags.get("--package", [])
    launch.from_spec = packages[0] if packages else ""
    if packages:
        launch.pin_specs = list(packages)
        launch.package_spec = packages[0]
    elif positional is not None:
        launch.package_spec = positional.text
        launch.pin_specs = [positional.text]
    if positional is not None:
        launch.server_args = list(args[index + 1 :])
    launch.package_name = _name_of(launch.package_spec)
    launch.local_target = bool(launch.pin_specs) and all(
        _is_local_spec(s) for s in launch.pin_specs
    )


def _resolve_uvx(launch: EffectiveLaunch, runner: str, args: list[Token]) -> None:
    launch.runner = runner
    positional, index, flags = _scan_flags(args, _UVX_VALUE_FLAGS)
    from_values = flags.get("--from", [])
    launch.from_spec = from_values[0] if from_values else ""
    specs: list[str] = []
    if from_values:
        specs.append(from_values[0])
    elif positional is not None:
        specs.append(positional.text)
    specs.extend(flags.get("--with", []))
    launch.pin_specs = specs
    if positional is not None:
        launch.package_spec = positional.text
        launch.server_args = list(args[index + 1 :])
    launch.package_name = _name_of(launch.from_spec or launch.package_spec)
    if from_values and positional is not None and not launch.package_name:
        launch.package_name = positional.text.lower()
    launch.local_target = bool(specs) and _is_local_spec(specs[0])


def _resolve_uv_run(launch: EffectiveLaunch, args: list[Token]) -> None:
    launch.runner = "uv run"
    positional, index, flags = _scan_flags(args, _UV_RUN_VALUE_FLAGS)
    launch.pin_specs = list(flags.get("--with", []))
    if positional is not None:
        launch.package_name = positional.text.lower()
        launch.server_args = list(args[index + 1 :])


def _resolve_pipx(launch: EffectiveLaunch, args: list[Token]) -> None:
    launch.runner = "pipx run"
    positional, index, flags = _scan_flags(args, _PIPX_VALUE_FLAGS)
    spec_values = flags.get("--spec", [])
    launch.from_spec = spec_values[0] if spec_values else ""
    if positional is not None:
        launch.package_spec = positional.text
        launch.server_args = list(args[index + 1 :])
    spec = launch.from_spec or launch.package_spec
    launch.pin_specs = [spec] if spec else []
    launch.package_name = _name_of(spec) or launch.package_spec.lower()
    launch.local_target = bool(spec) and _is_local_spec(spec)


def _resolve_deno(launch: EffectiveLaunch, args: list[Token]) -> None:
    launch.runner = "deno"
    positional, index, _flags = _scan_flags(args, _DENO_VALUE_FLAGS)
    if positional is None:
        return
    launch.server_args = list(args[index + 1 :])
    text = positional.text
    if text.startswith(("npm:", "jsr:")):
        launch.package_spec = text
        launch.pin_specs = [text]
        launch.package_name = _name_of(text)
    else:
        launch.package_name = ""
        launch.local_target = True


# ---------------------------------------------------------------------------
# Containers
# ---------------------------------------------------------------------------

# docker run options that take a value (generated from ``docker run --help``, Docker 29.8.0)
_RUN_VALUE_OPTIONS: Final = frozenset(
    {
        "--add-host", "--annotation", "--attach", "--blkio-weight", "--blkio-weight-device",
        "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-count",
        "--cpu-percent", "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime",
        "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device",
        "--device-cgroup-rule", "--device-read-bps", "--device-read-iops", "--device-write-bps",
        "--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname",
        "--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
        "--health-interval", "--health-retries", "--health-start-interval",
        "--health-start-period", "--health-timeout", "--hostname", "--io-maxbandwidth",
        "--io-maxiops", "--ip", "--ip6", "--ipc", "--isolation", "--label", "--label-file",
        "--link", "--link-local-ip", "--log-driver", "--log-opt", "--mac-address", "--memory",
        "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
        "--network", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform",
        "--publish", "--pull", "--restart", "--runtime", "--security-opt", "--shm-size",
        "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs", "--ulimit",
        "--umask", "--user", "--userns", "--uts", "--volume", "--volume-driver", "--volumes-from",
        "--workdir",
        # hidden aliases docker still accepts
        "--net", "--net-alias",
        # podman only
        "--authfile", "--cgroup-conf", "--cgroups", "--chrootdirs", "--conmon-pidfile",
        "--decryption-key", "--env-merge", "--gidmap", "--hostuser", "--image-volume",
        "--init-path", "--passwd-entry", "--personality", "--pidfile", "--pod", "--pod-id-file",
        "--preserve-fd", "--preserve-fds", "--requires", "--retry", "--retry-delay", "--sdnotify",
        "--seccomp-policy", "--secret", "--subgidname", "--subuidname", "--timeout", "--tz",
        "--uidmap", "--unsetenv", "--variant",
    }
)  # fmt: skip
# docker run options that are booleans; every other unknown option is read as a boolean too
_RUN_BOOLEAN_OPTIONS: Final = frozenset(
    {
        "--detach", "--help", "--init", "--interactive", "--no-healthcheck", "--oom-kill-disable",
        "--privileged", "--publish-all", "--quiet", "--read-only", "--rm", "--sig-proxy", "--tty",
        "--use-api-socket",
        # podman only
        "--env-host", "--http-proxy", "--read-only-tmpfs", "--replace", "--rootfs",
        "--unsetenv-all",
    }
)  # fmt: skip
_RUN_SHORT_VALUE: Final = {
    "-a": "--attach",
    "-c": "--cpu-shares",
    "-e": "--env",
    "-h": "--hostname",
    "-l": "--label",
    "-m": "--memory",
    "-p": "--publish",
    "-u": "--user",
    "-v": "--volume",
    "-w": "--workdir",
}
_RUN_SHORT_BOOL: Final = {
    "-d": "--detach",
    "-i": "--interactive",
    "-P": "--publish-all",
    "-q": "--quiet",
    "-t": "--tty",
}
_RUN_ALIASES: Final = {"--net": "--network", "--net-alias": "--network-alias"}

# global options before the subcommand (docker --help, plus podman's)
_GLOBAL_VALUE_OPTIONS: Final = frozenset(
    {
        "--config", "--context", "--host", "--log-level", "--tlscacert", "--tlscert", "--tlskey",
        "-H", "-c", "-l",
        # podman only
        "--cgroup-manager", "--conmon", "--connection", "--events-backend", "--hooks-dir",
        "--identity", "--imagestore", "--module", "--network-cmd-path", "--network-config-dir",
        "--registries-conf", "--root", "--runroot", "--runtime", "--runtime-flag",
        "--storage-driver", "--storage-opt", "--tmpdir", "--url", "--volumepath", "--namespace",
    }
)  # fmt: skip


def _resolve_container(launch: EffectiveLaunch, runtime: str, args: list[Token]) -> None:
    launch.runner = runtime
    launch.container_runtime = runtime
    i = 0
    while i < len(args):
        text = args[i].text
        if text.startswith("-"):
            name = text.split("=", 1)[0]
            i += 2 if name in _GLOBAL_VALUE_OPTIONS and "=" not in text else 1
            continue
        break
    if i >= len(args):
        return
    sub = args[i].text
    i += 1
    if sub == "container" and i < len(args) and not args[i].text.startswith("-"):
        sub = f"container {args[i].text}"
        i += 1
    launch.container_subcommand = sub
    if sub not in ("run", "container run"):
        launch.server_args = list(args[i:])
        return
    options, image_index = _parse_run_options(args, i)
    launch.container_options = options
    if image_index is None:
        return
    launch.image = args[image_index].text
    launch.package_spec = launch.image
    parsed = parse_image_ref(launch.image)
    launch.package_name = parsed.name.lower() if parsed.repository else ""
    launch.pin_specs = [launch.image]
    launch.server_args = list(args[image_index + 1 :])


def _parse_run_options(args: list[Token], start: int) -> tuple[list[ContainerOption], int | None]:
    """Parse ``docker run`` options up to the image; return them and the image index."""
    options: list[ContainerOption] = []
    i = start
    while i < len(args):
        tok = args[i]
        text = tok.text
        if text == "--":
            return options, (i + 1 if i + 1 < len(args) else None)
        if not text.startswith("-") or text == "-":
            return options, i
        if text.startswith("--"):
            name, eq, value = text.partition("=")
            name = _RUN_ALIASES.get(name, name)
            if eq:
                options.append(ContainerOption(name, value, tok.origin))
                i += 1
            elif name in _RUN_VALUE_OPTIONS:
                if i + 1 < len(args):
                    options.append(ContainerOption(name, args[i + 1].text, args[i + 1].origin))
                i += 2
            else:
                options.append(ContainerOption(name, None, tok.origin))
                i += 1
            continue
        # A cluster of short flags such as -it, -ie KEY=V, -v/a:/b or -p8080:80
        consumed = 1
        j = 1
        while j < len(text):
            letter = f"-{text[j]}"
            if letter in _RUN_SHORT_VALUE:
                name = _RUN_SHORT_VALUE[letter]
                attached = text[j + 1 :]
                if attached:
                    options.append(ContainerOption(name, attached.lstrip("="), tok.origin))
                elif i + 1 < len(args):
                    options.append(ContainerOption(name, args[i + 1].text, args[i + 1].origin))
                    consumed = 2
                break
            if letter in _RUN_SHORT_BOOL:
                options.append(ContainerOption(_RUN_SHORT_BOOL[letter], None, tok.origin))
            j += 1
        i += consumed
    return options, None


def option_values(launch: EffectiveLaunch, *names: str) -> list[ContainerOption]:
    """Every container option with one of these canonical long names, in order."""
    return [o for o in launch.container_options if o.name in names]


_HOST_NAMESPACES: Final = ("--pid", "--ipc", "--uts", "--userns", "--cgroupns")
_UNCONFINED: Final = ("seccomp=unconfined", "apparmor=unconfined", "systempaths=unconfined")


def container_flags(launch: EffectiveLaunch) -> list[str]:
    """Container options that give the container host-level reach, as ``--flag=value`` text.

    Flags are parsed uniformly in the ``--flag=value`` and ``--flag value`` forms, so
    ``--privileged=false`` is not privileged.
    Bind mounts are classified by the caller, which owns the path classifier.
    """
    flags: list[str] = []
    for opt in launch.container_options:
        if opt.name == "--privileged" and opt.enabled:
            flags.append("--privileged")
        elif opt.name == "--network" and (opt.value or "").strip().lower() == "host":
            flags.append("--network=host")
        elif opt.name in _HOST_NAMESPACES and (opt.value or "").strip().lower() == "host":
            flags.append(f"{opt.name}=host")
        elif opt.name == "--cap-add" and opt.value:
            cap = normalize_capability(opt.value)
            if cap in DANGEROUS_CAPABILITIES:
                flags.append(f"--cap-add={cap}")
        elif opt.name == "--device" and opt.value:
            flags.append(f"--device={opt.value.split(':', 1)[0]}")
        elif opt.name == "--user" and opt.value:
            first = opt.value.strip().split(":", 1)[0].lower()
            if first in ("root", "0"):
                flags.append(f"--user={opt.value.strip()}")
        elif opt.name == "--security-opt" and opt.value:
            normalized = opt.value.strip().replace(":", "=", 1).lower()
            if normalized in _UNCONFINED:
                flags.append(f"--security-opt={normalized}")
            elif normalized in ("no-new-privileges=false", "no-new-privileges=0"):
                flags.append("--security-opt=no-new-privileges=false")
            elif normalized in ("label=disable", "label=false"):
                flags.append("--security-opt=label=disable")
    return flags


def lacks_no_new_privileges(launch: EffectiveLaunch) -> bool:
    """True for a ``docker run`` launch that never sets ``no-new-privileges`` (informational)."""
    if launch.container_subcommand not in ("run", "container run"):
        return False
    for opt in option_values(launch, "--security-opt"):
        value = (opt.value or "").strip().replace(":", "=", 1).lower()
        if value in ("no-new-privileges", "no-new-privileges=true", "no-new-privileges=1"):
            return False
    return True


def bind_mount_sources(launch: EffectiveLaunch) -> list[str]:
    """Host paths bind-mounted with ``-v``/``--volume`` or ``--mount type=bind``."""
    sources: list[str] = []
    for opt in option_values(launch, "--volume"):
        value = (opt.value or "").strip()
        if not value:
            continue
        # A Windows drive letter ("C:\\data:/data") has a colon that does not separate fields
        match = re.match(r"^([A-Za-z]:[\\/][^:]*)", value)
        source = match.group(1) if match else value.split(":", 1)[0]
        if source and _looks_like_host_path(source):
            sources.append(source)
    for opt in option_values(launch, "--mount"):
        fields = dict(p.split("=", 1) for p in (opt.value or "").split(",") if "=" in p)
        kind = fields.get("type", "volume" if "source" not in fields else "bind")
        source = fields.get("source") or fields.get("src") or ""
        if kind == "bind" and source:
            sources.append(source)
    return sources


def _looks_like_host_path(source: str) -> bool:
    return bool(
        source.startswith(("/", "~", ".", "$", "%", "\\")) or re.match(r"^[A-Za-z]:[\\/]", source)
    )


# ---------------------------------------------------------------------------
# Bridges
# ---------------------------------------------------------------------------


def _apply_bridge(launch: EffectiveLaunch) -> None:
    name = launch.package_name
    bridge = next((b for b in _BRIDGES if name == b), "")
    if not bridge:
        return
    launch.bridge = bridge
    args = launch.server_args
    i = 0
    stdio_command: Token | None = None
    while i < len(args):
        tok = args[i]
        text = tok.text
        low = text.lower()
        if low == "--allow-http":
            launch.allow_http = True
        elif _URL_RE.match(text) and not launch.remote_url:
            launch.remote_url, launch.remote_url_origin = text, tok.origin
        elif low in ("--sse", "--streamablehttp", "--sse-url", "--url") and i + 1 < len(args):
            if _URL_RE.match(args[i + 1].text) and not launch.remote_url:
                launch.remote_url = args[i + 1].text
                launch.remote_url_origin = args[i + 1].origin
            i += 1
        elif low == "--stdio" and i + 1 < len(args):
            stdio_command = args[i + 1]
            i += 1
        elif low.startswith("--header=") or low.startswith("--headers="):
            _add_header(launch, text.split("=", 1)[1], tok.origin)
        elif low in ("--header", "-h") and bridge != "mcp-proxy" and i + 1 < len(args):
            _add_header(launch, args[i + 1].text, args[i + 1].origin)
            i += 1
        elif low in ("--headers", "-h") and bridge == "mcp-proxy" and i + 2 < len(args):
            # mcp-proxy takes the header name and value as two arguments
            launch.extra_headers[args[i + 1].text] = args[i + 2].text
            launch.header_origins[args[i + 1].text] = args[i + 2].origin
            i += 2
        elif low == "--oauth2bearer" and i + 1 < len(args):
            launch.extra_headers["Authorization"] = f"Bearer {args[i + 1].text}"
            launch.header_origins["Authorization"] = args[i + 1].origin
            i += 1
        i += 1
    if bridge == "supergateway" and stdio_command is not None and not launch.remote_url:
        # supergateway --stdio "<command>" serves a local command; that command is the server
        launch.wrappers.append("supergateway")
        launch.bridge = ""
        inner = _tokens(_split_posix(stdio_command.text), stdio_command.origin)
        launch.split_origins.add(stdio_command.origin)
        if inner:
            _resolve_into(launch, inner, depth=1)


def _add_header(launch: EffectiveLaunch, text: str, origin: int) -> None:
    name, sep, value = text.partition(":")
    if sep and name.strip():
        launch.extra_headers[name.strip()] = value.strip()
        launch.header_origins[name.strip()] = origin


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_LAUNCHER_NAMES: Final = (
    frozenset({"cmd", "env", "sudo", "doas", "nohup", "exec", "command", "wsl", "winpty"})
    | _SHELLS
    | _PWSH
    | frozenset(_NODE_RUNNERS)
    | frozenset({"uvx", "pipx", "deno", "docker", "podman", "npm", "pnpm", "yarn", "bun", "uv"})
)


def _resolve_into(launch: EffectiveLaunch, argv: list[Token], depth: int) -> None:
    """Unwrap ``argv`` (at most ``MAX_UNWRAP_DEPTH`` layers in total) and resolve its runner."""
    while depth < MAX_UNWRAP_DEPTH and argv:
        step = _unwrap_once(argv)
        if step is None or not step.argv:
            break
        launch.wrappers.append(step.wrapper)
        for key, (value, origin) in step.env.items():
            launch.env_overrides[key] = value
            launch.env_origins[key] = origin
        if step.split_origin is not None:
            launch.split_origins.add(step.split_origin)
        argv = step.argv
        depth += 1
    if not argv:
        return
    _resolve_runner(launch, argv)
    _apply_bridge(launch)


def resolve_launch(command: str, args: list[str]) -> EffectiveLaunch:
    """Compute the effective launch of a server entry's ``command`` and ``args``."""
    launch = EffectiveLaunch()
    words = command.strip()
    argv: list[Token]
    if (
        words
        and not args
        and re.search(r"\s", words)
        and basename(words.split()[0]) in _LAUNCHER_NAMES
    ):
        # "command": "npx -y pkg" written as one string
        argv = _tokens(_split_windows(words), -1)
        launch.split_origins.add(-1)
    else:
        argv = [Token(command, -1)] if command else []
        argv.extend(Token(a, i) for i, a in enumerate(args))
    if not argv:
        return launch
    _resolve_into(launch, argv, depth=0)
    return launch


# ---------------------------------------------------------------------------
# Pinning policy
# ---------------------------------------------------------------------------

_EXACT_SEMVER: Final = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)
_HEX40: Final = re.compile(r"^[0-9a-fA-F]{40}$")
_VERSION_TAG: Final = re.compile(r"^[A-Za-z_-]{0,12}v?\d+(?:\.\d+){1,3}(?:[-+.][0-9A-Za-z.]+)?$")
_PEP440_EXACT: Final = re.compile(
    r"^[0-9]+(?:![0-9]+)?(?:\.[0-9]+)*(?:[-.]?(?:a|b|rc|post|dev)[0-9]*)*(?:\+[0-9A-Za-z.]+)?$"
)
_RANGE_CHARS: Final = re.compile(r"[\^~<>|*]|\s-\s|\bx\b|\.x\b|\|\|")
_IMAGE_VERSION_TAG: Final = re.compile(
    r"\d+\.\d+|^v?\d{8}$|\d{4}[-.]\d{2}[-.]\d{2}|(?:^|[-_])sha-?[0-9a-f]{7,}"
)

# A package spec is "pinned", "unpinned" with a reason, or "skip" (a local target)
_PINNED: Final = ("pinned", "")
_SKIP: Final = ("skip", "")


def _git_ref_status(ref: str) -> tuple[str, str]:
    ref = ref.strip()
    if not ref:
        return "unpinned", "git-no-ref"
    if ref.lower().startswith("semver:"):
        return "unpinned", "range"
    if _HEX40.match(ref) or _VERSION_TAG.match(ref):
        return _PINNED
    return "unpinned", "branch"


def classify_npm_spec(spec: str) -> tuple[str, str]:
    """``(status, reason)`` for an npm package spec; status is pinned, unpinned or skip.

    Pinned means an exact semver, a git ref that is a 40-hex commit or a version tag.
    Ranges, partial versions and dist-tags are unpinned by policy, even when they are
    narrow: only an exact version cannot change under the config.
    """
    s = re.sub(r"^(?:npm|jsr):", "", spec.strip())
    if not s:
        return "skip", ""
    if _is_local_spec(spec):
        return _SKIP
    if s.startswith(("github:", "gitlab:", "bitbucket:", "git+", "git://", "git@", "ssh://")):
        return _git_ref_status(s.partition("#")[2])
    if re.match(r"^[\w.-]+/[\w.-]+(#.*)?$", s) and not s.startswith("@"):
        return _git_ref_status(s.partition("#")[2])
    if s.startswith(("http://", "https://")):
        return "unpinned", "remote-url"
    body = s[1:] if s.startswith("@") else s
    if "@" not in body:
        return "unpinned", "no-version"
    version = body.rsplit("@", 1)[1].strip()
    if not version:
        return "unpinned", "no-version"
    if _EXACT_SEMVER.match(version):
        return _PINNED
    if _RANGE_CHARS.search(version) or version in ("*", "x"):
        return "unpinned", "range"
    if re.match(r"^v?\d+(?:\.\d+)?$", version):
        return "unpinned", "partial-version"
    return "unpinned", "dist-tag"


def classify_py_spec(spec: str) -> tuple[str, str]:
    """``(status, reason)`` for a Python package spec (uvx, pipx, ``uv run --with``).

    Pinned means ``==`` with an exact version (also uv's ``pkg@1.2.3``) or a VCS ref that is a
    40-hex commit or a version tag, never a branch.
    """
    s = spec.strip()
    if not s:
        return "skip", ""
    if _is_local_spec(s):
        return _SKIP
    direct = re.match(r"^[A-Za-z0-9._\[\],-]+\s*@\s*(\S+://\S+)$", s)  # PEP 508 direct reference
    if direct:
        s = direct.group(1)
    if "://" in s or s.startswith("git+"):
        base = s.split("#", 1)[0]
        tail = base.rsplit("/", 1)[-1] if "://" in base else base
        if "@" not in tail:
            return "unpinned", "git-no-ref" if s.startswith("git+") else "remote-url"
        return _git_ref_status(tail.rsplit("@", 1)[1])
    if re.search(r"(?<![=!<>~])===?\s*[^=]", s):
        version = re.split(r"===?", s, maxsplit=1)[1].split(",")[0].strip().split(";")[0].strip()
        if "*" not in version and _PEP440_EXACT.match(version):
            return _PINNED
        return "unpinned", "range"
    if re.search(r"[<>!~]=?|,", s):
        return "unpinned", "range"
    if "@" in s:
        version = s.rsplit("@", 1)[1].strip()
        if _PEP440_EXACT.match(version) and re.search(r"\d", version):
            return _PINNED
        return "unpinned", "dist-tag" if version else "no-version"
    return "unpinned", "no-version"


def classify_image(image: str) -> tuple[str, str]:
    """``(status, reason)`` for a container image reference.

    Pinned means a digest, or a tag that is not floating and looks like a version.
    An image whose name holds a ``${VAR}`` is unknown and is not reported.
    """
    ref = parse_image_ref(image)
    if not ref.repository or ref.kind != "registry":
        return _SKIP
    if ref.digest:
        return _PINNED
    tag = ref.tag.strip()
    if not tag:
        return "unpinned", "no-tag"
    if tag.lower() in FLOATING_TAGS:
        return "unpinned", "floating-tag"
    if _IMAGE_VERSION_TAG.search(tag.lower()):
        return _PINNED
    return "unpinned", "floating-tag"


def scrub_userinfo(spec: str) -> str:
    """Replace the credentials of a ``scheme://user:pass@host`` spec so it is safe to store."""
    return re.sub(r"(://)[^/@\s]+@", r"\1[REDACTED]@", spec)


def unpinned_packages(launch: EffectiveLaunch) -> list[tuple[str, str]]:
    """``(spec, reason)`` for each package or image the launch fetches without an exact pin."""
    results: list[tuple[str, str]] = []
    runner = launch.runner
    classify: Callable[[str], tuple[str, str]]
    if runner in _NPM_FAMILY or runner == "deno":
        classify = classify_npm_spec
    elif runner in _PY_FAMILY:
        classify = classify_py_spec
    elif launch.container_runtime and launch.image:
        classify = classify_image
    else:
        return results
    for spec in launch.pin_specs:
        status, reason = classify(spec)
        if status == "unpinned":
            results.append((scrub_userinfo(spec), reason))
    return results
