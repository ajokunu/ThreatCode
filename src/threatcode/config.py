"""Configuration: the ``.threatcode.yml`` model, its loader and the settings resolver.

Where a setting comes from, in order of precedence:

1. the command-line flag (``None`` when the flag was not given, which is how presence is told apart
   from a flag whose value equals the default);
2. an environment variable: ``THREATCODE_FAIL_ON``, ``THREATCODE_MIN_SEVERITY``,
   ``THREATCODE_FORMAT`` and ``THREATCODE_LLM``;
3. the config file;
4. the built-in default.

``resolve_settings`` applies that order once, for the CLI and the Python API alike.

Trust: a config file named with ``--config`` is trusted and every key is honored.
An auto-discovered ``.threatcode.yml`` (in the scan root or the current directory) comes from the
repository being scanned, so only ``min_severity`` and ``output_format`` are read from it.
``fail_on``, ``extra_rule_paths``, ``llm``, ``redaction`` and the graph limits are ignored and
reported, because a scanned repository must not be able to disable its own gate, load its own
rules, point the tool at its own model server, weaken what is redacted before a prompt leaves the
machine or raise the resource limits.
Every model rejects unknown keys, so a typo is an error that names the key.
"""

from __future__ import annotations

import difflib
import logging
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from threatcode.exceptions import ConfigError, UsageError
from threatcode.models.threat import Severity

logger = logging.getLogger(__name__)

SEVERITY_CHOICES: tuple[str, ...] = tuple(s.value for s in Severity)
FAIL_ON_CHOICES: tuple[str, ...] = (*SEVERITY_CHOICES, "none")
DEFAULT_FAIL_ON = "high"
DEFAULT_MIN_SEVERITY = "info"

ENV_FAIL_ON = "THREATCODE_FAIL_ON"
ENV_MIN_SEVERITY = "THREATCODE_MIN_SEVERITY"
ENV_FORMAT = "THREATCODE_FORMAT"
ENV_LLM = "THREATCODE_LLM"

# Keys read from an auto-discovered (untrusted) config file; everything else is ignored.
_SAFE_AUTO_FIELDS = frozenset({"min_severity", "output_format"})

# Keys that earlier versions accepted and that no longer do, with what to use instead.
_REMOVED_KEYS: dict[str, str] = {
    "no_llm": "the LLM is off unless llm.enabled is true or --llm is given",
    "dry_run": "use the --dry-run flag",
}

# Providers that talk to a self-hosted model server and may opt in to
# loopback and private base_url addresses via llm.allow_local_network.
_LOCAL_PROVIDERS = frozenset({"ollama", "local"})
# The Anthropic provider may opt in too, for a gateway or proxy on a private network that fronts
# the API (set with base_url or ANTHROPIC_BASE_URL).
_LOCAL_NETWORK_PROVIDERS = _LOCAL_PROVIDERS | {"anthropic"}

# The model a fresh config uses. The installed anthropic SDK lists it among its known model ids.
DEFAULT_LLM_MODEL = "claude-sonnet-5-5"
# Seconds a single model call may take, and how many times the SDK or client retries it.
DEFAULT_LLM_TIMEOUT = 120
DEFAULT_LLM_MAX_RETRIES = 1
# The estimated size, in tokens, above which the request is refused rather than sent.
DEFAULT_LLM_MAX_INPUT_TOKENS = 60_000

# The environment variable each provider's API key is read from unless llm.api_key_env names
# another; ollama and local servers take no key by default.
DEFAULT_API_KEY_ENV: dict[str, str] = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}

_TRUE_WORDS = frozenset({"1", "true", "yes", "on"})
_FALSE_WORDS = frozenset({"0", "false", "no", "off"})


class LLMConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Opt-in: no client is built, and nothing is sent anywhere, unless this is true
    # (or --llm is given). Honored only from a config named with --config.
    enabled: bool = False
    provider: Literal["anthropic", "openai", "ollama", "local"] = "anthropic"
    model: str = DEFAULT_LLM_MODEL
    api_key: str = ""
    # The environment variable the API key is read from when api_key is empty.
    # Default: ANTHROPIC_API_KEY for anthropic, OPENAI_API_KEY for openai, none for ollama/local.
    api_key_env: str | None = None
    base_url: str = ""
    max_tokens: int = 4096
    # None sends no temperature at all, which is what current models require. A value is sent
    # as configured; a model that rejects it gets one retry without it.
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    # Seconds a single call may take, and retries on a transient failure.
    timeout: int = Field(default=DEFAULT_LLM_TIMEOUT, ge=1, le=3600)
    max_retries: int = Field(default=DEFAULT_LLM_MAX_RETRIES, ge=0, le=5)
    # Requests estimated above this many tokens (characters / 3.5) are refused, not truncated.
    max_input_tokens: int = Field(default=DEFAULT_LLM_MAX_INPUT_TOKENS, ge=1_000)
    # Explicit opt-in for model servers on a private network: lets base_url use plain http
    # and resolve to loopback or private addresses. Only valid for the ollama, local and
    # anthropic providers, and only honored from a --config file because the whole llm
    # section is stripped from auto-discovered configs.
    allow_local_network: bool = False

    @field_validator("api_key_env")
    @classmethod
    def _check_api_key_env(cls, value: str | None) -> str | None:
        if value is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
            raise ValueError(f"'{value}' is not an environment variable name")
        return value

    @model_validator(mode="after")
    def _check_allow_local_network(self) -> LLMConfig:
        if self.allow_local_network and self.provider not in _LOCAL_NETWORK_PROVIDERS:
            raise ValueError(
                f"allow_local_network requires provider 'ollama' or 'local', not '{self.provider}'"
            )
        return self

    def api_key_variable(self) -> str:
        """The environment variable the key comes from, or '' when the provider takes none."""
        return self.api_key_env or DEFAULT_API_KEY_ENV.get(self.provider, "")


class RedactionConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    strategy: Literal["placeholder", "hash"] = "placeholder"
    fields: list[str] = Field(default_factory=lambda: ["arn", "account_id", "tags", "ip_address"])


class ThreatCodeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    llm: LLMConfig = Field(default_factory=LLMConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    # None means "not set in the file", so the resolver can tell it from a value.
    min_severity: Literal["critical", "high", "medium", "low", "info"] | None = None
    output_format: str | None = None
    # Honored only from a config named with --config.
    fail_on: Literal["critical", "high", "medium", "low", "info", "none"] | None = None
    extra_rule_paths: list[str] = Field(default_factory=list)
    # Graph limits; None keeps the graph's own default (or its environment variable).
    max_nodes: int | None = Field(default=None, gt=0)
    max_edges: int | None = Field(default=None, gt=0)
    # False turns a declared edge to an unknown node from an error into a warning.
    strict_edges: bool = True

    @field_validator("output_format")
    @classmethod
    def _check_output_format(cls, value: str | None) -> str | None:
        if value is None:
            return value
        from threatcode.formatters import format_names

        names = format_names()
        if value not in names:
            raise ValueError(f"'{value}' is not an output format; choose one of {', '.join(names)}")
        return value


@dataclass(frozen=True)
class LoadedConfig:
    """A config as loaded: the model plus where it came from and what was used or ignored."""

    config: ThreatCodeConfig = field(default_factory=ThreatCodeConfig)
    path: Path | None = None
    # True when the file was named with --config.
    trusted: bool = False
    # Top-level keys the file sets and that took effect.
    used: tuple[str, ...] = ()
    # Top-level keys the file sets that were dropped because the file is not trusted.
    ignored: tuple[str, ...] = ()
    # Warnings for the user, one line each.
    notices: tuple[str, ...] = ()

    @property
    def auto_discovered(self) -> bool:
        return self.path is not None and not self.trusted


def discover_config(
    config_path: Path | None = None, search_dirs: Sequence[Path] | None = None
) -> LoadedConfig:
    """Load the config named by ``config_path``, else the first auto-discovered one.

    Auto-discovery looks for ``.threatcode.yml`` and ``.threatcode.yaml`` in each of
    ``search_dirs`` (default: the current directory) and then, outside CI, in the home directory.
    A named file must exist and is trusted; a discovered file is not.

    Raises:
        ConfigError: The file is missing (when named), is not a mapping or has invalid content.
    """
    if config_path is not None:
        if not config_path.exists():
            raise ConfigError(f"Config file not found: {config_path}")
        return _load_from_file(config_path, trusted=True)

    directories: list[Path] = []
    for directory in search_dirs if search_dirs is not None else [Path.cwd()]:
        if directory not in directories:
            directories.append(directory)
    candidates = [d / name for d in directories for name in (".threatcode.yml", ".threatcode.yaml")]
    # Skip the home directory when running in CI
    if not os.environ.get("CI"):
        candidates.append(Path.home() / ".threatcode.yml")

    for candidate in candidates:
        if candidate.is_file():
            return _load_from_file(candidate, trusted=False)
    return LoadedConfig()


def load_config(
    config_path: Path | None = None, search_dirs: Sequence[Path] | None = None
) -> ThreatCodeConfig:
    """Load config from ``config_path`` or an auto-discovered ``.threatcode.yml``, else defaults.

    Auto-discovered configs are restricted to safe fields; the notices about what was ignored are
    logged as warnings. In CI, name the file with ``--config`` rather than relying on discovery.
    """
    loaded = discover_config(config_path, search_dirs)
    for notice in loaded.notices:
        logger.warning("%s", notice)
    return loaded.config


def _load_from_file(path: Path, *, trusted: bool) -> LoadedConfig:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as e:
        raise ConfigError(f"Failed to load config from {path}: {e}") from e
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(
            f"Invalid config {path}: it must be a mapping of settings, not a {_yaml_kind(raw)}"
        )
    data: dict[str, Any] = {str(k): v for k, v in raw.items()}
    notices: list[str] = []

    llm_data = data.get("llm")
    if isinstance(llm_data, dict) and llm_data.get("api_key"):
        provider = str(llm_data.get("provider") or "anthropic")
        variable = str(llm_data.get("api_key_env") or DEFAULT_API_KEY_ENV.get(provider, ""))
        advice = (
            f"Use the {variable} environment variable instead."
            if variable
            else "Keep keys out of files that are committed."
        )
        notices.append(f"api_key found in config file {path}. {advice}")

    ignored: tuple[str, ...] = ()
    if not trusted:
        restricted = sorted(set(data) - _SAFE_AUTO_FIELDS)
        if restricted:
            ignored = tuple(restricted)
            message = (
                f"Auto-discovered config {path} contains restricted fields {restricted}; "
                "these are ignored for security. Use --config to load a trusted config file."
            )
            if "fail_on" in restricted:
                message += " fail_on is honored only from --config, so a scanned repository cannot "
                message += "turn off its own gate."
            notices.append(message)
            data = {k: v for k, v in data.items() if k in _SAFE_AUTO_FIELDS}

    try:
        config = ThreatCodeConfig(**data)
    except ValidationError as e:
        raise ConfigError(f"Invalid config {path}: {_format_validation_error(e)}") from e
    return LoadedConfig(
        config=config,
        path=path,
        trusted=trusted,
        used=tuple(sorted(data)),
        ignored=ignored,
        notices=tuple(notices),
    )


def _yaml_kind(value: object) -> str:
    if isinstance(value, list):
        return "list"
    if isinstance(value, str):
        return "string"
    return type(value).__name__


def _format_validation_error(error: ValidationError) -> str:
    """Render pydantic errors as 'field.path: message' without pydantic boilerplate."""
    parts = []
    for err in error.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "config"
        if err["type"] == "extra_forbidden":
            parts.append(f"{loc}: {_unknown_key_message(err['loc'])}")
            continue
        msg = str(err["msg"]).removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}")
    return "; ".join(parts)


def _unknown_key_message(loc: tuple[int | str, ...]) -> str:
    key = str(loc[-1])
    if len(loc) == 1 and key in _REMOVED_KEYS:
        return f"unknown key (removed: {_REMOVED_KEYS[key]})"
    model: type[BaseModel] = ThreatCodeConfig
    if len(loc) == 2 and loc[0] == "llm":
        model = LLMConfig
    elif len(loc) == 2 and loc[0] == "redaction":
        model = RedactionConfig
    close = difflib.get_close_matches(key, list(model.model_fields), n=1)
    hint = f" (did you mean '{close[0]}'?)" if close else ""
    return f"unknown key{hint}"


@dataclass(frozen=True)
class ResolvedSettings:
    """Every setting the scan reads, with the config it came from.

    ``output_format`` stays ``None`` when nothing set it: the CLI then picks ``text`` for a
    terminal and ``json`` otherwise. ``sources`` names where each of ``fail_on``,
    ``min_severity``, ``output_format`` and ``llm`` came from (``cli``, ``env THREATCODE_X``,
    ``config`` or ``default``).
    """

    fail_on: str = DEFAULT_FAIL_ON
    min_severity: str = DEFAULT_MIN_SEVERITY
    output_format: str | None = None
    llm_enabled: bool = False
    dry_run: bool = False
    dry_run_output: str | None = None
    extra_rule_paths: tuple[Path, ...] = ()
    max_nodes: int | None = None
    max_edges: int | None = None
    strict_edges: bool = True
    config: ThreatCodeConfig = field(default_factory=ThreatCodeConfig)
    sources: Mapping[str, str] = field(default_factory=dict)

    @property
    def use_llm(self) -> bool:
        """Whether an LLM client is built: requested explicitly, or ``--dry-run``."""
        return self.llm_enabled or self.dry_run


def _env_choice(env: Mapping[str, str], name: str, choices: Sequence[str]) -> str | None:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return None
    if raw not in choices:
        raise ConfigError(f"{name} must be one of {', '.join(choices)}, got '{raw}'")
    return raw


def _env_bool(env: Mapping[str, str], name: str) -> bool | None:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return None
    if raw in _TRUE_WORDS:
        return True
    if raw in _FALSE_WORDS:
        return False
    raise ConfigError(f"{name} must be true or false, got '{raw}'")


def resolve_settings(
    cli: Mapping[str, Any],
    loaded: LoadedConfig | ThreatCodeConfig | None = None,
    env: Mapping[str, str] | None = None,
) -> ResolvedSettings:
    """Resolve the settings: CLI flag, then environment, then config file, then default.

    ``cli`` holds the flags the user gave, with ``None`` (or an absent key) for the ones they did
    not: ``fail_on``, ``min_severity``, ``output_format``, ``llm`` (True for ``--llm``, False for
    ``--no-llm``), ``dry_run``, ``dry_run_output``, ``rules``, ``max_nodes`` and ``max_edges``.

    Raises:
        ConfigError: An environment variable holds an invalid value.
        UsageError: ``--dry-run`` was combined with ``--no-llm``.
    """
    if isinstance(loaded, ThreatCodeConfig):
        loaded = LoadedConfig(config=loaded)
    loaded = loaded or LoadedConfig()
    config = loaded.config
    environment = os.environ if env is None else env
    sources: dict[str, str] = {}

    def pick(
        key: str, cli_value: Any, env_name: str, env_value: Any, config_value: Any, default: Any
    ) -> Any:
        if cli_value is not None:
            sources[key] = "cli"
            return cli_value
        if env_value is not None:
            sources[key] = f"env {env_name}"
            return env_value
        if config_value is not None:
            sources[key] = "config"
            return config_value
        sources[key] = "default"
        return default

    fail_on = pick(
        "fail_on",
        cli.get("fail_on"),
        ENV_FAIL_ON,
        _env_choice(environment, ENV_FAIL_ON, FAIL_ON_CHOICES),
        config.fail_on,
        DEFAULT_FAIL_ON,
    )
    min_severity = pick(
        "min_severity",
        cli.get("min_severity"),
        ENV_MIN_SEVERITY,
        _env_choice(environment, ENV_MIN_SEVERITY, SEVERITY_CHOICES),
        config.min_severity,
        DEFAULT_MIN_SEVERITY,
    )
    env_format = environment.get(ENV_FORMAT, "").strip().lower() or None
    if env_format is not None:
        from threatcode.formatters import format_names

        if env_format not in format_names():
            raise ConfigError(
                f"{ENV_FORMAT} must be one of {', '.join(format_names())}, got '{env_format}'"
            )
    output_format = pick(
        "output_format",
        cli.get("output_format"),
        ENV_FORMAT,
        env_format,
        config.output_format,
        None,
    )
    llm_flag = cli.get("llm")
    dry_run = bool(cli.get("dry_run"))
    if dry_run and llm_flag is False:
        raise UsageError("--dry-run builds the LLM request, so it cannot be combined with --no-llm")
    llm_enabled = pick(
        "llm",
        llm_flag,
        ENV_LLM,
        _env_bool(environment, ENV_LLM),
        config.llm.enabled if "enabled" in config.llm.model_fields_set else None,
        False,
    )

    base = loaded.path.parent if loaded.path is not None else Path.cwd()
    rules: list[Path] = []
    for entry in config.extra_rule_paths:
        path = Path(entry)
        rules.append(path if path.is_absolute() else base / path)
    rules.extend(Path(p) for p in cli.get("rules") or ())

    return ResolvedSettings(
        fail_on=fail_on,
        min_severity=min_severity,
        output_format=output_format,
        llm_enabled=bool(llm_enabled),
        dry_run=dry_run,
        dry_run_output=cli.get("dry_run_output"),
        extra_rule_paths=tuple(rules),
        max_nodes=cli.get("max_nodes") if cli.get("max_nodes") is not None else config.max_nodes,
        max_edges=cli.get("max_edges") if cli.get("max_edges") is not None else config.max_edges,
        strict_edges=config.strict_edges,
        config=config,
        sources=sources,
    )
