"""Pydantic configuration model + .threatcode.yml loader.

Security: config auto-discovery loads .threatcode.yml from CWD.
In CI, use --config to specify an explicit path rather than relying on auto-discovery,
which could load a malicious config from a cloned repository.
Auto-discovered configs are restricted to safe fields only.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, ValidationError, model_validator

from threatcode.exceptions import ConfigError

logger = logging.getLogger(__name__)

# Fields safe to load from auto-discovered (untrusted) config files.
# Security-sensitive fields like llm.api_key, llm.base_url, extra_rule_paths
# are stripped from auto-discovered configs with a warning.
_SAFE_AUTO_FIELDS = frozenset(
    {
        "min_severity",
        "output_format",
        "no_llm",
        "dry_run",
        "redaction",
    }
)

# Providers that talk to a self-hosted model server and may opt in to
# loopback and private base_url addresses via llm.allow_local_network.
_LOCAL_PROVIDERS = frozenset({"ollama", "local"})


class LLMConfig(BaseModel):
    provider: Literal["anthropic", "openai", "ollama", "local"] = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 4096
    temperature: float = 0.2
    # Explicit opt-in for local model servers: lets base_url use plain http
    # and resolve to loopback or private addresses. Only valid for the
    # ollama and local providers, and only honored from a --config file
    # because the whole llm section is stripped from auto-discovered configs.
    allow_local_network: bool = False

    @model_validator(mode="after")
    def _check_allow_local_network(self) -> LLMConfig:
        if self.allow_local_network and self.provider not in _LOCAL_PROVIDERS:
            raise ValueError(
                f"allow_local_network requires provider 'ollama' or 'local', not '{self.provider}'"
            )
        return self


class RedactionConfig(BaseModel):
    strategy: Literal["placeholder", "hash"] = "placeholder"
    fields: list[str] = Field(default_factory=lambda: ["arn", "account_id", "tags", "ip_address"])


class ThreatCodeConfig(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    min_severity: Literal["critical", "high", "medium", "low", "info"] = "info"
    extra_rule_paths: list[str] = Field(default_factory=list)
    output_format: Literal[
        "json", "sarif", "markdown", "bitbucket", "matrix", "diagram", "cyclonedx"
    ] = "json"
    no_llm: bool = False
    dry_run: bool = False


def load_config(config_path: Path | None = None) -> ThreatCodeConfig:
    """Load config from .threatcode.yml, falling back to defaults.

    Security note: auto-discovery from CWD means a cloned repo can supply
    its own .threatcode.yml. In CI, always use --config with an explicit path.
    Auto-discovered configs are restricted to safe fields only.
    """
    if config_path:
        if not config_path.exists():
            raise ConfigError(f"Config file not found: {config_path}")
        return _load_from_file(config_path, trusted=True)

    # Skip home directory search when running in CI
    in_ci = bool(os.environ.get("CI"))

    candidates = [
        Path.cwd() / ".threatcode.yml",
        Path.cwd() / ".threatcode.yaml",
    ]
    if not in_ci:
        candidates.append(Path.home() / ".threatcode.yml")

    for candidate in candidates:
        if candidate.exists():
            logger.info(
                "Auto-discovered config at %s — use --config for explicit path in CI",
                candidate,
            )
            cfg = _load_from_file(candidate, trusted=False)
            return cfg

    return ThreatCodeConfig()


def _load_from_file(path: Path, *, trusted: bool = False) -> ThreatCodeConfig:
    try:
        content = path.read_text(encoding="utf-8")
        data: dict[str, Any] = yaml.safe_load(content) or {}
    except Exception as e:
        raise ConfigError(f"Failed to load config from {path}: {e}") from e

    # Warn if api_key appears in any config file (should use env var)
    llm_data = data.get("llm", {})
    if isinstance(llm_data, dict) and llm_data.get("api_key"):
        sys.stderr.write(
            f"WARNING: api_key found in config file {path}. "
            "Use ANTHROPIC_API_KEY environment variable instead.\n"
        )

    if not trusted:
        # Strip restricted fields from auto-discovered configs
        restricted = set(data.keys()) - _SAFE_AUTO_FIELDS
        if restricted:
            sys.stderr.write(
                f"WARNING: Auto-discovered config {path} contains restricted fields "
                f"{sorted(restricted)} — these are ignored for security. "
                f"Use --config to load a trusted config file.\n"
            )
            data = {k: v for k, v in data.items() if k in _SAFE_AUTO_FIELDS}

    try:
        return ThreatCodeConfig(**data)
    except ValidationError as e:
        raise ConfigError(f"Invalid config {path}: {_format_validation_error(e)}") from e
    except Exception as e:
        raise ConfigError(f"Failed to load config from {path}: {e}") from e


def _format_validation_error(error: ValidationError) -> str:
    """Render pydantic errors as 'field.path: message' without pydantic boilerplate."""
    parts = []
    for err in error.errors():
        loc = ".".join(str(part) for part in err["loc"]) or "config"
        msg = str(err["msg"]).removeprefix("Value error, ")
        parts.append(f"{loc}: {msg}")
    return "; ".join(parts)
