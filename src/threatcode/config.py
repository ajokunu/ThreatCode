"""Pydantic configuration model + .threatcode.yml loader.

Security: config auto-discovery loads .threatcode.yml from CWD.
In CI, use --config to specify an explicit path rather than relying on auto-discovery,
which could load a malicious config from a cloned repository.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from threatcode.exceptions import ConfigError

logger = logging.getLogger(__name__)


class LLMConfig(BaseModel):
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    api_key: str = ""
    base_url: str = ""
    max_tokens: int = 4096
    temperature: float = 0.2


class RedactionConfig(BaseModel):
    enabled: bool = True
    strategy: str = "placeholder"  # "placeholder" or "hash"
    fields: list[str] = Field(default_factory=lambda: ["arn", "account_id", "tags", "ip_address"])


class ThreatCodeConfig(BaseModel):
    llm: LLMConfig = Field(default_factory=LLMConfig)
    redaction: RedactionConfig = Field(default_factory=RedactionConfig)
    min_severity: str = "info"
    extra_rule_paths: list[str] = Field(default_factory=list)
    output_format: str = "json"
    no_llm: bool = False
    dry_run: bool = False


def load_config(config_path: Path | None = None) -> ThreatCodeConfig:
    """Load config from .threatcode.yml, falling back to defaults.

    Security note: auto-discovery from CWD means a cloned repo can supply
    its own .threatcode.yml. In CI, always use --config with an explicit path.
    """
    if config_path and config_path.exists():
        return _load_from_file(config_path)

    # Search from cwd then home
    for candidate in [
        Path.cwd() / ".threatcode.yml",
        Path.cwd() / ".threatcode.yaml",
        Path.home() / ".threatcode.yml",
    ]:
        if candidate.exists():
            logger.info(
                "Auto-discovered config at %s — use --config for explicit path in CI",
                candidate,
            )
            cfg = _load_from_file(candidate)
            # Security: warn if auto-discovered config sets LLM base_url
            if cfg.llm.base_url:
                logger.warning(
                    "Auto-discovered config sets llm.base_url='%s'. "
                    "In CI pipelines, use --config with a trusted config file.",
                    cfg.llm.base_url,
                )
            return cfg

    return ThreatCodeConfig()


def _load_from_file(path: Path) -> ThreatCodeConfig:
    try:
        content = path.read_text(encoding="utf-8")
        data: dict[str, Any] = yaml.safe_load(content) or {}
        return ThreatCodeConfig(**data)
    except Exception as e:
        raise ConfigError(f"Failed to load config from {path}: {e}") from e
