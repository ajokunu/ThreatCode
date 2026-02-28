"""Pydantic configuration model + .threatcode.yml loader."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from threatcode.exceptions import ConfigError


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
    """Load config from .threatcode.yml, falling back to defaults."""
    if config_path and config_path.exists():
        return _load_from_file(config_path)

    # Search up from cwd
    for candidate in [
        Path.cwd() / ".threatcode.yml",
        Path.cwd() / ".threatcode.yaml",
        Path.home() / ".threatcode.yml",
    ]:
        if candidate.exists():
            return _load_from_file(candidate)

    return ThreatCodeConfig()


def _load_from_file(path: Path) -> ThreatCodeConfig:
    try:
        content = path.read_text(encoding="utf-8")
        data: dict[str, Any] = yaml.safe_load(content) or {}
        return ThreatCodeConfig(**data)
    except Exception as e:
        raise ConfigError(f"Failed to load config from {path}: {e}") from e
