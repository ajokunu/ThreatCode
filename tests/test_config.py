"""Tests for threatcode.config."""

from __future__ import annotations

from pathlib import Path

import pytest
from threatcode.config import ThreatCodeConfig, load_config
from threatcode.exceptions import ConfigError


class TestThreatCodeConfig:
    def test_defaults(self) -> None:
        cfg = ThreatCodeConfig()
        assert cfg.no_llm is False
        assert cfg.dry_run is False
        assert cfg.output_format == "json"
        assert cfg.min_severity == "info"
        assert cfg.llm.provider == "anthropic"

    def test_llm_defaults(self) -> None:
        cfg = ThreatCodeConfig()
        assert cfg.llm.max_tokens == 4096
        assert cfg.llm.temperature == 0.2

    def test_redaction_defaults(self) -> None:
        cfg = ThreatCodeConfig()
        assert cfg.redaction.enabled is True
        assert cfg.redaction.strategy == "placeholder"


class TestLoadConfig:
    def test_load_defaults_when_no_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        cfg = load_config(None)
        assert isinstance(cfg, ThreatCodeConfig)

    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("no_llm: true\nmin_severity: high\n")
        cfg = load_config(config_file)
        assert cfg.no_llm is True
        assert cfg.min_severity == "high"

    def test_load_with_llm_section(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("llm:\n  provider: ollama\n  model: llama3\n")
        cfg = load_config(config_file)
        assert cfg.llm.provider == "ollama"
        assert cfg.llm.model == "llama3"

    def test_invalid_config_raises_error(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("no_llm: [invalid, structure]\n")
        with pytest.raises(ConfigError):
            load_config(config_file)

    def test_auto_discovery_from_cwd(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("no_llm: true\n")
        cfg = load_config(None)
        assert cfg.no_llm is True

    def test_nonexistent_explicit_path_returns_defaults(self) -> None:
        cfg = load_config(Path("/nonexistent/.threatcode.yml"))
        assert isinstance(cfg, ThreatCodeConfig)

    def test_base_url_warning_on_auto_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("llm:\n  base_url: http://evil.com\n")
        import logging
        with caplog.at_level(logging.WARNING):
            cfg = load_config(None)
        assert cfg.llm.base_url == "http://evil.com"
        assert any("base_url" in record.message for record in caplog.records)

    def test_yaml_with_extra_rule_paths(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("extra_rule_paths:\n  - rules/custom.yml\n")
        cfg = load_config(config_file)
        assert cfg.extra_rule_paths == ["rules/custom.yml"]
