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
        assert cfg.redaction.strategy == "placeholder"


class TestLoadConfig:
    def test_load_defaults_when_no_file(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
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
        monkeypatch.delenv("CI", raising=False)
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("no_llm: true\n")
        cfg = load_config(None)
        assert cfg.no_llm is True

    def test_nonexistent_explicit_path_raises_error(self) -> None:
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config(Path("/nonexistent/.threatcode.yml"))

    def test_restricted_fields_stripped_on_auto_discovery(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CI", raising=False)
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("llm:\n  base_url: http://evil.com\nno_llm: true\n")
        cfg = load_config(None)
        # llm section stripped (restricted), but no_llm is safe
        assert cfg.llm.base_url == ""  # stripped
        assert cfg.no_llm is True  # safe field kept
        captured = capsys.readouterr()
        assert "restricted" in captured.err.lower()

    def test_allow_local_network_defaults_off(self) -> None:
        assert ThreatCodeConfig().llm.allow_local_network is False

    @pytest.mark.parametrize("provider", ["ollama", "local"])
    def test_allow_local_network_for_local_providers(self, tmp_path: Path, provider: str) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text(
            f"llm:\n  provider: {provider}\n  base_url: http://localhost:11434\n"
            "  allow_local_network: true\n"
        )
        cfg = load_config(config_file)
        assert cfg.llm.allow_local_network is True

    @pytest.mark.parametrize("provider", ["openai", "anthropic"])
    def test_allow_local_network_rejected_for_hosted_providers(
        self, tmp_path: Path, provider: str
    ) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text(f"llm:\n  provider: {provider}\n  allow_local_network: true\n")
        expected = (
            f"llm: allow_local_network requires provider 'ollama' or 'local', not '{provider}'"
        )
        with pytest.raises(ConfigError, match=expected):
            load_config(config_file)

    def test_allow_local_network_stripped_on_auto_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cloned repo's .threatcode.yml must not be able to opt in to local addresses."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CI", raising=False)
        (tmp_path / ".threatcode.yml").write_text(
            "llm:\n  provider: ollama\n  base_url: http://10.0.0.5:11434\n"
            "  allow_local_network: true\n"
        )
        cfg = load_config(None)
        assert cfg.llm.allow_local_network is False
        assert cfg.llm.provider == "anthropic"
        assert cfg.llm.base_url == ""

    def test_validation_error_message_has_no_pydantic_boilerplate(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("min_severity: extreme\n")
        with pytest.raises(ConfigError) as exc_info:
            load_config(config_file)
        message = str(exc_info.value)
        assert "min_severity:" in message
        assert "errors.pydantic.dev" not in message

    def test_yaml_with_extra_rule_paths(self, tmp_path: Path) -> None:
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("extra_rule_paths:\n  - rules/custom.yml\n")
        cfg = load_config(config_file)
        assert cfg.extra_rule_paths == ["rules/custom.yml"]
