"""Security regression tests for configuration discovery and trust.

A scanned repository supplies its own .threatcode.yml, so what an auto-discovered file may
change is a security boundary: it can never set the gate, load rules, enable or redirect the LLM
or raise the resource limits.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from threatcode.config import discover_config, load_config, resolve_settings


@pytest.fixture(autouse=True)
def hermetic_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("THREATCODE_FAIL_ON", raising=False)


class TestConfigHardening:
    def test_auto_discovered_config_strips_restricted_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A01-01: auto-discovered configs are restricted to safe fields."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".threatcode.yml").write_text(
            "llm:\n  base_url: http://evil.com\n  api_key: secret\n  enabled: true\n"
            "min_severity: high\n",
            encoding="utf-8",
        )
        cfg = load_config(None)
        assert cfg.llm.base_url == ""
        assert cfg.llm.api_key == ""
        assert cfg.llm.enabled is False
        assert cfg.min_severity == "high"

    def test_a_repository_cannot_disable_its_own_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".threatcode.yml").write_text("fail_on: none\n", encoding="utf-8")
        loaded = discover_config(None, [tmp_path])
        assert loaded.config.fail_on is None
        assert resolve_settings({}, loaded, {}).fail_on == "high"
        assert "fail_on" in loaded.ignored

    def test_a_repository_cannot_enable_the_llm_or_load_rules(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcode.yml").write_text(
            "llm:\n  enabled: true\nextra_rule_paths: [evil.yml]\n", encoding="utf-8"
        )
        loaded = discover_config(None, [tmp_path])
        settings = resolve_settings({}, loaded, {})
        assert settings.use_llm is False
        assert settings.extra_rule_paths == ()

    def test_a_repository_cannot_raise_the_graph_limits(self, tmp_path: Path) -> None:
        (tmp_path / ".threatcode.yml").write_text(
            "max_nodes: 100000000\nstrict_edges: false\n", encoding="utf-8"
        )
        settings = resolve_settings({}, discover_config(None, [tmp_path]), {})
        assert settings.max_nodes is None
        assert settings.strict_edges is True

    def test_the_same_keys_are_honored_from_an_explicit_config(self, tmp_path: Path) -> None:
        path = tmp_path / "trusted.yml"
        path.write_text(
            "fail_on: low\nllm:\n  enabled: true\nextra_rule_paths: [mine.yml]\nmax_nodes: 5\n",
            encoding="utf-8",
        )
        settings = resolve_settings({}, discover_config(path), {})
        assert settings.fail_on == "low"
        assert settings.use_llm is True
        assert settings.extra_rule_paths == (tmp_path / "mine.yml",)
        assert settings.max_nodes == 5

    def test_api_key_in_config_warning(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        """A02-01: warn when api_key is found in a config file."""
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("llm:\n  api_key: sk-secret-key\n", encoding="utf-8")
        with caplog.at_level(logging.WARNING, logger="threatcode.config"):
            load_config(config_file)
        assert "api_key" in caplog.text
        assert "sk-secret-key" not in caplog.text

    def test_ci_env_skips_home_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A07-02: skip the home directory search in CI."""
        (tmp_path / "home" / ".threatcode.yml").write_text(
            "min_severity: critical\n", encoding="utf-8"
        )
        elsewhere = tmp_path / "work"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        assert load_config(None).min_severity == "critical"
        monkeypatch.setenv("CI", "true")
        assert load_config(None).min_severity is None

    def test_trusted_config_keeps_all_fields(self, tmp_path: Path) -> None:
        """An explicit --config path keeps all fields (trusted)."""
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text(
            "llm:\n  base_url: http://my-ollama:11434\n  provider: ollama\n", encoding="utf-8"
        )
        cfg = load_config(config_file)
        assert cfg.llm.base_url == "http://my-ollama:11434"
        assert cfg.llm.provider == "ollama"

    def test_allow_local_network_stripped_on_auto_discovery(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A cloned repo's .threatcode.yml must not be able to opt in to local addresses."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".threatcode.yml").write_text(
            "llm:\n  provider: ollama\n  base_url: http://10.0.0.5:11434\n"
            "  allow_local_network: true\n",
            encoding="utf-8",
        )
        cfg = load_config(None)
        assert cfg.llm.allow_local_network is False
        assert cfg.llm.provider == "anthropic"
        assert cfg.llm.base_url == ""

    def test_redaction_config_no_enabled_field(self) -> None:
        """LLM02-02: RedactionConfig.enabled removed."""
        from threatcode.config import RedactionConfig

        assert "enabled" not in RedactionConfig.model_fields
