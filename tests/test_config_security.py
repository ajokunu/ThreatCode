"""Security regression tests for configuration discovery and trust.

Moved from tests/test_security.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class TestConfigHardening:
    def test_auto_discovered_config_strips_restricted_fields(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A01-01: Auto-discovered configs restricted to safe fields."""
        from threatcode.config import load_config

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("CI", raising=False)
        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text(
            "llm:\n  base_url: http://evil.com\n  api_key: secret\n"
            "no_llm: true\nmin_severity: high\n"
        )
        cfg = load_config(None)
        # Restricted fields stripped
        assert cfg.llm.base_url == ""
        assert cfg.llm.api_key == ""
        # Safe fields kept
        assert cfg.no_llm is True
        assert cfg.min_severity == "high"

    def test_api_key_in_config_warning(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """A02-01: Warn when api_key found in config file."""
        from threatcode.config import load_config

        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("llm:\n  api_key: sk-secret-key\n")
        load_config(config_file)
        captured = capsys.readouterr()
        assert "api_key" in captured.err

    def test_ci_env_skips_home_directory(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A07-02: Skip home dir search in CI."""
        from threatcode.config import load_config

        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("CI", "true")
        # Even if home has a config, CI skips it
        cfg = load_config(None)
        assert cfg.no_llm is False  # defaults

    def test_trusted_config_keeps_all_fields(self, tmp_path: Path) -> None:
        """Explicit --config path keeps all fields (trusted)."""
        from threatcode.config import load_config

        config_file = tmp_path / ".threatcode.yml"
        config_file.write_text("llm:\n  base_url: http://my-ollama:11434\n  provider: ollama\n")
        cfg = load_config(config_file)
        assert cfg.llm.base_url == "http://my-ollama:11434"
        assert cfg.llm.provider == "ollama"

    def test_redaction_config_no_enabled_field(self) -> None:
        """LLM02-02: RedactionConfig.enabled removed."""
        from threatcode.config import RedactionConfig

        rc = RedactionConfig()
        assert not hasattr(rc, "enabled") or "enabled" not in rc.model_fields
