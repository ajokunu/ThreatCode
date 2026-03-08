"""Integration tests for image scanner."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.image.scanner import _SENSITIVE_ENV_PATTERNS, ImageScanner


class TestEnvRedaction:
    def test_sensitive_env_redacted(self) -> None:
        config: dict[str, Any] = {
            "config": {
                "Env": [
                    "PATH=/usr/bin",
                    "DB_PASSWORD=supersecret",
                    "API_TOKEN=tok_abc123",
                    "AUTH_KEY=mykey",
                    "NORMAL_VAR=hello",
                ],
            },
        }
        metadata = ImageScanner._extract_metadata(config)
        env = metadata["env"]
        assert "PATH=/usr/bin" in env
        assert "DB_PASSWORD=[REDACTED]" in env
        assert "API_TOKEN=[REDACTED]" in env
        assert "AUTH_KEY=[REDACTED]" in env
        assert "NORMAL_VAR=hello" in env
        # No actual secret values leaked
        assert not any("supersecret" in e for e in env)
        assert not any("tok_abc123" in e for e in env)

    def test_env_without_equals_preserved(self) -> None:
        config: dict[str, Any] = {"config": {"Env": ["NOEQUALS"]}}
        metadata = ImageScanner._extract_metadata(config)
        assert "NOEQUALS" in metadata["env"]

    def test_empty_config_handled(self) -> None:
        metadata = ImageScanner._extract_metadata({})
        assert metadata["env"] == []
        assert metadata["architecture"] == ""


class TestSensitiveEnvPattern:
    @pytest.mark.parametrize(
        "key",
        ["DB_PASSWORD", "API_TOKEN", "SECRET_KEY", "AWS_CREDENTIAL", "AUTH_HEADER"],
    )
    def test_matches_sensitive_keys(self, key: str) -> None:
        assert _SENSITIVE_ENV_PATTERNS.search(key)

    @pytest.mark.parametrize(
        "key",
        ["PATH", "HOME", "LANG", "NORMAL_VAR", "MY_SETTING"],
    )
    def test_skips_non_sensitive_keys(self, key: str) -> None:
        assert not _SENSITIVE_ENV_PATTERNS.search(key)
