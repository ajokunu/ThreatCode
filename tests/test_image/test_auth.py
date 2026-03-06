"""Tests for registry authentication."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from threatcode.image.auth import (
    CredentialStore,
    RegistryCredential,
    TokenProvider,
    _HELPER_NAME_RE,
    _validate_realm_url,
)


class TestValidateRealmUrl:
    def test_rejects_http_scheme(self) -> None:
        with pytest.raises(ValueError, match="HTTPS"):
            _validate_realm_url("http://auth.docker.io/token", "docker.io")

    def test_rejects_empty_hostname(self) -> None:
        with pytest.raises(ValueError, match="hostname"):
            _validate_realm_url("https:///token", "docker.io")

    def test_warns_on_hostname_mismatch(self, caplog: pytest.LogCaptureFixture) -> None:
        import logging

        # Use a hostname that will fail DNS — that's fine, we just want the warning
        with caplog.at_level(logging.WARNING):
            with pytest.raises(ValueError, match="resolve"):
                _validate_realm_url(
                    "https://evil-auth-server.invalid/token", "docker.io"
                )
        assert any("differs from registry" in r.message for r in caplog.records)

    def test_rejects_loopback(self) -> None:
        with patch("threatcode.image.auth.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("127.0.0.1", 443)),
            ]
            with pytest.raises(ValueError, match="non-public"):
                _validate_realm_url("https://auth.docker.io/token", "docker.io")

    def test_rejects_private_ip(self) -> None:
        with patch("threatcode.image.auth.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("10.0.0.1", 443)),
            ]
            with pytest.raises(ValueError, match="non-public"):
                _validate_realm_url("https://auth.docker.io/token", "docker.io")

    def test_accepts_public_ip(self) -> None:
        with patch("threatcode.image.auth.socket.getaddrinfo") as mock_gai:
            mock_gai.return_value = [
                (2, 1, 6, "", ("104.18.124.25", 443)),
            ]
            # Should not raise
            _validate_realm_url("https://auth.docker.io/token", "docker.io")


class TestHelperNameValidation:
    def test_valid_names(self) -> None:
        assert _HELPER_NAME_RE.match("desktop")
        assert _HELPER_NAME_RE.match("ecr-login")
        assert _HELPER_NAME_RE.match("gcloud_helper")

    def test_rejects_path_injection(self) -> None:
        assert not _HELPER_NAME_RE.match("../../evil")
        assert not _HELPER_NAME_RE.match("helper;rm -rf /")
        assert not _HELPER_NAME_RE.match("helper name")
        assert not _HELPER_NAME_RE.match("")


class TestCredentialStore:
    def test_reads_inline_auths(self, tmp_path: Path) -> None:
        import base64

        encoded = base64.b64encode(b"user:pass").decode()
        config = {"auths": {"ghcr.io": {"auth": encoded}}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        store = CredentialStore(docker_config_path=config_file)
        cred = store.get("ghcr.io")
        assert cred is not None
        assert cred.username == "user"
        assert cred.password == "pass"

    def test_missing_config_returns_none(self, tmp_path: Path) -> None:
        store = CredentialStore(docker_config_path=tmp_path / "nonexistent.json")
        assert store.get("ghcr.io") is None

    def test_invalid_base64_returns_none(self, tmp_path: Path) -> None:
        config = {"auths": {"ghcr.io": {"auth": "not-valid-base64!!!"}}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        store = CredentialStore(docker_config_path=config_file)
        assert store.get("ghcr.io") is None

    def test_cred_helper_invalid_name_skipped(self, tmp_path: Path) -> None:
        config = {"credHelpers": {"ghcr.io": "../evil"}}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config))
        store = CredentialStore(docker_config_path=config_file)
        assert store.get("ghcr.io") is None


class TestTokenProvider:
    def test_no_auth_required(self) -> None:
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_client.get.return_value = mock_resp
        provider = TokenProvider(mock_client)
        token = provider.get_token("ghcr.io", "owner/repo")
        assert token is None

    def test_realm_validation_failure_returns_none(self) -> None:
        mock_client = MagicMock()
        # First call: probe returns 401 with bearer
        probe_resp = MagicMock()
        probe_resp.status_code = 401
        probe_resp.headers = {
            "Www-Authenticate": 'Bearer realm="http://evil.com/token",service="ghcr.io"'
        }
        mock_client.get.return_value = probe_resp
        provider = TokenProvider(mock_client)
        token = provider.get_token("ghcr.io", "owner/repo")
        # Should return None because http realm is rejected
        assert token is None
