"""Tests for threatcode.engine.llm.client."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from threatcode.engine.llm.client import (
    DryRunLLMClient,
    OpenAICompatibleLLMClient,
    _validate_base_url,
)
from threatcode.exceptions import LLMError

_PATCH_GAI = "threatcode.engine.llm.client.socket.getaddrinfo"


def _mock_resolve(
    ip: str, port: int = 443, family: int = 2,
) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    """Create a mock getaddrinfo result."""
    return [(family, 1, 6, "", (ip, port))]


class TestValidateBaseUrl:
    def test_valid_https_url(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("104.18.6.192")):
            _validate_base_url("https://api.openai.com")

    def test_valid_http_url(self) -> None:
        rv = _mock_resolve("93.184.216.34", port=11434)
        with patch(_PATCH_GAI, return_value=rv):
            _validate_base_url("http://my-ollama.example.com:11434")

    def test_blocks_localhost(self) -> None:
        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("http://127.0.0.1:11434")

    def test_blocks_127_0_0_1(self) -> None:
        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("http://127.0.0.1:11434")

    def test_blocks_metadata_endpoint(self) -> None:
        with pytest.raises(LLMError, match="link-local|private"):
            _validate_base_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_10_x_private_range(self) -> None:
        with pytest.raises(LLMError, match="private"):
            _validate_base_url("http://10.0.0.1/v1")

    def test_blocks_172_16_private_range(self) -> None:
        with pytest.raises(LLMError, match="private"):
            _validate_base_url("http://172.16.0.1/v1")

    def test_allows_172_outside_private(self) -> None:
        rv1 = _mock_resolve("172.15.0.1", port=80)
        with patch(_PATCH_GAI, return_value=rv1):
            _validate_base_url("http://172.15.0.1/v1")
        rv2 = _mock_resolve("172.32.0.1", port=80)
        with patch(_PATCH_GAI, return_value=rv2):
            _validate_base_url("http://172.32.0.1/v1")

    def test_blocks_192_168_private_range(self) -> None:
        with pytest.raises(LLMError, match="private"):
            _validate_base_url("http://192.168.1.1/v1")

    def test_blocks_ftp_scheme(self) -> None:
        with pytest.raises(LLMError, match="Unsafe URL scheme"):
            _validate_base_url("ftp://example.com/v1")

    def test_blocks_empty_hostname(self) -> None:
        with pytest.raises(LLMError, match="hostname"):
            _validate_base_url("http:///v1")

    def test_blocks_ipv6_loopback(self) -> None:
        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("http://[::1]:11434")

    def test_blocks_zero_address(self) -> None:
        with pytest.raises(LLMError):
            _validate_base_url("http://0.0.0.0:11434")

    def test_blocks_metadata_google(self) -> None:
        rv = _mock_resolve("169.254.169.254", port=80)
        with patch(_PATCH_GAI, return_value=rv):
            with pytest.raises(LLMError, match="link-local|private"):
                _validate_base_url("http://metadata.google.internal/v1")

    def test_blocks_dns_rebinding_to_private(self) -> None:
        """DNS rebinding: hostname resolves to private IP."""
        rv = _mock_resolve("10.0.0.1")
        with patch(_PATCH_GAI, return_value=rv):
            with pytest.raises(LLMError, match="private"):
                _validate_base_url("https://evil.com")


class TestOpenAICompatibleClient:
    def test_constructor_validates_url(self) -> None:
        with pytest.raises(LLMError):
            OpenAICompatibleLLMClient(base_url="http://127.0.0.1:11434")

    def test_constructor_accepts_valid_url(self) -> None:
        rv = _mock_resolve("93.184.216.34")
        with patch(_PATCH_GAI, return_value=rv):
            client = OpenAICompatibleLLMClient(
                base_url="https://api.example.com",
                model="test",
            )
            assert client._model == "test"


class TestDryRunClient:
    def test_returns_empty_threats(self) -> None:
        client = DryRunLLMClient()
        result = client.analyze("test prompt")
        assert '"threats"' in result
        assert "[]" in result

    def test_writes_metadata_to_stderr(
        self, capsys: pytest.CaptureFixture[str],
    ) -> None:
        client = DryRunLLMClient()
        client.analyze("test prompt")
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.err
        assert "chars" in captured.err.lower()
