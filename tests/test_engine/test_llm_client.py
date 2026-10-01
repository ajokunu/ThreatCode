"""Tests for threatcode.engine.llm.client."""

from __future__ import annotations

import logging
import socket
import urllib.request
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from threatcode.engine.llm.client import (
    DryRunLLMClient,
    OpenAICompatibleLLMClient,
    _SafeRedirectHandler,
    _validate_base_url,
)
from threatcode.exceptions import LLMError

if TYPE_CHECKING:
    from tests.conftest import FakeLLMServer

_PATCH_GAI = "threatcode.engine.llm.client.socket.getaddrinfo"


def _mock_resolve(
    ip: str,
    port: int = 443,
    family: int = 2,
) -> list[tuple[int, int, int, str, tuple[str, int]]]:
    """Create a mock getaddrinfo result."""
    return [(family, 1, 6, "", (ip, port))]


class TestValidateBaseUrl:
    """Default mode: https only, public addresses only."""

    def test_valid_https_url(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("104.18.6.192")):
            _validate_base_url("https://api.openai.com")

    def test_http_blocked_by_default(self) -> None:
        with pytest.raises(LLMError, match="Unsafe URL scheme 'http' - only https is allowed"):
            _validate_base_url("http://my-ollama.example.com:11434")

    def test_http_error_names_the_opt_in(self) -> None:
        with pytest.raises(LLMError, match="allow_local_network"):
            _validate_base_url("http://localhost:11434")

    def test_blocks_ftp_scheme(self) -> None:
        with pytest.raises(LLMError, match="Unsafe URL scheme 'ftp' - only https is allowed"):
            _validate_base_url("ftp://example.com/v1")

    def test_blocks_empty_hostname(self) -> None:
        with pytest.raises(LLMError, match="hostname"):
            _validate_base_url("https:///v1")

    def test_blocks_localhost(self) -> None:
        with pytest.raises(LLMError, match="loopback.*allow_local_network"):
            _validate_base_url("https://localhost:11434")

    def test_blocks_127_0_0_1(self) -> None:
        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("https://127.0.0.1:11434")

    def test_blocks_ipv6_loopback(self) -> None:
        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("https://[::1]:11434")

    def test_blocks_ipv4_mapped_loopback(self) -> None:
        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("https://[::ffff:127.0.0.1]:11434")

    def test_blocks_10_x_private_range(self) -> None:
        with pytest.raises(LLMError, match="private"):
            _validate_base_url("https://10.0.0.1/v1")

    def test_blocks_172_16_private_range(self) -> None:
        with pytest.raises(LLMError, match="private"):
            _validate_base_url("https://172.16.0.1/v1")

    def test_blocks_192_168_private_range(self) -> None:
        with pytest.raises(LLMError, match="private"):
            _validate_base_url("https://192.168.1.1/v1")

    def test_blocks_shared_address_space(self) -> None:
        with pytest.raises(LLMError, match="shared"):
            _validate_base_url("https://100.64.0.1/v1")

    def test_allows_172_outside_private(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("172.15.0.1")):
            _validate_base_url("https://172.15.0.1/v1")
        with patch(_PATCH_GAI, return_value=_mock_resolve("172.32.0.1")):
            _validate_base_url("https://172.32.0.1/v1")

    def test_blocks_metadata_endpoint(self) -> None:
        with pytest.raises(LLMError, match="link-local"):
            _validate_base_url("https://169.254.169.254/latest/meta-data/")

    def test_blocks_zero_address(self) -> None:
        with pytest.raises(LLMError, match="unspecified"):
            _validate_base_url("https://0.0.0.0:11434")

    def test_blocks_dns_rebinding_to_private(self) -> None:
        """DNS rebinding: hostname resolves to private IP."""
        with patch(_PATCH_GAI, return_value=_mock_resolve("10.0.0.1")):
            with pytest.raises(LLMError, match="private"):
                _validate_base_url("https://evil.com")

    def test_blocks_when_any_resolved_address_is_private(self) -> None:
        rv = _mock_resolve("93.184.216.34") + _mock_resolve("10.0.0.1")
        with patch(_PATCH_GAI, return_value=rv):
            with pytest.raises(LLMError, match="private"):
                _validate_base_url("https://mixed.example.com")


class TestValidateBaseUrlLocalNetwork:
    """allow_local_network: the opt-in used by the ollama and local providers."""

    def test_allows_http_localhost(self) -> None:
        # Real resolution: localhost may yield 127.0.0.1 and ::1, both loopback.
        _validate_base_url("http://localhost:11434", allow_local_network=True)

    def test_allows_http_127_0_0_1(self) -> None:
        _validate_base_url("http://127.0.0.1:11434", allow_local_network=True)

    def test_allows_http_ipv6_loopback(self) -> None:
        _validate_base_url("http://[::1]:11434", allow_local_network=True)

    def test_allows_https_loopback(self) -> None:
        _validate_base_url("https://127.0.0.1:8443", allow_local_network=True)

    @pytest.mark.parametrize(
        "url",
        [
            "http://10.0.0.5:11434",
            "http://172.16.4.2:11434",
            "http://192.168.1.20:11434",
            "http://[fd00::20]:11434",
            "http://100.101.102.103:11434",
        ],
    )
    def test_allows_private_and_shared_addresses(self, url: str) -> None:
        _validate_base_url(url, allow_local_network=True)

    def test_allows_hostname_on_private_network(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("10.0.0.5", port=11434)):
            _validate_base_url("http://gpu-box.lan:11434", allow_local_network=True)

    def test_allows_https_public_address(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("93.184.216.34")):
            _validate_base_url("https://llm.example.com", allow_local_network=True)

    def test_rejects_http_to_public_address(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("93.184.216.34", port=80)):
            with pytest.raises(LLMError, match="plain http.*public address 93.184.216.34"):
                _validate_base_url("http://llm.example.com", allow_local_network=True)

    def test_rejects_http_when_any_resolved_address_is_public(self) -> None:
        rv = _mock_resolve("127.0.0.1", port=80) + _mock_resolve("93.184.216.34", port=80)
        with patch(_PATCH_GAI, return_value=rv):
            with pytest.raises(LLMError, match="public address"):
                _validate_base_url("http://split.example.com", allow_local_network=True)

    @pytest.mark.parametrize(
        ("url", "kind"),
        [
            ("http://169.254.169.254/latest/meta-data/", "link-local"),
            ("http://[::ffff:169.254.169.254]/", "link-local"),
            ("http://[fe80::1]:11434", "link-local"),
            ("http://0.0.0.0:11434", "unspecified"),
            ("http://[::]:11434", "unspecified"),
            ("http://224.0.0.1:11434", "multicast"),
            ("http://240.0.0.1:11434", "reserved"),
        ],
    )
    def test_still_blocks_dangerous_addresses(self, url: str, kind: str) -> None:
        with pytest.raises(LLMError, match=kind):
            _validate_base_url(url, allow_local_network=True)

    def test_still_blocks_metadata_hostname(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("169.254.169.254", port=80)):
            with pytest.raises(LLMError, match="link-local"):
                _validate_base_url("http://metadata.google.internal/v1", allow_local_network=True)

    def test_still_blocks_non_http_schemes(self) -> None:
        with pytest.raises(LLMError, match="Unsafe URL scheme 'file' - only http/https"):
            _validate_base_url("file:///etc/passwd", allow_local_network=True)


class TestSafeRedirectHandler:
    """Redirects get the strict default check, whatever the base_url used."""

    def _redirect(self, newurl: str) -> urllib.request.Request | None:
        req = urllib.request.Request("http://127.0.0.1:11434/v1/chat/completions")
        return _SafeRedirectHandler().redirect_request(req, None, 302, "Found", {}, newurl)  # type: ignore[arg-type]

    def test_blocks_redirect_to_loopback(self) -> None:
        with pytest.raises(LLMError, match="Unsafe URL scheme 'http'"):
            self._redirect("http://127.0.0.1:8080/admin")

    def test_blocks_https_redirect_to_private(self) -> None:
        with pytest.raises(LLMError, match="private"):
            self._redirect("https://10.0.0.1/")

    def test_blocks_redirect_to_metadata(self) -> None:
        with pytest.raises(LLMError):
            self._redirect("http://169.254.169.254/latest/meta-data/")

    def test_allows_https_redirect_to_public(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("93.184.216.34")):
            new_req = self._redirect("https://llm.example.com/v1/chat/completions")
        assert new_req is not None
        assert new_req.full_url == "https://llm.example.com/v1/chat/completions"


class TestOpenAICompatibleClient:
    def test_constructor_validates_url(self) -> None:
        with pytest.raises(LLMError):
            OpenAICompatibleLLMClient(base_url="https://127.0.0.1:11434")

    def test_constructor_rejects_local_http_without_opt_in(self) -> None:
        with pytest.raises(LLMError, match="allow_local_network"):
            OpenAICompatibleLLMClient(base_url="http://localhost:11434")

    def test_constructor_accepts_local_http_with_opt_in(self) -> None:
        client = OpenAICompatibleLLMClient(
            base_url="http://localhost:11434/",
            model="llama3.2",
            allow_local_network=True,
        )
        assert client._base_url == "http://localhost:11434"

    @pytest.mark.parametrize("suffix", ["", "/", "/v1", "/v1/"])
    def test_base_url_with_or_without_v1(self, suffix: str, fake_llm_server: FakeLLMServer) -> None:
        client = OpenAICompatibleLLMClient(
            base_url=fake_llm_server.base_url + suffix, allow_local_network=True
        )
        client.analyze("prompt")
        assert fake_llm_server.requests[0]["path"] == "/v1/chat/completions"

    def test_constructor_accepts_valid_url(self) -> None:
        rv = _mock_resolve("93.184.216.34")
        with patch(_PATCH_GAI, return_value=rv):
            client = OpenAICompatibleLLMClient(
                base_url="https://api.example.com",
                model="test",
            )
            assert client._model == "test"

    def test_warns_when_api_key_sent_over_http(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            OpenAICompatibleLLMClient(
                base_url="http://127.0.0.1:11434",
                api_key="sk-secret",
                allow_local_network=True,
            )
        assert any("plain http" in r.message for r in caplog.records)

    @pytest.mark.parametrize("api_key", ["", "not-needed"])
    def test_no_http_warning_without_api_key(
        self, api_key: str, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            OpenAICompatibleLLMClient(
                base_url="http://127.0.0.1:11434",
                api_key=api_key,
                allow_local_network=True,
            )
        assert not any("plain http" in r.message for r in caplog.records)

    def test_analyze_against_local_server(self, fake_llm_server: FakeLLMServer) -> None:
        fake_llm_server.reply = '{"threats": [{"title": "x"}]}'
        client = OpenAICompatibleLLMClient(
            base_url=fake_llm_server.base_url,
            model="llama3.2",
            allow_local_network=True,
        )
        assert client.analyze("prompt") == '{"threats": [{"title": "x"}]}'
        assert len(fake_llm_server.requests) == 1
        request = fake_llm_server.requests[0]
        assert request["path"] == "/v1/chat/completions"
        assert request["body"]["model"] == "llama3.2"

    def test_analyze_raises_llm_error_when_server_down(self) -> None:
        # Grab a free loopback port and release it so nothing is listening there.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        client = OpenAICompatibleLLMClient(
            base_url=f"http://127.0.0.1:{port}", allow_local_network=True, timeout=5
        )
        with pytest.raises(LLMError, match="API call failed"):
            client.analyze("prompt")


class TestDryRunClient:
    def test_returns_empty_threats(self) -> None:
        client = DryRunLLMClient()
        result = client.analyze("test prompt")
        assert '"threats"' in result
        assert "[]" in result

    def test_writes_metadata_to_stderr(
        self,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        client = DryRunLLMClient()
        client.analyze("test prompt")
        captured = capsys.readouterr()
        assert "DRY RUN" in captured.err
        assert "chars" in captured.err.lower()
