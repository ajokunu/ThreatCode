"""Tests for threatcode.engine.llm.client."""

from __future__ import annotations

import json
import logging
import socket
import threading
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from unittest.mock import patch

import pytest

from threatcode.config import DEFAULT_LLM_MODEL, LLMConfig, ResolvedSettings, ThreatCodeConfig
from threatcode.engine.llm import client as client_module
from threatcode.engine.llm.client import (
    DEPRECATED_MODELS,
    MAX_PROMPT_LENGTH,
    AnthropicLLMClient,
    DryRunLLMClient,
    OpenAICompatibleLLMClient,
    _SafeRedirectHandler,
    _validate_base_url,
)
from threatcode.engine.llm.factory import build_client, resolve_api_key
from threatcode.engine.llm.prompts import SYSTEM_PROMPT
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
    """A redirect stays inside the origin of the request; nothing is forwarded elsewhere."""

    def _redirect(
        self,
        newurl: str,
        *,
        origin: str = "http://127.0.0.1:11434",
        allow_local_network: bool = True,
        code: int = 307,
    ) -> urllib.request.Request | None:
        req = urllib.request.Request(
            f"{origin}/v1/chat/completions",
            data=b"{}",
            headers={"Authorization": "Bearer sk-secret"},
            method="POST",
        )
        handler = _SafeRedirectHandler(origin, allow_local_network)
        return handler.redirect_request(req, None, code, "Moved", {}, newurl)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "newurl",
        [
            "http://127.0.0.1:8080/admin",  # another port
            "http://localhost:11434/v1/chat/completions",  # another host name
            "https://127.0.0.1:11434/v1/chat/completions",  # another scheme
            "https://llm.example.com/v1/chat/completions",  # another host
            "http://169.254.169.254/latest/meta-data/",
            "http://10.0.0.1:11434/",
        ],
    )
    def test_refuses_every_cross_origin_redirect(self, newurl: str) -> None:
        assert self._redirect(newurl) is None

    def test_refuses_to_downgrade_https_to_http(self) -> None:
        assert self._redirect("http://api.example.com/x", origin="https://api.example.com") is None

    def test_follows_a_same_origin_redirect(self) -> None:
        new_req = self._redirect("http://127.0.0.1:11434/v1/chat/completions/")
        assert new_req is not None
        assert new_req.full_url == "http://127.0.0.1:11434/v1/chat/completions/"
        assert new_req.data == b"{}"  # 307 keeps the method and the body

    def test_a_same_origin_redirect_is_still_validated(self) -> None:
        with pytest.raises(LLMError, match="Unsafe URL scheme 'http'"):
            self._redirect(
                "http://127.0.0.1:11434/x",
                origin="http://127.0.0.1:11434",
                allow_local_network=False,
            )

    def test_the_default_port_is_part_of_the_origin(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("93.184.216.34")):
            new_req = self._redirect(
                "https://api.example.com:443/v1/x",
                origin="https://api.example.com",
                allow_local_network=False,
            )
        assert new_req is not None


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


class TestDryRunRequest:
    def test_the_exact_request_is_written_to_stderr_by_default(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        DryRunLLMClient().analyze("USER PROMPT BODY")
        err = capsys.readouterr().err
        assert "USER PROMPT BODY" in err
        assert SYSTEM_PROMPT[:40] in err
        assert "about" in err and "tokens" in err

    def test_the_request_can_go_to_a_file_as_json(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        target = tmp_path / "payload.json"
        DryRunLLMClient(output=str(target)).analyze("PROMPT <&> text")
        request = json.loads(target.read_text(encoding="utf-8"))
        assert request["system"] == SYSTEM_PROMPT
        assert request["messages"] == [{"role": "user", "content": "PROMPT <&> text"}]
        captured = capsys.readouterr()
        assert "PROMPT <&> text" not in captured.err  # the file holds it, stderr the summary
        assert str(target) in captured.err
        assert captured.out == ""

    def test_an_unwritable_destination_is_an_llm_error(self, tmp_path: Path) -> None:
        with pytest.raises(LLMError, match="Cannot write the dry-run request"):
            DryRunLLMClient(output=str(tmp_path / "missing" / "p.json")).analyze("x")

    def test_it_never_touches_the_network(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def refuse(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("the dry run opened a connection")

        monkeypatch.setattr(urllib.request, "build_opener", refuse)
        monkeypatch.setattr(urllib.request, "urlopen", refuse)
        monkeypatch.setattr(socket, "create_connection", refuse)
        assert DryRunLLMClient().analyze("p") == '{"threats": []}'

    def test_the_factory_hands_the_output_path_to_the_client(self, tmp_path: Path) -> None:
        settings = ResolvedSettings(dry_run=True, dry_run_output=str(tmp_path / "o.json"))
        client = build_client(settings)
        assert isinstance(client, DryRunLLMClient)
        assert client.provider == "dry-run"
        client.analyze("p")
        assert (tmp_path / "o.json").is_file()


# ----------------------------------------------------------------------------------------------
# Anthropic
# ----------------------------------------------------------------------------------------------


@dataclass
class Block:
    type: str
    text: str = ""
    thinking: str = ""

    def __post_init__(self) -> None:
        # A thinking block has no `text` attribute in the SDK.
        if self.type != "text":
            del self.text


@dataclass
class FakeMessage:
    content: list[Any]
    stop_reason: str = "end_turn"


class FakeBadRequestError(Exception):
    status_code = 400


class FakeMessagesAcceptingTemperature:
    """messages.create that takes any keyword, as older SDK versions did."""

    def __init__(self, replies: list[Any]) -> None:
        self.replies = replies
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        reply = self.replies.pop(0) if self.replies else FakeMessage([Block("text", "{}")])
        if isinstance(reply, Exception):
            raise reply
        return reply


class FakeMessagesWithoutTemperature:
    """messages.create with the signature of current SDKs: no temperature parameter."""

    def __init__(self, replies: list[Any]) -> None:
        self.replies = replies
        self.calls: list[dict[str, Any]] = []

    def create(
        self,
        *,
        model: str,
        max_tokens: int,
        messages: list[dict[str, str]],
        system: str = "",
        extra_body: object | None = None,
    ) -> Any:
        self.calls.append(
            {
                "model": model,
                "max_tokens": max_tokens,
                "messages": messages,
                "system": system,
                "extra_body": extra_body,
            }
        )
        reply = self.replies.pop(0) if self.replies else FakeMessage([Block("text", "{}")])
        if isinstance(reply, Exception):
            raise reply
        return reply


@dataclass
class SdkProbe:
    """The patched anthropic.Anthropic: remembers how it was built and holds the fake API."""

    constructed: list[dict[str, Any]] = field(default_factory=list)
    replies: list[Any] = field(default_factory=list)
    accepts_temperature: bool = True
    messages: Any = None


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> SdkProbe:
    import anthropic

    probe = SdkProbe()

    class FakeAnthropic:
        def __init__(self, **kwargs: Any) -> None:
            probe.constructed.append(kwargs)
            cls = (
                FakeMessagesAcceptingTemperature
                if probe.accepts_temperature
                else FakeMessagesWithoutTemperature
            )
            probe.messages = cls(probe.replies)
            self.messages = probe.messages

    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    monkeypatch.delenv("ANTHROPIC_BASE_URL", raising=False)
    return probe


class TestAnthropicResponse:
    def test_thinking_blocks_are_skipped(self, sdk: SdkProbe) -> None:
        sdk.replies.append(
            FakeMessage([Block("thinking", thinking="hmm"), Block("text", "ANSWER")])
        )
        assert AnthropicLLMClient(api_key="k").analyze("p") == "ANSWER"

    def test_two_text_blocks_are_joined(self, sdk: SdkProbe) -> None:
        sdk.replies.append(FakeMessage([Block("text", '{"threats": '), Block("text", "[]}")]))
        assert AnthropicLLMClient(api_key="k").analyze("p") == '{"threats": []}'

    def test_only_thinking_is_an_error(self, sdk: SdkProbe) -> None:
        sdk.replies.append(FakeMessage([Block("thinking", thinking="hmm")]))
        with pytest.raises(LLMError, match="no text content block"):
            AnthropicLLMClient(api_key="k").analyze("p")

    def test_empty_content_is_an_error(self, sdk: SdkProbe) -> None:
        sdk.replies.append(FakeMessage([]))
        with pytest.raises(LLMError, match="no text content block"):
            AnthropicLLMClient(api_key="k").analyze("p")

    def test_a_refusal_is_an_error(self, sdk: SdkProbe) -> None:
        sdk.replies.append(FakeMessage([Block("text", "no")], stop_reason="refusal"))
        with pytest.raises(LLMError, match="refused"):
            AnthropicLLMClient(api_key="k").analyze("p")

    def test_truncation_warns_and_still_returns_the_text(
        self, sdk: SdkProbe, caplog: pytest.LogCaptureFixture
    ) -> None:
        sdk.replies.append(
            FakeMessage([Block("text", '{"threats": [{"ti')], stop_reason="max_tokens")
        )
        with caplog.at_level(logging.WARNING):
            text = AnthropicLLMClient(api_key="k", max_tokens=100).analyze("p")
        assert text == '{"threats": [{"ti'
        assert any("cut off at max_tokens (100)" in r.message for r in caplog.records)

    def test_an_api_failure_is_wrapped(self, sdk: SdkProbe) -> None:
        sdk.replies.append(RuntimeError("connection reset"))
        with pytest.raises(LLMError, match="Anthropic API call failed: connection reset"):
            AnthropicLLMClient(api_key="k").analyze("p")

    def test_an_oversized_prompt_is_refused_not_cut(self, sdk: SdkProbe) -> None:
        client = AnthropicLLMClient(api_key="k")
        with pytest.raises(LLMError, match="too large"):
            client.analyze("x" * (MAX_PROMPT_LENGTH + 1))
        assert sdk.messages.calls == []


class TestAnthropicTemperature:
    def test_no_temperature_is_sent_by_default(self, sdk: SdkProbe) -> None:
        AnthropicLLMClient(api_key="k").analyze("p")
        call = sdk.messages.calls[0]
        assert "temperature" not in call
        assert "extra_body" not in call

    def test_a_configured_temperature_is_sent(self, sdk: SdkProbe) -> None:
        AnthropicLLMClient(api_key="k", temperature=0.3).analyze("p")
        assert sdk.messages.calls[0]["temperature"] == 0.3

    def test_an_sdk_without_the_parameter_gets_it_in_the_body(self, sdk: SdkProbe) -> None:
        sdk.accepts_temperature = False
        AnthropicLLMClient(api_key="k", temperature=0.3).analyze("p")
        assert sdk.messages.calls[0]["extra_body"] == {"temperature": 0.3}

    def test_an_sdk_without_the_parameter_gets_nothing_by_default(self, sdk: SdkProbe) -> None:
        sdk.accepts_temperature = False
        AnthropicLLMClient(api_key="k").analyze("p")
        assert sdk.messages.calls[0]["extra_body"] is None

    def test_a_rejected_temperature_is_retried_once_without_it(
        self, sdk: SdkProbe, caplog: pytest.LogCaptureFixture
    ) -> None:
        sdk.replies.extend(
            [
                FakeBadRequestError("temperature is not supported for this model"),
                FakeMessage([Block("text", "OK")]),
            ]
        )
        with caplog.at_level(logging.WARNING):
            text = AnthropicLLMClient(api_key="k", temperature=0.2).analyze("p")
        assert text == "OK"
        assert len(sdk.messages.calls) == 2
        assert "temperature" in sdk.messages.calls[0]
        assert "temperature" not in sdk.messages.calls[1]
        assert any("rejected the temperature" in r.message for r in caplog.records)

    def test_another_bad_request_is_not_retried(self, sdk: SdkProbe) -> None:
        sdk.replies.append(FakeBadRequestError("max_tokens must be positive"))
        with pytest.raises(LLMError, match="max_tokens must be positive"):
            AnthropicLLMClient(api_key="k", temperature=0.2).analyze("p")
        assert len(sdk.messages.calls) == 1

    def test_the_retry_happens_once_only(self, sdk: SdkProbe) -> None:
        sdk.replies.extend(
            [FakeBadRequestError("temperature"), FakeBadRequestError("temperature again")]
        )
        with pytest.raises(LLMError, match="temperature again"):
            AnthropicLLMClient(api_key="k", temperature=0.2).analyze("p")
        assert len(sdk.messages.calls) == 2


class TestAnthropicModelAndConfiguration:
    def test_the_default_model_is_current(self) -> None:
        import inspect

        default = inspect.signature(AnthropicLLMClient).parameters["model"].default
        assert default == DEFAULT_LLM_MODEL == "claude-sonnet-5-5"
        assert LLMConfig().model == DEFAULT_LLM_MODEL
        assert default not in DEPRECATED_MODELS

    def test_the_installed_sdk_knows_the_default_model(self) -> None:
        import typing

        types = pytest.importorskip("anthropic.types")
        model_param = getattr(types, "ModelParam", None)
        if model_param is None:
            pytest.skip("this SDK version does not export its model ids")

        def literals(tp: Any) -> list[str]:
            found: list[str] = []
            for arg in typing.get_args(tp):
                found.extend([arg] if isinstance(arg, str) else literals(arg))
            return found

        known = literals(model_param)
        if not known:
            pytest.skip("this SDK version does not list model ids")
        assert DEFAULT_LLM_MODEL in known

    def test_a_deprecated_model_warns(
        self, sdk: SdkProbe, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            AnthropicLLMClient(api_key="k", model="claude-sonnet-4-20250514")
        assert any("deprecated" in r.message for r in caplog.records)

    def test_provider_and_model_are_exposed(self, sdk: SdkProbe) -> None:
        client = AnthropicLLMClient(api_key="k", model="claude-test")
        assert (client.provider, client.model) == ("anthropic", "claude-test")

    def test_timeout_and_retries_reach_the_sdk(self, sdk: SdkProbe) -> None:
        AnthropicLLMClient(api_key="k", timeout=33, max_retries=4)
        built = sdk.constructed[0]
        assert built["timeout"] == 33.0
        assert built["max_retries"] == 4
        assert built["base_url"] is None

    def test_a_local_base_url_from_the_environment_is_refused(
        self, sdk: SdkProbe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:8765")
        with pytest.raises(LLMError, match="http"):
            AnthropicLLMClient(api_key="k")
        assert sdk.constructed == []

    def test_a_metadata_address_in_the_environment_is_refused(
        self, sdk: SdkProbe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://169.254.169.254")
        with pytest.raises(LLMError, match="link-local"):
            AnthropicLLMClient(api_key="k")

    def test_a_public_https_url_is_accepted_and_passed_on(
        self, sdk: SdkProbe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://gateway.example.com")
        with patch(_PATCH_GAI, return_value=_mock_resolve("93.184.216.34")):
            AnthropicLLMClient(api_key="k")
        assert sdk.constructed[0]["base_url"] == "https://gateway.example.com"

    def test_the_config_url_wins_over_the_environment(
        self, sdk: SdkProbe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", "http://127.0.0.1:1")
        with patch(_PATCH_GAI, return_value=_mock_resolve("93.184.216.34")):
            AnthropicLLMClient(api_key="k", base_url="https://proxy.example.com")
        assert sdk.constructed[0]["base_url"] == "https://proxy.example.com"

    def test_the_local_network_opt_in_accepts_a_private_gateway(self, sdk: SdkProbe) -> None:
        AnthropicLLMClient(api_key="k", base_url="http://10.1.2.3:8080", allow_local_network=True)
        assert sdk.constructed[0]["base_url"] == "http://10.1.2.3:8080"

    def test_the_opt_in_still_blocks_link_local(self, sdk: SdkProbe) -> None:
        with pytest.raises(LLMError, match="link-local"):
            AnthropicLLMClient(
                api_key="k", base_url="http://169.254.169.254", allow_local_network=True
            )

    def test_a_missing_sdk_names_the_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "anthropic":
                raise ImportError("No module named 'anthropic'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(LLMError, match=r"pip install 'threatcode\[llm\]'"):
            AnthropicLLMClient(api_key="k")


class TestFactoryKeyResolution:
    def _config(self, **llm: Any) -> ThreatCodeConfig:
        return ThreatCodeConfig(llm=LLMConfig(**llm))

    def test_anthropic_reads_its_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env")
        assert resolve_api_key(LLMConfig()) == "sk-ant-env"

    def test_openai_reads_openai_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env")
        assert resolve_api_key(LLMConfig(provider="openai")) == "sk-openai-env"

    def test_a_config_key_wins_over_the_environment(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env")
        assert resolve_api_key(LLMConfig(provider="openai", api_key="from-config")) == "from-config"

    def test_api_key_env_names_another_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("MY_GATEWAY_KEY", "gw-key")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env")
        llm = LLMConfig(provider="openai", api_key_env="MY_GATEWAY_KEY")
        assert resolve_api_key(llm) == "gw-key"

    @pytest.mark.parametrize("provider", ["ollama", "local"])
    def test_local_servers_read_no_variable_by_default(
        self, provider: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-openai-env")
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env")
        assert resolve_api_key(LLMConfig.model_validate({"provider": provider})) == ""

    def test_a_missing_key_is_a_warning_and_no_client(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        with caplog.at_level(logging.WARNING):
            assert build_client(ResolvedSettings(llm_enabled=True)) is None
        assert any("ANTHROPIC_API_KEY" in r.message for r in caplog.records)

    def test_the_factory_passes_every_setting_to_the_openai_client(
        self, monkeypatch: pytest.MonkeyPatch, fake_llm_server: FakeLLMServer
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "sk-env-key")
        config = self._config(
            provider="local",
            base_url=fake_llm_server.base_url,
            allow_local_network=True,
            model="m",
            api_key_env="OPENAI_API_KEY",
            temperature=0.4,
            timeout=7,
            max_retries=2,
        )
        client = build_client(ResolvedSettings(llm_enabled=True, config=config))
        assert isinstance(client, OpenAICompatibleLLMClient)
        assert client._api_key == "sk-env-key"
        assert client._temperature == 0.4
        assert client._timeout == 7
        assert client._attempts == 3

    def test_the_factory_passes_every_setting_to_the_anthropic_client(
        self, sdk: SdkProbe, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env")
        config = self._config(temperature=0.5, timeout=9, max_retries=3, max_tokens=2048)
        client = build_client(ResolvedSettings(llm_enabled=True, config=config))
        assert isinstance(client, AnthropicLLMClient)
        assert client._temperature == 0.5
        assert sdk.constructed[0]["timeout"] == 9.0
        assert sdk.constructed[0]["max_retries"] == 3
        assert sdk.constructed[0]["api_key"] == "sk-ant-env"


# ----------------------------------------------------------------------------------------------
# OpenAI-compatible
# ----------------------------------------------------------------------------------------------


@dataclass
class Seen:
    path: str
    headers: dict[str, str]
    body: dict[str, Any]


@dataclass
class ScriptedServer:
    base_url: str
    seen: list[Seen] = field(default_factory=list)


Responder = Callable[[int, Seen], tuple[int, dict[str, str], bytes]]


def _ok(content: str, finish_reason: str = "stop") -> tuple[int, dict[str, str], bytes]:
    body = json.dumps(
        {"choices": [{"message": {"content": content}, "finish_reason": finish_reason}]}
    ).encode()
    return 200, {"Content-Type": "application/json"}, body


@pytest.fixture
def scripted() -> Iterator[Callable[[Responder], ScriptedServer]]:
    servers: list[ThreadingHTTPServer] = []

    def start(responder: Responder) -> ScriptedServer:
        state = ScriptedServer(base_url="")

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server naming
                length = int(self.headers.get("Content-Length", 0))
                raw = self.rfile.read(length)
                seen = Seen(
                    self.path,
                    {k.lower(): v for k, v in self.headers.items()},
                    json.loads(raw) if raw else {},
                )
                state.seen.append(seen)
                status, headers, body = responder(len(state.seen), seen)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: Any) -> None:
                pass

        class QuietServer(ThreadingHTTPServer):
            def handle_error(self, request: Any, client_address: Any) -> None:
                pass  # a client that gave up is not a test failure

        server = QuietServer(("127.0.0.1", 0), Handler)
        state.base_url = f"http://127.0.0.1:{server.server_address[1]}"
        threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()
        servers.append(server)
        return state

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def delays(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record the backoff sleeps instead of waiting for them."""
    recorded: list[float] = []
    monkeypatch.setattr(client_module, "_sleep", recorded.append)
    return recorded


def _client(base_url: str, **kwargs: Any) -> OpenAICompatibleLLMClient:
    return OpenAICompatibleLLMClient(base_url=base_url, allow_local_network=True, **kwargs)


class TestOpenAIAuthentication:
    def test_the_key_is_sent_as_a_bearer_token(self, scripted: Any) -> None:
        server = scripted(lambda n, seen: _ok("x"))
        _client(server.base_url, api_key="sk-test").analyze("p")
        assert server.seen[0].headers["authorization"] == "Bearer sk-test"

    @pytest.mark.parametrize("key", ["", "not-needed"])
    def test_no_authorization_header_without_a_key(self, scripted: Any, key: str) -> None:
        server = scripted(lambda n, seen: _ok("x"))
        _client(server.base_url, api_key=key).analyze("p")
        assert "authorization" not in server.seen[0].headers


class TestOpenAIRequestBody:
    def test_no_temperature_by_default_and_max_tokens_for_other_servers(
        self, scripted: Any
    ) -> None:
        server = scripted(lambda n, seen: _ok("x"))
        _client(server.base_url, max_tokens=512).analyze("p")
        body = server.seen[0].body
        assert "temperature" not in body
        assert body["max_tokens"] == 512
        assert "max_completion_tokens" not in body

    def test_a_configured_temperature_is_sent(self, scripted: Any) -> None:
        server = scripted(lambda n, seen: _ok("x"))
        _client(server.base_url, temperature=0.4).analyze("p")
        assert server.seen[0].body["temperature"] == 0.4

    def test_openai_itself_gets_max_completion_tokens(self) -> None:
        with patch(_PATCH_GAI, return_value=_mock_resolve("104.18.6.192")):
            client = OpenAICompatibleLLMClient(base_url="https://api.openai.com/v1", api_key="k")
        assert client._token_parameter == "max_completion_tokens"

    def test_the_prompt_is_refused_not_cut(self, scripted: Any) -> None:
        server = scripted(lambda n, seen: _ok("x"))
        with pytest.raises(LLMError, match="too large"):
            _client(server.base_url).analyze("x" * (MAX_PROMPT_LENGTH + 1))
        assert server.seen == []

    def test_provider_and_model_are_exposed(self, scripted: Any) -> None:
        server = scripted(lambda n, seen: _ok("x"))
        client = _client(server.base_url, model="llama3.2")
        assert (client.provider, client.model) == ("openai", "llama3.2")


class TestOpenAIFailures:
    def test_a_timeout_is_an_llm_error(
        self, scripted: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = scripted(lambda n, seen: _ok("x"))

        def time_out(*args: Any, **kwargs: Any) -> None:
            raise TimeoutError("timed out")

        monkeypatch.setattr(urllib.request.OpenerDirector, "open", time_out)
        with pytest.raises(LLMError, match="timed out"):
            _client(server.base_url).analyze("p")

    def test_a_socket_error_is_an_llm_error(
        self, scripted: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server = scripted(lambda n, seen: _ok("x"))

        def reset(*args: Any, **kwargs: Any) -> None:
            raise ConnectionResetError("reset by peer")

        monkeypatch.setattr(urllib.request.OpenerDirector, "open", reset)
        with pytest.raises(LLMError, match="reset by peer"):
            _client(server.base_url).analyze("p")

    def test_a_slow_server_hits_the_timeout(self, scripted: Any) -> None:
        import time

        def slow(n: int, seen: Seen) -> tuple[int, dict[str, str], bytes]:
            time.sleep(1.5)
            return _ok("x")

        server = scripted(slow)
        with pytest.raises(LLMError, match="API call failed"):
            _client(server.base_url, timeout=1).analyze("p")

    def test_429_then_200_succeeds_after_one_retry(
        self, scripted: Any, delays: list[float]
    ) -> None:
        def respond(n: int, seen: Seen) -> tuple[int, dict[str, str], bytes]:
            return (429, {}, b"{}") if n == 1 else _ok("RECOVERED")

        server = scripted(respond)
        assert _client(server.base_url).analyze("p") == "RECOVERED"
        assert len(server.seen) == 2
        assert len(delays) == 1
        assert 1.0 <= delays[0] <= 1.5  # first backoff step plus jitter

    def test_retry_after_is_honored_within_a_cap(self, scripted: Any, delays: list[float]) -> None:
        def respond(n: int, seen: Seen) -> tuple[int, dict[str, str], bytes]:
            return (429, {"Retry-After": "7"}, b"{}") if n == 1 else _ok("ok")

        server = scripted(respond)
        _client(server.base_url).analyze("p")
        assert delays == [7.0]

    def test_a_huge_retry_after_is_capped(self, scripted: Any, delays: list[float]) -> None:
        def respond(n: int, seen: Seen) -> tuple[int, dict[str, str], bytes]:
            return (503, {"Retry-After": "86400"}, b"{}") if n == 1 else _ok("ok")

        server = scripted(respond)
        _client(server.base_url).analyze("p")
        assert delays == [30.0]

    def test_attempts_are_bounded_at_three_with_growing_backoff(
        self, scripted: Any, delays: list[float]
    ) -> None:
        server = scripted(lambda n, seen: (503, {}, b"{}"))
        with pytest.raises(LLMError, match="HTTP 503"):
            _client(server.base_url, max_retries=5).analyze("p")
        assert len(server.seen) == 3
        assert len(delays) == 2
        assert delays[1] > delays[0]

    def test_max_retries_zero_means_one_attempt(self, scripted: Any, delays: list[float]) -> None:
        server = scripted(lambda n, seen: (503, {}, b"{}"))
        with pytest.raises(LLMError, match="HTTP 503"):
            _client(server.base_url, max_retries=0).analyze("p")
        assert len(server.seen) == 1
        assert delays == []

    @pytest.mark.parametrize("status", [400, 401, 403, 404, 422])
    def test_other_client_errors_are_not_retried(
        self, scripted: Any, delays: list[float], status: int
    ) -> None:
        server = scripted(lambda n, seen: (status, {}, b"{}"))
        with pytest.raises(LLMError, match=f"HTTP {status}"):
            _client(server.base_url).analyze("p")
        assert len(server.seen) == 1
        assert delays == []

    def test_a_success_is_never_resent(self, scripted: Any, delays: list[float]) -> None:
        server = scripted(lambda n, seen: _ok("once"))
        _client(server.base_url).analyze("p")
        assert len(server.seen) == 1

    def test_finish_reason_length_warns_and_returns_the_text(
        self, scripted: Any, caplog: pytest.LogCaptureFixture
    ) -> None:
        server = scripted(lambda n, seen: _ok('{"threats": [{"ti', finish_reason="length"))
        with caplog.at_level(logging.WARNING):
            text = _client(server.base_url, max_tokens=64).analyze("p")
        assert text == '{"threats": [{"ti'
        assert any("cut off at max tokens (64)" in r.message for r in caplog.records)

    def test_a_reply_without_text_is_an_error(self, scripted: Any) -> None:
        body = json.dumps({"choices": [{"message": {"content": None}}]}).encode()
        server = scripted(lambda n, seen: (200, {}, body))
        with pytest.raises(LLMError, match="no text content"):
            _client(server.base_url).analyze("p")


class TestOpenAIRedirects:
    """SEC-05: the API key and the redacted request never follow a redirect to another origin."""

    def _pair(self, scripted: Any, status: int) -> tuple[ScriptedServer, ScriptedServer]:
        target = scripted(lambda n, seen: _ok("FROM-TARGET"))
        origin = scripted(lambda n, seen: (status, {"Location": target.base_url + seen.path}, b""))
        return origin, target

    @pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
    def test_a_cross_origin_redirect_never_reaches_the_other_server(
        self, scripted: Any, status: int
    ) -> None:
        origin, target = self._pair(scripted, status)
        with pytest.raises(LLMError, match=f"HTTP {status}"):
            _client(origin.base_url, api_key="sk-must-not-leak").analyze("SECRET-PROMPT")
        assert len(origin.seen) == 1
        assert target.seen == []

    def test_a_same_origin_redirect_still_works(self, scripted: Any) -> None:
        def respond(n: int, seen: Seen) -> tuple[int, dict[str, str], bytes]:
            if seen.path == "/v1/chat/completions":
                return 308, {"Location": "/v1/chat/completions/"}, b""
            return _ok("FOLLOWED")

        server = scripted(respond)
        client = _client(server.base_url, api_key="sk-same-origin")
        assert client.analyze("p") == "FOLLOWED"
        assert [s.path for s in server.seen] == ["/v1/chat/completions", "/v1/chat/completions/"]
        assert server.seen[1].headers["authorization"] == "Bearer sk-same-origin"
        assert server.seen[1].body["messages"][1]["content"] == "p"

    def test_a_redirect_is_not_retried(self, scripted: Any, delays: list[float]) -> None:
        origin, target = self._pair(scripted, 307)
        with pytest.raises(LLMError):
            _client(origin.base_url).analyze("p")
        assert delays == []
