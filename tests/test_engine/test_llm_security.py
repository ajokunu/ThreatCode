"""Security regression tests for the LLM layer: SSRF guard, prompt hardening, redaction,
output validation, dry run and token limits.

Moved from tests/test_security.py; each test validates a specific OWASP audit finding fix.
"""

from __future__ import annotations

import json
import logging
from unittest.mock import MagicMock, patch

import pytest


class TestSSRFProtection:
    """Validate _validate_base_url blocks unsafe URLs."""

    def test_blocks_localhost(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("https://localhost:8080")

    def test_blocks_127_0_0_1(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("https://127.0.0.1:8080")

    def test_blocks_private_10_range(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="private"):
            _validate_base_url("https://10.0.0.1:8080")

    def test_blocks_private_192_168(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="private"):
            _validate_base_url("https://192.168.1.1:8080")

    def test_blocks_link_local_169_254(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="link-local"):
            _validate_base_url("https://169.254.169.254/latest/meta-data/")

    def test_local_network_opt_in_still_blocks_link_local(self) -> None:
        """The ollama/local opt-in must never open up cloud metadata endpoints."""
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="link-local"):
            _validate_base_url("http://169.254.169.254/latest/meta-data/", allow_local_network=True)

    def test_blocks_non_http_scheme(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="Unsafe URL scheme"):
            _validate_base_url("file:///etc/passwd")

    def test_blocks_empty_hostname(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="hostname"):
            _validate_base_url("https://")

    def test_http_key_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """A07-01: Warn when API key sent over plain HTTP."""

        from threatcode.engine.llm.client import OpenAICompatibleLLMClient

        with caplog.at_level(logging.WARNING):
            OpenAICompatibleLLMClient(
                base_url="http://127.0.0.1:11434",
                api_key="sk-secret",
                allow_local_network=True,
            )
        assert any("plain http" in r.message for r in caplog.records)


class TestPromptHardening:
    def test_sanitize_for_prompt_strips_control_chars(self) -> None:
        """LLM01-01: Control characters stripped."""
        from threatcode.engine.llm.prompts import _sanitize_for_prompt

        result = _sanitize_for_prompt("hello\x00world\x01test")
        assert "\x00" not in result
        assert "\x01" not in result
        assert "hello" in result

    def test_sanitize_for_prompt_truncates(self) -> None:
        from threatcode.engine.llm.prompts import _sanitize_for_prompt

        result = _sanitize_for_prompt("a" * 500, max_len=100)
        assert len(result) == 100

    def test_rule_ids_sanitized_in_prompt(self) -> None:
        """LLM01-02: Rule IDs sanitized before prompt inclusion."""
        from threatcode.engine.llm.prompts import build_analysis_prompt

        malicious_id = 'RULE_1"; DROP TABLE threats; --'
        prompt = build_analysis_prompt({"nodes": {}, "edges": []}, {malicious_id})
        # Semicolons, quotes, spaces should be stripped
        assert '";' not in prompt
        assert "DROP TABLE" not in prompt

    def test_graph_wrapped_in_xml_delimiters(self) -> None:
        """LLM07-01: Graph data wrapped in XML-style delimiters."""
        from threatcode.engine.llm.prompts import build_analysis_prompt

        prompt = build_analysis_prompt({"nodes": {}, "edges": []}, set())
        assert "<infrastructure_data>" in prompt
        assert "</infrastructure_data>" in prompt

    def test_system_prompt_no_redaction_hints(self) -> None:
        """LLM07-01: System prompt doesn't reveal specific redaction naming."""
        from threatcode.engine.llm.prompts import SYSTEM_PROMPT

        assert "REDACTED_" not in SYSTEM_PROMPT


class TestRedactorImprovements:
    def test_name_field_redacted(self) -> None:
        """LLM02-01: 'name' field is now in sensitive keys."""
        from threatcode.engine.llm.redactor import Redactor

        r = Redactor()
        result = r.redact({"name": "my-production-db"})
        assert "my-production-db" not in str(result)

    def test_module_field_redacted(self) -> None:
        from threatcode.engine.llm.redactor import Redactor

        r = Redactor()
        result = r.redact({"module": "modules/vpc"})
        assert "modules/vpc" not in str(result)

    def test_provider_field_redacted(self) -> None:
        from threatcode.engine.llm.redactor import Redactor

        r = Redactor()
        result = r.redact({"provider": "aws.us-east-1"})
        assert "aws.us-east-1" not in str(result)

    def test_mapping_cap_at_max(self) -> None:
        """LLM10-07: Mapping capped at MAX_REDACTION_MAPPINGS."""
        from threatcode.engine.llm.redactor import MAX_REDACTION_MAPPINGS, Redactor

        r = Redactor()
        # Fill up the mapping
        for i in range(MAX_REDACTION_MAPPINGS):
            r._get_placeholder(f"value_{i}", "test")
        assert len(r._mapping) == MAX_REDACTION_MAPPINGS

        # Next entry should get overflow placeholder
        overflow = r._get_placeholder("overflow_value", "test")
        assert "overflow" in overflow

    def test_aws_account_id_requires_context(self) -> None:
        """Improved regex requires context — plain 12-digit numbers not matched."""
        from threatcode.engine.llm.redactor import Redactor

        r = Redactor()
        # Plain 12-digit number should NOT be redacted
        result = r._redact_string("The value is 123456789012 here")
        assert "123456789012" in result

        # With account_id context, SHOULD be redacted
        result2 = r._redact_string("account_id: 123456789012")
        assert "123456789012" not in result2


class TestLLMOutputValidation:
    def test_unknown_mitre_technique_dropped(self) -> None:
        """LLM05-03: Unknown MITRE technique IDs dropped."""
        from threatcode.engine.llm.parser import parse_llm_threats

        response = json.dumps(
            {
                "threats": [
                    {
                        "title": "Test threat",
                        "severity": "high",
                        "stride_category": "tampering",
                        "mitre_techniques": ["T1530", "T9999"],  # T9999 is fake
                        "mitre_tactics": ["TA0009", "TA9999"],  # TA9999 is fake
                    }
                ]
            }
        )
        threats = parse_llm_threats(response)
        assert len(threats) == 1
        assert "T1530" in threats[0]["mitre_techniques"]
        assert "T9999" not in threats[0]["mitre_techniques"]
        assert "TA0009" in threats[0]["mitre_tactics"]
        assert "TA9999" not in threats[0]["mitre_tactics"]

    def test_truncation_warning_logged(self, caplog: pytest.LogCaptureFixture) -> None:
        """LLM09-02: Log warning when response truncated."""

        from threatcode.engine.llm.parser import MAX_RESPONSE_LENGTH, parse_llm_threats

        long_response = '{"threats": []}' + " " * (MAX_RESPONSE_LENGTH + 100)
        with caplog.at_level(logging.WARNING):
            parse_llm_threats(long_response)
        assert any("truncated" in r.message for r in caplog.records)


class TestDryRunSecurity:
    def test_dryrun_no_prompt_content_in_debug(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A02-02: DryRun DEBUG logs must not contain prompt content."""

        from threatcode.engine.llm.client import DryRunLLMClient

        client = DryRunLLMClient()
        secret_prompt = "SUPER_SECRET_INFRA_DATA_12345"
        with caplog.at_level(logging.DEBUG):
            client.analyze(secret_prompt)
        # Ensure no log record contains the actual prompt content
        for record in caplog.records:
            assert secret_prompt not in record.message


class TestMaxTokensValidation:
    def test_max_tokens_clamped_high(self) -> None:
        """LLM10-04: max_tokens > 8192 is clamped."""

        with patch("threatcode.engine.llm.client.anthropic", create=True) as mock_mod:
            mock_mod.Anthropic.return_value = MagicMock()
            from threatcode.engine.llm.client import AnthropicLLMClient

            client = AnthropicLLMClient(api_key="test", max_tokens=99999)
            assert client._max_tokens == 8192

    def test_max_tokens_clamped_low(self) -> None:
        """LLM10-04: max_tokens < 1 is clamped."""
        with patch("threatcode.engine.llm.client.anthropic", create=True) as mock_mod:
            from unittest.mock import MagicMock

            mock_mod.Anthropic.return_value = MagicMock()
            from threatcode.engine.llm.client import AnthropicLLMClient

            client = AnthropicLLMClient(api_key="test", max_tokens=0)
            assert client._max_tokens == 1
