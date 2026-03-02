"""Security regression tests for v0.4.0 OWASP hardening.

Each test validates a specific finding fix from OWASP_AUDIT_REPORT.md.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# 1. SSRF Protection (client.py) — A10-01..04, A07-01
# ---------------------------------------------------------------------------


class TestSSRFProtection:
    """Validate _validate_base_url blocks unsafe URLs."""

    def test_blocks_localhost(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("http://localhost:8080")

    def test_blocks_127_0_0_1(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="loopback"):
            _validate_base_url("http://127.0.0.1:8080")

    def test_blocks_private_10_range(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="private"):
            _validate_base_url("http://10.0.0.1:8080")

    def test_blocks_private_192_168(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="private"):
            _validate_base_url("http://192.168.1.1:8080")

    def test_blocks_link_local_169_254(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        # 169.254.x.x may be classified as link-local or private depending on platform
        with pytest.raises(LLMError, match="link-local|private"):
            _validate_base_url("http://169.254.169.254/latest/meta-data/")

    def test_blocks_non_http_scheme(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="Unsafe URL scheme"):
            _validate_base_url("file:///etc/passwd")

    def test_blocks_empty_hostname(self) -> None:
        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with pytest.raises(LLMError, match="hostname"):
            _validate_base_url("http://")

    def test_http_key_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """A07-01: Warn when API key sent over plain HTTP."""
        import logging

        from threatcode.engine.llm.client import _validate_base_url
        from threatcode.exceptions import LLMError

        with caplog.at_level(logging.WARNING):
            # This will fail on DNS resolution (good — we just want the warning check)
            with pytest.raises(LLMError):
                _validate_base_url("http://nonexistent-host-for-test.invalid")
        assert any("plain HTTP" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 2. Config Auto-Discovery Hardening (config.py) — A01-01, A02-01, A07-02
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 3. Prompt Injection Hardening (prompts.py) — LLM01-01, LLM01-02, LLM07-01
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 4. Redactor Improvements (redactor.py) — LLM02-01, LLM10-07
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# 5. LLM Output Validation (parser.py) — LLM05-03, LLM09-01
# ---------------------------------------------------------------------------


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
        import logging

        from threatcode.engine.llm.parser import MAX_RESPONSE_LENGTH, parse_llm_threats

        long_response = '{"threats": []}' + " " * (MAX_RESPONSE_LENGTH + 100)
        with caplog.at_level(logging.WARNING):
            parse_llm_threats(long_response)
        assert any("truncated" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 6. Rule Loader Hardening (loader.py) — A01-03, A04-03, A08-01, LLM04-03
# ---------------------------------------------------------------------------


class TestRuleLoaderHardening:
    def test_symlink_blocked(self, tmp_path: Path) -> None:
        """A04-03: Symlinks in extra rule paths are blocked."""
        from threatcode.engine.rules.loader import load_all_rules
        from threatcode.exceptions import RuleLoadError

        real_file = tmp_path / "real.yml"
        real_file.write_text("rules:\n  - id: TEST\n    title: Test\n")
        link = tmp_path / "link.yml"
        try:
            link.symlink_to(real_file)
        except OSError:
            pytest.skip("Symlinks not supported on this platform")

        with pytest.raises(RuleLoadError, match="symlink"):
            load_all_rules([link])

    def test_large_rule_file_rejected(self, tmp_path: Path) -> None:
        """A08-01: Rule files over 1 MB rejected."""
        from threatcode.engine.rules.loader import MAX_RULE_FILE_SIZE, load_rules_from_file
        from threatcode.exceptions import RuleLoadError

        large_file = tmp_path / "large.yml"
        large_file.write_text("x" * (MAX_RULE_FILE_SIZE + 1))
        with pytest.raises(RuleLoadError, match="byte limit"):
            load_rules_from_file(large_file)

    def test_builtin_rules_log_file_info(self, caplog: pytest.LogCaptureFixture) -> None:
        """A08-01: Built-in rule files log file info at DEBUG level."""
        import logging

        from threatcode.engine.rules.loader import load_builtin_rules

        with caplog.at_level(logging.DEBUG):
            load_builtin_rules()
        assert any("Loading built-in rules:" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 7. Graph Limits (graph.py) — LLM10-05, LLM10-06
# ---------------------------------------------------------------------------


class TestGraphLimits:
    def test_max_nodes_raises(self) -> None:
        """LLM10-05: MAX_NODES exceeded raises ThreatCodeError."""
        from threatcode.exceptions import ThreatCodeError
        from threatcode.ir.graph import MAX_NODES, InfraGraph
        from threatcode.parsers.base import ParsedOutput, ParsedResource

        resources = [
            ParsedResource(
                address=f"aws_instance.node_{i}",
                resource_type="aws_instance",
                name=f"node_{i}",
                properties={},
                provider="aws",
            )
            for i in range(MAX_NODES + 1)
        ]
        parsed = ParsedOutput(resources=resources)
        with pytest.raises(ThreatCodeError, match="node limit"):
            InfraGraph.from_parsed(parsed)

    def test_max_edges_warns_and_skips(self, caplog: pytest.LogCaptureFixture) -> None:
        """LLM10-06: MAX_EDGES exceeded warns and skips."""
        import logging

        from threatcode.ir.edges import EdgeType
        from threatcode.ir.graph import MAX_EDGES, InfraGraph

        graph = InfraGraph()
        # Add two nodes
        from threatcode.parsers.base import ParsedResource

        resources = [
            ParsedResource(
                address="aws_instance.a",
                resource_type="aws_instance",
                name="a",
                properties={},
                provider="aws",
            ),
            ParsedResource(
                address="aws_instance.b",
                resource_type="aws_instance",
                name="b",
                properties={},
                provider="aws",
            ),
        ]
        for r in resources:
            graph._add_resource(r)

        # Fill edges to the limit
        fake_attrs = {
            "source": "a",
            "target": "b",
            "edge_type": EdgeType.DEPENDENCY,
            "crosses_trust_boundary": False,
            "metadata": {},
        }
        fake_edge_cls = type("FakeEdge", (), fake_attrs)
        for i in range(MAX_EDGES):
            graph._edges.append(fake_edge_cls())  # type: ignore[arg-type]

        # Next edge should be skipped with warning
        with caplog.at_level(logging.WARNING):
            graph._add_edge("aws_instance.a", "aws_instance.b", EdgeType.DEPENDENCY)
        assert any("Edge limit" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 8. CLI Hardening (cli.py) — A01-04, A05-01
# ---------------------------------------------------------------------------


class TestCLIHardening:
    def test_output_dir_rejected(self, tmp_path: Path) -> None:
        """A01-04: Output path that is a directory is rejected."""
        from click.testing import CliRunner

        from threatcode.cli import scan

        runner = CliRunner()
        # Create a minimal input file
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "test" { bucket = "test" }')
        result = runner.invoke(
            scan,
            [str(tf_file), "-o", str(tmp_path), "--no-llm"],
        )
        assert result.exit_code != 0
        stderr = (result.stderr_bytes or b"").decode().lower()
        assert "directory" in result.output.lower() or "directory" in stderr


# ---------------------------------------------------------------------------
# 9. Formatter Sanitization — LLM05-01, LLM05-02
# ---------------------------------------------------------------------------


class TestFormatterSanitization:
    def test_markdown_escapes_special_chars(self) -> None:
        """LLM05-01: Markdown formatter escapes < > [ ] ( )."""
        from threatcode.formatters.markdown import _escape_md

        result = _escape_md("test <script>alert(1)</script> [link](http://evil.com)")
        assert "<script>" not in result
        assert "\\<script\\>" in result
        assert "\\[link\\]" in result

    def test_sarif_safe_uri(self) -> None:
        """LLM05-02: SARIF formatter strips non-URI chars."""
        from threatcode.formatters.sarif import _safe_uri

        result = _safe_uri('aws_s3_bucket.test"; DROP TABLE')
        assert '"' not in result
        assert ";" not in result
        assert " " not in result
        assert "aws_s3_bucket.test" in result

    def test_diff_markdown_escapes(self) -> None:
        """LLM05-01: Diff formatter escapes markdown in titles."""
        from threatcode.formatters.diff import _escape_md

        result = _escape_md("<img src=x onerror=alert(1)>")
        assert "\\<img" in result


# ---------------------------------------------------------------------------
# 10. DryRun no prompt logging — A02-02, A09-02
# ---------------------------------------------------------------------------


class TestDryRunSecurity:
    def test_dryrun_no_prompt_content_in_debug(
        self,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """A02-02: DryRun DEBUG logs must not contain prompt content."""
        import logging

        from threatcode.engine.llm.client import DryRunLLMClient

        client = DryRunLLMClient()
        secret_prompt = "SUPER_SECRET_INFRA_DATA_12345"
        with caplog.at_level(logging.DEBUG):
            client.analyze(secret_prompt)
        # Ensure no log record contains the actual prompt content
        for record in caplog.records:
            assert secret_prompt not in record.message


# ---------------------------------------------------------------------------
# 11. max_tokens validation — LLM10-04
# ---------------------------------------------------------------------------


class TestMaxTokensValidation:
    def test_max_tokens_clamped_high(self) -> None:
        """LLM10-04: max_tokens > 8192 is clamped."""
        from unittest.mock import MagicMock

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
