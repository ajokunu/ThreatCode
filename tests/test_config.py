"""Tests for threatcode.config: the model, the loader and the settings resolver."""

from __future__ import annotations

import logging
import re
from pathlib import Path

import pytest

from threatcode.config import (
    DEFAULT_FAIL_ON,
    DEFAULT_MIN_SEVERITY,
    LoadedConfig,
    ResolvedSettings,
    ThreatCodeConfig,
    discover_config,
    load_config,
    resolve_settings,
)
from threatcode.exceptions import ConfigError, UsageError


@pytest.fixture(autouse=True)
def hermetic_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No config in the home directory and no THREATCODE_* variables leak into a test."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CI", raising=False)
    for name in (
        "THREATCODE_FAIL_ON",
        "THREATCODE_MIN_SEVERITY",
        "THREATCODE_FORMAT",
        "THREATCODE_LLM",
    ):
        monkeypatch.delenv(name, raising=False)


def write_config(tmp_path: Path, text: str, name: str = ".threatcode.yml") -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestThreatCodeConfig:
    def test_defaults_leave_presence_detectable(self) -> None:
        cfg = ThreatCodeConfig()
        assert cfg.min_severity is None
        assert cfg.output_format is None
        assert cfg.fail_on is None
        assert cfg.extra_rule_paths == []
        assert cfg.llm.provider == "anthropic"
        assert cfg.strict_edges is True

    def test_the_llm_is_off_by_default(self) -> None:
        assert ThreatCodeConfig().llm.enabled is False

    def test_the_dead_keys_are_gone(self) -> None:
        assert "no_llm" not in ThreatCodeConfig.model_fields
        assert "dry_run" not in ThreatCodeConfig.model_fields

    def test_llm_defaults(self) -> None:
        cfg = ThreatCodeConfig()
        assert cfg.llm.max_tokens == 4096
        # No temperature is sent unless one is configured: current models reject it
        assert cfg.llm.temperature is None
        assert cfg.llm.model == "claude-sonnet-5-5"
        assert cfg.llm.timeout == 120
        assert cfg.llm.max_retries == 1
        assert cfg.llm.max_input_tokens == 60_000
        assert cfg.llm.api_key_env is None

    def test_redaction_defaults(self) -> None:
        assert ThreatCodeConfig().redaction.strategy == "placeholder"

    def test_cyclonedx_is_no_longer_an_output_format(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "output_format: cyclonedx\n")
        with pytest.raises(ConfigError, match="output_format: 'cyclonedx' is not an output format"):
            load_config(path)

    def test_every_registry_format_is_accepted(self) -> None:
        from threatcode.formatters import format_names

        for name in format_names():
            assert ThreatCodeConfig(output_format=name).output_format == name

    def test_graph_limits_must_be_positive(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="max_nodes"):
            load_config(write_config(tmp_path, "max_nodes: 0\n"))
        cfg = load_config(write_config(tmp_path, "max_nodes: 50\nmax_edges: 80\n", "c.yml"))
        assert (cfg.max_nodes, cfg.max_edges) == (50, 80)


class TestLoadConfig:
    def test_load_defaults_when_no_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert load_config(None) == ThreatCodeConfig()

    def test_load_from_explicit_path(self, tmp_path: Path) -> None:
        cfg = load_config(write_config(tmp_path, "min_severity: high\nfail_on: medium\n"))
        assert cfg.min_severity == "high"
        assert cfg.fail_on == "medium"

    def test_load_with_llm_section(self, tmp_path: Path) -> None:
        cfg = load_config(
            write_config(tmp_path, "llm:\n  enabled: true\n  provider: ollama\n  model: llama3\n")
        )
        assert cfg.llm.enabled is True
        assert cfg.llm.provider == "ollama"
        assert cfg.llm.model == "llama3"

    def test_invalid_value_raises_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError):
            load_config(write_config(tmp_path, "strict_edges: [invalid, structure]\n"))

    def test_nonexistent_explicit_path_raises_error(self) -> None:
        with pytest.raises(ConfigError, match="Config file not found"):
            load_config(Path("/nonexistent/.threatcode.yml"))

    def test_an_empty_file_is_an_empty_config(self, tmp_path: Path) -> None:
        assert load_config(write_config(tmp_path, "")) == ThreatCodeConfig()

    @pytest.mark.parametrize(
        ("content", "kind"),
        [("- a\n- b\n", "list"), ("just text\n", "string"), ("3\n", "int")],
    )
    def test_a_file_that_is_not_a_mapping_is_a_config_error(
        self, tmp_path: Path, content: str, kind: str
    ) -> None:
        with pytest.raises(ConfigError, match=f"must be a mapping of settings, not a {kind}"):
            load_config(write_config(tmp_path, content))

    def test_a_file_that_is_not_yaml_is_a_config_error(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="Failed to load config"):
            load_config(write_config(tmp_path, "a: [unclosed\n"))

    def test_the_same_list_file_is_also_rejected_when_auto_discovered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        write_config(tmp_path, "- a\n")
        with pytest.raises(ConfigError, match="must be a mapping"):
            load_config(None)

    def test_yaml_with_extra_rule_paths(self, tmp_path: Path) -> None:
        cfg = load_config(write_config(tmp_path, "extra_rule_paths:\n  - rules/custom.yml\n"))
        assert cfg.extra_rule_paths == ["rules/custom.yml"]

    def test_validation_error_message_has_no_pydantic_boilerplate(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as exc_info:
            load_config(write_config(tmp_path, "min_severity: extreme\n"))
        message = str(exc_info.value)
        assert "min_severity:" in message
        assert "errors.pydantic.dev" not in message


class TestUnknownKeys:
    def test_a_typo_names_the_key_and_suggests_the_right_one(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as exc_info:
            load_config(write_config(tmp_path, "min_severty: high\n"))
        message = str(exc_info.value)
        assert "min_severty: unknown key (did you mean 'min_severity'?)" in message

    @pytest.mark.parametrize(
        ("key", "hint"),
        [("no_llm", "llm.enabled"), ("dry_run", "--dry-run")],
    )
    def test_removed_keys_say_what_replaces_them(self, tmp_path: Path, key: str, hint: str) -> None:
        with pytest.raises(ConfigError, match=rf"{key}: unknown key \(removed: .*{hint}"):
            load_config(write_config(tmp_path, f"{key}: true\n"))

    def test_nested_sections_forbid_unknown_keys_too(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match=r"llm\.temprature: unknown key"):
            load_config(write_config(tmp_path, "llm:\n  temprature: 0.5\n"))
        with pytest.raises(ConfigError, match=r"redaction\.field: unknown key"):
            load_config(write_config(tmp_path, "redaction:\n  field: [a]\n"))

    def test_the_model_itself_forbids_extra_fields(self) -> None:
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            ThreatCodeConfig(bogus=1)  # type: ignore[call-arg]


class TestAutoDiscovery:
    def test_found_in_the_working_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        write_config(tmp_path, "min_severity: high\n")
        loaded = discover_config(None)
        assert loaded.config.min_severity == "high"
        assert loaded.path == tmp_path / ".threatcode.yml"
        assert loaded.auto_discovered and not loaded.trusted
        assert loaded.used == ("min_severity",)

    def test_search_directories_come_before_the_working_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "root"
        cwd = tmp_path / "cwd"
        root.mkdir()
        cwd.mkdir()
        write_config(root, "min_severity: low\n")
        write_config(cwd, "min_severity: high\n")
        monkeypatch.chdir(cwd)
        assert discover_config(None, [root, cwd]).config.min_severity == "low"
        assert discover_config(None, [cwd, root]).config.min_severity == "high"

    def test_the_yaml_extension_is_found_too(self, tmp_path: Path) -> None:
        write_config(tmp_path, "min_severity: low\n", ".threatcode.yaml")
        assert discover_config(None, [tmp_path]).config.min_severity == "low"

    def test_the_home_directory_is_searched_outside_ci(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        write_config(tmp_path / "home", "min_severity: medium\n")
        assert discover_config(None, [empty]).config.min_severity == "medium"
        monkeypatch.setenv("CI", "true")
        assert discover_config(None, [empty]).config.min_severity is None

    def test_restricted_fields_are_dropped_and_reported(self, tmp_path: Path) -> None:
        write_config(
            tmp_path,
            "llm:\n  enabled: true\n  base_url: http://evil.com\n"
            "fail_on: none\nextra_rule_paths: [evil.yml]\nmin_severity: high\n",
        )
        loaded = discover_config(None, [tmp_path])
        cfg = loaded.config
        assert cfg.llm.base_url == "" and cfg.llm.enabled is False
        assert cfg.fail_on is None
        assert cfg.extra_rule_paths == []
        assert cfg.min_severity == "high"
        assert loaded.ignored == ("extra_rule_paths", "fail_on", "llm")
        assert loaded.used == ("min_severity",)
        (notice,) = loaded.notices
        assert "restricted fields" in notice
        assert "fail_on is honored only from --config" in notice

    def test_unknown_keys_in_a_discovered_file_only_warn(self, tmp_path: Path) -> None:
        write_config(tmp_path, "min_severity: high\nmystery: 1\nno_llm: true\n")
        loaded = discover_config(None, [tmp_path])
        assert loaded.config.min_severity == "high"
        assert loaded.ignored == ("mystery", "no_llm")

    def test_an_invalid_safe_field_is_still_an_error(self, tmp_path: Path) -> None:
        write_config(tmp_path, "min_severity: extreme\n")
        with pytest.raises(ConfigError, match="min_severity"):
            discover_config(None, [tmp_path])

    def test_an_explicit_config_is_trusted_and_keeps_every_field(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "fail_on: none\nllm:\n  base_url: http://my-ollama:11434\n")
        loaded = discover_config(path)
        assert loaded.trusted and not loaded.auto_discovered
        assert loaded.ignored == ()
        assert loaded.config.fail_on == "none"
        assert loaded.config.llm.base_url == "http://my-ollama:11434"

    def test_load_config_logs_the_notices(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture
    ) -> None:
        write_config(tmp_path, "fail_on: none\n")
        with caplog.at_level(logging.WARNING, logger="threatcode.config"):
            load_config(None, [tmp_path])
        assert "restricted fields" in caplog.text


class TestLlmConfigValidation:
    @pytest.mark.parametrize("provider", ["ollama", "local"])
    def test_allow_local_network_for_local_providers(self, tmp_path: Path, provider: str) -> None:
        cfg = load_config(
            write_config(
                tmp_path,
                f"llm:\n  provider: {provider}\n  base_url: http://localhost:11434\n"
                "  allow_local_network: true\n",
            )
        )
        assert cfg.llm.allow_local_network is True

    def test_allow_local_network_rejected_for_hosted_openai(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "llm:\n  provider: openai\n  allow_local_network: true\n")
        expected = (
            "llm: allow_local_network requires provider 'ollama' or 'local' "
            "(or 'anthropic' behind a gateway), not 'openai'"
        )
        with pytest.raises(ConfigError, match=re.escape(expected)):
            load_config(path)

    def test_the_error_names_every_provider_the_option_allows(self, tmp_path: Path) -> None:
        from threatcode.config import _LOCAL_NETWORK_PROVIDERS

        path = write_config(tmp_path, "llm:\n  provider: openai\n  allow_local_network: true\n")
        with pytest.raises(ConfigError) as caught:
            load_config(path)
        for provider in _LOCAL_NETWORK_PROVIDERS:
            assert f"'{provider}'" in str(caught.value)
        assert _LOCAL_NETWORK_PROVIDERS == {"ollama", "local", "anthropic"}

    def test_allow_local_network_is_accepted_for_anthropic_behind_a_gateway(
        self, tmp_path: Path
    ) -> None:
        path = write_config(
            tmp_path,
            "llm:\n  provider: anthropic\n  base_url: http://10.0.0.5:8080\n"
            "  allow_local_network: true\n",
        )
        assert load_config(path).llm.allow_local_network is True

    def test_allow_local_network_defaults_off(self) -> None:
        assert ThreatCodeConfig().llm.allow_local_network is False


class TestResolveSettings:
    """CLI flag, then environment, then config file, then default."""

    @pytest.mark.parametrize(
        ("cli", "env", "config", "expected", "source"),
        [
            (None, None, None, DEFAULT_FAIL_ON, "default"),
            (None, None, "medium", "medium", "config"),
            (None, "low", "medium", "low", "env THREATCODE_FAIL_ON"),
            ("critical", "low", "medium", "critical", "cli"),
            ("none", None, "critical", "none", "cli"),
            (None, "NONE", None, "none", "env THREATCODE_FAIL_ON"),
        ],
    )
    def test_fail_on_precedence(
        self,
        cli: str | None,
        env: str | None,
        config: str | None,
        expected: str,
        source: str,
    ) -> None:
        cfg = ThreatCodeConfig(fail_on=config)  # type: ignore[arg-type]
        environment = {"THREATCODE_FAIL_ON": env} if env else {}
        settings = resolve_settings({"fail_on": cli}, cfg, environment)
        assert settings.fail_on == expected
        assert settings.sources["fail_on"] == source

    @pytest.mark.parametrize(
        ("cli", "env", "config", "expected"),
        [
            (None, None, None, DEFAULT_MIN_SEVERITY),
            (None, None, "high", "high"),
            (None, "critical", "high", "critical"),
            ("low", "critical", "high", "low"),
        ],
    )
    def test_min_severity_precedence(
        self, cli: str | None, env: str | None, config: str | None, expected: str
    ) -> None:
        cfg = ThreatCodeConfig(min_severity=config)  # type: ignore[arg-type]
        environment = {"THREATCODE_MIN_SEVERITY": env} if env else {}
        assert resolve_settings({"min_severity": cli}, cfg, environment).min_severity == expected

    @pytest.mark.parametrize(
        ("cli", "env", "config", "expected"),
        [
            (None, None, None, None),
            (None, None, "markdown", "markdown"),
            (None, "sarif", "markdown", "sarif"),
            ("text", "sarif", "markdown", "text"),
        ],
    )
    def test_output_format_precedence(
        self, cli: str | None, env: str | None, config: str | None, expected: str | None
    ) -> None:
        cfg = ThreatCodeConfig(output_format=config)
        environment = {"THREATCODE_FORMAT": env} if env else {}
        assert resolve_settings({"output_format": cli}, cfg, environment).output_format == expected

    @pytest.mark.parametrize(
        ("cli", "env", "config", "expected"),
        [
            (None, None, None, False),
            (None, None, True, True),
            (None, "1", None, True),
            (None, "0", True, False),
            (None, "no", True, False),
            (True, "0", None, True),
            (False, "1", True, False),
            (False, None, True, False),
        ],
    )
    def test_llm_precedence(
        self, cli: bool | None, env: str | None, config: bool | None, expected: bool
    ) -> None:
        cfg = ThreatCodeConfig()
        if config is not None:
            cfg = ThreatCodeConfig.model_validate({"llm": {"enabled": config}})
        environment = {"THREATCODE_LLM": env} if env is not None else {}
        settings = resolve_settings({"llm": cli}, cfg, environment)
        assert settings.llm_enabled is expected

    def test_dry_run_implies_the_llm_path(self) -> None:
        settings = resolve_settings({"dry_run": True}, ThreatCodeConfig(), {})
        assert settings.dry_run is True
        assert settings.llm_enabled is False
        assert settings.use_llm is True

    def test_dry_run_with_no_llm_is_contradictory(self) -> None:
        with pytest.raises(UsageError, match="--dry-run .* --no-llm"):
            resolve_settings({"dry_run": True, "llm": False}, ThreatCodeConfig(), {})

    def test_nothing_requested_means_no_llm_path(self) -> None:
        assert resolve_settings({}, ThreatCodeConfig(), {}).use_llm is False

    @pytest.mark.parametrize(
        ("name", "value", "message"),
        [
            ("THREATCODE_FAIL_ON", "sometimes", "THREATCODE_FAIL_ON must be one of"),
            ("THREATCODE_MIN_SEVERITY", "none", "THREATCODE_MIN_SEVERITY must be one of"),
            ("THREATCODE_FORMAT", "xml", "THREATCODE_FORMAT must be one of"),
            ("THREATCODE_LLM", "maybe", "THREATCODE_LLM must be true or false"),
        ],
    )
    def test_an_invalid_environment_value_names_the_variable(
        self, name: str, value: str, message: str
    ) -> None:
        with pytest.raises(ConfigError, match=message):
            resolve_settings({}, ThreatCodeConfig(), {name: value})

    def test_blank_environment_values_are_ignored(self) -> None:
        env = {"THREATCODE_FAIL_ON": "  ", "THREATCODE_LLM": ""}
        settings = resolve_settings({}, ThreatCodeConfig(), env)
        assert settings.fail_on == DEFAULT_FAIL_ON
        assert settings.llm_enabled is False

    def test_rule_paths_from_config_resolve_against_the_config_directory(
        self, tmp_path: Path
    ) -> None:
        path = write_config(tmp_path, "extra_rule_paths:\n  - rules/a.yml\n  - /abs/b.yml\n")
        loaded = discover_config(path)
        settings = resolve_settings({"rules": ["cli.yml"]}, loaded, {})
        assert settings.extra_rule_paths == (
            tmp_path / "rules" / "a.yml",
            Path("/abs/b.yml"),
            Path("cli.yml"),
        )

    def test_graph_limits_prefer_the_flag_over_the_config(self) -> None:
        cfg = ThreatCodeConfig(max_nodes=10, max_edges=20)
        settings = resolve_settings({"max_nodes": 5}, cfg, {})
        assert (settings.max_nodes, settings.max_edges) == (5, 20)

    def test_strict_edges_comes_from_the_config(self) -> None:
        cfg = ThreatCodeConfig(strict_edges=False)
        assert resolve_settings({}, cfg, {}).strict_edges is False

    def test_a_bare_config_or_loaded_config_or_nothing_all_work(self) -> None:
        assert resolve_settings({}, None, {}).fail_on == DEFAULT_FAIL_ON
        assert resolve_settings({}, ThreatCodeConfig(), {}).fail_on == DEFAULT_FAIL_ON
        loaded = LoadedConfig(config=ThreatCodeConfig(fail_on="low"))
        assert resolve_settings({}, loaded, {}).fail_on == "low"

    def test_the_process_environment_is_used_when_none_is_passed(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_FAIL_ON", "low")
        assert resolve_settings({}, ThreatCodeConfig()).fail_on == "low"

    def test_every_config_field_changes_behavior_when_set(self) -> None:
        """Each documented key is read by the resolver or by a consumer, none is decoration."""
        baseline = resolve_settings({}, ThreatCodeConfig(), {})
        changed = {
            "min_severity": ThreatCodeConfig(min_severity="high"),
            "output_format": ThreatCodeConfig(output_format="sarif"),
            "fail_on": ThreatCodeConfig(fail_on="none"),
            "extra_rule_paths": ThreatCodeConfig(extra_rule_paths=["r.yml"]),
            "max_nodes": ThreatCodeConfig(max_nodes=7),
            "max_edges": ThreatCodeConfig(max_edges=7),
            "strict_edges": ThreatCodeConfig(strict_edges=False),
        }
        for key, cfg in changed.items():
            assert resolve_settings({}, cfg, {}) != baseline, key
        llm = ThreatCodeConfig.model_validate({"llm": {"enabled": True}})
        assert resolve_settings({}, llm, {}).llm_enabled is True
        covered = set(changed) | {"llm", "redaction"}
        assert covered == set(ThreatCodeConfig.model_fields)

    def test_settings_are_immutable(self) -> None:
        settings = ResolvedSettings()
        with pytest.raises(AttributeError):
            settings.fail_on = "none"  # type: ignore[misc]


class TestLlmSection:
    def test_unknown_llm_keys_are_rejected_with_a_hint(self, tmp_path: Path) -> None:
        with pytest.raises(
            ConfigError, match=r"llm\.max_retry: unknown key \(did you mean 'max_retries'"
        ):
            load_config(write_config(tmp_path, "llm:\n  max_retry: 2\n"))

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("temperature: 3", "temperature"),
            ("temperature: -0.1", "temperature"),
            ("timeout: 0", "timeout"),
            ("max_retries: 9", "max_retries"),
            ("max_retries: -1", "max_retries"),
            ("max_input_tokens: 10", "max_input_tokens"),
            ("api_key_env: 'NOT A VAR'", "not an environment variable name"),
        ],
    )
    def test_out_of_range_values_name_the_key(
        self, tmp_path: Path, text: str, message: str
    ) -> None:
        with pytest.raises(ConfigError, match=message):
            load_config(write_config(tmp_path, f"llm:\n  {text}\n"))

    def test_every_new_key_is_read_from_an_explicit_config(self, tmp_path: Path) -> None:
        cfg = load_config(
            write_config(
                tmp_path,
                "llm:\n  enabled: true\n  provider: openai\n  model: gpt-x\n  api_key_env: MY_KEY\n"
                "  base_url: https://gateway.example.com\n  max_tokens: 2048\n  temperature: 0.3\n"
                "  timeout: 30\n  max_retries: 2\n  max_input_tokens: 20000\n",
            )
        )
        llm = cfg.llm
        assert (llm.provider, llm.model, llm.api_key_env) == ("openai", "gpt-x", "MY_KEY")
        assert (llm.temperature, llm.timeout, llm.max_retries) == (0.3, 30, 2)
        assert (llm.max_input_tokens, llm.max_tokens) == (20_000, 2048)
        assert llm.api_key_variable() == "MY_KEY"

    def test_the_default_key_variable_follows_the_provider(self) -> None:
        from threatcode.config import LLMConfig

        assert LLMConfig().api_key_variable() == "ANTHROPIC_API_KEY"
        assert LLMConfig(provider="openai").api_key_variable() == "OPENAI_API_KEY"
        assert LLMConfig(provider="ollama").api_key_variable() == ""
        assert LLMConfig(provider="local", api_key_env="K").api_key_variable() == "K"

    def test_auto_discovery_ignores_every_llm_key(self, tmp_path: Path) -> None:
        path = write_config(
            tmp_path,
            "llm:\n  timeout: 1\n  max_retries: 5\n  api_key_env: EVIL\n"
            "  max_input_tokens: 1000000\n",
        )
        loaded = discover_config(None, [path.parent])
        assert loaded.config.llm.api_key_env is None
        assert loaded.config.llm.timeout == 120
        assert "llm" in loaded.ignored

    def test_the_default_model_is_not_deprecated(self) -> None:
        from threatcode.config import DEFAULT_LLM_MODEL
        from threatcode.engine.llm.client import DEPRECATED_MODELS

        assert DEFAULT_LLM_MODEL not in DEPRECATED_MODELS


class TestOneNamePerSetting:
    """The config key is the flag's name: ``format`` and ``rules``, not ``output_format`` and
    ``extra_rule_paths``, which still load and say that they were renamed."""

    def test_format_and_rules_load_without_a_notice(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "format: sarif\nrules:\n  - rules/custom.yml\n", "c.yml")
        loaded = discover_config(path, [tmp_path])
        assert loaded.config.output_format == "sarif"
        assert loaded.config.extra_rule_paths == ["rules/custom.yml"]
        assert loaded.notices == ()

    def test_the_old_spellings_still_load_and_name_the_new_ones(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "output_format: sarif\nextra_rule_paths: [a.yml]\n", "c.yml")
        loaded = discover_config(path, [tmp_path])
        assert loaded.config.output_format == "sarif"
        assert loaded.config.extra_rule_paths == ["a.yml"]
        assert any("output_format" in n and "now called format" in n for n in loaded.notices)
        assert any("extra_rule_paths" in n and "now called rules" in n for n in loaded.notices)

    def test_both_spellings_of_one_setting_are_an_error(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "format: sarif\noutput_format: json\n", "c.yml")
        with pytest.raises(ConfigError, match="output_format and format are the same setting"):
            discover_config(path, [tmp_path])

    def test_a_bad_value_names_the_key_as_written(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match="format: 'nope' is not an output format"):
            load_config(write_config(tmp_path, "format: nope\n", "c.yml"))

    def test_the_resolver_reads_format_and_rules_from_a_named_file(self, tmp_path: Path) -> None:
        path = write_config(tmp_path, "format: markdown\nrules: [mine.yml]\n", "c.yml")
        settings = resolve_settings({}, discover_config(path, [tmp_path]), {})
        assert settings.output_format == "markdown"
        assert settings.extra_rule_paths == (tmp_path / "mine.yml",)

    def test_an_auto_discovered_file_may_set_format_but_never_rules(self, tmp_path: Path) -> None:
        write_config(tmp_path, "format: markdown\nrules: [evil.yml]\n")
        loaded = discover_config(None, [tmp_path])
        assert loaded.config.output_format == "markdown"
        assert loaded.config.extra_rule_paths == []
        assert loaded.ignored == ("rules",)
        assert loaded.used == ("format",)
        (notice,) = loaded.notices
        assert "restricted fields ['rules']" in notice

    def test_an_auto_discovered_file_cannot_smuggle_rules_under_the_old_name(
        self, tmp_path: Path
    ) -> None:
        write_config(tmp_path, "extra_rule_paths: [evil.yml]\n")
        loaded = discover_config(None, [tmp_path])
        assert loaded.config.extra_rule_paths == []
        assert loaded.ignored == ("extra_rule_paths",)
        # A key that was dropped needs no advice about how to spell it.
        (notice,) = loaded.notices
        assert "now called" not in notice

    def test_a_typo_is_pointed_at_the_new_spelling(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError, match=r"unknown key \(did you mean 'format'\?\)"):
            load_config(write_config(tmp_path, "formatt: sarif\n", "c.yml"))
        with pytest.raises(ConfigError, match=r"unknown key \(did you mean 'rules'\?\)"):
            load_config(write_config(tmp_path, "rulez: [a.yml]\n", "c.yml"))
