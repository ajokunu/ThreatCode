"""Tests for the MCP client configuration parser."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

from tests.helpers.scan import scan_files
from threatcode.exceptions import UnsupportedFormatError
from threatcode.formatters.json_out import format_json
from threatcode.formatters.markdown import format_markdown
from threatcode.formatters.sarif import format_sarif
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput
from threatcode.parsers.mcp_config import (
    MCPConfigParser,
    is_broad_path,
    is_loopback_host,
    is_mcp_config,
    is_sensitive_path,
    normalize_path,
    strip_jsonc,
)

MCP_FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _servers(path: Path) -> dict[str, dict[str, Any]]:
    parsed = detect_and_parse(path)
    assert parsed.format_type == "mcp_config"
    return {r.address: r.properties for r in parsed.resources if r.resource_type == "mcp_server"}


def _by_name(path: Path) -> dict[str, dict[str, Any]]:
    parsed = detect_and_parse(path)
    return {r.name: r.properties for r in parsed.resources if r.resource_type == "mcp_server"}


def _parse(entry: dict[str, Any], name: str = "s") -> ParsedOutput:
    return MCPConfigParser().parse({"mcpServers": {name: entry}})


def _props(entry: dict[str, Any], name: str = "s") -> dict[str, Any]:
    servers = [r for r in _parse(entry, name).resources if r.resource_type == "mcp_server"]
    assert len(servers) == 1
    return servers[0].properties


class TestDetection:
    @pytest.mark.parametrize(
        "relpath",
        [
            "vulnerable/.mcp.json",
            "fixed/.mcp.json",
            "vscode/.vscode/mcp.json",
            "project/.cursor/mcp.json",
            "clients/claude_desktop_config.json",
            "clients/mcp_config.json",
            "clients/.claude.json",
            "gemini/settings.json",
        ],
    )
    def test_fixture_detected(self, relpath: str) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / relpath)
        assert parsed.format_type == "mcp_config"
        servers = [r for r in parsed.resources if r.resource_type == "mcp_server"]
        assert servers
        assert {r.resource_type for r in parsed.resources} <= {"mcp_server", "mcp_agent"}

    @pytest.mark.parametrize(
        "relpath",
        [
            "terraform/multi_service_insecure.plan.json",
            "realistic/01_aws_ecommerce_platform.json",
        ],
    )
    def test_other_json_formats_not_claimed(self, relpath: str) -> None:
        parsed = detect_and_parse(FIXTURES / relpath)
        assert parsed.format_type != "mcp_config"

    def test_servers_key_requires_mcp_json_name(self, tmp_path: Path) -> None:
        data = {"servers": {"a": {"command": "node"}}}
        assert is_mcp_config(Path("mcp.json"), data)
        assert not is_mcp_config(Path("settings.json"), data)

    def test_servers_key_requires_server_shaped_values(self) -> None:
        assert not is_mcp_config(Path("mcp.json"), {"servers": {"a": "not-a-server"}})

    def test_a_settings_json_with_an_mcp_servers_key_is_accepted(self) -> None:
        data = {"theme": "Default", "mcpServers": {"a": {"httpUrl": "https://h/mcp"}}}
        assert is_mcp_config(Path("settings.json"), data)

    @pytest.mark.parametrize(
        "data",
        [
            {"mcp": {"a": {"type": "local", "command": ["npx", "x"]}}},  # OpenCode
            {"context_servers": {"a": {"command": {"path": "npx", "args": ["x"]}}}},  # Zed
        ],
    )
    def test_opencode_and_zed_shapes_are_documented_as_unsupported(
        self, data: dict[str, Any]
    ) -> None:
        assert not is_mcp_config(Path("settings.json"), data)
        assert not is_mcp_config(Path("opencode.json"), data)

    def test_jsonc_only_tolerated_for_mcp_file_names(self, tmp_path: Path) -> None:
        body = '{\n  // comment\n  "mcpServers": {"a": {"command": "node",},},\n}\n'
        mcp = tmp_path / "mcp.json"
        mcp.write_text(body)
        assert detect_and_parse(mcp).format_type == "mcp_config"

        other = tmp_path / "other.json"
        other.write_text(body)
        with pytest.raises(UnsupportedFormatError):
            detect_and_parse(other)


class TestStripJsonc:
    def test_keeps_comment_markers_inside_strings(self) -> None:
        text = '{"url": "https://host/a//b", "note": "/* not a comment */"} // tail'
        assert json.loads(strip_jsonc(text)) == {
            "url": "https://host/a//b",
            "note": "/* not a comment */",
        }

    def test_removes_trailing_commas_and_block_comments(self) -> None:
        text = '{/* c */ "a": [1, 2,], "b": {"c": 1,},}'
        assert json.loads(strip_jsonc(text)) == {"a": [1, 2], "b": {"c": 1}}

    def test_escaped_quote_in_string(self) -> None:
        text = '{"a": "say \\"hi\\" // still string"}'
        assert json.loads(strip_jsonc(text)) == {"a": 'say "hi" // still string'}

    @pytest.mark.parametrize("value", ["abc,}", "x, ]", "a,\n}", "[1,]", '{"k": 1,}', ",}", ", ]"])
    def test_a_string_holding_a_comma_before_a_bracket_survives(self, value: str) -> None:
        text = '{"password": ' + json.dumps(value) + ", }"
        assert json.loads(strip_jsonc(text)) == {"password": value}

    def test_a_trailing_comma_after_a_comment_is_still_removed(self) -> None:
        text = '{"a": [1, 2, // last\n  ], "b": 1, /* x */ }'
        assert json.loads(strip_jsonc(text)) == {"a": [1, 2], "b": 1}

    def test_a_comma_between_values_is_kept(self) -> None:
        assert json.loads(strip_jsonc('{"a": 1, // c\n "b": [1, 2]}')) == {"a": 1, "b": [1, 2]}

    def test_comment_markers_in_strings_survive_next_to_trailing_commas(self) -> None:
        text = '{"a": "// keep", "b": "/* keep */",}'
        assert json.loads(strip_jsonc(text)) == {"a": "// keep", "b": "/* keep */"}

    def test_block_comments_keep_their_newlines_so_line_numbers_match(self) -> None:
        text = '{\n/* one\ntwo\nthree */\n"a": 1}'
        assert strip_jsonc(text).count("\n") == text.count("\n")

    def test_a_leading_byte_order_mark_is_dropped(self) -> None:
        assert json.loads(strip_jsonc('\ufeff{"a": 1,}')) == {"a": 1}

    def test_unterminated_block_comment_does_not_hang(self) -> None:
        assert strip_jsonc('{"a": 1} /* never closed').strip() == '{"a": 1}'

    @settings(max_examples=100, deadline=None, derandomize=True)
    @given(
        st.text(alphabet=st.sampled_from(list(',}]\\"/*x \n[{')), max_size=20),
        st.booleans(),
    )
    @example("abc,}", True)
    @example("x, ]", False)
    def test_a_string_value_round_trips_with_or_without_a_trailing_comma(
        self, value: str, trailing: bool
    ) -> None:
        body = '{"v": ' + json.dumps(value) + (",}" if trailing else "}")
        assert json.loads(strip_jsonc(body)) == {"v": value}


class TestEncodedInputs:
    """Inputs with a byte order mark or UTF-16 text parse like plain UTF-8."""

    @pytest.mark.parametrize("name", [".mcp.json", "claude_desktop_config.json", "mcp.json"])
    def test_a_utf8_bom_mcp_config(self, tmp_path: Path, name: str) -> None:
        path = tmp_path / name
        path.write_bytes(b"\xef\xbb\xbf" + b'{"mcpServers": {"a": {"command": "node"}}}')
        assert [r.name for r in detect_and_parse(path).resources][0] == "a"

    @pytest.mark.parametrize("codec", ["utf-16-le", "utf-16-be"])
    def test_a_utf16_mcp_config(self, tmp_path: Path, codec: str) -> None:
        text = '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"]}}}'
        bom = b"\xff\xfe" if codec.endswith("le") else b"\xfe\xff"
        path = tmp_path / ".mcp.json"
        path.write_bytes(bom + text.encode(codec))
        parsed = detect_and_parse(path)
        assert parsed.format_type == "mcp_config"
        server = next(r for r in parsed.resources if r.resource_type == "mcp_server")
        assert server.properties["package_unpinned"] is True

    def test_a_bom_jsonc_mcp_config_with_comments_and_trailing_commas(self, tmp_path: Path) -> None:
        path = tmp_path / "mcp.json"
        body = '// c\n{"servers": {"a": {"command": "node",},},}\n'
        path.write_bytes(b"\xef\xbb\xbf" + body.encode())
        assert detect_and_parse(path).format_type == "mcp_config"

    def test_a_bom_terraform_plan(self, tmp_path: Path) -> None:
        source = (FIXTURES / "terraform" / "simple_s3.plan.json").read_bytes()
        path = tmp_path / "plan.json"
        path.write_bytes(b"\xef\xbb\xbf" + source)
        assert detect_and_parse(path).format_type != "mcp_config"
        assert detect_and_parse(path).resources

    def test_a_bom_yaml_manifest(self, tmp_path: Path) -> None:
        source = (FIXTURES / "kubernetes" / "insecure_deployment.yml").read_bytes()
        path = tmp_path / "deploy.yml"
        path.write_bytes(b"\xef\xbb\xbf" + source)
        assert detect_and_parse(path).resources

    def test_a_bom_dockerfile(self, tmp_path: Path) -> None:
        path = tmp_path / "Dockerfile"
        path.write_bytes(b"\xef\xbb\xbfFROM alpine:3.20\nUSER app\n")
        assert detect_and_parse(path).resources

    def test_the_line_numbers_of_a_bom_file_are_right(self, tmp_path: Path) -> None:
        path = tmp_path / ".mcp.json"
        path.write_bytes(
            b"\xef\xbb\xbf" + b'{\n  "mcpServers": {\n    "a": {"command": "node"}\n  }\n}\n'
        )
        server = next(r for r in detect_and_parse(path).resources if r.name == "a")
        assert server.start_line == 3


class TestClientShapes:
    def test_claude_code_project_file(self) -> None:
        servers = _servers(MCP_FIXTURES / "vulnerable" / ".mcp.json")
        assert set(servers) == {
            "mcp_server.weather",
            "mcp_server.home-files",
            "mcp_server.terminal",
            "mcp_server.builder",
            "mcp_server.inventory",
        }
        assert servers["mcp_server.weather"]["transport"] == "stdio"
        assert servers["mcp_server.inventory"]["transport"] == "http"
        assert servers["mcp_server.inventory"]["is_remote"] is True

    def test_vscode_servers_shape_with_comments(self) -> None:
        servers = _servers(MCP_FIXTURES / "vscode" / ".vscode" / "mcp.json")
        assert set(servers) == {"mcp_server.github", "mcp_server.python-tools"}
        github = servers["mcp_server.github"]
        assert github["client_format"] == "vscode"
        assert github["has_configured_auth"] is True
        assert github["has_literal_secret"] is False

    def test_windsurf_server_url_key(self) -> None:
        servers = _servers(MCP_FIXTURES / "clients" / "mcp_config.json")
        tickets = servers["mcp_server.tickets"]
        assert tickets["is_remote"] is True
        assert tickets["url_host"] == "tickets.corp.internal"

    def test_gemini_http_url_key_is_read_like_url(self) -> None:
        servers = _by_name(MCP_FIXTURES / "gemini" / "settings.json")
        search = servers["search"]
        assert search["is_remote"] is True
        assert search["transport"] == "http"
        assert search["url_host"] == "mcp.example.com"
        assert search["uses_plaintext_transport"] is True
        assert search["remote_without_configured_auth"] is True

    def test_gemini_loopback_http_url_is_not_remote_trouble(self) -> None:
        local = _by_name(MCP_FIXTURES / "gemini" / "settings.json")["local"]
        assert local["is_loopback"] is True
        assert local["uses_plaintext_transport"] is False
        assert local["remote_without_configured_auth"] is False

    def test_claude_json_user_and_project_scopes(self) -> None:
        servers = _servers(MCP_FIXTURES / "clients" / ".claude.json")
        assert "mcp_server.search" in servers
        project = [a for a in servers if a != "mcp_server.search"]
        assert len(project) == 1
        # The address holds a short hash of the full project path, the name stays the key
        assert project[0].startswith("mcp_server.shop-")
        assert project[0].endswith(".db")
        assert servers[project[0]]["scope"] == "shop"
        assert servers[project[0]]["server_name"] == "db"

    def test_a_list_command_is_read_like_command_and_args(self) -> None:
        props = _props({"command": ["npx", "-y", "pkg"], "args": ["--flag"]})
        assert props["runner"] == "npx"
        assert props["package_unpinned"] is True

    def test_non_dict_entries_skipped(self) -> None:
        parsed = MCPConfigParser().parse({"mcpServers": {"a": "x", "b": {"command": "node"}}})
        assert [r.name for r in parsed.resources if r.resource_type == "mcp_server"] == ["b"]

    def test_a_config_with_no_servers_parses_to_nothing(self) -> None:
        assert MCPConfigParser().parse({"mcpServers": {}}).resources == []
        assert MCPConfigParser().parse([]).resources == []  # type: ignore[arg-type]


class TestSourceLines:
    def test_each_server_points_at_its_own_line(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "vulnerable" / ".mcp.json")
        lines = {r.name: r.start_line for r in parsed.resources if r.resource_type == "mcp_server"}
        assert lines == {
            "weather": 3,
            "home-files": 10,
            "terminal": 14,
            "builder": 18,
            "inventory": 26,
        }

    def test_the_source_location_is_the_file_without_a_line_suffix(self) -> None:
        path = MCP_FIXTURES / "vulnerable" / ".mcp.json"
        parsed = detect_and_parse(path)
        assert {r.source_location for r in parsed.resources} == {str(path)}

    def test_a_key_repeated_in_other_scopes_gets_its_own_line(self, tmp_path: Path) -> None:
        text = (MCP_FIXTURES / "claude_json_collision" / ".claude.json").read_text()
        path = tmp_path / ".claude.json"
        path.write_text(text)
        parsed = detect_and_parse(path)
        lines = sorted(
            (r.start_line, r.name) for r in parsed.resources if r.resource_type == "mcp_server"
        )
        assert [name for _line, name in lines] == ["github", "github", "archive"]
        assert len({line for line, _ in lines}) == 3

    def test_jsonc_comments_do_not_shift_the_lines(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "vscode" / ".vscode" / "mcp.json")
        lines = {r.name: r.start_line for r in parsed.resources if r.resource_type == "mcp_server"}
        assert lines == {"github": 13, "python-tools": 20}

    def test_a_server_named_like_another_key_is_not_confused(self, tmp_path: Path) -> None:
        text = '{\n  "env": 1,\n  "mcpServers": {\n    "env": {"command": "node"}\n  }\n}\n'
        path = tmp_path / ".mcp.json"
        path.write_text(text)
        server = next(r for r in detect_and_parse(path).resources if r.name == "env")
        assert server.start_line == 4

    def test_a_server_with_no_file_has_no_line(self) -> None:
        parsed = _parse({"command": "node"})
        assert parsed.resources[0].start_line is None


class TestUnknownShapes:
    def test_an_entry_with_no_launch_key_is_unknown_with_a_warning(self) -> None:
        parsed = MCPConfigParser().parse(
            {"mcpServers": {"mystery": {"type": "plugin", "plugin": "x"}}}
        )
        server = parsed.resources[0]
        assert server.properties["transport"] == "unknown"
        assert server.properties["is_remote"] is False
        warnings = [d for d in parsed.diagnostics if d.code == "mcp.unknown_entry"]
        assert len(warnings) == 1
        assert warnings[0].level == "warning"
        assert "mystery" in warnings[0].message

    def test_the_warning_carries_the_file_and_line(self) -> None:
        path = MCP_FIXTURES / "unknown_shape" / ".mcp.json"
        parsed = detect_and_parse(path)
        warning = next(d for d in parsed.diagnostics if d.code == "mcp.unknown_entry")
        assert warning.file == str(path)
        assert warning.line == 3

    def test_known_shapes_raise_no_unknown_entry_warning(self) -> None:
        for relpath in ("vulnerable/.mcp.json", "gemini/settings.json", "clients/.claude.json"):
            parsed = detect_and_parse(MCP_FIXTURES / relpath)
            assert not [d for d in parsed.diagnostics if d.code == "mcp.unknown_entry"], relpath

    def test_the_graph_carries_the_warning(self) -> None:
        graph = scan_files([MCP_FIXTURES / "unknown_shape" / ".mcp.json"]).graph
        assert any(d.code == "mcp.unknown_entry" for d in graph.diagnostics)


class TestSecrets:
    @pytest.mark.parametrize(
        "value",
        [
            "${API_KEY}",
            "${env:API_KEY}",
            "${input:api-key}",
            "<YOUR_API_KEY>",
            "",
            "$API_KEY",
            "%API_KEY%",
            "$env:API_KEY",
            "{{ api_key }}",
            "${API_KEY:-}",
            "YOUR_API_KEY_HERE",
            "your-token-here",
            "changeme",
            "xxxxxxxx",
            "...",
        ],
    )
    def test_placeholders_are_not_secrets(self, value: str) -> None:
        props = _props({"command": "node", "env": {"API_KEY": value}})
        assert props["has_literal_secret"] is False

    @pytest.mark.parametrize(
        "env",
        [
            {"TOKEN_URL": "https://auth.example.com/oauth/token"},
            {"AUTH_URL": "https://auth.example.com/authorize"},
            {"AUTH_TYPE": "service-account"},
            {"AWS_SECRET_NAME": "prod/db/credentials"},
            {"OAUTH_CLIENT_ID": "Iv1.8a61f9b3a7aba766"},
            {"BRAVE_API_KEY": "YOUR_API_KEY_HERE"},
            {"API_TOKEN": "your-token-here"},
            {"API_TOKEN": "%API_TOKEN%"},
            {"GITHUB_AUTHOR": "Aaron Lindahl"},
            {"PASSWORD_FILE": "/run/secrets/db_password"},
            {"AUTH_MODE": "oauth"},
            {"LOG_LEVEL": "debug-verbose-mode"},
            {"SECRET_ENABLED": "true"},
            {"TOKEN_TTL": "3600"},
            {"GITHUB_TOKEN": "GITHUB_TOKEN"},
            {"SLACK_TOKEN": "${input:slack-token}"},
            {"DB_URL": "postgresql://readonly@db.corp.internal/api"},
        ],
    )
    def test_every_false_positive_of_the_audit_stays_clean(self, env: dict[str, str]) -> None:
        props = _props({"command": "node", "env": env})
        assert props["has_literal_secret"] is False
        assert props["literal_secret_keys"] == []

    @pytest.mark.parametrize(
        ("env", "label", "confidence"),
        [
            ({"PASSWORD": "abc123"}, "env:PASSWORD", "medium"),
            ({"DB_PASSWD": "x1"}, "env:DB_PASSWD", "medium"),
            ({"CLIENT_SECRET": "hunter2"}, "env:CLIENT_SECRET", "medium"),
            ({"GITHUB_PAT": "ghp_16C7e42F292c6912E7710c838347Ae178B4a"}, "env:GITHUB_PAT", "high"),
            ({"BEARER": "abcd1234efgh"}, "env:BEARER", "medium"),
            ({"SERVICE_TOKEN": "a8f3k2m9q7w1z5x0"}, "env:SERVICE_TOKEN", "high"),
            (
                {"WEATHER_API_KEY": "9f8e2c4b7a1d6e3f5c0b8a7d2e4f6c1b"},
                "env:WEATHER_API_KEY",
                "high",
            ),
            ({"apiKey": "Xk29Lm4Qr8Tz1Vb7"}, "env:apiKey", "high"),
            ({"X": "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"}, "env:X", "high"),
            (
                {"API_TOKEN": "${API_TOKEN:-sk-live-4eC39HqLyjWDarjtT1zdp7dc}"},
                "env:API_TOKEN",
                "high",
            ),
            (
                {"API_TOKEN": "sk-live-4eC39HqLyjWDarjtT1zdp7dc${SUFFIX}"},
                "env:API_TOKEN",
                "high",
            ),
            (
                {"DATABASE_URL": "postgres://u:Kq7vR2mXp9sLw4Tz@db:5432/x"},
                "env:DATABASE_URL",
                "high",
            ),
        ],
    )
    def test_every_true_positive_is_flagged(
        self, env: dict[str, str], label: str, confidence: str
    ) -> None:
        props = _props({"command": "node", "env": env})
        assert props["literal_secret_keys"] == [label]
        assert props["secret_confidence"] == confidence
        assert props["has_high_confidence_secret"] is (confidence == "high")
        assert props["has_possible_secret"] is (confidence == "medium")

    def test_the_value_is_never_in_the_parsed_output(self) -> None:
        values = ["abc123", "ghp_16C7e42F292c6912E7710c838347Ae178B4a", "Kq7vR2mXp9sLw4Tz"]
        env = {
            "PASSWORD": values[0],
            "GITHUB_PAT": values[1],
            "DATABASE_URL": f"postgres://u:{values[2]}@db/x",
        }
        parsed = _parse({"command": "node", "env": env})
        dumped = json.dumps([r.properties for r in parsed.resources])
        for value in values:
            assert value not in dumped

    def test_bearer_header_with_literal_token(self) -> None:
        props = _props(
            {"url": "https://h/mcp", "headers": {"Authorization": "Bearer a8f3k2m9q7w1z5x0"}}
        )
        assert props["literal_secret_keys"] == ["header:Authorization"]
        assert props["secret_confidence"] == "high"

    def test_basic_header_with_literal_value(self) -> None:
        props = _props({"url": "https://h/mcp", "headers": {"Authorization": "Basic dTpwYXNz"}})
        assert props["literal_secret_keys"] == ["header:Authorization"]

    def test_bearer_header_with_placeholder(self) -> None:
        props = _props({"url": "https://h/mcp", "headers": {"Authorization": "Bearer ${TOKEN}"}})
        assert props["has_literal_secret"] is False
        assert props["has_configured_auth"] is True

    def test_api_key_header_with_literal(self) -> None:
        props = _props(
            {"url": "https://h/mcp", "headers": {"x-api-key": "c7d1e9a4b2f80635de41a97c"}}
        )
        assert props["literal_secret_keys"] == ["header:x-api-key"]

    def test_secret_in_url_query(self) -> None:
        props = _props({"url": "https://h/mcp?api_key=a8f3k2m9q7w1z5x0&region=eu"})
        assert props["literal_secret_keys"] == ["url:api_key"]

    def test_a_query_credential_counts_as_configured_auth(self) -> None:
        literal = _props({"url": "https://h/mcp?api_key=a8f3k2m9q7w1z5x0"})
        assert literal["has_configured_auth"] is True
        assert literal["remote_without_configured_auth"] is False
        referenced = _props({"url": "https://h/mcp?api_key=${KEY}"})
        assert referenced["has_configured_auth"] is True
        assert referenced["has_literal_secret"] is False

    def test_url_userinfo_is_a_literal_secret_and_configured_auth(self) -> None:
        props = _props({"url": "https://deploy:s3cretP4ssw0rd@mcp.example.com/mcp"})
        assert props["literal_secret_keys"] == ["url:userinfo"]
        assert props["has_configured_auth"] is True
        assert props["remote_without_configured_auth"] is False

    def test_url_userinfo_without_a_password_is_auth_but_not_a_secret(self) -> None:
        props = _props({"url": "https://deploy@mcp.example.com/mcp"})
        assert props["has_literal_secret"] is False
        assert props["has_configured_auth"] is True

    def test_a_token_as_the_url_username_is_a_secret(self) -> None:
        props = _props(
            {"url": "https://ghp_16C7e42F292c6912E7710c838347Ae178B4a@mcp.example.com/mcp"}
        )
        assert props["literal_secret_keys"] == ["url:userinfo"]

    def test_a_long_token_in_the_url_path_is_a_medium_confidence_secret(self) -> None:
        props = _props({"url": "https://actions.example.com/s/abcdef1234567890abcdef12/mcp"})
        assert props["literal_secret_keys"] == ["url:path"]
        assert props["secret_confidence"] == "medium"
        assert props["has_configured_auth"] is True

    def test_ordinary_path_segments_are_not_secrets(self) -> None:
        props = _props({"url": "https://h.example.com/api/v2/servers/documentation-search/mcp"})
        assert props["has_literal_secret"] is False

    def test_connection_string_pattern(self) -> None:
        props = _props(
            {"command": "node", "env": {"DATABASE_URL": "postgres://u:Kq7vR2mXp9sLw4Tz@db:5432/x"}}
        )
        assert props["literal_secret_keys"] == ["env:DATABASE_URL"]


class TestSecretsInArguments:
    @pytest.mark.parametrize(
        ("command", "args", "label"),
        [
            (
                "docker",
                [
                    "run",
                    "-i",
                    "--rm",
                    "-e",
                    "GITHUB_PERSONAL_ACCESS_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                    "img:1.0",
                ],
                "arg:GITHUB_PERSONAL_ACCESS_TOKEN",
            ),
            (
                "docker",
                ["run", "--env", "API_TOKEN=a8f3k2m9q7w1z5x0", "img:1.0"],
                "arg:API_TOKEN",
            ),
            (
                "docker",
                ["run", "--env=API_TOKEN=a8f3k2m9q7w1z5x0", "img:1.0"],
                "arg:API_TOKEN",
            ),
            ("docker", ["run", "-eAPI_TOKEN=a8f3k2m9q7w1z5x0", "img:1.0"], "arg:API_TOKEN"),
            ("npx", ["-y", "pkg@1.0.0", "--api-key=a8f3k2m9q7w1z5x0"], "arg:--api-key"),
            ("npx", ["-y", "pkg@1.0.0", "--token", "a8f3k2m9q7w1z5x0"], "arg:--token"),
            ("npx", ["-y", "pkg@1.0.0", "--access-token=a8f3k2m9q7w1z5x0"], "arg:--access-token"),
            (
                "npx",
                ["-y", "pkg@1.0.0", "--header", "Authorization: Bearer a8f3k2m9q7w1z5x0"],
                "arg:Authorization",
            ),
            (
                "npx",
                ["-y", "pkg@1.0.0", "--header=Authorization: Bearer a8f3k2m9q7w1z5x0"],
                "arg:Authorization",
            ),
            ("npx", ["-y", "pkg@1.0.0", "-H", "X-Api-Key: c7d1e9a4b2f80635"], "arg:X-Api-Key"),
            ("npx", ["-y", "pkg@1.0.0", "Bearer a8f3k2m9q7w1z5x0"], "arg:Authorization"),
            ("env", ["API_TOKEN=a8f3k2m9q7w1z5x0", "npx", "-y", "pkg@1.0.0"], "arg:API_TOKEN"),
            ("bash", ["-c", "npx -y pkg@1.0.0 --token a8f3k2m9q7w1z5x0"], "arg:--token"),
            (
                "npx",
                [
                    "-y",
                    "@modelcontextprotocol/server-postgres@1.0.0",
                    "postgresql://u:pw3Kq7vR2@h/db",
                ],
                "arg:url",
            ),
        ],
    )
    def test_every_argument_form_is_flagged(
        self, command: str, args: list[str], label: str
    ) -> None:
        props = _props({"command": command, "args": args})
        assert props["has_literal_secret"] is True
        assert props["literal_secret_keys"] == [label]

    def test_docker_env_with_no_value_is_a_reference_not_a_secret(self) -> None:
        props = _props(
            {"command": "docker", "args": ["run", "-e", "GITHUB_PERSONAL_ACCESS_TOKEN", "img:1.0"]}
        )
        assert props["has_literal_secret"] is False

    @pytest.mark.parametrize(
        "args",
        [
            ["--api-key=${API_KEY}"],
            ["--api-key", "${env:API_KEY}"],
            ["--token=$TOKEN"],
            ["--password-file", "/run/secrets/pw"],
            ["--auth-type", "service-account"],
            ["--token-url", "https://auth.example.com/token"],
            ["--header", "Authorization: Bearer ${TOKEN}"],
            ["--header", "Accept: application/json"],
            ["-e", "LOG_LEVEL=debug"],
        ],
    )
    def test_argument_false_positives_stay_clean(self, args: list[str]) -> None:
        props = _props({"command": "npx", "args": ["-y", "pkg@1.0.0", *args]})
        assert props["has_literal_secret"] is False

    def test_the_argument_index_is_recorded_not_the_value(self) -> None:
        props = _props(
            {"command": "npx", "args": ["-y", "pkg@1.0.0", "--token", "a8f3k2m9q7w1z5x0"]}
        )
        assert props["literal_secret_arg_indexes"] == [3]
        assert "a8f3k2m9q7w1z5x0" not in json.dumps(props)

    def test_args_are_redacted_in_place_and_the_rest_stays_readable(self) -> None:
        props = _props(
            {
                "command": "docker",
                "args": [
                    "run",
                    "-e",
                    "GITHUB_PERSONAL_ACCESS_TOKEN=ghp_16C7e42F292c6912E7710c838347Ae178B4a",
                    "-e",
                    "GITHUB_HOST",
                    "--api-key=a8f3k2m9q7w1z5x0",
                    "img:1.0",
                ],
            }
        )
        assert props["args"] == [
            "run",
            "-e",
            "GITHUB_PERSONAL_ACCESS_TOKEN=[REDACTED]",
            "-e",
            "GITHUB_HOST",
            "--api-key=[REDACTED]",
            "img:1.0",
        ]

    def test_a_url_password_is_redacted_but_the_host_survives(self) -> None:
        props = _props(
            {
                "command": "npx",
                "args": ["-y", "pkg@1.0.0", "postgresql://postgres:postgres@localhost/api"],
            }
        )
        assert props["args"][-1] == "postgresql://postgres:[REDACTED]@localhost/api"

    def test_a_secret_inside_a_shell_string_is_redacted_inside_it(self) -> None:
        props = _props({"command": "bash", "args": ["-c", "npx -y pkg --token a8f3k2m9q7w1z5x0"]})
        assert props["args"] == ["-c", "npx -y pkg --token [REDACTED]"]

    def test_a_header_secret_is_redacted_but_the_header_name_stays(self) -> None:
        props = _props(
            {
                "command": "npx",
                "args": [
                    "mcp-remote@0.1.5",
                    "https://h/sse",
                    "--header",
                    "Authorization: Bearer a8f3k2m9q7w1z5x0",
                ],
            }
        )
        assert props["args"][-1] == "Authorization: [REDACTED]"

    def test_nothing_secret_survives_any_output_format(self) -> None:
        values = [
            "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
            "a8f3k2m9q7w1z5x0",
            "sk-live-4eC39HqLyjWDarjtT1zdp7dc",
            "s3cretP4ssw0rd",
            "abcdef1234567890abcdef12",
            "1f0e9d8c7b6a5f4e3d2c1b0a99887766",
        ]
        result = scan_files([MCP_FIXTURES / "secrets" / ".mcp.json"])
        everything = [
            json.dumps([r.properties for p in result.parsed for r in p.resources]),
            json.dumps(result.graph.to_dict()),
            format_json(result.report),
            format_sarif(result.report),
            format_markdown(result.report),
            repr(result.graph.diagnostics),
        ]
        for text in everything:
            for value in values:
                assert value not in text, value

    def test_the_fixture_reports_exactly_the_expected_secrets(self) -> None:
        servers = _by_name(MCP_FIXTURES / "secrets" / ".mcp.json")
        flagged = {n: p["secret_confidence"] for n, p in servers.items() if p["has_literal_secret"]}
        assert flagged == {
            "password-key": "medium",
            "docker-env": "high",
            "flag-equals": "high",
            "flag-space": "high",
            "default-literal": "high",
            "userinfo": "high",
            "path-token": "medium",
            "query-auth": "high",
        }
        assert servers["false-positives"]["has_literal_secret"] is False


class TestBridges:
    def test_mcp_remote_with_http_url_and_literal_bearer(self) -> None:
        props = _props(
            {
                "command": "npx",
                "args": [
                    "-y",
                    "mcp-remote@0.1.5",
                    "http://host.example.net/sse",
                    "--header",
                    "Authorization: Bearer a8f3k2m9q7w1z5x0",
                    "--allow-http",
                ],
            }
        )
        assert props["transport"] == "stdio-bridge"
        assert props["bridge"] == "mcp-remote"
        assert props["bridge_allow_http"] is True
        assert props["is_remote"] is True
        assert props["url_host"] == "host.example.net"
        assert props["uses_plaintext_transport"] is True
        assert props["has_literal_secret"] is True
        assert props["has_configured_auth"] is True
        assert props["remote_without_configured_auth"] is False

    def test_mcp_remote_without_a_header_is_remote_without_auth(self) -> None:
        props = _props(
            {"command": "npx", "args": ["-y", "mcp-remote", "https://h.example.com/sse"]}
        )
        assert props["is_remote"] is True
        assert props["uses_plaintext_transport"] is False
        assert props["remote_without_configured_auth"] is True

    def test_mcp_remote_with_a_referenced_header_is_authenticated_without_a_secret(self) -> None:
        props = _props(
            {
                "command": "npx",
                "args": [
                    "mcp-remote@0.1.12",
                    "https://h.example.com/sse",
                    "--header",
                    "Authorization: Bearer ${DOCS_MCP_TOKEN}",
                ],
            }
        )
        assert props["has_configured_auth"] is True
        assert props["has_literal_secret"] is False

    def test_a_loopback_bridge_url_is_not_plaintext(self) -> None:
        props = _props({"command": "npx", "args": ["mcp-remote", "http://localhost:3000/sse"]})
        assert props["is_remote"] is True
        assert props["is_loopback"] is True
        assert props["uses_plaintext_transport"] is False
        assert props["remote_without_configured_auth"] is False

    def test_a_secret_in_the_bridge_url_userinfo_is_flagged_and_redacted(self) -> None:
        props = _props(
            {
                "command": "npx",
                "args": ["mcp-remote", "https://u:Kq7vR2mXp9sLw4Tz@h.example.com/sse"],
            }
        )
        assert props["literal_secret_keys"] == ["url:userinfo"]
        assert "Kq7vR2mXp9sLw4Tz" not in json.dumps(props)
        assert props["args"][-1] == "https://u:[REDACTED]@h.example.com/sse"

    def test_the_bridged_server_is_in_the_internet_zone(self) -> None:
        graph = scan_files([MCP_FIXTURES / "wrappers" / "claude_desktop_config.json"]).graph
        assert graph.nodes["mcp_server.bridge-plain"].trust_zone.value == "internet"

    def test_a_bridge_over_a_cmd_launcher_is_still_a_bridge(self) -> None:
        props = _props(
            {"command": "cmd", "args": ["/c", "npx", "-y", "mcp-remote@0.1.5", "https://h/sse"]}
        )
        assert props["bridge"] == "mcp-remote"
        assert props["is_remote"] is True


class TestWrappers:
    def test_the_wrappers_fixture_reports_each_launcher(self) -> None:
        servers = _by_name(MCP_FIXTURES / "wrappers" / "claude_desktop_config.json")
        unpinned = {n for n, p in servers.items() if p["package_unpinned"]}
        assert unpinned == {
            "win-npx",
            "bash-npx",
            "env-npx",
            "npm-exec",
            "pnpm-exec",
            "pipx",
            "uv-tool",
            "deno",
        }
        assert servers["pinned-cmd"]["package_unpinned"] is False
        assert servers["win-npx"]["package_name"] == "@acme/win-mcp"
        assert servers["win-npx"]["launch_wrappers"] == ["cmd"]
        assert servers["win-npx"]["unpinned_reasons"] == ["@acme/win-mcp: no-version"]

    def test_a_deeply_nested_launcher_is_not_analysed(self) -> None:
        props = _props(
            {"command": "nohup", "args": ["nohup", "nohup", "nohup", "nohup", "npx", "pkg"]}
        )
        assert props["package_unpinned"] is False

    def test_a_secret_behind_a_launcher_is_found(self) -> None:
        props = _props(
            {
                "command": "cmd",
                "args": ["/c", "npx", "-y", "pkg@1.0.0", "--token", "a8f3k2m9q7w1z5x0"],
            }
        )
        assert props["literal_secret_keys"] == ["arg:--token"]
        assert props["args"][-1] == "[REDACTED]"

    def test_a_filesystem_path_behind_a_launcher_is_found(self) -> None:
        props = _props(
            {
                "command": "cmd",
                "args": [
                    "/c",
                    "npx",
                    "-y",
                    "@modelcontextprotocol/server-filesystem@1.0.0",
                    "C:\\Users\\dev",
                ],
            }
        )
        assert props["broad_filesystem_access"] is True


class TestTransport:
    def test_plaintext_remote(self) -> None:
        props = _props({"type": "http", "url": "http://mcp.corp.internal/mcp"})
        assert props["uses_plaintext_transport"] is True
        assert props["remote_without_configured_auth"] is True

    @pytest.mark.parametrize(
        "host", ["localhost", "127.0.0.1", "[::1]", "foo.localhost", "127.1.2.3"]
    )
    def test_plaintext_loopback_allowed(self, host: str) -> None:
        props = _props({"type": "http", "url": f"http://{host}:3000/mcp"})
        assert props["uses_plaintext_transport"] is False
        assert props["is_loopback"] is True

    @pytest.mark.parametrize(
        "host",
        [
            "127.attacker.com",
            "127.0.0.1.nip.io",
            "localhost.attacker.com",
            "notlocalhost",
            "10.0.0.5",
            "0.0.0.0",
            "mcp.example.com",
        ],
    )
    def test_look_alike_hosts_are_remote_and_plaintext(self, host: str) -> None:
        props = _props({"type": "http", "url": f"http://{host}/mcp"})
        assert props["is_loopback"] is False
        assert props["uses_plaintext_transport"] is True

    @pytest.mark.parametrize(
        ("host", "expected"),
        [
            ("127.0.0.1", True),
            ("127.255.255.254", True),
            ("::1", True),
            ("[::1]", True),
            ("0:0:0:0:0:0:0:1", True),
            ("::ffff:127.0.0.1", True),
            ("localhost", True),
            ("LOCALHOST", True),
            ("localhost.", True),
            ("a.b.localhost", True),
            ("", False),
            ("128.0.0.1", False),
            ("127.attacker.com", False),
            ("::2", False),
            ("localhostx", False),
        ],
    )
    def test_loopback_table(self, host: str, expected: bool) -> None:
        assert is_loopback_host(host) is expected

    def test_websocket_plaintext(self) -> None:
        props = _props({"type": "ws", "url": "ws://mcp.corp.internal/ws"})
        assert props["uses_plaintext_transport"] is True

    def test_oauth_block_counts_as_auth(self) -> None:
        props = _props({"type": "http", "url": "https://h/mcp", "oauth": {"clientId": "x"}})
        assert props["remote_without_configured_auth"] is False

    def test_stdio_is_not_remote(self) -> None:
        props = _props({"command": "node", "args": ["server.js"]})
        assert props["is_remote"] is False
        assert props["remote_without_configured_auth"] is False

    def test_a_loopback_server_without_auth_is_not_remote_without_auth(self) -> None:
        props = _props({"type": "http", "url": "http://127.0.0.1:8931/mcp"})
        assert props["is_remote"] is True
        assert props["remote_without_configured_auth"] is False

    @pytest.mark.parametrize("key", ["url", "serverUrl", "httpUrl"])
    def test_every_url_key_is_read(self, key: str) -> None:
        props = _props({key: "http://mcp.example.com/mcp"})
        assert props["is_remote"] is True
        assert props["uses_plaintext_transport"] is True


class TestPinning:
    @pytest.mark.parametrize(
        ("command", "args", "unpinned"),
        [
            ("npx", ["-y", "@scope/pkg"], True),
            ("npx", ["-y", "@scope/pkg@1.2.3"], False),
            ("npx", ["-y", "@scope/pkg@latest"], True),
            ("npx", ["-y", "pkg@^1.2.3"], True),
            ("npx", ["-y", "pkg@>=1"], True),
            ("npx", ["-y", "pkg@1"], True),
            ("npx", ["-y", "pkg@beta"], True),
            ("npx", ["-y", "@s/pkg@canary"], True),
            ("npx", ["pkg"], True),
            ("npx", ["pkg@2.0.0", "--flag"], False),
            ("npx", ["-y", "-p", "pkg@1.0.0", "pkg-bin"], False),
            ("npx", ["-y", "--package=pkg", "pkg-bin"], True),
            ("npx", ["./server"], False),
            ("npx", ["file:./local"], False),
            ("npx", ["github:u/r#v1.2.3"], False),
            ("npx", ["github:u/r#main"], True),
            ("bunx", ["pkg"], True),
            ("pnpm", ["dlx", "pkg@1.0.0"], False),
            ("pnpm", ["dlx", "pkg"], True),
            ("pnpm", ["install"], False),
            ("uvx", ["pkg"], True),
            ("uvx", ["pkg==1.2.3"], False),
            ("uvx", ["pkg@1.2.3"], False),
            ("uvx", ["pkg>=1"], True),
            ("uvx", ["--from", "pkg==1.0", "pkg-cli"], False),
            ("uvx", ["--from", "git+ssh://git@github.com/o/r", "r"], True),
            ("uvx", ["--from", "git+https://github.com/o/r@v1.0", "r"], False),
            ("uvx", ["--from", "git+https://github.com/o/r@main", "r"], True),
            ("docker", ["run", "-i", "--rm", "image"], True),
            ("docker", ["run", "-i", "image:latest"], True),
            ("docker", ["run", "-i", "image:stable"], True),
            ("docker", ["run", "ghcr.io/o/img:main"], True),
            ("docker", ["run", "-i", "-e", "X=1", "ghcr.io/o/image:1.2"], False),
            ("docker", ["run", "img:1.4.2"], False),
            ("docker", ["run", "image@sha256:abc"], False),
            ("docker", ["run", "-v", "/a:/b", "registry:5000/image"], True),
            ("docker", ["run", "-i", "--rm", "--memory", "512m", "img:1.0"], False),
            ("docker", ["run", "--pull", "always", "img:1.0"], False),
            ("docker", ["--context", "x", "run", "img"], True),
            ("docker", ["-H", "ssh://h", "run", "img:1.0"], False),
            ("node", ["server.js"], False),
            ("/usr/local/bin/npx.cmd", ["pkg"], True),
        ],
    )
    def test_package_pinning(self, command: str, args: list[str], unpinned: bool) -> None:
        assert _props({"command": command, "args": args})["package_unpinned"] is unpinned

    def test_each_unpinned_package_carries_its_reason(self) -> None:
        props = _props({"command": "npx", "args": ["-y", "pkg@^1.2.3"]})
        assert props["unpinned_packages"] == ["pkg@^1.2.3"]
        assert props["unpinned_reasons"] == ["pkg@^1.2.3: range"]

    def test_the_rule_says_ranges_are_unpinned_by_policy(self) -> None:
        from threatcode.engine.rules.loader import load_builtin_rules

        rule = next(r for r in load_builtin_rules() if r.id == "MCP_UNPINNED_PACKAGE")
        assert "semver range" in rule.description
        assert "by policy" in rule.description.lower()
        assert "range" in rule.mitigation


class TestFilesystem:
    @pytest.mark.parametrize(
        "path",
        [
            "/",
            "~",
            "~/",
            "$HOME",
            "${HOME}",
            "${env:HOME}",
            "${userHome}",
            "%USERPROFILE%",
            "$env:USERPROFILE",
            "/Users",
            "/Users/",
            "/Users/alice",
            "/Users/alice/",
            "/home",
            "/home/bob",
            "/root",
            "/mnt",
            "/Volumes",
            "/mnt/c",
            "C:\\",
            "C:/",
            "C:\\Users",
            "C:\\Users\\dev",
            "D:\\",
            "~/..",
            "/Users/alice/projects/..",
        ],
    )
    def test_broad_filesystem_roots(self, path: str) -> None:
        props = _props(
            {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", path]}
        )
        assert props["broad_filesystem_access"] is True
        assert props["broad_filesystem_paths"] == [path]

    @pytest.mark.parametrize(
        "path",
        [
            "/Users/alice/src/app",
            "~/projects/shop",
            "${HOME}/src",
            "${workspaceFolder}",
            "./docs",
            "/srv/data",
            "/opt/app",
            "C:\\work\\shop",
            "/home/bob/src",
            "%USERPROFILE%\\src",
        ],
    )
    def test_scoped_filesystem_roots_are_not_broad(self, path: str) -> None:
        props = _props(
            {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", path]}
        )
        assert props["broad_filesystem_access"] is False

    @pytest.mark.parametrize(
        "path",
        [
            "~/.ssh",
            "~/.ssh/",
            "/Users/me/.aws",
            "/Users/me/.aws/credentials",
            "${env:HOME}/.gnupg",
            "%USERPROFILE%\\.kube",
            "$HOME/.config/gcloud",
            "~/Library/Keychains",
            "/etc",
            "/etc/ssh",
            "/var/run",
            "/var/run/docker.sock",
            "/proc",
            "/sys",
            "/dev",
            "C:\\Windows\\System32",
        ],
    )
    def test_credential_and_system_paths_are_reported_separately(self, path: str) -> None:
        props = _props(
            {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", path]}
        )
        assert props["exposes_sensitive_paths"] is True
        assert props["sensitive_filesystem_paths"] == [path]
        assert props["broad_filesystem_access"] is False

    def test_a_path_can_be_both_broad_and_sensitive_in_the_right_fields(self) -> None:
        props = _props(
            {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/", "/etc", "~/.ssh"],
            }
        )
        assert props["broad_filesystem_paths"] == ["/"]
        assert props["sensitive_filesystem_paths"] == ["/etc", "~/.ssh"]

    def test_allowed_directories_flag_form_on_any_server(self) -> None:
        props = _props(
            {"command": "npx", "args": ["-y", "acme-fs-mcp@1.0.0", "--allowed-directories=/"]}
        )
        assert props["broad_filesystem_access"] is True
        spaced = _props({"command": "npx", "args": ["-y", "acme-tool@1.0.0", "--root", "/home"]})
        assert spaced["broad_filesystem_access"] is True

    def test_a_custom_named_filesystem_server_is_flagged_by_its_package_words(self) -> None:
        props = _props({"command": "npx", "args": ["-y", "mcp-server-fs@1.0.0", "/Users/alice"]})
        assert props["broad_filesystem_access"] is True

    def test_a_bare_home_path_on_a_server_that_is_not_a_filesystem_server_is_ignored(self) -> None:
        props = _props({"command": "node", "args": ["server.js", "/Users/alice"]})
        assert props["broad_filesystem_access"] is False
        other = _props({"command": "npx", "args": ["-y", "pkg@1.0.0", "/Users/alice"]})
        assert other["broad_filesystem_access"] is False

    def test_the_server_script_path_is_not_a_root(self) -> None:
        props = _props(
            {"command": "node", "args": ["/home/me/mcp-servers/terminal-themes/index.js"]}
        )
        assert props["broad_filesystem_access"] is False
        assert props["exposes_shell_exec"] is False

    @pytest.mark.parametrize(
        ("raw", "normalized"),
        [
            ("~", "~"),
            ("~/", "~"),
            ("$HOME", "~"),
            ("${HOME}/", "~"),
            ("${env:HOME}", "~"),
            ("${userHome}/src", "~/src"),
            ("%USERPROFILE%", "~"),
            ("%USERPROFILE%\\.ssh", "~/.ssh"),
            ("$env:USERPROFILE\\docs", "~/docs"),
            ("/Users/me/", "/Users/me"),
            ("/a/./b//c/", "/a/b/c"),
            ("/a/b/..", "/a"),
            ("C:\\Users\\dev\\", "C:/Users/dev"),
            ("c:/", "C:/"),
            ("C:", "C:/"),
            ("~/..", "~/.."),
            ('"/Users/me"', "/Users/me"),
        ],
    )
    def test_path_normalization(self, raw: str, normalized: str) -> None:
        assert normalize_path(raw) == normalized

    def test_classifier_edges(self) -> None:
        assert is_broad_path("/") and is_broad_path("~") and is_broad_path("/Users/me")
        assert not is_broad_path("/Users/me/src") and not is_broad_path("")
        assert (
            is_sensitive_path("~/.ssh")
            and not is_sensitive_path("~/ssh")
            and not is_sensitive_path("")
        )


class TestContainerExposure:
    @pytest.mark.parametrize(
        "flags",
        [
            ["--privileged"],
            ["--privileged=true"],
            ["--network", "host"],
            ["--net=host"],
            ["--pid=host"],
            ["--userns=host"],
            ["--cap-add", "SYS_ADMIN"],
            ["--cap-add", "NET_ADMIN"],
            ["--cap-add=BPF"],
            ["--device", "/dev/mem"],
            ["--security-opt", "seccomp=unconfined"],
            ["--user", "root"],
            ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
            ["-v", "/:/host"],
            ["-v", "/etc:/etc"],
            ["-v", "/var/run:/var/run"],
            ["--mount", "type=bind,source=/,target=/host"],
            ["--mount", "type=bind,source=/proc,target=/p"],
        ],
    )
    def test_privileged_container_flags(self, flags: list[str]) -> None:
        args = ["run", "-i", "--rm", *flags, "image@sha256:abc"]
        props = _props({"command": "docker", "args": args})
        assert props["container_privileged"] is True
        assert props["container_flags"]

    def test_unprivileged_container(self) -> None:
        args = ["run", "-i", "--rm", "--cap-drop=ALL", "-v", "/src:/src:ro", "image@sha256:abc"]
        assert _props({"command": "podman", "args": args})["container_privileged"] is False

    def test_privileged_false_is_clean(self) -> None:
        args = ["run", "--privileged=false", "image@sha256:abc"]
        assert _props({"command": "docker", "args": args})["container_privileged"] is False

    def test_a_home_bind_mount_is_broad_filesystem_access(self) -> None:
        args = ["run", "-i", "-v", "/Users/me:/projects", "ghcr.io/o/img:1.0"]
        props = _props({"command": "docker", "args": args})
        assert props["broad_filesystem_access"] is True
        assert props["broad_filesystem_paths"] == ["/Users/me"]
        assert props["container_privileged"] is False

    def test_a_credential_bind_mount_is_sensitive_not_broad(self) -> None:
        args = ["run", "-i", "-v", "/Users/me/.ssh:/root/.ssh:ro", "ghcr.io/o/img:1.0"]
        props = _props({"command": "docker", "args": args})
        assert props["sensitive_filesystem_paths"] == ["/Users/me/.ssh"]
        assert props["broad_filesystem_access"] is False

    def test_a_named_volume_is_not_a_host_path(self) -> None:
        args = ["run", "-v", "data:/data", "ghcr.io/o/img:1.0"]
        props = _props({"command": "docker", "args": args})
        assert props["broad_filesystem_paths"] == []

    def test_the_containers_fixture(self) -> None:
        servers = _by_name(MCP_FIXTURES / "containers" / ".mcp.json")
        privileged = {n for n, p in servers.items() if p["container_privileged"]}
        assert privileged == {"net-admin", "privileged-true", "device", "etc-mount", "root-user"}
        assert servers["home-mount"]["broad_filesystem_access"] is True
        assert servers["not-privileged"]["container_privileged"] is False
        assert servers["not-privileged"]["package_unpinned"] is False
        assert servers["not-privileged"]["container_lacks_no_new_privileges"] is False
        assert servers["net-admin"]["container_lacks_no_new_privileges"] is True

    def test_the_filesystem_fixture(self) -> None:
        servers = _by_name(MCP_FIXTURES / "filesystem" / ".mcp.json")
        assert {n for n, p in servers.items() if p["exposes_sensitive_paths"]} == {"ssh-dir", "etc"}
        assert {n for n, p in servers.items() if p["broad_filesystem_access"]} == {
            "env-home",
            "windows-home",
            "custom-name",
        }
        assert servers["scoped"]["broad_filesystem_access"] is False


class TestShellExec:
    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("npx", ["-y", "@wonderwhy-er/desktop-commander@0.2.52"]),
            ("npx", ["-y", "mcp-server-commands"]),
            ("npx", ["-y", "acme-shell-mcp"]),
            ("npx", ["-y", "iterm-mcp"]),
            ("npx", ["-y", "ssh-mcp@1.0.0"]),
            ("uvx", ["mcp-server-ssh"]),
            ("uvx", ["mcp-shell-server==1.1.12"]),
            ("cmd", ["/c", "npx", "-y", "mcp-server-commands"]),
            ("python", ["-m", "mcp_server_shell"]),
            ("mcp-shell-server", []),
            ("docker", ["run", "-i", "ghcr.io/acme/mcp-terminal:1.0.0"]),
        ],
    )
    def test_shell_exec_servers(self, command: str, args: list[str]) -> None:
        assert _props({"command": command, "args": args})["exposes_shell_exec"] is True

    @pytest.mark.parametrize(
        ("command", "args"),
        [
            ("npx", ["-y", "@modelcontextprotocol/server-memory"]),
            ("node", ["/Users/me/projects/mcp-shell-docs/server.js"]),
            ("node", ["/home/me/mcp-servers/terminal-themes/index.js"]),
            ("npx", ["-y", "pkg@1.0.0", "/srv/mcp-shell-docs"]),
            ("npx", ["-y", "shell-themes"]),
            ("python", ["-m", "docs_server", "--topic", "mcp-shell"]),
        ],
    )
    def test_directories_and_unrelated_packages_are_not_shell_servers(
        self, command: str, args: list[str]
    ) -> None:
        assert _props({"command": command, "args": args})["exposes_shell_exec"] is False

    def test_the_server_key_name_is_not_a_signal(self) -> None:
        props = _props(
            {"command": "npx", "args": ["-y", "@acme/notes-mcp@1.0.0"]}, name="shell-mcp"
        )
        assert props["exposes_shell_exec"] is False


class TestDisabledServers:
    def test_the_disabled_fixture(self) -> None:
        servers = _by_name(MCP_FIXTURES / "disabled" / ".mcp.json")
        assert {n for n, p in servers.items() if p["disabled"]} == {
            "off-by-flag",
            "off-by-enabled",
            "off-by-list",
            "off-with-secret",
        }
        assert servers["on"]["disabled"] is False

    def test_every_server_has_a_disabled_flag(self) -> None:
        assert _props({"command": "node"})["disabled"] is False

    @pytest.mark.parametrize(
        ("entry", "disabled"),
        [
            ({"command": "node", "disabled": True}, True),
            ({"command": "node", "disabled": False}, False),
            ({"command": "node", "enabled": False}, True),
            ({"command": "node", "enabled": True}, False),
            ({"command": "node", "disabled": "no"}, False),
        ],
    )
    def test_the_entry_flags(self, entry: dict[str, Any], disabled: bool) -> None:
        assert _props(entry)["disabled"] is disabled

    def test_a_project_level_disabled_list_applies_to_that_project_only(self) -> None:
        servers = _servers(MCP_FIXTURES / "claude_json_collision" / ".claude.json")
        archives = [p for a, p in servers.items() if a.endswith(".archive")]
        assert len(archives) == 1  # app-a lists archive as disabled but has no such server
        assert archives[0]["disabled"] is False

    def test_a_top_level_disabled_list(self) -> None:
        parsed = MCPConfigParser().parse(
            {
                "disabledMcpServers": ["a"],
                "mcpServers": {"a": {"command": "node"}, "b": {"command": "node"}},
            }
        )
        flags = {
            r.name: r.properties["disabled"]
            for r in parsed.resources
            if r.resource_type == "mcp_server"
        }
        assert flags == {"a": True, "b": False}

    def test_the_disabled_mcpjson_list_marks_servers_disabled(self) -> None:
        parsed = MCPConfigParser().parse(
            {
                "projects": {
                    "/p/x": {
                        "disabledMcpjsonServers": ["a"],
                        "mcpServers": {"a": {"command": "node"}},
                    }
                }
            }
        )
        assert parsed.resources[0].properties["disabled"] is True


class TestScopesAndAddresses:
    def test_two_projects_sharing_a_basename_get_distinct_addresses(self) -> None:
        servers = _servers(MCP_FIXTURES / "claude_json_collision" / ".claude.json")
        github = [a for a in servers if a.endswith(".github")]
        assert len(github) == 2
        assert len(set(github)) == 2
        assert all(a.startswith("mcp_server.app-") for a in github)

    def test_the_address_hash_is_stable_across_parses_and_depends_on_the_full_path(self) -> None:
        data = {
            "projects": {
                "/work/a/app": {"mcpServers": {"s": {"command": "node"}}},
                "/work/b/app": {"mcpServers": {"s": {"command": "node"}}},
            }
        }
        first = [r.address for r in MCPConfigParser().parse(data).resources]
        second = [r.address for r in MCPConfigParser().parse(data).resources]
        assert first == second
        assert len(set(first)) == len(first)

    def test_the_project_secret_is_not_lost_to_the_other_project(self) -> None:
        result = scan_files([MCP_FIXTURES / "claude_json_collision" / ".claude.json"])
        secret_hits = [t for t in result.threats if t.rule_id == "MCP_SECRET_IN_CONFIG"]
        assert len(secret_hits) == 1
        assert len([n for n in result.graph.nodes.values() if n.name == "github"]) == 2
        assert result.graph.duplicate_count == 0

    def test_the_basename_is_readable_in_the_properties_and_a_weird_one_is_sanitized(self) -> None:
        parsed = MCPConfigParser().parse(
            {"projects": {"/work/my app (v2)": {"mcpServers": {"s": {"command": "node"}}}}}
        )
        server = parsed.resources[0]
        assert server.properties["scope"] == "my app (v2)"
        assert server.address.startswith("mcp_server.my_app_v2-")
        assert server.name == "s"

    def test_the_file_scope_keeps_the_plain_address(self) -> None:
        assert (
            MCPConfigParser().parse({"mcpServers": {"a": {"command": "node"}}}).resources[0].address
            == "mcp_server.a"
        )

    def test_address_hash_collision_is_disambiguated_by_the_graph(self) -> None:
        # Two servers that end up with one address stay two nodes
        from threatcode.ir.graph import InfraGraph

        parsed = MCPConfigParser().parse({"mcpServers": {"a": {"command": "node"}}})
        twin = MCPConfigParser().parse({"mcpServers": {"a": {"command": "npx", "args": ["pkg"]}}})
        parsed.resources.extend(twin.resources)
        graph = InfraGraph.from_parsed(parsed)
        assert {"mcp_server.a", "mcp_server.a#2"} <= set(graph.nodes)
        assert graph.duplicate_count >= 1


class TestAgentNode:
    def test_each_scope_gets_one_agent_with_an_edge_pair_per_enabled_server(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "vulnerable" / ".mcp.json")
        agents = [r for r in parsed.resources if r.resource_type == "mcp_agent"]
        assert [a.address for a in agents] == ["mcp_agent.config"]
        invokes = [e for e in parsed.edges if e.edge_type == "iam_binding"]
        returns = [e for e in parsed.edges if e.edge_type == "data_flow"]
        assert {(e.source, e.target) for e in invokes} == {
            ("mcp_agent.config", f"mcp_server.{n}")
            for n in ("weather", "home-files", "terminal", "builder", "inventory")
        }
        assert {(e.target, e.source) for e in returns} == {(e.source, e.target) for e in invokes}
        assert all(e.declared is False for e in parsed.edges)
        assert {e.metadata["relation"] for e in invokes} == {"invokes"}
        assert {e.metadata["relation"] for e in returns} == {"returns_content"}

    def test_edges_carry_protocol_and_authentication(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "fixed" / ".mcp.json")
        by_server = {e.target: e for e in parsed.edges if e.edge_type == "iam_binding"}
        assert by_server["mcp_server.inventory"].metadata["protocol"] == "https"
        assert by_server["mcp_server.inventory"].metadata["authenticated"] is True
        assert by_server["mcp_server.weather"].metadata["protocol"] == "stdio"

    def test_a_server_without_a_credential_leaves_the_authenticated_flag_off(self) -> None:
        # RW-06: the lack of a credential shows nothing, because a client that follows the MCP
        # authorization spec discovers OAuth when it connects; so the edge says nothing, it does
        # not say False
        parsed = _parse({"type": "http", "url": "https://docs.example.org/mcp"})
        edges = [
            e for e in parsed.edges if e.source.startswith("mcp_") or e.target.startswith("mcp_")
        ]
        assert len(edges) == 2
        for edge in edges:
            assert "authenticated" not in edge.metadata
            assert edge.metadata["protocol"] == "https"

    def test_a_stdio_server_leaves_the_authenticated_flag_off(self) -> None:
        parsed = _parse({"command": "node", "args": ["server.js"]})
        assert all("authenticated" not in e.metadata for e in parsed.edges)

    @pytest.mark.parametrize(
        "entry",
        [
            {
                "type": "http",
                "url": "https://docs.example.org/mcp",
                "headers": {"Authorization": "Bearer ${T}"},
            },
            {"type": "http", "url": "https://docs.example.org/mcp", "oauth": {"clientId": "x"}},
            {"type": "http", "url": "https://user:pw@docs.example.org/mcp"},
        ],
        ids=["authorization-header", "oauth-block", "userinfo-in-url"],
    )
    def test_a_configured_credential_sets_the_flag_to_true_on_both_edges(
        self, entry: dict[str, Any]
    ) -> None:
        parsed = _parse(entry)
        flags = [e.metadata.get("authenticated") for e in parsed.edges]
        assert flags == [True, True]
        assert False not in flags

    def test_the_agent_is_wired_to_enabled_servers_only(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "disabled" / ".mcp.json")
        targets = {e.target for e in parsed.edges if e.edge_type == "iam_binding"}
        assert targets == {"mcp_server.on"}
        agent = next(r for r in parsed.resources if r.resource_type == "mcp_agent")
        assert agent.properties["server_count"] == 5
        assert agent.properties["enabled_server_count"] == 1

    def test_a_scope_with_only_disabled_servers_has_no_agent(self) -> None:
        parsed = MCPConfigParser().parse(
            {"mcpServers": {"a": {"command": "node", "disabled": True}}}
        )
        assert [r.resource_type for r in parsed.resources] == ["mcp_server"]
        assert parsed.edges == []

    def test_each_project_scope_has_its_own_agent(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "claude_json_collision" / ".claude.json")
        agents = [r for r in parsed.resources if r.resource_type == "mcp_agent"]
        assert len(agents) == 2
        assert len({a.address for a in agents}) == 2
        assert all(a.address.startswith("mcp_agent.app-") for a in agents)

    def test_the_agent_node_is_private_compute_and_wired_in_the_graph(self) -> None:
        graph = scan_files([MCP_FIXTURES / "fixed" / ".mcp.json"]).graph
        agent = graph.nodes["mcp_agent.config"]
        assert agent.category.value == "compute"
        assert agent.trust_zone.value == "private"
        assert {e.target for e in graph.edges_from(agent.id)} >= {"mcp_server.weather"}
        assert any(e.source == "mcp_server.inventory" and e.target == agent.id for e in graph.edges)


class TestDiagnostics:
    def test_unknown_servers_are_listed_as_unknown_capability(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "unknown_servers" / ".mcp.json")
        infos = [d for d in parsed.diagnostics if d.code == "mcp.unknown_capability"]
        assert len(infos) == 2
        assert {d.level for d in infos} == {"info"}
        assert {d.line for d in infos} == {3, 7}

    def test_known_servers_raise_no_unknown_capability_info(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "trifecta" / ".mcp.json")
        names = {
            d.message.split("'")[1]
            for d in parsed.diagnostics
            if d.code == "mcp.unknown_capability"
        }
        assert names == {"tracker"}

    def test_a_disabled_server_raises_no_unknown_capability_info(self) -> None:
        parsed = MCPConfigParser().parse(
            {"mcpServers": {"a": {"command": "npx", "args": ["x"], "disabled": True}}}
        )
        assert not [d for d in parsed.diagnostics if d.code == "mcp.unknown_capability"]


class TestHostileInput:
    """Hostile values are judged in bounded time and never crash the parser."""

    # The ids are named: a value of 200,000 characters as a test id is longer than a Windows
    # environment variable may be, and pytest keeps the id of the running test in one
    @pytest.mark.parametrize(
        "value",
        [
            pytest.param("${" * 100_000, id="open-placeholders"),
            pytest.param("<" * 200_000, id="angle-brackets"),
            pytest.param("{{" * 100_000, id="double-braces"),
            pytest.param("${A:-" * 40_000, id="nested-defaults"),
            pytest.param("x-here" * 40_000, id="repeated-word"),
        ],
    )
    def test_a_value_built_to_make_the_placeholder_scan_slow_stays_fast(self, value: str) -> None:
        import time

        started = time.monotonic()
        props = _props({"command": "node", "env": {"API_TOKEN": value}})
        assert time.monotonic() - started < 3
        assert isinstance(props["has_literal_secret"], bool)

    def test_odd_arguments_do_not_crash_the_parser(self) -> None:
        args = ["\x00", "'", '"', "\\", "--", "-", "", "\U0001f44d", "-e", "--env=", "--token"]
        for command in ("cmd", "bash", "env", "docker", "npx", "uvx", "sudo", "supergateway", ""):
            assert _props({"command": command, "args": args}) is not None
            assert _props({"command": command, "args": args[::-1]}) is not None

    def test_a_malformed_url_is_not_a_crash(self) -> None:
        for url in ("http://[::1", "https://u:p@h/%zz?a=b&&c", "http://", "://", "ws://x:99999999"):
            props = _props({"type": "http", "url": url})
            assert isinstance(props["is_remote"], bool)
