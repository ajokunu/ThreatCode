"""Tests for the MCP client configuration parser."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatcode.exceptions import UnsupportedFormatError
from threatcode.parsers import detect_and_parse
from threatcode.parsers.mcp_config import MCPConfigParser, is_mcp_config, strip_jsonc

MCP_FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"
FIXTURES = Path(__file__).parent.parent / "fixtures"


def _servers(path: Path) -> dict[str, dict[str, object]]:
    parsed = detect_and_parse(path)
    assert parsed.format_type == "mcp_config"
    return {r.address: r.properties for r in parsed.resources}


def _props(entry: dict[str, object], name: str = "s") -> dict[str, object]:
    parsed = MCPConfigParser().parse({"mcpServers": {name: entry}})
    assert len(parsed.resources) == 1
    return parsed.resources[0].properties


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
        ],
    )
    def test_fixture_detected(self, relpath: str) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / relpath)
        assert parsed.format_type == "mcp_config"
        assert parsed.resources
        assert all(r.resource_type == "mcp_server" for r in parsed.resources)

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

    def test_claude_json_user_and_project_scopes(self) -> None:
        servers = _servers(MCP_FIXTURES / "clients" / ".claude.json")
        assert set(servers) == {"mcp_server.search", "mcp_server.shop.db"}

    def test_source_location_has_line_number(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "vulnerable" / ".mcp.json")
        by_name = {r.name: r for r in parsed.resources}
        assert by_name["weather"].source_location.endswith(".mcp.json:3")

    def test_values_are_not_stored(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "vulnerable" / ".mcp.json")
        dumped = json.dumps([r.properties for r in parsed.resources])
        assert "9f8e2c4b7a1d6e3f5c0b8a7d2e4f6c1b" not in dumped
        weather = next(r for r in parsed.resources if r.name == "weather")
        assert weather.properties["env_keys"] == ["WEATHER_API_KEY"]
        assert weather.properties["literal_secret_keys"] == ["env:WEATHER_API_KEY"]

    def test_non_dict_entries_skipped(self) -> None:
        parsed = MCPConfigParser().parse({"mcpServers": {"a": "x", "b": {"command": "node"}}})
        assert [r.name for r in parsed.resources] == ["b"]


class TestSecrets:
    @pytest.mark.parametrize(
        "value",
        ["${API_KEY}", "${env:API_KEY}", "${input:api-key}", "<YOUR_API_KEY>", "", "$API_KEY"],
    )
    def test_placeholders_are_not_secrets(self, value: str) -> None:
        props = _props({"command": "node", "env": {"API_KEY": value}})
        assert props["has_literal_secret"] is False

    def test_literal_env_value_under_secret_name(self) -> None:
        props = _props({"command": "node", "env": {"SERVICE_TOKEN": "a8f3k2m9q7w1z5x0"}})
        assert props["literal_secret_keys"] == ["env:SERVICE_TOKEN"]

    def test_bearer_header_with_literal_token(self) -> None:
        props = _props(
            {"url": "https://h/mcp", "headers": {"Authorization": "Bearer a8f3k2m9q7w1z5x0"}}
        )
        assert props["literal_secret_keys"] == ["header:Authorization"]

    def test_bearer_header_with_placeholder(self) -> None:
        props = _props({"url": "https://h/mcp", "headers": {"Authorization": "Bearer ${TOKEN}"}})
        assert props["has_literal_secret"] is False
        assert props["has_configured_auth"] is True

    def test_secret_in_url_query(self) -> None:
        props = _props({"url": "https://h/mcp?api_key=a8f3k2m9q7w1z5x0&region=eu"})
        assert props["literal_secret_keys"] == ["url:api_key"]

    def test_connection_string_pattern(self) -> None:
        props = _props(
            {"command": "node", "env": {"DATABASE_URL": "postgres://u:Kq7vR2mXp9sLw4Tz@db:5432/x"}}
        )
        assert props["literal_secret_keys"] == ["env:DATABASE_URL"]

    @pytest.mark.parametrize(
        "env",
        [
            {"GITHUB_AUTHOR": "Aaron Lindahl"},
            {"PASSWORD_FILE": "/run/secrets/db_password"},
            {"AUTH_MODE": "oauth"},
            {"LOG_LEVEL": "debug-verbose-mode"},
        ],
    )
    def test_non_secret_values(self, env: dict[str, str]) -> None:
        assert _props({"command": "node", "env": env})["has_literal_secret"] is False


class TestTransport:
    def test_plaintext_remote(self) -> None:
        props = _props({"type": "http", "url": "http://mcp.corp.internal/mcp"})
        assert props["uses_plaintext_transport"] is True
        assert props["remote_without_configured_auth"] is True

    @pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "[::1]"])
    def test_plaintext_loopback_allowed(self, host: str) -> None:
        props = _props({"type": "http", "url": f"http://{host}:3000/mcp"})
        assert props["uses_plaintext_transport"] is False

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


class TestPinning:
    @pytest.mark.parametrize(
        ("command", "args", "unpinned"),
        [
            ("npx", ["-y", "@scope/pkg"], True),
            ("npx", ["-y", "@scope/pkg@1.2.3"], False),
            ("npx", ["-y", "@scope/pkg@latest"], True),
            ("npx", ["pkg"], True),
            ("npx", ["pkg@2.0.0", "--flag"], False),
            ("npx", ["-y", "-p", "pkg@1.0.0", "pkg-bin"], False),
            ("npx", ["-y", "--package=pkg", "pkg-bin"], True),
            ("bunx", ["pkg"], True),
            ("pnpm", ["dlx", "pkg@1.0.0"], False),
            ("pnpm", ["dlx", "pkg"], True),
            ("pnpm", ["install"], False),
            ("uvx", ["pkg"], True),
            ("uvx", ["pkg==1.2.3"], False),
            ("uvx", ["pkg@1.2.3"], False),
            ("uvx", ["--from", "pkg==1.0", "pkg-cli"], False),
            ("uvx", ["--from", "git+ssh://git@github.com/o/r", "r"], True),
            ("uvx", ["--from", "git+https://github.com/o/r@v1.0", "r"], False),
            ("docker", ["run", "-i", "--rm", "image"], True),
            ("docker", ["run", "-i", "image:latest"], True),
            ("docker", ["run", "-i", "-e", "X=1", "ghcr.io/o/image:1.2"], False),
            ("docker", ["run", "image@sha256:abc"], False),
            ("docker", ["run", "-v", "/a:/b", "registry:5000/image"], True),
            ("node", ["server.js"], False),
            ("/usr/local/bin/npx.cmd", ["pkg"], True),
        ],
    )
    def test_package_pinning(self, command: str, args: list[str], unpinned: bool) -> None:
        assert _props({"command": command, "args": args})["package_unpinned"] is unpinned


class TestPrivilege:
    @pytest.mark.parametrize(
        "path", ["/", "~", "~/", "$HOME", "${userHome}", "/Users/alice", "/home/bob", "C:\\"]
    )
    def test_broad_filesystem_roots(self, path: str) -> None:
        props = _props(
            {"command": "npx", "args": ["@modelcontextprotocol/server-filesystem", path]}
        )
        assert props["broad_filesystem_access"] is True

    def test_scoped_filesystem_root(self) -> None:
        args = ["@modelcontextprotocol/server-filesystem", "/Users/alice/src/app"]
        assert _props({"command": "npx", "args": args})["broad_filesystem_access"] is False

    def test_home_path_on_non_filesystem_server_ignored(self) -> None:
        props = _props({"command": "node", "args": ["server.js", "/Users/alice"]})
        assert props["broad_filesystem_access"] is False

    @pytest.mark.parametrize(
        "args",
        [
            ["-y", "@wonderwhy-er/desktop-commander@0.2.52"],
            ["-y", "mcp-server-commands"],
            ["-y", "acme-shell-mcp"],
        ],
    )
    def test_shell_exec_servers(self, args: list[str]) -> None:
        assert _props({"command": "npx", "args": args})["exposes_shell_exec"] is True

    def test_uvx_shell_server(self) -> None:
        props = _props({"command": "uvx", "args": ["mcp-shell-server==1.1.12"]})
        assert props["exposes_shell_exec"] is True

    def test_ordinary_server_not_shell(self) -> None:
        props = _props({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]})
        assert props["exposes_shell_exec"] is False

    @pytest.mark.parametrize(
        "flags",
        [
            ["--privileged"],
            ["--network", "host"],
            ["--net=host"],
            ["--pid=host"],
            ["--cap-add", "SYS_ADMIN"],
            ["--security-opt", "seccomp=unconfined"],
            ["-v", "/var/run/docker.sock:/var/run/docker.sock"],
            ["-v", "/:/host"],
            ["--mount", "type=bind,source=/,target=/host"],
        ],
    )
    def test_privileged_container_flags(self, flags: list[str]) -> None:
        args = ["run", "-i", "--rm", *flags, "image@sha256:abc"]
        assert _props({"command": "docker", "args": args})["container_privileged"] is True

    def test_unprivileged_container(self) -> None:
        args = ["run", "-i", "--rm", "--cap-drop=ALL", "-v", "/src:/src:ro", "image@sha256:abc"]
        assert _props({"command": "podman", "args": args})["container_privileged"] is False
