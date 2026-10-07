"""Graph-level assertions on real-shape MCP and AI-agent configs.

The fixtures under ``tests/fixtures/real_shapes/mcp`` are client files as each client writes
them: ``mcp-remote`` wrappers, ``cmd /c`` launchers, ``docker run -e`` secrets, a
``~/.claude.json`` whose projects share a directory name, Gemini ``httpUrl`` servers and
disabled servers.

Today the parser reads each server's ``command`` and ``args`` as written, so a wrapper hides the
real package, a literal token passed with ``docker -e`` is missed, a remote server addressed with
``httpUrl`` is not remote, and two projects that share a basename collapse into one node.
Assertions that hold now run now; each one a later package delivers is its own pending test.
"""

from __future__ import annotations

from tests.helpers.graph_assert import assert_edge, assert_nodes, assert_path, assert_zone
from tests.helpers.pending import pending
from tests.helpers.scan import scan_real_shape

DESKTOP = "mcp/desktop/claude_desktop_config.json"
HOME = "mcp/claude_home/.claude.json"
GEMINI = "mcp/gemini/settings.json"
PROJECT = "mcp/project/.mcp.json"


def _servers(path: str) -> dict[str, object]:
    """Server nodes of a scan, keyed by the server's own name."""
    graph = scan_real_shape(path).graph
    return {n.name: n for n in graph.nodes.values() if n.resource_type == "mcp_server"}


class TestDesktopConfig:
    def test_every_server_is_a_node_named_after_its_key(self) -> None:
        names = set(_servers(DESKTOP))
        assert names == {"remote-docs", "legacy-http-bridge", "windows-files", "github", "git"}

    def test_local_launchers_are_in_the_private_zone(self) -> None:
        graph = scan_real_shape(DESKTOP).graph
        assert_zone(graph, "mcp_server.git", "private")
        assert_zone(graph, "mcp_server.windows-files", "private")

    def test_an_unpinned_uvx_package_is_flagged(self) -> None:
        props = _servers(DESKTOP)["git"].properties  # type: ignore[attr-defined]
        assert props["package_unpinned"] is True

    @pending("WP-2-6", "an mcp-remote wrapper lifts its URL, so the server is remote")
    def test_the_mcp_remote_wrapper_is_a_remote_server_in_the_internet_zone(self) -> None:
        graph = scan_real_shape(DESKTOP).graph
        props = graph.nodes["mcp_server.remote-docs"].properties
        assert props["is_remote"] is True
        assert_zone(graph, "mcp_server.remote-docs", "internet")

    @pending("WP-2-6", "mcp-remote --allow-http over a plain http URL is plaintext transport")
    def test_the_http_bridge_uses_plaintext_transport(self) -> None:
        props = scan_real_shape(DESKTOP).graph.nodes["mcp_server.legacy-http-bridge"].properties
        assert props["uses_plaintext_transport"] is True

    def test_a_broad_windows_path_is_flagged_even_behind_a_cmd_launcher(self) -> None:
        props = scan_real_shape(DESKTOP).graph.nodes["mcp_server.windows-files"].properties
        assert props["broad_filesystem_access"] is True

    @pending("WP-2-6", "cmd /c is unwrapped, so the npx package behind it is checked for pinning")
    def test_the_package_behind_the_cmd_launcher_is_unpinned(self) -> None:
        props = scan_real_shape(DESKTOP).graph.nodes["mcp_server.windows-files"].properties
        assert props["package_unpinned"] is True

    @pending("WP-2-6", "docker run -e KEY=value arguments are scanned for literal secrets")
    def test_the_docker_server_has_a_literal_token(self) -> None:
        props = scan_real_shape(DESKTOP).graph.nodes["mcp_server.github"].properties
        assert props["has_literal_secret"] is True

    @pending("WP-2-6", "secret-bearing arguments are redacted in properties['args']")
    def test_the_literal_token_is_not_stored_in_the_graph(self) -> None:
        props = scan_real_shape(DESKTOP).graph.nodes["mcp_server.github"].properties
        assert "ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in str(props)

    @pending("WP-2-6", "each config scope gets an mcp_agent node with an edge to every server")
    def test_one_agent_node_is_connected_to_every_server(self) -> None:
        graph = scan_real_shape(DESKTOP).graph
        agents = [n for n in graph.nodes.values() if n.resource_type == "mcp_agent"]
        assert len(agents) == 1
        for name in ("remote-docs", "windows-files", "github", "git"):
            assert_edge(graph, agents[0].id, f"mcp_server.{name}")


class TestClaudeHome:
    def test_the_user_scoped_server_is_a_node(self) -> None:
        assert "memory" in _servers(HOME)

    @pending(
        "WP-2-6", "project-scoped addresses hash the full project path so basenames cannot collide"
    )
    def test_two_projects_sharing_a_basename_keep_both_servers(self) -> None:
        graph = scan_real_shape(HOME).graph
        postgres = [n for n in graph.nodes.values() if n.name == "postgres"]
        assert len(postgres) == 2
        assert len({n.id for n in postgres}) == 2

    @pending("WP-2-6", "a project's disabledMcpjsonServers mark servers disabled")
    def test_the_work_and_personal_servers_keep_their_own_connection_strings(self) -> None:
        graph = scan_real_shape(HOME).graph
        texts = sorted(
            str(n.properties.get("args")) for n in graph.nodes.values() if n.name == "postgres"
        )
        assert any("db.work.example.com" in t for t in texts)
        assert any("localhost" in t for t in texts)


class TestGeminiSettings:
    def test_both_servers_are_nodes(self) -> None:
        assert set(_servers(GEMINI)) == {"internal-search", "local-tools"}

    def test_the_literal_bearer_token_is_found(self) -> None:
        props = _servers(GEMINI)["internal-search"].properties  # type: ignore[attr-defined]
        assert props["has_literal_secret"] is True

    @pending("WP-2-6", "httpUrl is read like url, so the Gemini server is remote")
    def test_the_httpurl_server_is_remote_and_in_the_internet_zone(self) -> None:
        graph = scan_real_shape(GEMINI).graph
        assert graph.nodes["mcp_server.internal-search"].properties["is_remote"] is True
        assert_zone(graph, "mcp_server.internal-search", "internet")


class TestProjectConfig:
    def test_every_server_is_a_node_including_the_disabled_one(self) -> None:
        graph = scan_real_shape(PROJECT).graph
        assert_nodes(
            graph,
            [
                "mcp_server.fetch",
                "mcp_server.filesystem-home",
                "mcp_server.scratch",
                "mcp_server.analytics",
            ],
            exact=True,
        )

    def test_the_remote_server_is_in_the_internet_zone_and_the_others_are_private(self) -> None:
        graph = scan_real_shape(PROJECT).graph
        assert_zone(graph, "mcp_server.analytics", "internet")
        for name in ("fetch", "filesystem-home", "scratch"):
            assert_zone(graph, f"mcp_server.{name}", "private")

    def test_the_pinned_uvx_server_is_not_unpinned(self) -> None:
        props = scan_real_shape(PROJECT).graph.nodes["mcp_server.fetch"].properties
        assert props["package_unpinned"] is False

    @pending("WP-2-6", "disabled servers keep a node with disabled true and rules skip them")
    def test_the_disabled_server_is_marked_and_raises_no_finding(self) -> None:
        result = scan_real_shape(PROJECT)
        assert result.graph.nodes["mcp_server.scratch"].properties["disabled"] is True
        assert not result.threats_for("mcp_server.scratch")

    @pending("WP-2-6", "each config scope gets an mcp_agent node with an edge to enabled servers")
    def test_the_agent_is_connected_to_the_enabled_servers_only(self) -> None:
        graph = scan_real_shape(PROJECT).graph
        agents = [n for n in graph.nodes.values() if n.resource_type == "mcp_agent"]
        assert len(agents) == 1
        for name in ("fetch", "filesystem-home", "analytics"):
            assert_edge(graph, agents[0].id, f"mcp_server.{name}")

    @pending(
        "WP-4-1", "internet to an untrusted-content server, through the agent, to private data"
    )
    def test_untrusted_content_can_reach_the_home_directory_through_the_agent(self) -> None:
        graph = scan_real_shape(PROJECT).graph
        path = assert_path(graph, "internet", "mcp_server.filesystem-home")
        assert "mcp_server.fetch" in path
