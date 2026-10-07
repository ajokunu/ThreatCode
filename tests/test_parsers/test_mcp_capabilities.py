"""Tests for the agent capability model (``_mcp_capabilities``) and the agent node."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from tests.helpers.scan import scan_files
from threatcode.parsers import detect_and_parse
from threatcode.parsers._mcp_capabilities import (
    CAN_EXFILTRATE_OR_ACT,
    CAPABILITY_TAGS,
    COMMAND_PATTERNS,
    IMAGES,
    INGESTS_UNTRUSTED_CONTENT,
    PACKAGES,
    READS_PRIVATE_DATA,
    ServerCapability,
    aggregate,
    basename_of,
    lookup,
    normalize_name,
    server_capability,
)
from threatcode.parsers.mcp_config import MCPConfigParser

MCP_FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"

R, U, A = READS_PRIVATE_DATA, INGESTS_UNTRUSTED_CONTENT, CAN_EXFILTRATE_OR_ACT

# The reviewed table, written out again so that adding or changing an entry fails a test
# until a reviewer has looked at it here too.
EXPECTED: dict[str, frozenset[str]] = {
    "@modelcontextprotocol/server-filesystem": frozenset({R}),
    "@modelcontextprotocol/server-memory": frozenset(),
    "@modelcontextprotocol/server-everything": frozenset(),
    "@modelcontextprotocol/server-sequential-thinking": frozenset(),
    "@modelcontextprotocol/server-postgres": frozenset({R}),
    "@modelcontextprotocol/server-sqlite": frozenset({R}),
    "@modelcontextprotocol/server-redis": frozenset({R}),
    "@modelcontextprotocol/server-github": frozenset({R, U, A}),
    "@modelcontextprotocol/server-gitlab": frozenset({R, U, A}),
    "@modelcontextprotocol/server-brave-search": frozenset({U}),
    "@modelcontextprotocol/server-puppeteer": frozenset({U, A}),
    "@modelcontextprotocol/server-slack": frozenset({R, U, A}),
    "@modelcontextprotocol/server-gdrive": frozenset({R, U}),
    "mcp-server-fetch": frozenset({U, A}),
    "mcp-server-git": frozenset({R}),
    "mcp-server-time": frozenset(),
    "mcp-server-sqlite": frozenset({R}),
    "@playwright/mcp": frozenset({U, A}),
    "@executeautomation/playwright-mcp-server": frozenset({U, A}),
    "@wonderwhy-er/desktop-commander": frozenset({R, A}),
    "mcp-server-commands": frozenset({R, A}),
    "super-shell-mcp": frozenset({R, A}),
    "mcp-shell-server": frozenset({R, A}),
    "mcp-server-shell": frozenset({R, A}),
    "iterm-mcp": frozenset({R, A}),
    "ssh-mcp": frozenset({R, A}),
    "mcp-server-ssh": frozenset({R, A}),
    "@notionhq/notion-mcp-server": frozenset({R, U, A}),
    "@upstash/context7-mcp": frozenset({U}),
    "duckduckgo-mcp-server": frozenset({U}),
}


def _agent(entries: dict[str, dict[str, Any]]) -> dict[str, Any]:
    parsed = MCPConfigParser().parse({"mcpServers": entries})
    agents = [r for r in parsed.resources if r.resource_type == "mcp_agent"]
    assert len(agents) == 1
    return agents[0].properties


class TestTable:
    def test_the_table_is_exactly_the_reviewed_one(self) -> None:
        assert {name: entry.tags for name, entry in PACKAGES.items()} == EXPECTED

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_each_entry_is_known_and_carries_its_tags(self, name: str) -> None:
        found = lookup(name)
        assert found is not None
        entry, how = found
        assert how == "package"
        assert entry.tags == EXPECTED[name]
        assert entry.note.strip()
        assert entry.tags <= set(CAPABILITY_TAGS)

    @pytest.mark.parametrize("name", sorted(EXPECTED))
    def test_each_entry_resolves_through_a_server_entry(self, name: str) -> None:
        capability = server_capability(name)
        assert capability.known is True
        assert capability.tags == EXPECTED[name]

    def test_pypi_names_match_with_underscores(self) -> None:
        assert lookup("mcp_server_fetch") is not None
        assert normalize_name("MCP_Server_Fetch") == "mcp-server-fetch"
        assert normalize_name("@Scope/Pkg_X") == "@scope/pkg_x"

    def test_every_image_entry_points_at_a_table_entry(self) -> None:
        assert IMAGES
        for image, entry in IMAGES.items():
            assert entry in PACKAGES.values(), image
            found = lookup(image, container=True)
            assert found is not None and found[1] == "image"

    def test_an_image_is_not_looked_up_as_a_package_and_the_reverse(self) -> None:
        assert lookup("docker.io/mcp/fetch") is None
        assert lookup("mcp-server-fetch", container=True) is None

    @pytest.mark.parametrize(
        ("name", "tags"),
        [
            ("acme-shell-mcp", {R, A}),
            ("mcp-terminal", {R, A}),
            ("@acme/terminal-mcp", {R, A}),
            ("playwright-tools", {U, A}),
            ("acme-puppeteer-server", {U, A}),
        ],
    )
    def test_name_patterns(self, name: str, tags: set[str]) -> None:
        found = lookup(name)
        assert found is not None
        assert found[1] == "pattern"
        assert found[0].tags == tags

    @pytest.mark.parametrize(
        "name",
        ["@acme/inventory-mcp", "shell-themes", "terminal-colors", "mcpx", "playwrights", ""],
    )
    def test_names_that_only_look_similar_are_unknown(self, name: str) -> None:
        assert lookup(name) is None

    def test_there_are_few_patterns_and_each_is_exercised_above(self) -> None:
        assert len(COMMAND_PATTERNS) == 2

    def test_basename_takes_the_part_after_the_scope(self) -> None:
        assert basename_of("@scope/Pkg_Name") == "pkg_name"
        assert basename_of("ghcr.io/o/img") == "img"


class TestServerCapability:
    def test_an_unknown_server_adds_nothing_and_is_unknown(self) -> None:
        capability = server_capability("@acme/inventory-mcp")
        assert capability == ServerCapability(frozenset(), False, "unknown")

    def test_structure_adds_tags_but_never_makes_a_server_known(self) -> None:
        remote = server_capability("", remote_server=True)
        assert remote.tags == {A}
        assert remote.known is False
        assert remote.source == "structure"
        files = server_capability("@acme/x", reaches_private_files=True)
        assert files.tags == {R} and files.known is False
        shell = server_capability("@acme/x", exposes_shell_exec=True)
        assert shell.tags == {R, A}

    def test_structure_adds_to_a_known_entry(self) -> None:
        capability = server_capability("mcp-server-time", remote_server=True)
        assert capability.known is True
        assert capability.tags == {A}

    def test_aggregation_unions_tags_and_lists_unknown_servers(self) -> None:
        result = aggregate(
            [
                ("files", server_capability("@modelcontextprotocol/server-filesystem")),
                ("mystery", server_capability("@acme/x")),
                ("web", server_capability("mcp-server-fetch")),
            ]
        )
        assert result.tags == {R, U, A}
        assert result.unknown_servers == ("mystery",)
        assert result.lethal_trifecta is True

    def test_two_of_three_is_not_a_trifecta(self) -> None:
        for names in (
            ["@modelcontextprotocol/server-filesystem"],
            ["mcp-server-fetch"],
            ["@modelcontextprotocol/server-filesystem", "@modelcontextprotocol/server-postgres"],
            ["@modelcontextprotocol/server-brave-search", "mcp-server-time"],
        ):
            result = aggregate((n, server_capability(n)) for n in names)
            assert result.lethal_trifecta is False, names

    def test_no_servers_is_no_capability(self) -> None:
        result = aggregate([])
        assert result.tags == frozenset() and result.unknown_servers == ()


class TestAgentProperties:
    def test_the_trifecta_fixture_has_all_three_capabilities(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "trifecta" / ".mcp.json")
        agent = next(r for r in parsed.resources if r.resource_type == "mcp_agent")
        props = agent.properties
        assert props[READS_PRIVATE_DATA] is True
        assert props[INGESTS_UNTRUSTED_CONTENT] is True
        assert props[CAN_EXFILTRATE_OR_ACT] is True
        assert props["capabilities"] == list(CAPABILITY_TAGS)
        assert props["unknown_capability_servers"] == ["tracker"]

    def test_the_same_config_without_the_untrusted_content_server_has_two(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "trifecta_missing_untrusted" / ".mcp.json")
        agent = next(r for r in parsed.resources if r.resource_type == "mcp_agent")
        assert agent.properties[INGESTS_UNTRUSTED_CONTENT] is False
        assert agent.properties["capabilities"] == [READS_PRIVATE_DATA, CAN_EXFILTRATE_OR_ACT]

    def test_unknown_servers_contribute_no_capability(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "unknown_servers" / ".mcp.json")
        agent = next(r for r in parsed.resources if r.resource_type == "mcp_agent")
        assert agent.properties["capabilities"] == []
        assert agent.properties["unknown_capability_servers"] == ["inventory", "billing"]

    def test_a_disabled_server_does_not_count(self) -> None:
        props = _agent(
            {
                "files": {
                    "command": "npx",
                    "args": ["@modelcontextprotocol/server-filesystem", "./x"],
                },
                "web": {"command": "uvx", "args": ["mcp-server-fetch"], "disabled": True},
            }
        )
        assert props[INGESTS_UNTRUSTED_CONTENT] is False
        assert props["enabled_server_count"] == 1
        assert props["server_count"] == 2

    def test_a_shell_server_alone_reads_and_acts(self) -> None:
        props = _agent({"shell": {"command": "npx", "args": ["-y", "mcp-server-commands"]}})
        assert props["capabilities"] == [READS_PRIVATE_DATA, CAN_EXFILTRATE_OR_ACT]

    def test_a_broad_filesystem_path_makes_any_server_read_private_data(self) -> None:
        props = _agent(
            {"x": {"command": "npx", "args": ["-y", "@acme/x@1.0.0", "--allowed-directories=/"]}}
        )
        assert props[READS_PRIVATE_DATA] is True

    def test_a_remote_server_can_exfiltrate_but_a_loopback_one_cannot(self) -> None:
        remote = _agent({"r": {"type": "http", "url": "https://h.example.com/mcp"}})
        assert remote[CAN_EXFILTRATE_OR_ACT] is True
        loopback = _agent({"r": {"type": "http", "url": "http://127.0.0.1:9/mcp"}})
        assert loopback[CAN_EXFILTRATE_OR_ACT] is False

    def test_a_docker_image_in_the_table_is_known(self) -> None:
        props = _agent(
            {
                "gh": {
                    "command": "docker",
                    "args": ["run", "-i", "ghcr.io/github/github-mcp-server:v0.5.0"],
                }
            }
        )
        assert props["capabilities"] == list(CAPABILITY_TAGS)
        assert props["unknown_capability_servers"] == []

    def test_capability_tags_are_on_each_server_too(self) -> None:
        parsed = detect_and_parse(MCP_FIXTURES / "trifecta" / ".mcp.json")
        servers = {
            r.name: r.properties for r in parsed.resources if r.resource_type == "mcp_server"
        }
        assert servers["files"]["capability_tags"] == [READS_PRIVATE_DATA]
        assert servers["files"]["capability_known"] is True
        assert servers["web"]["capability_tags"] == sorted(
            [INGESTS_UNTRUSTED_CONTENT, CAN_EXFILTRATE_OR_ACT]
        )
        assert servers["tracker"]["capability_known"] is False
        assert servers["tracker"]["capability_tags"] == [CAN_EXFILTRATE_OR_ACT]


class TestTrifectaRule:
    def test_the_rule_fires_on_the_agent_with_all_three(self) -> None:
        result = scan_files([MCP_FIXTURES / "trifecta" / ".mcp.json"])
        assert result.fired("MCP_LETHAL_TRIFECTA", "mcp_agent.config")

    def test_it_does_not_fire_with_one_capability_missing(self) -> None:
        result = scan_files([MCP_FIXTURES / "trifecta_missing_untrusted" / ".mcp.json"])
        assert "MCP_LETHAL_TRIFECTA" not in result.rule_ids

    def test_it_does_not_fire_on_unknown_servers(self) -> None:
        result = scan_files([MCP_FIXTURES / "unknown_servers" / ".mcp.json"])
        assert "MCP_LETHAL_TRIFECTA" not in result.rule_ids

    def test_each_enabled_project_is_judged_on_its_own_servers(self, tmp_path: Path) -> None:
        # The files server is in one project and the fetch server in another: no trifecta
        path = tmp_path / ".claude.json"
        path.write_text(
            '{"projects": {'
            '"/a": {"mcpServers": {"files": {"command": "npx", "args": '
            '["@modelcontextprotocol/server-filesystem", "./x"]}}},'
            '"/b": {"mcpServers": {"web": {"command": "uvx", "args": ["mcp-server-fetch"]}}}}}'
        )
        assert "MCP_LETHAL_TRIFECTA" not in scan_files([path]).rule_ids

    def test_the_finding_has_owasp_and_attack_metadata(self) -> None:
        result = scan_files([MCP_FIXTURES / "trifecta" / ".mcp.json"])
        threat = next(t for t in result.threats if t.rule_id == "MCP_LETHAL_TRIFECTA")
        metadata = threat.to_dict()["metadata"]
        assert metadata["owasp"]["mcp_top_10"] == ["MCP06:2025", "MCP10:2025"]
        assert metadata["owasp"]["agentic_top_10"] == ["ASI01", "ASI02"]
        assert threat.mitre_techniques == ["T1567"]
        assert threat.severity.value == "high"

    def test_the_rule_names_no_atlas_ids(self) -> None:
        from threatcode.engine.rules.loader import load_builtin_rules

        rule = next(r for r in load_builtin_rules() if r.id == "MCP_LETHAL_TRIFECTA")
        assert "controls" not in rule.metadata
        assert rule.confidence == "heuristic"
