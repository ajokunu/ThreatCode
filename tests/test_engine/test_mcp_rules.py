"""Tests for MCP client configuration rules."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.engine.rules.loader import Rule, load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import TrustZone
from threatcode.parsers import detect_and_parse

MCP_FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"

MCP_RULE_IDS = {
    "MCP_SECRET_IN_CONFIG",
    "MCP_PLAINTEXT_TRANSPORT",
    "MCP_REMOTE_NO_AUTH",
    "MCP_UNPINNED_PACKAGE",
    "MCP_BROAD_FILESYSTEM",
    "MCP_SHELL_EXEC",
    "MCP_CONTAINER_PRIVILEGED",
}

_MCP_ID_RE = re.compile(r"^MCP(0[1-9]|10):2025$")
_ASI_ID_RE = re.compile(r"^ASI(0[1-9]|10)$")


@pytest.fixture(scope="module")
def mcp_rules() -> list[Rule]:
    return [r for r in load_all_rules() if r.matches_type("mcp_server")]


def _fired(relpath: str) -> set[tuple[str, str]]:
    path = MCP_FIXTURES / relpath
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    report = HybridEngine().analyze(graph, input_file=str(path))
    return {(t.resource_address, t.rule_id) for t in report.threats}


class TestMcpRuleDefinitions:
    def test_all_rules_loaded(self, mcp_rules: list[Rule]) -> None:
        assert {r.id for r in mcp_rules} == MCP_RULE_IDS

    def test_rules_map_to_owasp_ids(self, mcp_rules: list[Rule]) -> None:
        for rule in mcp_rules:
            owasp = rule.metadata["owasp"]
            assert owasp["mcp_top_10"], rule.id
            assert owasp["agentic_top_10"], rule.id
            assert all(_MCP_ID_RE.match(i) for i in owasp["mcp_top_10"]), rule.id
            assert all(_ASI_ID_RE.match(i) for i in owasp["agentic_top_10"]), rule.id

    def test_rules_map_to_known_attack_techniques(self, mcp_rules: list[Rule]) -> None:
        for rule in mcp_rules:
            techniques = rule.metadata["mitre"]["techniques"]
            assert techniques, rule.id
            assert all(t in TECHNIQUE_DB for t in techniques), rule.id


class TestVulnerableFixture:
    def test_every_rule_fires_on_its_entry(self) -> None:
        assert _fired("vulnerable/.mcp.json") == {
            ("mcp_server.weather", "MCP_SECRET_IN_CONFIG"),
            ("mcp_server.weather", "MCP_UNPINNED_PACKAGE"),
            ("mcp_server.home-files", "MCP_BROAD_FILESYSTEM"),
            ("mcp_server.terminal", "MCP_SHELL_EXEC"),
            ("mcp_server.builder", "MCP_CONTAINER_PRIVILEGED"),
            ("mcp_server.builder", "MCP_UNPINNED_PACKAGE"),
            ("mcp_server.inventory", "MCP_PLAINTEXT_TRANSPORT"),
            ("mcp_server.inventory", "MCP_REMOTE_NO_AUTH"),
        }

    def test_threats_carry_owasp_metadata(self) -> None:
        path = MCP_FIXTURES / "vulnerable" / ".mcp.json"
        graph = InfraGraph.from_parsed(detect_and_parse(path))
        report = HybridEngine().analyze(graph, input_file=str(path))
        secret = next(t for t in report.threats if t.rule_id == "MCP_SECRET_IN_CONFIG")
        assert secret.to_dict()["metadata"]["owasp"]["mcp_top_10"] == ["MCP01:2025"]
        assert secret.mitre_techniques == ["T1552.001"]

    def test_remote_server_placed_in_internet_zone(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(MCP_FIXTURES / "vulnerable" / ".mcp.json"))
        assert graph.nodes["mcp_server.inventory"].trust_zone == TrustZone.INTERNET
        assert graph.nodes["mcp_server.weather"].trust_zone == TrustZone.PRIVATE


class TestFixedFixture:
    def test_no_rules_fire(self) -> None:
        assert _fired("fixed/.mcp.json") == set()

    def test_loopback_server_stays_private(self) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(MCP_FIXTURES / "fixed" / ".mcp.json"))
        assert graph.nodes["mcp_server.local-dev"].trust_zone == TrustZone.PRIVATE


class TestOtherClients:
    def test_vscode_jsonc(self) -> None:
        assert _fired("vscode/.vscode/mcp.json") == {
            ("mcp_server.python-tools", "MCP_UNPINNED_PACKAGE"),
        }

    def test_cursor(self) -> None:
        assert _fired("project/.cursor/mcp.json") == {
            ("mcp_server.docs", "MCP_PLAINTEXT_TRANSPORT"),
            ("mcp_server.docs", "MCP_SECRET_IN_CONFIG"),
        }

    def test_claude_desktop(self) -> None:
        assert _fired("clients/claude_desktop_config.json") == {
            ("mcp_server.filesystem", "MCP_BROAD_FILESYSTEM"),
            ("mcp_server.filesystem", "MCP_UNPINNED_PACKAGE"),
        }

    def test_windsurf(self) -> None:
        assert _fired("clients/mcp_config.json") == {
            ("mcp_server.tickets", "MCP_PLAINTEXT_TRANSPORT"),
            ("mcp_server.tickets", "MCP_REMOTE_NO_AUTH"),
            ("mcp_server.shell", "MCP_SHELL_EXEC"),
        }

    def test_claude_code_user_config(self) -> None:
        assert _fired("clients/.claude.json") == {
            ("mcp_server.shop.db", "MCP_SECRET_IN_CONFIG"),
            ("mcp_server.shop.db", "MCP_UNPINNED_PACKAGE"),
        }
