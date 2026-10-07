"""Tests for MCP client configuration rules."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.helpers.scan import scan_files
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import TECHNIQUE_DB, is_revoked, tactics_for_techniques
from threatcode.engine.rules.loader import Rule, load_all_rules
from threatcode.engine.rules.matcher import matches_rule
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import TrustZone
from threatcode.parsers import detect_and_parse

MCP_FIXTURES = Path(__file__).parent.parent / "fixtures" / "mcp"

SERVER_RULE_IDS = {
    "MCP_SECRET_IN_CONFIG",
    "MCP_SECRET_LIKELY_IN_CONFIG",
    "MCP_PLAINTEXT_TRANSPORT",
    "MCP_REMOTE_NO_AUTH",
    "MCP_UNPINNED_PACKAGE",
    "MCP_BROAD_FILESYSTEM",
    "MCP_SENSITIVE_PATHS",
    "MCP_SHELL_EXEC",
    "MCP_CONTAINER_PRIVILEGED",
}
AGENT_RULE_IDS = {"MCP_LETHAL_TRIFECTA"}
MCP_RULE_IDS = SERVER_RULE_IDS | AGENT_RULE_IDS
# A credential in the file is a leak whether or not the server runs
SECRET_RULE_IDS = {"MCP_SECRET_IN_CONFIG", "MCP_SECRET_LIKELY_IN_CONFIG"}

_MCP_ID_RE = re.compile(r"^MCP(0[1-9]|10):2025$")
_ASI_ID_RE = re.compile(r"^ASI(0[1-9]|10)$")


@pytest.fixture(scope="module")
def mcp_rules() -> list[Rule]:
    return [
        r for r in load_all_rules() if r.matches_type("mcp_server") or r.matches_type("mcp_agent")
    ]


def _fired(relpath: str) -> set[tuple[str, str]]:
    path = MCP_FIXTURES / relpath
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    report = HybridEngine().analyze(graph, input_file=str(path))
    return {(t.resource_address, t.rule_id) for t in report.threats if t.rule_id}


def _fired_by_name(relpath: str) -> set[tuple[str, str]]:
    """Fired rules keyed by the server name (the address holds a project hash)."""
    result = scan_files([MCP_FIXTURES / relpath])
    return {
        (result.graph.nodes[t.resource_address].name, t.rule_id)
        for t in result.threats
        if t.rule_id
    }


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

    def test_rules_map_to_known_current_attack_techniques(self, mcp_rules: list[Rule]) -> None:
        for rule in mcp_rules:
            techniques = list(rule.metadata["mitre"]["techniques"])
            assert techniques, rule.id
            assert all(t in TECHNIQUE_DB for t in techniques), rule.id
            assert not [t for t in techniques if is_revoked(t)], rule.id

    def test_rule_tactics_are_the_tactics_of_their_techniques(self, mcp_rules: list[Rule]) -> None:
        for rule in mcp_rules:
            mitre = rule.metadata["mitre"]
            assert sorted(mitre["tactics"]) == tactics_for_techniques(list(mitre["techniques"])), (
                rule.id
            )

    def test_every_rule_declares_a_confidence_and_the_calibration_holds(
        self, mcp_rules: list[Rule]
    ) -> None:
        expected = {
            "MCP_SECRET_IN_CONFIG": "definitive",
            "MCP_SECRET_LIKELY_IN_CONFIG": "heuristic",
            "MCP_PLAINTEXT_TRANSPORT": "definitive",
            "MCP_REMOTE_NO_AUTH": "absence",
            "MCP_UNPINNED_PACKAGE": "absence",
            "MCP_BROAD_FILESYSTEM": "heuristic",
            "MCP_SENSITIVE_PATHS": "heuristic",
            "MCP_SHELL_EXEC": "heuristic",
            "MCP_CONTAINER_PRIVILEGED": "definitive",
            "MCP_LETHAL_TRIFECTA": "heuristic",
        }
        assert {r.id: r.confidence for r in mcp_rules} == expected
        for rule in mcp_rules:
            if rule.confidence == "absence":
                assert rule.severity in ("medium", "low", "info"), rule.id
            if rule.confidence == "heuristic":
                assert rule.severity != "critical", rule.id
            if rule.severity == "critical":
                assert rule.confidence == "definitive", rule.id

    def test_the_two_secret_rules_share_a_root_cause(self, mcp_rules: list[Rule]) -> None:
        causes = {r.root_cause for r in mcp_rules if r.id in SECRET_RULE_IDS}
        assert causes == {"mcp-literal-credential"}

    def test_every_rule_but_the_secret_rules_skips_disabled_servers(
        self, mcp_rules: list[Rule]
    ) -> None:
        for rule in mcp_rules:
            if rule.resource_type != "mcp_server" or rule.id in SECRET_RULE_IDS:
                continue
            assert "disabled" in str(dict(rule.condition)), rule.id

    def test_a_server_stays_clean_when_it_is_disabled_whatever_else_is_true(
        self, mcp_rules: list[Rule]
    ) -> None:
        graph = InfraGraph.from_parsed(detect_and_parse(MCP_FIXTURES / "disabled" / ".mcp.json"))
        off = graph.nodes["mcp_server.off-by-flag"]
        on = graph.nodes["mcp_server.on"]
        unpinned = next(r for r in mcp_rules if r.id == "MCP_UNPINNED_PACKAGE")
        assert off.properties["package_unpinned"] is True
        assert not matches_rule(unpinned, off)
        assert matches_rule(unpinned, on)

    def test_a_disabled_server_with_a_literal_secret_is_still_reported(self) -> None:
        fired = _fired("disabled/.mcp.json")
        assert ("mcp_server.off-with-secret", "MCP_SECRET_IN_CONFIG") in fired
        assert not {a for a, _r in fired} - {"mcp_server.off-with-secret", "mcp_server.on"}

    def test_the_unpinned_rule_documents_the_range_policy(self, mcp_rules: list[Rule]) -> None:
        rule = next(r for r in mcp_rules if r.id == "MCP_UNPINNED_PACKAGE")
        assert "semver range" in rule.description
        assert "not a pin" in rule.mitigation

    def test_every_rule_has_a_bad_and_a_good_case(self, mcp_rules: list[Rule]) -> None:
        cases = Path(__file__).parent.parent / "test_rules" / "cases"
        groups = {"mcp__servers": SERVER_RULE_IDS, "mcp__agents": AGENT_RULE_IDS}
        for group, ids in groups.items():
            for rule_id in ids:
                found = sorted(p.name for p in (cases / group / rule_id).glob("*.mcp.json"))
                assert found == ["bad.mcp.json", "good.mcp.json"], (group, rule_id)


class TestVulnerableFixture:
    def test_every_rule_fires_on_its_entry(self) -> None:
        assert _fired("vulnerable/.mcp.json") == {
            ("mcp_server.weather", "MCP_SECRET_IN_CONFIG"),
            ("mcp_server.weather", "MCP_UNPINNED_PACKAGE"),
            ("mcp_server.home-files", "MCP_BROAD_FILESYSTEM"),
            ("mcp_server.terminal", "MCP_SHELL_EXEC"),
            ("mcp_server.builder", "MCP_CONTAINER_PRIVILEGED"),
            ("mcp_server.builder", "MCP_SENSITIVE_PATHS"),
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
        assert _fired_by_name("clients/.claude.json") == {
            ("db", "MCP_SECRET_IN_CONFIG"),
            ("db", "MCP_UNPINNED_PACKAGE"),
        }

    def test_gemini_cli_http_url(self) -> None:
        assert _fired("gemini/settings.json") == {
            ("mcp_server.search", "MCP_PLAINTEXT_TRANSPORT"),
            ("mcp_server.search", "MCP_REMOTE_NO_AUTH"),
        }


class TestNewFixtures:
    def test_wrapped_launchers_and_the_bridge(self) -> None:
        fired = _fired("wrappers/claude_desktop_config.json")
        unpinned = {a for a, r in fired if r == "MCP_UNPINNED_PACKAGE"}
        assert unpinned == {
            f"mcp_server.{n}"
            for n in (
                "win-npx",
                "bash-npx",
                "env-npx",
                "npm-exec",
                "pnpm-exec",
                "pipx",
                "uv-tool",
                "deno",
            )
        }
        assert ("mcp_server.bridge-plain", "MCP_PLAINTEXT_TRANSPORT") in fired
        assert ("mcp_server.bridge-plain", "MCP_SECRET_IN_CONFIG") in fired
        # The literal Authorization header is configured auth, so no missing-auth finding
        assert ("mcp_server.bridge-plain", "MCP_REMOTE_NO_AUTH") not in fired
        assert not {a for a, _r in fired if a == "mcp_server.pinned-cmd"}

    def test_secret_forms(self) -> None:
        fired = _fired("secrets/.mcp.json")
        assert {a for a, r in fired if r == "MCP_SECRET_IN_CONFIG"} == {
            f"mcp_server.{n}"
            for n in (
                "docker-env",
                "flag-equals",
                "flag-space",
                "default-literal",
                "userinfo",
                "query-auth",
            )
        }
        assert {a for a, r in fired if r == "MCP_SECRET_LIKELY_IN_CONFIG"} == {
            "mcp_server.password-key",
            "mcp_server.path-token",
        }
        # A credential in the query string is configured auth, so it is not also "no auth"
        assert not {a for a, r in fired if r == "MCP_REMOTE_NO_AUTH"}
        assert not {a for a, _r in fired if a == "mcp_server.false-positives"}

    def test_filesystem_exposure(self) -> None:
        fired = _fired("filesystem/.mcp.json")
        assert {a for a, r in fired if r == "MCP_SENSITIVE_PATHS"} == {
            "mcp_server.ssh-dir",
            "mcp_server.etc",
        }
        assert {a for a, r in fired if r == "MCP_BROAD_FILESYSTEM"} == {
            "mcp_server.env-home",
            "mcp_server.windows-home",
            "mcp_server.custom-name",
        }

    def test_container_privileges(self) -> None:
        fired = _fired("containers/.mcp.json")
        assert {a for a, r in fired if r == "MCP_CONTAINER_PRIVILEGED"} == {
            f"mcp_server.{n}"
            for n in ("net-admin", "privileged-true", "device", "etc-mount", "root-user")
        }
        assert ("mcp_server.home-mount", "MCP_BROAD_FILESYSTEM") in fired
        assert not {a for a, _r in fired if a == "mcp_server.not-privileged"}

    def test_trifecta(self) -> None:
        assert _fired("trifecta/.mcp.json") == {("mcp_agent.config", "MCP_LETHAL_TRIFECTA")}
        assert _fired("trifecta_missing_untrusted/.mcp.json") == set()
        assert _fired("unknown_servers/.mcp.json") == set()

    def test_project_scoped_findings_keep_their_own_project(self) -> None:
        result = scan_files([MCP_FIXTURES / "claude_json_collision" / ".claude.json"])
        secret = next(t for t in result.threats if t.rule_id == "MCP_SECRET_IN_CONFIG")
        node = result.graph.nodes[secret.resource_address]
        assert node.properties["env_keys"] == ["GITHUB_TOKEN"]
        assert node.start_line == 5

    def test_nothing_fires_on_unknown_entry_shapes(self) -> None:
        assert _fired("unknown_shape/.mcp.json") == set()

    def test_the_threat_does_not_carry_the_secret(self) -> None:
        result = scan_files([MCP_FIXTURES / "secrets" / ".mcp.json"])
        for threat in result.threats:
            text = str(threat.to_dict())
            assert "a8f3k2m9q7w1z5x0" not in text
            assert "ghp_16C7e42F292c6912E7710c838347Ae178B4a" not in text
