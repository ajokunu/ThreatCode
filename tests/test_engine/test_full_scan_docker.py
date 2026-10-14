"""End-to-end scan tests for Dockerfiles."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from tests.helpers.graph_assert import assert_edge
from tests.helpers.scan import scan_files, scan_text
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "docker"


def _report(name: str):
    path = FIXTURES_DIR / name
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    return graph, HybridEngine().analyze(graph, input_file=str(path))


class TestInsecureDockerfile:
    def test_headline_findings_fire(self) -> None:
        _graph, report = _report("insecure.Dockerfile")
        fired = {t.rule_id for t in report.threats if t.source == ThreatSource.RULE}
        assert {
            "DOCKER_NO_USER",
            "DOCKER_LATEST_TAG",
            "DOCKER_EXPOSED_SSH",
            "DOCKER_NO_HEALTHCHECK",
            "DOCKER_RUN_CURL_PIPE",
            "DOCKER_RUN_SUDO",
        } <= fired

    def test_instruction_rules_report_instruction_nodes(self) -> None:
        graph, report = _report("insecure.Dockerfile")
        by_rule = defaultdict(set)
        for threat in report.threats:
            if threat.source == ThreatSource.RULE:
                by_rule[threat.rule_id].add(graph.nodes[threat.resource_address].resource_type)
        assert by_rule["DOCKER_RUN_SUDO"] == {"dockerfile_run"}
        assert by_rule["DOCKER_NO_USER"] == {"dockerfile_image"}

    def test_every_finding_sits_on_a_type_the_rule_declares(self) -> None:
        _graph, report = _report("insecure.Dockerfile")
        rules = {r.id: r for r in load_all_rules()}
        for threat in report.threats:
            if threat.source == ThreatSource.RULE:
                assert rules[threat.rule_id].matches_type(threat.resource_type), threat.rule_id


class TestSecureDockerfile:
    def test_nothing_serious_fires(self) -> None:
        _graph, report = _report("secure.Dockerfile")
        assert [t.rule_id for t in report.threats if t.severity >= Severity.HIGH] == []

    def test_it_has_fewer_findings_than_the_insecure_one(self) -> None:
        _g1, secure = _report("secure.Dockerfile")
        _g2, insecure = _report("insecure.Dockerfile")
        assert len(secure.threats) < len(insecure.threats)


# ---------------------------------------------------------------------------
# Stages, zones and the hardened corpus, through the whole scan path
# ---------------------------------------------------------------------------

HARDENED = (
    Path(__file__).parent.parent / "fixtures" / "real_shapes" / "hardened" / "docker"
) / "hardened.Dockerfile"


def _scan(name: str):
    return scan_files([FIXTURES_DIR / name])


class TestStagesInTheGraph:
    def test_the_multistage_fixture_has_a_node_per_stage(self) -> None:
        graph = _scan("multistage.Dockerfile").graph
        stages = sorted(n.id for n in graph.nodes.values() if n.resource_type == "dockerfile_stage")
        assert stages == ["dockerfile.stage.1", "dockerfile.stage.builder"]

    def test_copy_from_links_the_final_stage_to_the_builder(self) -> None:
        graph = _scan("multistage.Dockerfile").graph
        assert_edge(
            graph,
            "dockerfile.stage.1",
            "dockerfile.stage.builder",
            type="dependency",
            relation="copy_from",
        )

    def test_a_base_stage_chain_is_linked_by_base_edges(self) -> None:
        graph = _scan("multistage_platform.Dockerfile").graph
        assert_edge(
            graph,
            "dockerfile.stage.test",
            "dockerfile.stage.builder",
            type="dependency",
            relation="base",
        )
        assert_edge(
            graph,
            "dockerfile.stage.2",
            "dockerfile.stage.builder",
            type="dependency",
            relation="copy_from",
        )

    def test_every_instruction_is_contained_in_a_stage(self) -> None:
        result = _scan("insecure.Dockerfile")
        for node in result.graph.nodes.values():
            if node.resource_type in ("dockerfile_image", "dockerfile_stage"):
                continue
            targets = [
                e.target for e in result.graph.edges_from(node.id) if e.edge_type == "containment"
            ]
            assert targets == ["dockerfile.stage.0"], node.id

    def test_stage_edges_are_inferred_never_declared(self) -> None:
        graph = _scan("multistage.Dockerfile").graph
        assert graph.edges
        assert all(edge.declared is False for edge in graph.edges)

    def test_stage_edges_do_not_become_trust_boundary_threats(self) -> None:
        for name in (
            "multistage.Dockerfile",
            "multistage_platform.Dockerfile",
            "secure.Dockerfile",
        ):
            result = _scan(name)
            assert not [e for e in result.graph.edges if e.crosses_trust_boundary], name
            assert not [t for t in result.threats if t.source == ThreatSource.BOUNDARY], name

    def test_no_rule_fires_on_a_stage_node(self) -> None:
        for name in ("multistage.Dockerfile", "multistage_platform.Dockerfile"):
            result = _scan(name)
            assert not [t for t in result.threats if t.resource_type == "dockerfile_stage"]

    def test_a_node_carries_the_physical_lines_of_its_instruction(self) -> None:
        text = "FROM a:1\nRUN true \\\n && curl x | sh\nEXPOSE 22\n"
        graph = scan_text(text, "Dockerfile").graph
        run = next(n for n in graph.nodes.values() if n.resource_type == "dockerfile_run")
        expose = next(n for n in graph.nodes.values() if n.resource_type == "dockerfile_expose")
        assert (run.start_line, run.end_line) == (2, 3)
        assert expose.start_line == 4


class TestZones:
    def test_expose_and_user_are_private_in_a_real_graph(self) -> None:
        graph = _scan("insecure.Dockerfile").graph
        exposes = [n for n in graph.nodes.values() if n.resource_type == "dockerfile_expose"]
        assert len(exposes) == 3
        assert {n.trust_zone.value for n in graph.nodes.values()} == {"private"}

    def test_a_dockerfile_has_no_boundary_findings_at_all(self) -> None:
        for name in ("insecure.Dockerfile", "secure.Dockerfile", "multistage.Dockerfile"):
            assert not [t for t in _scan(name).threats if t.source == ThreatSource.BOUNDARY]


class TestRecordedBehaviour:
    def test_the_insecure_fixture_findings_by_instruction(self) -> None:
        result = _scan("insecure.Dockerfile")
        by_rule: dict[str, set[str]] = defaultdict(set)
        for threat in result.threats:
            if threat.source == ThreatSource.RULE:
                by_rule[threat.rule_id].add(threat.resource_address)
        assert by_rule["DOCKER_NO_USER"] == {"dockerfile.image.summary"}
        assert by_rule["DOCKER_ARG_SECRET"] == {"dockerfile.arg.1"}
        assert by_rule["DOCKER_ENV_SECRET"] == {"dockerfile.env.2"}
        assert by_rule["DOCKER_RUN_CURL_PIPE"] == {"dockerfile.run.4"}
        assert by_rule["DOCKER_APT_NO_CLEAN"] == {"dockerfile.run.3"}
        # ADD of a local archive is legitimate; ADD of id_rsa is not
        assert by_rule["DOCKER_ADD_INSTEAD_OF_COPY"] == {"dockerfile.add.7"}
        assert by_rule["DOCKER_SENSITIVE_FILE_ADD"] == {"dockerfile.add.7"}
        # A root image has no ownership mismatch to flag
        assert "DOCKER_COPY_NO_CHOWN" not in by_rule
        # Privileged ports are not a finding
        assert "DOCKER_EXPOSED_PRIVILEGED_PORT" not in by_rule

    def test_severities_follow_the_calibration(self) -> None:
        result = _scan("insecure.Dockerfile")
        severity = {t.rule_id: t.severity for t in result.threats if t.source == ThreatSource.RULE}
        assert severity["DOCKER_NO_USER"] == Severity.MEDIUM
        assert severity["DOCKER_ENV_SECRET"] == Severity.HIGH
        assert Severity.CRITICAL not in set(severity.values())

    def test_the_secure_fixture_has_only_low_findings(self) -> None:
        result = _scan("secure.Dockerfile")
        assert {t.rule_id for t in result.threats} == {"DOCKER_NO_DIGEST_PIN"}

    def test_a_lowercase_dockerfile_is_judged_like_an_uppercase_one(self) -> None:
        lower = scan_text("from ubuntu:22.04\nuser root\n", "Dockerfile").rule_ids
        upper = scan_text("FROM ubuntu:22.04\nUSER root\n", "Dockerfile").rule_ids
        assert lower == upper
        assert "DOCKER_ROOT_USER" in lower
        assert "DOCKER_NO_USER" not in lower

    def test_the_hardened_dockerfile_scans_clean(self) -> None:
        result = scan_files([HARDENED])
        assert result.rule_ids == set()

    def test_a_containerfile_and_dockerfile_variants_are_scanned(self, tmp_path: Path) -> None:
        for name in ("Containerfile", "Dockerfile.dev", "Dockerfile-api", "app.containerfile"):
            path = tmp_path / name
            path.write_text("FROM ubuntu:22.04\nUSER root\n")
            assert "DOCKER_ROOT_USER" in scan_files([path]).rule_ids, name
