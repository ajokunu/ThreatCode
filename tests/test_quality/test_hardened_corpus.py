"""A hardened input must scan clean: the other half of rule accuracy.

``tests/fixtures/real_shapes/hardened`` holds one input per format that is hardened throughout.
Each scan is expected to report no rule finding, apart from an explicit allowlist in which every
entry carries the reason the finding is right. A rule that fires on these inputs is wrong about
them, which is how the pod-level security context, a default-deny NetworkPolicy, a multi-stage
build and an environment-referenced secret were all reported as problems.

Where a scan still reports findings they are all false positives. The zero-finding tests are pending
on the package that owns each remaining format's rules and parser, so each fix is proven by the same
fixture. A format whose package has delivered carries no marker and runs for real.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.pending import pending
from tests.helpers.scan import REAL_SHAPES_DIR, scan_files
from threatcode.engine.rules.loader import load_builtin_rules

HARDENED_DIR = REAL_SHAPES_DIR / "hardened"

# format -> (file, package that makes the scan clean or None once it is clean, why it is not
# clean today)
CORPUS: dict[str, tuple[str, str | None, str]] = {
    "kubernetes": (
        "kubernetes/hardened_workloads.yaml",
        "WP-3-6",
        "rules read pod-level security context, probes on the right containers and NetworkPolicy",
    ),
    "docker": ("docker/hardened.Dockerfile", None, ""),
    "mcp": (
        "mcp/.mcp.json",
        "WP-2-6",
        "a loopback server and an environment-referenced header count as configured auth",
    ),
}

# fixture file -> {rule id: why this finding is correct on a hardened input}
ALLOWED: dict[str, dict[str, str]] = {}


def rule_findings(relative: str) -> dict[str, list[str]]:
    """Rule id to the resources it fired on, for one hardened input."""
    result = scan_files([HARDENED_DIR / relative])
    found: dict[str, list[str]] = {}
    for threat in result.threats:
        if threat.rule_id:
            found.setdefault(threat.rule_id, []).append(threat.resource_address)
    return found


def unexpected(relative: str) -> dict[str, list[str]]:
    allowed = ALLOWED.get(relative, {})
    return {rule: where for rule, where in rule_findings(relative).items() if rule not in allowed}


class TestTheCorpus:
    @pytest.mark.parametrize("fmt", CORPUS)
    def test_each_hardened_input_parses_into_nodes(self, fmt: str) -> None:
        relative = CORPUS[fmt][0]
        result = scan_files([HARDENED_DIR / relative])
        assert result.graph.node_count >= 4, relative

    def test_every_allowed_finding_names_a_real_rule_and_gives_a_reason(self) -> None:
        known = {rule.id for rule in load_builtin_rules()}
        for relative, entries in ALLOWED.items():
            assert (HARDENED_DIR / relative).is_file()
            for rule_id, reason in entries.items():
                assert rule_id in known, f"{relative}: {rule_id} is not a builtin rule"
                assert len(reason.split()) >= 4, f"{relative}: {rule_id} needs a real reason"

    def test_the_kubernetes_input_covers_every_pod_workload_kind(self) -> None:
        graph = scan_files([HARDENED_DIR / CORPUS["kubernetes"][0]]).graph
        kinds = {n.resource_type for n in graph.nodes.values()}
        assert kinds >= {
            "kubernetes_deployment",
            "kubernetes_stateful_set",
            "kubernetes_daemon_set",
            "kubernetes_replica_set",
            "kubernetes_job",
            "kubernetes_cron_job",
            "kubernetes_pod",
            "kubernetes_namespace",
            "kubernetes_network_policy",
            "kubernetes_service_account",
        }

    def test_no_hardened_input_contains_a_known_bad_construct(self) -> None:
        bad = {
            "kubernetes": [
                "privileged: true",
                "hostNetwork: true",
                "hostPath",
                ":latest",
                "NET_ADMIN",
            ],
            "docker": ["USER root", ":latest", "curl | sh", "ADD http"],
            "mcp": ["ghp_", "sk-live", '"http://tools'],
        }
        for fmt, needles in bad.items():
            text = (HARDENED_DIR / CORPUS[fmt][0]).read_text(encoding="utf-8")
            for needle in needles:
                assert needle not in text, f"{fmt}: hardened input contains {needle!r}"


class TestHardenedInputsScanClean:
    @pytest.mark.parametrize(
        "fmt",
        [
            pytest.param(fmt, marks=pending(package, why) if package else ())
            for fmt, (_relative, package, why) in CORPUS.items()
        ],
    )
    def test_no_rule_fires_outside_the_allowlist(self, fmt: str) -> None:
        relative = CORPUS[fmt][0]
        found = unexpected(relative)
        assert not found, f"{relative}: false positives {found}"

    def test_the_pending_markers_are_honest_the_scans_are_not_clean_today(self) -> None:
        """If this fails, a scan is already clean: remove its pending marker."""
        for fmt, (relative, package, _why) in CORPUS.items():
            if package is None:
                continue
            assert unexpected(relative), f"{fmt}: {relative} already scans clean"

    def test_a_finding_on_a_synthetic_bad_input_is_not_masked_by_the_allowlist(
        self, tmp_path: Path
    ) -> None:
        """The check must see findings at all, or a clean result means nothing."""
        bad = tmp_path / "Dockerfile"
        bad.write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
        found = {t.rule_id for t in scan_files([bad]).threats if t.rule_id}
        assert {"DOCKER_ROOT_USER", "DOCKER_LATEST_TAG"} <= found
