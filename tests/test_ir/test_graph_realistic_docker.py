"""Graph-level assertions on real-shape Dockerfiles.

The fixtures under ``tests/fixtures/real_shapes/docker`` are Dockerfiles as teams write them:
lowercase instructions, line continuations with comments inside them, heredocs, multi-stage
builds with ``--platform`` and ``ARG`` tags, ``ONBUILD`` triggers and a ``Containerfile``.

The parser reads these the way BuildKit does: lowercase keywords, comments inside
continuations, heredocs, ``--platform`` flags, stages and ``ONBUILD`` triggers.
"""

from __future__ import annotations

import json

from tests.helpers.graph_assert import assert_edge, assert_zone
from tests.helpers.scan import scan_real_shape
from threatcode.engine import paths
from threatcode.ir.edges import REACHABILITY

SUMMARY = "dockerfile.image.summary"
REACHABILITY_VALUES = {t.value for t in REACHABILITY}

# Node types a Dockerfile may legitimately produce: every instruction keyword, the image summary
# and the stage node. Anything else means body text was read as an instruction.
KNOWN_NODE_TYPES = {
    f"dockerfile_{name}"
    for name in (
        "from",
        "run",
        "cmd",
        "label",
        "maintainer",
        "expose",
        "env",
        "add",
        "copy",
        "entrypoint",
        "volume",
        "user",
        "workdir",
        "arg",
        "onbuild",
        "stopsignal",
        "healthcheck",
        "shell",
        "image",
        "stage",
    )
}


def _nodes_of(result_nodes: dict, resource_type: str) -> list:
    return [n for n in result_nodes.values() if n.resource_type == resource_type]


class TestContinuations:
    PATH = "docker/continuations.Dockerfile"

    def test_every_instruction_kind_is_a_node(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        types = {n.resource_type for n in nodes.values()}
        assert types >= {
            "dockerfile_from",
            "dockerfile_run",
            "dockerfile_env",
            "dockerfile_copy",
            "dockerfile_user",
            "dockerfile_healthcheck",
            "dockerfile_entrypoint",
            "dockerfile_image",
        }

    def test_the_summary_reads_the_base_user_and_healthcheck(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "debian:12-slim"
        assert props["has_user"] is True
        assert props["user_value"] == "app"
        assert props["has_healthcheck"] is True
        assert props["uses_latest_tag"] is False

    def test_the_summary_is_in_the_private_zone(self) -> None:
        assert_zone(scan_real_shape(self.PATH).graph, SUMMARY, "private")

    def test_the_run_instruction_is_one_command_without_the_comments(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        run = _nodes_of(nodes, "dockerfile_run")[0]
        args = run.properties["arguments"]
        assert "apt-get install -y --no-install-recommends" in args
        assert "rm -rf /var/lib/apt/lists/*" in args
        assert "#" not in args

    def test_the_multi_line_env_is_parsed_into_every_key(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        env = _nodes_of(nodes, "dockerfile_env")
        keys = {key for n in env for key in n.properties.get("keys", [n.properties.get("key")])}
        assert {"APP_HOME", "APP_PORT", "LOG_LEVEL"} <= keys

    def test_instructions_are_contained_in_their_stage(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        stage = next(n for n in graph.nodes.values() if n.resource_type == "dockerfile_stage")
        run = _nodes_of(graph.nodes, "dockerfile_run")[0]
        assert_edge(graph, run.id, stage.id, type="containment")


class TestLowercase:
    PATH = "docker/lowercase.Dockerfile"

    def test_the_summary_node_exists(self) -> None:
        assert SUMMARY in scan_real_shape(self.PATH).graph.nodes

    def test_lowercase_instructions_are_read(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        props = graph.nodes[SUMMARY].properties
        assert props["base_image"] == "python:3.12-slim"
        assert props["user_value"] == "10001"
        assert props["has_user"] is True
        assert props["has_workdir"] is True
        assert props["exposed_ports"] == [8000]

    def test_every_lowercase_instruction_is_a_node(self) -> None:
        types = {n.resource_type for n in scan_real_shape(self.PATH).graph.nodes.values()}
        assert {"dockerfile_from", "dockerfile_run", "dockerfile_copy", "dockerfile_cmd"} <= types


class TestHeredoc:
    PATH = "docker/heredoc.Dockerfile"

    def test_the_summary_reads_the_base_and_user(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "alpine:3.20"
        assert props["user_value"] == "app"

    def test_the_run_instruction_carries_its_heredoc_body(self) -> None:
        run = _nodes_of(scan_real_shape(self.PATH).graph.nodes, "dockerfile_run")[0]
        assert "apk add --no-cache curl ca-certificates" in json.dumps(run.properties)

    def test_heredoc_bodies_are_never_read_as_instructions(self) -> None:
        """A body line such as ``set -eux`` must not become a dockerfile_set node.

        Lowercase keywords are accepted, so a naive lexer would read ``set -eux`` as an
        instruction; heredoc bodies belong to the RUN or COPY that opens them.
        """
        nodes = scan_real_shape(self.PATH).graph.nodes
        unknown = {n.resource_type for n in nodes.values()} - KNOWN_NODE_TYPES
        assert not unknown, f"heredoc body lines became nodes: {sorted(unknown)}"
        assert len(_nodes_of(nodes, "dockerfile_copy")) == 1
        assert len(_nodes_of(nodes, "dockerfile_run")) == 1


class TestMultiStage:
    PATH = "docker/multistage.Dockerfile"

    def test_the_final_user_is_read_from_the_last_stage(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["user_value"] == "65532:65532"
        assert props["has_user"] is True

    def test_one_from_node_per_stage(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        assert len(_nodes_of(nodes, "dockerfile_from")) == 3

    def test_the_platform_flag_is_not_the_base_image(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        images = {n.properties["image"] for n in _nodes_of(nodes, "dockerfile_from")}
        assert "--platform=$BUILDPLATFORM" not in images
        assert "golang:1.22" in images or "golang:${GO_VERSION}" in images

    def test_the_summary_describes_the_distroless_final_stage(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"].startswith("gcr.io/distroless/static-debian12")
        assert props["uses_latest_tag"] is False
        assert props["final_stage_uses_latest_tag"] is False
        assert props["stage_count"] == 3

    def test_the_runtime_tag_comes_from_the_arg_default(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "gcr.io/distroless/static-debian12:nonroot"

    def test_every_stage_is_a_node(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        stages = {n.id for n in graph.nodes.values() if n.resource_type == "dockerfile_stage"}
        assert stages == {
            "dockerfile.stage.build",
            "dockerfile.stage.test",
            "dockerfile.stage.runtime",
        }

    def test_the_test_stage_is_based_on_the_build_stage(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        assert_edge(graph, "dockerfile.stage.test", "dockerfile.stage.build", "dependency", "base")

    def test_the_runtime_stage_copies_from_the_build_stage(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        assert_edge(
            graph,
            "dockerfile.stage.runtime",
            "dockerfile.stage.build",
            type="dependency",
            relation="copy_from",
        )

    def test_expose_and_user_are_private(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        for node in _nodes_of(graph.nodes, "dockerfile_expose"):
            assert_zone(graph, node.id, "private")
        for node in _nodes_of(graph.nodes, "dockerfile_user"):
            assert_zone(graph, node.id, "private")


class TestOnbuild:
    PATH = "docker/onbuild.Dockerfile"

    def test_the_summary_is_unaffected_by_the_triggers(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "node:20-alpine"
        assert props["user_value"] == "node"

    def test_the_triggers_are_unwrapped_into_their_instruction_type(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        runs = [n for n in _nodes_of(nodes, "dockerfile_run") if n.properties.get("onbuild")]
        copies = [n for n in _nodes_of(nodes, "dockerfile_copy") if n.properties.get("onbuild")]
        assert len(runs) == 1
        assert len(copies) == 2
        assert not _nodes_of(nodes, "dockerfile_onbuild")


class TestContainerfile:
    PATH = "docker/Containerfile"

    def test_a_containerfile_is_read(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "registry.access.redhat.com/ubi9/ubi-minimal:9.4"
        assert props["user_value"] == "1001"


class TestEveryRealShape:
    FILES = (
        "Containerfile",
        "continuations.Dockerfile",
        "heredoc.Dockerfile",
        "lowercase.Dockerfile",
        "multistage.Dockerfile",
        "onbuild.Dockerfile",
    )

    def test_no_file_produces_a_node_of_an_unknown_type(self) -> None:
        for name in self.FILES:
            nodes = scan_real_shape(f"docker/{name}").graph.nodes
            unknown = {n.resource_type for n in nodes.values()} - KNOWN_NODE_TYPES
            assert not unknown, f"{name}: {sorted(unknown)}"

    def test_no_file_has_a_trust_boundary_crossing(self) -> None:
        for name in self.FILES:
            graph = scan_real_shape(f"docker/{name}").graph
            assert not [e for e in graph.edges if e.crosses_trust_boundary], name

    def test_every_instruction_node_is_contained_in_exactly_one_stage(self) -> None:
        for name in self.FILES:
            graph = scan_real_shape(f"docker/{name}").graph
            for node in graph.nodes.values():
                if node.resource_type in ("dockerfile_image", "dockerfile_stage"):
                    continue
                stages = [
                    e.target
                    for e in graph.edges
                    if e.source == node.id and e.edge_type.value == "containment"
                ]
                assert len(stages) <= 1, (name, node.id)

    def test_every_dockerfile_has_exactly_one_summary(self) -> None:
        for name in self.FILES:
            nodes = scan_real_shape(f"docker/{name}").graph.nodes
            assert len(_nodes_of(nodes, "dockerfile_image")) == 1, name

    def test_the_summary_user_matches_the_file(self) -> None:
        expected = {
            "Containerfile": "1001",
            "continuations.Dockerfile": "app",
            "heredoc.Dockerfile": "app",
            "lowercase.Dockerfile": "10001",
            "multistage.Dockerfile": "65532:65532",
            "onbuild.Dockerfile": "node",
        }
        for name, user in expected.items():
            props = scan_real_shape(f"docker/{name}").graph.nodes[SUMMARY].properties
            assert props["user_value"] == user, name
            assert props["is_root_user"] is False, name

    def test_the_continuation_run_keeps_every_command_after_the_comments(self) -> None:
        nodes = scan_real_shape("docker/continuations.Dockerfile").graph.nodes
        run = _nodes_of(nodes, "dockerfile_run")[0]
        assert run.start_line == 4
        assert run.end_line == 11
        assert run.properties["has_apt_no_recommends"] is False
        assert run.properties["has_apt_no_clean"] is False

    def test_the_heredoc_copy_is_in_the_copy_node_not_in_instructions(self) -> None:
        nodes = scan_real_shape("docker/heredoc.Dockerfile").graph.nodes
        copy = _nodes_of(nodes, "dockerfile_copy")[0]
        assert "listen" in copy.properties["heredoc_body"]
        assert copy.properties["sources"] == []


class TestNoReachability:
    """A Dockerfile says how an image is built, not who can reach it."""

    FILES = (
        "docker/continuations.Dockerfile",
        "docker/lowercase.Dockerfile",
        "docker/heredoc.Dockerfile",
        "docker/multistage.Dockerfile",
        "docker/onbuild.Dockerfile",
        "docker/Containerfile",
    )

    def test_an_exposed_port_is_not_an_entry_from_the_internet(self) -> None:
        for relative in self.FILES:
            graph = scan_real_shape(relative).graph
            assert graph.internet_node is None, relative
            assert not [e for e in graph.edges if e.edge_type.value in REACHABILITY_VALUES], (
                relative
            )

    def test_no_instruction_is_a_crown_jewel_or_part_of_a_path(self) -> None:
        for relative in self.FILES:
            result = scan_real_shape(relative)
            assert result.report.attack_paths == [], relative
            for node in result.graph.nodes.values():
                assert paths.crown_jewel_kind(result.graph, node) == "", node.id
