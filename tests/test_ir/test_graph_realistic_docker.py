"""Graph-level assertions on real-shape Dockerfiles.

The fixtures under ``tests/fixtures/real_shapes/docker`` are Dockerfiles as teams write them:
lowercase instructions, line continuations with comments inside them, heredocs, multi-stage
builds with ``--platform`` and ``ARG`` tags, ``ONBUILD`` triggers and a ``Containerfile``.

Today the lexer reads only uppercase single-line instructions, treats ``--platform=...`` as the
base image and has no notion of stages. Assertions that hold now run now; each one a later
package delivers is its own pending test.
"""

from __future__ import annotations

import json

from tests.helpers.graph_assert import assert_edge, assert_zone
from tests.helpers.pending import pending
from tests.helpers.scan import scan_real_shape

SUMMARY = "dockerfile.image.summary"

# Node types a Dockerfile may legitimately produce: every instruction keyword, the image summary
# and the stage node a later package adds. Anything else means body text was read as an instruction.
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

    @pending("WP-2-5", "comment lines inside a continuation are dropped from the RUN command")
    def test_the_run_instruction_is_one_command_without_the_comments(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        run = _nodes_of(nodes, "dockerfile_run")[0]
        args = run.properties["arguments"]
        assert "apt-get install -y --no-install-recommends" in args
        assert "rm -rf /var/lib/apt/lists/*" in args
        assert "#" not in args

    @pending("WP-2-5", "ENV parses every KEY=VALUE pair of a multi-line instruction")
    def test_the_multi_line_env_is_parsed_into_every_key(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        env = _nodes_of(nodes, "dockerfile_env")
        keys = {key for n in env for key in n.properties.get("keys", [n.properties.get("key")])}
        assert {"APP_HOME", "APP_PORT", "LOG_LEVEL"} <= keys

    @pending("WP-2-5", "a synthetic stage node contains the instructions of its stage")
    def test_instructions_are_contained_in_their_stage(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        stage = next(n for n in graph.nodes.values() if n.resource_type == "dockerfile_stage")
        run = _nodes_of(graph.nodes, "dockerfile_run")[0]
        assert_edge(graph, run.id, stage.id, type="containment")


class TestLowercase:
    PATH = "docker/lowercase.Dockerfile"

    def test_the_summary_node_exists(self) -> None:
        assert SUMMARY in scan_real_shape(self.PATH).graph.nodes

    @pending("WP-2-5", "the lexer matches instruction keywords case-insensitively")
    def test_lowercase_instructions_are_read(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        props = graph.nodes[SUMMARY].properties
        assert props["base_image"] == "python:3.12-slim"
        assert props["user_value"] == "10001"
        assert props["has_user"] is True
        assert props["has_workdir"] is True
        assert props["exposed_ports"] == [8000]

    @pending("WP-2-5", "the lexer matches instruction keywords case-insensitively")
    def test_every_lowercase_instruction_is_a_node(self) -> None:
        types = {n.resource_type for n in scan_real_shape(self.PATH).graph.nodes.values()}
        assert {"dockerfile_from", "dockerfile_run", "dockerfile_copy", "dockerfile_cmd"} <= types


class TestHeredoc:
    PATH = "docker/heredoc.Dockerfile"

    def test_the_summary_reads_the_base_and_user(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "alpine:3.20"
        assert props["user_value"] == "app"

    @pending("WP-2-5", "a heredoc body is attached to its RUN instruction")
    def test_the_run_instruction_carries_its_heredoc_body(self) -> None:
        run = _nodes_of(scan_real_shape(self.PATH).graph.nodes, "dockerfile_run")[0]
        assert "apk add --no-cache curl ca-certificates" in json.dumps(run.properties)

    def test_heredoc_bodies_are_never_read_as_instructions(self) -> None:
        """A body line such as ``set -eux`` must not become a dockerfile_set node.

        This holds today because only uppercase keywords are read; it must keep holding once
        lowercase keywords are accepted, which is when a naive lexer would break it.
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

    @pending("WP-2-5", "FROM flags such as --platform are not read as the image reference")
    def test_the_platform_flag_is_not_the_base_image(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        images = {n.properties["image"] for n in _nodes_of(nodes, "dockerfile_from")}
        assert "--platform=$BUILDPLATFORM" not in images
        assert "golang:1.22" in images or "golang:${GO_VERSION}" in images

    @pending("WP-2-5", "the image summary is computed from the final stage")
    def test_the_summary_describes_the_distroless_final_stage(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"].startswith("gcr.io/distroless/static-debian12")
        assert props["uses_latest_tag"] is False
        assert props["final_stage_uses_latest_tag"] is False
        assert props["stage_count"] == 3

    @pending("WP-2-5", "ARG defaults before the first FROM are substituted into the reference")
    def test_the_runtime_tag_comes_from_the_arg_default(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "gcr.io/distroless/static-debian12:nonroot"

    @pending("WP-2-5", "each FROM opens a stage node named after the stage")
    def test_every_stage_is_a_node(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        stages = {n.id for n in graph.nodes.values() if n.resource_type == "dockerfile_stage"}
        assert stages == {
            "dockerfile.stage.build",
            "dockerfile.stage.test",
            "dockerfile.stage.runtime",
        }

    @pending("WP-2-5", "FROM <stage> is a dependency edge with relation base")
    def test_the_test_stage_is_based_on_the_build_stage(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        assert_edge(graph, "dockerfile.stage.test", "dockerfile.stage.build", "dependency", "base")

    @pending("WP-2-5", "COPY --from is a dependency edge with relation copy_from")
    def test_the_runtime_stage_copies_from_the_build_stage(self) -> None:
        graph = scan_real_shape(self.PATH).graph
        assert_edge(
            graph,
            "dockerfile.stage.runtime",
            "dockerfile.stage.build",
            type="dependency",
            relation="copy_from",
        )

    @pending("WP-2-5", "EXPOSE and USER are PRIVATE: a declared port is not internet exposure")
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

    @pending("WP-2-5", "ONBUILD <INSTR> is unwrapped and flagged onbuild")
    def test_the_triggers_are_unwrapped_into_their_instruction_type(self) -> None:
        nodes = scan_real_shape(self.PATH).graph.nodes
        runs = [n for n in _nodes_of(nodes, "dockerfile_run") if n.properties.get("onbuild")]
        copies = [n for n in _nodes_of(nodes, "dockerfile_copy") if n.properties.get("onbuild")]
        assert len(runs) == 1
        assert len(copies) == 2
        assert not _nodes_of(nodes, "dockerfile_onbuild")


class TestContainerfile:
    PATH = "docker/Containerfile"

    @pending("WP-1-4", "Containerfile is recognized as a Dockerfile name")
    def test_a_containerfile_is_read(self) -> None:
        props = scan_real_shape(self.PATH).graph.nodes[SUMMARY].properties
        assert props["base_image"] == "registry.access.redhat.com/ubi9/ubi-minimal:9.4"
        assert props["user_value"] == "1001"
