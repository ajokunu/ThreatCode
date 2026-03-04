"""Tests for Docker security rules."""

from pathlib import Path

import pytest

from threatcode.engine.rules.loader import load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule
from threatcode.parsers.dockerfile import DockerfileParser


@pytest.fixture
def docker_rules():
    rules = load_all_rules()
    return [r for r in rules if r.id.startswith("DOCKER_")]


@pytest.fixture
def insecure_resources():
    parser = DockerfileParser()
    content = Path("tests/fixtures/docker/insecure.Dockerfile").read_text()
    return parser.parse(content).resources


@pytest.fixture
def secure_resources():
    parser = DockerfileParser()
    content = Path("tests/fixtures/docker/secure.Dockerfile").read_text()
    return parser.parse(content).resources


class TestDockerRulesExist:
    def test_docker_rules_loaded(self, docker_rules) -> None:
        rule_ids = {r.id for r in docker_rules}
        assert "DOCKER_NO_USER" in rule_ids
        assert "DOCKER_LATEST_TAG" in rule_ids
        assert "DOCKER_EXPOSED_SSH" in rule_ids
        assert "DOCKER_ENV_SECRET" in rule_ids
        assert "DOCKER_RUN_CURL_PIPE" in rule_ids
        assert "DOCKER_RUN_SUDO" in rule_ids
        assert "DOCKER_NO_HEALTHCHECK" in rule_ids
        assert "DOCKER_ROOT_USER" in rule_ids
        assert len(docker_rules) >= 15


class TestDockerRulesInsecure:
    def test_insecure_fires_rules(self, docker_rules, insecure_resources) -> None:
        fired = set()
        for rule in docker_rules:
            for resource in insecure_resources:
                if resource.resource_type == rule.resource_type:
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        # Key rules should fire on insecure Dockerfile
        assert "DOCKER_NO_USER" in fired
        assert "DOCKER_LATEST_TAG" in fired
        assert "DOCKER_EXPOSED_SSH" in fired
        assert "DOCKER_NO_HEALTHCHECK" in fired
        assert "DOCKER_RUN_CURL_PIPE" in fired
        assert "DOCKER_RUN_SUDO" in fired
        assert "DOCKER_MISSING_WORKDIR" in fired


class TestDockerRulesSecure:
    def test_secure_no_fires(self, docker_rules, secure_resources) -> None:
        fired = set()
        for rule in docker_rules:
            for resource in secure_resources:
                if resource.resource_type == rule.resource_type:
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        # Secure Dockerfile should not fire critical/high rules
        high_critical_fired = {
            rid
            for rid in fired
            if any(r.id == rid and r.severity in ("high", "critical") for r in docker_rules)
        }
        assert len(high_critical_fired) == 0
