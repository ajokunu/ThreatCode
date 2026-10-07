"""Tests for Docker security rules."""

from pathlib import Path
from typing import Any

import pytest

from tests.helpers.scan import scan_text
from threatcode.engine.mitre import TECHNIQUE_DB, is_revoked, tactics_for_techniques
from threatcode.engine.rules.loader import (
    CONFIDENCE_LEVELS,
    Rule,
    deprecated_rule_ids,
    load_all_rules,
    load_builtin_rules,
)
from threatcode.engine.rules.matcher import evaluate_rule
from threatcode.models.threat import Severity
from threatcode.parsers.dockerfile import DockerfileParser


@pytest.fixture
def docker_rules():
    rules = load_all_rules()
    return [r for r in rules if r.id.startswith("DOCKER_")]


@pytest.fixture
def insecure_resources():
    parser = DockerfileParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "docker" / "insecure.Dockerfile"
    content = fixture.read_text()
    return parser.parse(content).resources


@pytest.fixture
def secure_resources():
    parser = DockerfileParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "docker" / "secure.Dockerfile"
    content = fixture.read_text()
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
                if rule.matches_type(resource.resource_type):
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
        # The revived rules read properties the parser now emits
        assert "DOCKER_NO_DIGEST_PIN" in fired
        assert "DOCKER_NON_MINIMAL_BASE" in fired
        assert "DOCKER_APT_NO_CLEAN" in fired


class TestDockerRulesSecure:
    def test_secure_no_fires(self, docker_rules, secure_resources) -> None:
        fired = set()
        for rule in docker_rules:
            for resource in secure_resources:
                if rule.matches_type(resource.resource_type):
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        # Secure Dockerfile should not fire critical/high rules
        high_critical_fired = {
            rid
            for rid in fired
            if any(r.id == rid and r.severity in ("high", "critical") for r in docker_rules)
        }
        assert len(high_critical_fired) == 0


class TestDockerRuleTyping:
    def test_instruction_rules_bind_to_their_own_instruction_type(self, docker_rules) -> None:
        by_id = {r.id: r for r in docker_rules}
        assert by_id["DOCKER_ENV_SECRET"].matches_type("dockerfile_env")
        assert not by_id["DOCKER_ENV_SECRET"].matches_type("dockerfile_arg")
        assert not by_id["DOCKER_NO_USER"].matches_type("dockerfile_user")
        assert by_id["DOCKER_NO_USER"].matches_type("dockerfile_image")

    def test_no_docker_rule_matches_by_prefix(self, docker_rules) -> None:
        for rule in docker_rules:
            assert not any(t.endswith("*") for t in rule.resource_types), rule.id


def fired(text: str) -> set[str]:
    """Ids of the Docker rules that fire on a Dockerfile, through the whole scan path."""
    return {r for r in scan_text(text, "Dockerfile").rule_ids if r.startswith("DOCKER_")}


def docker_rule_objects() -> list[Rule]:
    return [r for r in load_builtin_rules() if r.id.startswith("DOCKER_")]


class TestCalibration:
    def test_every_docker_rule_declares_a_confidence_that_the_convention_allows(self) -> None:
        rules = docker_rule_objects()
        assert rules
        for rule in rules:
            assert rule.confidence in CONFIDENCE_LEVELS, rule.id
            if rule.confidence == "absence":
                assert Severity(rule.severity) <= Severity.MEDIUM, rule.id
            if rule.confidence == "heuristic":
                assert Severity(rule.severity) <= Severity.HIGH, rule.id

    def test_no_docker_rule_is_critical(self) -> None:
        # Critical is reserved for definitive, direct exposure of data or control
        assert all(rule.severity != "critical" for rule in docker_rule_objects())

    def test_the_name_based_secret_rules_are_heuristic_and_high(self) -> None:
        by_id = {r.id: r for r in docker_rule_objects()}
        for rule_id in ("DOCKER_ENV_SECRET", "DOCKER_ARG_SECRET"):
            assert by_id[rule_id].confidence == "heuristic"
            assert by_id[rule_id].severity == "high"

    def test_missing_something_rules_are_absence_rules(self) -> None:
        by_id = {r.id: r for r in docker_rule_objects()}
        for rule_id in (
            "DOCKER_NO_USER",
            "DOCKER_NO_HEALTHCHECK",
            "DOCKER_MISSING_WORKDIR",
            "DOCKER_NO_DIGEST_PIN",
            "DOCKER_APT_NO_CLEAN",
        ):
            assert by_id[rule_id].confidence == "absence", rule_id
        assert by_id["DOCKER_NO_USER"].severity == "medium"
        assert by_id["DOCKER_ROOT_USER"].confidence == "definitive"
        assert by_id["DOCKER_ROOT_USER"].severity == "high"

    def test_recoverability_uses_denial_of_service(self) -> None:
        by_id = {r.id: r for r in docker_rule_objects()}
        assert by_id["DOCKER_NO_HEALTHCHECK"].stride_category == "denial_of_service"

    def test_every_technique_exists_and_none_is_revoked(self) -> None:
        for rule in docker_rule_objects():
            for technique in (rule.metadata.get("mitre") or {}).get("techniques", []):
                assert technique in TECHNIQUE_DB, (rule.id, technique)
                assert not is_revoked(technique), (rule.id, technique)

    def test_tactics_are_derived_from_the_techniques_not_written_by_hand(self) -> None:
        for rule in docker_rule_objects():
            mitre = rule.metadata.get("mitre") or {}
            assert "tactics" not in mitre, rule.id
            if mitre.get("techniques"):
                assert tactics_for_techniques(list(mitre["techniques"]))

    def test_findings_carry_the_derived_tactics(self) -> None:
        result = scan_text("FROM ubuntu:22.04\nUSER root\n", "Dockerfile")
        threat = next(t for t in result.threats if t.rule_id == "DOCKER_ROOT_USER")
        assert threat.mitre_techniques == ["T1611"]
        assert threat.mitre_tactics == ["TA0004"]

    def test_related_findings_share_a_root_cause(self) -> None:
        by_id = {r.id: r for r in docker_rule_objects()}
        assert by_id["DOCKER_NO_USER"].root_cause == by_id["DOCKER_ROOT_USER"].root_cause != ""
        assert by_id["DOCKER_LATEST_TAG"].root_cause == by_id["DOCKER_NO_DIGEST_PIN"].root_cause
        secrets = {
            by_id[i].root_cause
            for i in (
                "DOCKER_ENV_SECRET",
                "DOCKER_ARG_SECRET",
                "DOCKER_SENSITIVE_FILE_COPY",
                "DOCKER_SENSITIVE_FILE_ADD",
            )
        }
        assert len(secrets) == 1 and "" not in secrets

    def test_the_env_secret_description_does_not_claim_to_cover_arg(self) -> None:
        by_id = {r.id: r for r in docker_rule_objects()}
        assert "ENV or ARG" not in by_id["DOCKER_ENV_SECRET"].description
        assert "ENV or ARG" not in by_id["DOCKER_ENV_SECRET"].title

    def test_the_privileged_port_rule_is_deleted_and_recorded(self) -> None:
        assert "DOCKER_EXPOSED_PRIVILEGED_PORT" not in {r.id for r in docker_rule_objects()}
        assert "DOCKER_EXPOSED_PRIVILEGED_PORT" in deprecated_rule_ids()

    def test_exposing_a_low_port_is_no_longer_a_finding(self) -> None:
        found = fired(
            "FROM nginx:1.25\nEXPOSE 80 443\nUSER 101\nWORKDIR /x\nHEALTHCHECK CMD true\n"
        )
        assert found <= {"DOCKER_NO_DIGEST_PIN"}


class TestEveryRuleReadsAPropertyTheParserEmits:
    """A rule keyed on a property no parser writes can never fire (the seven dead rules)."""

    def emitted(self) -> dict[str, set[str]]:
        keys: dict[str, set[str]] = {}
        sources = sorted(Path("tests/fixtures/docker").glob("*.Dockerfile"))
        sources += sorted(Path("tests/fixtures/real_shapes/docker").glob("*Dockerfile"))
        sources += sorted(Path("tests/test_rules/cases").glob("docker__*/*/bad.Dockerfile"))
        for source in sources:
            for resource in DockerfileParser().parse(source.read_text()).resources:
                keys.setdefault(resource.resource_type, set()).update(resource.properties)
        return keys

    @staticmethod
    def condition_keys(condition: Any) -> set[str]:
        found: set[str] = set()
        if isinstance(condition, dict):
            for key, value in condition.items():
                if key in ("all_of", "any_of", "none_of", "not"):
                    items = value if isinstance(value, list) else [value]
                    for item in items:
                        found |= TestEveryRuleReadsAPropertyTheParserEmits.condition_keys(item)
                else:
                    found.add(key.split(".")[0])
        return found

    def test_every_condition_key_is_emitted_for_the_rule_resource_type(self) -> None:
        emitted = self.emitted()
        for rule in docker_rule_objects():
            produced = set().union(*(emitted.get(t, set()) for t in rule.resource_types))
            missing = self.condition_keys(dict(rule.condition)) - produced
            assert not missing, f"{rule.id} reads {sorted(missing)}, which no Dockerfile produces"

    def test_every_docker_rule_fires_on_its_bad_case(self) -> None:
        for rule in docker_rule_objects():
            bad = next(Path("tests/test_rules/cases").glob(f"docker__*/{rule.id}/bad.Dockerfile"))
            assert rule.id in fired(bad.read_text()), rule.id


class TestFinalStageSemantics:
    BUILDER_HARDENED = """\
FROM golang:1.22 AS build
RUN useradd --uid 10001 builder
USER builder
HEALTHCHECK CMD true
WORKDIR /src
RUN go build -o /out/app ./cmd/app

FROM debian:12-slim
COPY --from=build /out/app /app
"""

    def test_a_hardened_builder_and_a_root_final_stage_fire_user_and_healthcheck(self) -> None:
        found = fired(self.BUILDER_HARDENED)
        assert {"DOCKER_NO_USER", "DOCKER_NO_HEALTHCHECK", "DOCKER_MISSING_WORKDIR"} <= found

    def test_a_root_builder_and_a_hardened_final_stage_stay_quiet(self) -> None:
        text = """\
FROM golang:1.22 AS build
USER root
RUN go build -o /out/app ./cmd/app

FROM debian:12-slim
WORKDIR /app
COPY --from=build /out/app /app/app
USER 10001
HEALTHCHECK CMD ["/app/app", "-h"]
"""
        found = fired(text)
        assert not {"DOCKER_NO_USER", "DOCKER_ROOT_USER", "DOCKER_NO_HEALTHCHECK"} & found

    def test_inheriting_from_a_base_that_sets_user_is_non_root(self) -> None:
        text = "FROM debian:12-slim AS base\nUSER 10001\nFROM base\nCOPY a /a\n"
        assert "DOCKER_NO_USER" not in fired(text)

    def test_the_audit_multistage_file_has_no_latest_tag_finding(self) -> None:
        text = (
            "ARG GO_VERSION=1.22\n"
            "FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}@sha256:" + "a" * 64 + " AS build\n"
            "FROM build AS test\n"
            "FROM gcr.io/distroless/static-debian12:nonroot@sha256:" + "b" * 64 + "\n"
            "USER 65532:65532\n"
        )
        assert "DOCKER_LATEST_TAG" not in fired(text)

    def test_scratch_and_stage_references_are_not_latest(self) -> None:
        assert "DOCKER_LATEST_TAG" not in fired(
            "FROM golang:1.22 AS b\nFROM b AS t\nFROM scratch\n"
        )

    def test_a_registry_with_a_port_and_no_tag_is_latest(self) -> None:
        assert "DOCKER_LATEST_TAG" in fired("FROM registry.local:5000/team/app\n")

    def test_an_arg_default_of_latest_is_latest(self) -> None:
        assert "DOCKER_LATEST_TAG" in fired("ARG TAG=latest\nFROM base:${TAG}\n")

    def test_an_unresolved_tag_variable_is_not_judged(self) -> None:
        assert "DOCKER_LATEST_TAG" not in fired("ARG TAG\nFROM base:${TAG}\n")

    def test_no_digest_pin_does_not_fire_for_scratch_or_an_unresolved_base(self) -> None:
        assert "DOCKER_NO_DIGEST_PIN" not in fired("FROM scratch\n")
        assert "DOCKER_NO_DIGEST_PIN" not in fired("FROM ${BASE}\n")
        assert "DOCKER_NO_DIGEST_PIN" in fired("FROM debian:12-slim\n")

    def test_a_non_minimal_final_stage_fires_but_a_non_minimal_builder_does_not(self) -> None:
        assert "DOCKER_NON_MINIMAL_BASE" in fired("FROM ubuntu:22.04\n")
        assert "DOCKER_NON_MINIMAL_BASE" not in fired("FROM ubuntu:22.04 AS b\nFROM alpine:3.20\n")


class TestRuleExamplesFromTheAudit:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("from ubuntu:22.04\nrun true\nuser root\n", "DOCKER_ROOT_USER"),
            ("FROM a:1\nUSER 0:0\n", "DOCKER_ROOT_USER"),
            ("FROM a:1\nUSER root:root\n", "DOCKER_ROOT_USER"),
            ("FROM a:1\nUSER 0:root\n", "DOCKER_ROOT_USER"),
            ("FROM a:1\nENV APP=web DB_PASSWORD=hunter2 PORT=80\n", "DOCKER_ENV_SECRET"),
            ("FROM a:1\nENV API_TOKEN hunter2\n", "DOCKER_ENV_SECRET"),
            ("FROM a:1\nRUN wget -qO- https://x.sh | sudo bash\n", "DOCKER_RUN_CURL_PIPE"),
            ("FROM a:1\nRUN curl https://x.py | python3\n", "DOCKER_RUN_CURL_PIPE"),
            ("FROM a:1\nRUN sudo make\n", "DOCKER_RUN_SUDO"),
            (
                'FROM a:1\nCOPY ["server.key", "/etc/"]\n',
                "DOCKER_SENSITIVE_FILE_COPY",
            ),
            ("FROM a:1\nADD --chown=app:app server.pem /etc/ssl/\n", "DOCKER_SENSITIVE_FILE_ADD"),
            ("FROM a:1\nADD https://example.com/f.tar /opt/\n", "DOCKER_ADD_FROM_URL"),
            ("FROM a:1\nEXPOSE 8000-8010 ${PORT} 22-25\n", "DOCKER_EXPOSED_SSH"),
            ("FROM a:1\nRUN apt-get install -y curl\n", "DOCKER_APT_NO_CLEAN"),
            ("FROM a:1\nARG NPM_TOKEN=abc123xyz\n", "DOCKER_ARG_SECRET"),
            ("FROM a:1\nADD config.json /app/\n", "DOCKER_ADD_INSTEAD_OF_COPY"),
        ],
    )
    def test_the_finding_fires(self, text: str, expected: str) -> None:
        assert expected in fired(text)

    @pytest.mark.parametrize(
        ("text", "absent"),
        [
            (
                "FROM a:1\nRUN curl -fsSL https://x/c.sha256 | sha256sum -c -\n",
                "DOCKER_RUN_CURL_PIPE",
            ),
            ("FROM a:1\nRUN apt-get install -y sudo\n", "DOCKER_RUN_SUDO"),
            (
                "FROM a:1\nENV KEYBOARD_LAYOUT=us AUTHORS=t PUBLIC_KEY_PATH=/k SECRET_FILE=/s\n",
                "DOCKER_ENV_SECRET",
            ),
            ("FROM a:1\nARG TOKEN\nARG KEY_VERSION=3\n", "DOCKER_ARG_SECRET"),
            ("FROM a:1\nADD --checksum=sha256:abc https://x/f.tar /opt/\n", "DOCKER_ADD_FROM_URL"),
            (
                "FROM a:1\nADD --checksum=sha256:abc https://x/f.tar /opt/\n",
                "DOCKER_ADD_INSTEAD_OF_COPY",
            ),
            ("FROM a:1\nADD rootfs.tar.gz /\n", "DOCKER_ADD_INSTEAD_OF_COPY"),
            ("FROM a:1 AS b\nFROM c:1\nCOPY --from=b /x /x\nUSER app\n", "DOCKER_COPY_NO_CHOWN"),
            ("FROM a:1\nCOPY --chmod=755 x /x\n", "DOCKER_COPY_NO_CHOWN"),
            ("FROM a:1\nEXPOSE 8000-8010 23-25\n", "DOCKER_EXPOSED_SSH"),
            ("FROM a:1\nUSER 1000:1000\n", "DOCKER_ROOT_USER"),
            ("FROM a:1\nARG U\nUSER ${U}\n", "DOCKER_ROOT_USER"),
            ("FROM a:1\nARG U\nUSER ${U}\n", "DOCKER_NO_USER"),
        ],
    )
    def test_the_false_positive_is_gone(self, text: str, absent: str) -> None:
        assert absent not in fired(text)

    def test_heredoc_bodies_are_checked_but_never_become_instructions(self) -> None:
        text = (
            "FROM a:1\nUSER app\n"
            "COPY <<EOF /etc/x.conf\nUSER root\nEXPOSE 22\nEOF\n"
            "RUN <<EOF\nsudo true\ncurl https://x | sh\nEOF\n"
        )
        found = fired(text)
        assert {"DOCKER_RUN_SUDO", "DOCKER_RUN_CURL_PIPE"} <= found
        assert not {"DOCKER_ROOT_USER", "DOCKER_EXPOSED_SSH"} & found

    def test_onbuild_triggers_run_command_checks_but_not_the_summary_rules(self) -> None:
        text = "FROM a:1\nUSER app\nONBUILD RUN curl https://x | sh\nONBUILD USER root\n"
        found = fired(text)
        assert "DOCKER_RUN_CURL_PIPE" in found
        assert "DOCKER_ROOT_USER" not in found

    def test_a_secret_value_never_reaches_a_finding(self) -> None:
        result = scan_text("FROM a:1\nENV DB_PASSWORD=hunter2hunter2\n", "Dockerfile")
        assert "hunter2hunter2" not in repr([t.to_dict() for t in result.threats])
        assert "hunter2hunter2" not in repr(result.graph.to_dict())
