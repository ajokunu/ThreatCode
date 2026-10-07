"""Tests for the LLM phase of the analysis pipeline, on its own and through the engine."""

from __future__ import annotations

import json
import logging
import re
from typing import Any

import pytest

from tests.test_engine.llm_fakes import (
    CANARIES,
    CANARY_NAME,
    FakeLLMClient,
    canary_graph,
    raw_threat,
    threats_reply,
)
from threatcode.config import LLMConfig, RedactionConfig, ThreatCodeConfig
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.llm.client import DryRunLLMClient
from threatcode.engine.llm.phase import run_llm_phase
from threatcode.exceptions import LLMError
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id


def _reply(*threats: dict[str, Any]) -> str:
    return json.dumps({"threats": list(threats)})


def _raw(**overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "title": "Lateral movement from the public bucket role",
        "description": "desc",
        "stride_category": "elevation_of_privilege",
        "severity": "high",
        "resource_type": "aws_s3_bucket",
        "resource_address": "aws_s3_bucket.public_assets",
        "mitigation": "Split the role",
        "confidence": 0.9,
    }
    raw.update(overrides)
    return raw


def _prompt_json(prompt: str) -> dict[str, Any]:
    """The JSON between the delimiter tags of a recorded prompt."""
    match = re.search(r"<(infrastructure_data_[0-9a-f]{16})>\n(.*)\n</\1>", prompt, re.DOTALL)
    assert match is not None, "the prompt carries no delimited data"
    data = json.loads(match.group(2))
    assert isinstance(data, dict)
    return data


class TestNoClient:
    def test_returns_nothing_and_a_skipped_status(self, simple_s3_graph: InfraGraph) -> None:
        threats, status = run_llm_phase(simple_s3_graph, [], None, None)
        assert threats == []
        assert status["status"] == "skipped"
        assert status["threat_count"] == 0
        assert status["error"] == ""
        assert set(status) == {"provider", "model", "status", "error", "threat_count"}


class TestSuccessfulRun:
    def test_converts_raw_threats_and_reports_ran(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeLLMClient(_reply(_raw()))
        threats, status = run_llm_phase(simple_s3_graph, [], client, None)

        assert len(threats) == 1
        t = threats[0]
        assert t.source == ThreatSource.LLM
        assert t.severity == Severity.HIGH
        assert t.stride_category == "elevation_of_privilege"
        assert t.resource_address == "aws_s3_bucket.public_assets"
        assert t.resource_type == "aws_s3_bucket"
        assert t.confidence == 0.9
        assert t.id == hash_id("LLM_aws_s3_bucket.public_assets_elevation_of_privilege_")
        assert status["status"] == "ran"
        assert status["threat_count"] == 1
        assert status["error"] == ""

    def test_the_model_can_answer_with_a_handle(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeLLMClient(_reply(_raw(resource_address="aws_s3_bucket.n1")))
        threats, _ = run_llm_phase(simple_s3_graph, [], client, None)
        assert [t.resource_address for t in threats] == [next(iter(simple_s3_graph.nodes))]

    def test_tactics_derived_from_techniques(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeLLMClient(_reply(_raw(mitre_techniques=["T1190"], mitre_tactics=["TA0009"])))
        threats, _ = run_llm_phase(simple_s3_graph, [], client, None)
        assert threats[0].mitre_techniques == ["T1190"]
        # The model's own tactics are ignored when it gave techniques
        assert threats[0].mitre_tactics == ["TA0001"]

    def test_a_revoked_technique_is_normalized_end_to_end(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        client = FakeLLMClient(_reply(_raw(mitre_techniques=["T1562.008"])))
        threats, _ = run_llm_phase(simple_s3_graph, [], client, None)
        assert threats[0].mitre_techniques == ["T1685.002"]
        assert threats[0].mitre_tactics == ["TA0112"]

    def test_status_records_provenance(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeLLMClient(_reply(_raw()))
        _, status = run_llm_phase(simple_s3_graph, [], client, None)
        assert (status["provider"], status["model"]) == ("fake", "fake-model")
        assert re.fullmatch(r"[0-9a-f]{16}", status["prompt_hash"])
        assert status["input_tokens_estimate"] > 0
        assert status["redaction"] == "placeholder"
        assert status["parsed_count"] == 1
        assert status["unattributed_count"] == 0
        assert status["context"]["nodes_total"] == len(simple_s3_graph.nodes)
        assert status["context"]["reduced"] is False

    def test_the_prompt_hash_is_stable_for_the_same_input(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        first = run_llm_phase(simple_s3_graph, [], FakeLLMClient(), None)[1]
        second = run_llm_phase(simple_s3_graph, [], FakeLLMClient(), None)[1]
        assert first["prompt_hash"] == second["prompt_hash"]

    def test_the_prompt_hash_changes_with_the_input(self, simple_s3_graph: InfraGraph) -> None:
        first = run_llm_phase(simple_s3_graph, [], FakeLLMClient(), None)[1]
        other = run_llm_phase(canary_graph(), [], FakeLLMClient(), None)[1]
        assert first["prompt_hash"] != other["prompt_hash"]

    def test_the_per_request_delimiter_differs_between_calls(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        client = FakeLLMClient()
        run_llm_phase(simple_s3_graph, [], client, None)
        run_llm_phase(simple_s3_graph, [], client, None)
        tags = [re.search(r"infrastructure_data_[0-9a-f]{16}", p) for p in client.prompts]
        assert tags[0] and tags[1] and tags[0].group() != tags[1].group()

    def test_each_resource_lists_the_rules_that_fired_on_it(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        addresses = list(simple_s3_graph.nodes)
        existing = [
            Threat(
                id="r1",
                title="t",
                description="d",
                stride_category="tampering",
                severity=Severity.LOW,
                source=ThreatSource.RULE,
                resource_type="aws_s3_bucket",
                resource_address=addresses[0],
                rule_id="S3_NO_ENCRYPTION",
            ),
            Threat(
                id="b1",
                title="t",
                description="d",
                stride_category="tampering",
                severity=Severity.LOW,
                source=ThreatSource.BOUNDARY,
                resource_type="aws_s3_bucket",
                resource_address=addresses[0],
            ),
        ]
        client = FakeLLMClient()
        run_llm_phase(simple_s3_graph, existing, client, None)

        assert len(client.prompts) == 1
        nodes = _prompt_json(client.prompts[0])["nodes"]
        assert nodes["aws_s3_bucket.n1"]["rules"] == ["S3_NO_ENCRYPTION", "boundary_crossing"]
        # A rule id shows up on its own resource only
        assert client.prompts[0].count("S3_NO_ENCRYPTION") == 1

    def test_unparseable_reply_is_a_successful_run_with_no_threats(
        self, simple_s3_graph: InfraGraph, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING):
            threats, status = run_llm_phase(simple_s3_graph, [], FakeLLMClient("not json"), None)
        assert threats == []
        assert status["status"] == "ran"
        assert status["threat_count"] == 0
        assert any("not valid JSON" in r.message for r in caplog.records)

    def test_dry_run_client_reports_its_provider(
        self, simple_s3_graph: InfraGraph, capsys: pytest.CaptureFixture[str]
    ) -> None:
        threats, status = run_llm_phase(simple_s3_graph, [], DryRunLLMClient(), None)
        assert threats == []
        assert status["status"] == "ran"
        assert status["provider"] == "dry-run"
        assert status["model"] == ""
        assert "DRY RUN" in capsys.readouterr().err

    def test_a_dry_run_shows_the_redacted_payload_and_never_the_canaries(
        self, tmp_path: Any
    ) -> None:
        target = tmp_path / "payload.json"
        run_llm_phase(canary_graph(), [], DryRunLLMClient(output=str(target)), None)
        text = target.read_text(encoding="utf-8")
        request = json.loads(text)
        assert "infrastructure_data_" in request["messages"][0]["content"]
        assert [c for c in CANARIES if c in text] == []
        assert "aws_db_instance.n1" in text
        assert '\\"publicly_accessible\\":true' in text

    def test_provider_and_model_come_from_config_for_other_clients(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        class Bare(FakeLLMClient):
            provider = ""
            model = ""

        config = ThreatCodeConfig(llm=LLMConfig(provider="openai", model="some-model"))
        _, status = run_llm_phase(simple_s3_graph, [], Bare(), config)
        assert status["provider"] == "openai"
        assert status["model"] == "some-model"


class TestPromptsLeakNothing:
    def test_no_canary_appears_anywhere_in_the_prompt(self) -> None:
        client = FakeLLMClient()
        run_llm_phase(canary_graph(), [], client, None)
        prompt = client.prompts[0]
        assert [c for c in CANARIES if c in prompt] == []

    def test_no_canary_appears_with_the_hash_strategy_either(self) -> None:
        client = FakeLLMClient()
        config = ThreatCodeConfig(redaction=RedactionConfig(strategy="hash"))
        run_llm_phase(canary_graph(), [], client, config)
        assert [c for c in CANARIES if c in client.prompts[0]] == []

    def test_security_relevant_flags_do_reach_the_model(self) -> None:
        client = FakeLLMClient()
        run_llm_phase(canary_graph(), [], client, None)
        nodes = _prompt_json(client.prompts[0])["nodes"]
        database = nodes["aws_db_instance.n1"]
        assert database["props"]["publicly_accessible"] is True
        assert database["props"]["storage_encrypted"] is False
        bucket = nodes["aws_s3_bucket.n3"]
        assert bucket["props"]["acl"] == "public-read"
        group = nodes["aws_security_group.n2"]
        rule = group["props"]["derived"]["ingress"][0]
        assert rule["cidr_blocks"][0] == "0.0.0.0/0"
        assert rule["from_port"] == 5432

    def test_a_redaction_field_from_the_config_reaches_the_redactor(self) -> None:
        graph = canary_graph()
        for node in graph.nodes.values():
            if node.resource_type == "aws_db_instance":
                node.properties["engine"] = "postgres-with-a-marker-value"
        client = FakeLLMClient()
        config = ThreatCodeConfig(redaction=RedactionConfig(fields=["engine"]))
        run_llm_phase(graph, [], client, config)
        assert "postgres-with-a-marker-value" not in client.prompts[0]

        client = FakeLLMClient()
        run_llm_phase(graph, [], client, ThreatCodeConfig())
        assert "postgres-with-a-marker-value" in client.prompts[0]

    def test_the_model_answer_maps_back_without_leaking(self) -> None:
        graph = canary_graph()
        client = FakeLLMClient(
            _reply(
                raw_threat(
                    resource_address="aws_db_instance.n1",
                    title="Public database aws_db_instance.n1 is reachable",
                    description="Reachable via aws_security_group.n2",
                )
            )
        )
        threats, _ = run_llm_phase(graph, [], client, None)
        assert threats[0].resource_address == f"aws_db_instance.{CANARY_NAME}"
        assert threats[0].resource_type == "aws_db_instance"
        assert threats[0].title == f"Public database aws_db_instance.{CANARY_NAME} is reachable"
        assert f"aws_security_group.{CANARY_NAME}_sg" in threats[0].description

    def test_a_secret_placeholder_in_the_answer_is_not_restored(self) -> None:
        graph = canary_graph()
        # Learn the placeholder the redactor issues for the password, then echo it back.
        from threatcode.engine.llm.redactor import Redactor

        probe = Redactor()
        placeholder = probe.redact({"password": "x"})["password"]
        assert placeholder.startswith("REDACTED_password_")
        client = FakeLLMClient(
            _reply(
                raw_threat(
                    resource_address="aws_db_instance.n1",
                    description=f"The value {placeholder} and REDACTED_password_1 are exposed",
                )
            )
        )
        threats, _ = run_llm_phase(graph, [], client, None)
        assert CANARIES[1] not in threats[0].description
        assert "REDACTED_password_1" in threats[0].description


class TestFailures:
    def test_llm_error_returns_failed_status_without_raising(
        self, simple_s3_graph: InfraGraph, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = FakeLLMClient(LLMError("server unreachable"))
        with caplog.at_level("WARNING", logger="threatcode.engine.llm.phase"):
            threats, status = run_llm_phase(simple_s3_graph, [], client, None)

        assert threats == []
        assert status["status"] == "failed"
        assert status["error"] == "server unreachable"
        assert status["threat_count"] == 0
        assert any("server unreachable" in r.getMessage() for r in caplog.records)
        # Expected failures log one line, not a traceback.
        assert all(r.exc_info is None for r in caplog.records)

    def test_unexpected_error_is_contained_and_logged_with_traceback(
        self, simple_s3_graph: InfraGraph, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = FakeLLMClient(RuntimeError("kaboom"))
        with caplog.at_level("ERROR", logger="threatcode.engine.llm.phase"):
            threats, status = run_llm_phase(simple_s3_graph, [], client, None)

        assert threats == []
        assert status["status"] == "failed"
        assert status["error"] == "RuntimeError: kaboom"
        assert any(r.exc_info is not None for r in caplog.records)

    def test_error_text_is_bounded(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeLLMClient(LLMError("x" * 5000))
        _, status = run_llm_phase(simple_s3_graph, [], client, None)
        assert len(status["error"]) == 500

    def test_a_failed_run_still_records_what_was_prepared(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        _, status = run_llm_phase(simple_s3_graph, [], FakeLLMClient(LLMError("down")), None)
        assert status["status"] == "failed"
        assert status["prompt_hash"]

    def test_one_malformed_item_does_not_cost_the_batch(self, simple_s3_graph: InfraGraph) -> None:
        reply = _reply(
            _raw(title="Null fields", description=None, severity=None, mitigation=["a"]),
            "not an object",
            _raw(title="Good"),
        )
        threats, status = run_llm_phase(simple_s3_graph, [], FakeLLMClient(reply), None)
        assert {t.title for t in threats} == {"Null fields", "Good"}
        assert len({t.id for t in threats}) == 2  # same address and category, no clash
        assert status["status"] == "ran"
        assert status["skipped_items"] == 1

    def test_a_truncated_reply_keeps_the_complete_threats(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        full = _reply(_raw(title="Alpha"), _raw(title="Beta threat two", resource_address="x"))
        cut = full[: full.index("Beta") + 4]
        threats, status = run_llm_phase(simple_s3_graph, [], FakeLLMClient(cut), None)
        assert [t.title for t in threats] == ["Alpha"]
        assert status["salvaged_items"] == 1

    def test_a_request_over_the_token_limit_is_refused_before_sending(self) -> None:
        client = FakeLLMClient()
        config = ThreatCodeConfig(llm=LLMConfig(max_input_tokens=1_000))
        threats, status = run_llm_phase(canary_graph(), [], client, config)
        assert threats == []
        assert status["status"] == "failed"
        assert "max_input_tokens" in status["error"]
        assert client.prompts == []


class TestBudget:
    def _config(self, tokens: int) -> ThreatCodeConfig:
        return ThreatCodeConfig(llm=LLMConfig(max_input_tokens=tokens))

    def test_a_big_graph_is_summarized_into_valid_json_with_a_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        graph = canary_graph(extra_resources=900)
        client = FakeLLMClient()
        with caplog.at_level(logging.WARNING):
            _, status = run_llm_phase(graph, [], client, self._config(4_000))
        assert status["status"] == "ran"
        data = _prompt_json(client.prompts[0])
        assert data["groups"][0]["count"] == 900
        assert data["groups"][0]["summary"] == "900 x aws_subnet in zone private"
        assert len(data["nodes"]) == 3
        stats = status["context"]
        assert stats["reduced"] is True
        assert stats["nodes_summarized"] == 900
        assert stats["groups"] == 1
        assert any("LLM context reduced" in r.message for r in caplog.records)
        assert status["input_tokens_estimate"] <= 4_000

    def test_the_full_graph_is_sent_when_it_fits(self) -> None:
        graph = canary_graph(extra_resources=20)
        client = FakeLLMClient()
        _, status = run_llm_phase(graph, [], client, self._config(60_000))
        data = _prompt_json(client.prompts[0])
        assert "groups" not in data
        assert len(data["nodes"]) == 23
        assert status["context"]["reduced"] is False

    def test_edges_come_before_nodes(self) -> None:
        client = FakeLLMClient()
        run_llm_phase(canary_graph(), [], client, None)
        keys = list(_prompt_json(client.prompts[0]))
        assert keys.index("edges") < keys.index("nodes")

    def test_a_graph_that_cannot_fit_even_summarized_is_refused_not_cut(self) -> None:
        graph = canary_graph(extra_resources=0)
        client = FakeLLMClient()
        # Every node here carries findings, so none can be dropped or summarized.
        existing = [
            Threat(
                id=f"r{i}",
                title="t",
                description="d",
                stride_category="tampering",
                severity=Severity.LOW,
                source=ThreatSource.RULE,
                resource_type="x",
                resource_address=address,
                rule_id=f"RULE_{i}_{'X' * 50}",
            )
            for i, address in enumerate(graph.nodes)
        ]
        # Enough room for the template but not for the nodes.
        threats, status = run_llm_phase(graph, existing, client, self._config(1_250))
        assert threats == []
        assert status["status"] == "failed"
        assert client.prompts == []


class TestThroughTheEngine:
    def test_llm_threats_are_appended_last_and_status_is_recorded(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        engine = HybridEngine(llm_client=FakeLLMClient(_reply(_raw())))
        report = engine.analyze(simple_s3_graph)

        assert report.threats[-1].source == ThreatSource.LLM
        assert [t.source for t in report.threats].count(ThreatSource.LLM) == 1
        assert report.llm is not None
        assert report.llm["status"] == "ran"
        assert report.to_dict()["llm"]["threat_count"] == 1
        assert report.to_dict()["llm"]["prompt_hash"] == report.llm["prompt_hash"]

    def test_rules_boundary_and_llm_counts(self) -> None:
        graph = canary_graph()
        client = FakeLLMClient(
            _reply(raw_threat(resource_address="aws_security_group.n2", title="Exposed database"))
        )
        report = HybridEngine(llm_client=client).analyze(graph)
        by_source = [t.source for t in report.threats]
        assert by_source.count(ThreatSource.RULE) > 0
        assert by_source.count(ThreatSource.BOUNDARY) > 0
        assert by_source.count(ThreatSource.LLM) == 1

    def test_failed_llm_keeps_rule_results(self, simple_s3_graph: InfraGraph) -> None:
        baseline = HybridEngine().analyze(simple_s3_graph)
        engine = HybridEngine(llm_client=FakeLLMClient(LLMError("down")))
        report = engine.analyze(simple_s3_graph)

        assert [t.id for t in report.threats] == [t.id for t in baseline.threats]
        assert report.llm is not None
        assert report.llm["status"] == "failed"
        assert report.llm["error"] == "down"
        assert report.to_dict()["llm"]["status"] == "failed"

    def test_a_generic_exception_degrades_to_rules_only_without_a_traceback_to_the_caller(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        baseline = HybridEngine().analyze(simple_s3_graph)
        engine = HybridEngine(llm_client=FakeLLMClient(ValueError("weird")))
        report = engine.analyze(simple_s3_graph)
        assert [t.id for t in report.threats] == [t.id for t in baseline.threats]
        assert report.llm is not None and report.llm["status"] == "failed"

    def test_a_model_restating_a_rule_finding_adds_nothing(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        baseline = HybridEngine().analyze(simple_s3_graph)
        rule = next(t for t in baseline.threats if t.source is ThreatSource.RULE)
        duplicate = _raw(
            title=rule.title,
            stride_category=rule.stride_category,
            resource_address=rule.resource_address,
        )
        report = HybridEngine(llm_client=FakeLLMClient(_reply(duplicate))).analyze(simple_s3_graph)
        assert [t.source for t in report.threats].count(ThreatSource.LLM) == 0
        assert report.llm is not None
        assert report.llm["duplicate_count"] == 1

    def test_unattributed_findings_are_reported_but_not_added(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        reply = _reply(_raw(resource_address="aws_s3_bucket.invented"), _raw(resource_address=""))
        report = HybridEngine(llm_client=FakeLLMClient(reply)).analyze(simple_s3_graph)
        assert [t.source for t in report.threats].count(ThreatSource.LLM) == 0
        assert report.llm is not None
        assert report.llm["unattributed_count"] == 2
        assert {u["reason"] for u in report.llm["unattributed"]} == {
            "address is not in the graph",
            "no resource address",
        }
        assert report.to_dict()["llm"]["unattributed_count"] == 2

    def test_reworded_output_keeps_the_same_ids(self, simple_s3_graph: InfraGraph) -> None:
        first = HybridEngine(
            llm_client=FakeLLMClient(_reply(_raw(title="Wording one", mitre_techniques=["T1190"])))
        ).analyze(simple_s3_graph)
        second = HybridEngine(
            llm_client=FakeLLMClient(
                _reply(_raw(title="Entirely other words", mitre_techniques=["T1190"]))
            )
        ).analyze(simple_s3_graph)

        def llm_ids(report: Any) -> list[str]:
            return [t.id for t in report.threats if t.source is ThreatSource.LLM]

        assert llm_ids(first) == llm_ids(second) != []


class TestFakeClient:
    def test_it_replays_in_order_then_falls_back_to_the_default(self) -> None:
        client = FakeLLMClient("one", LLMError("two"), default="dflt")
        assert client.analyze("a") == "one"
        with pytest.raises(LLMError):
            client.analyze("b")
        assert client.analyze("c") == "dflt"
        assert client.prompts == ["a", "b", "c"]
        assert client.calls == 3

    def test_the_helpers_build_valid_replies(self) -> None:
        assert json.loads(threats_reply(raw_threat()))["threats"][0]["title"]
