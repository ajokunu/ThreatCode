"""Tests for the LLM phase of the analysis pipeline."""

from __future__ import annotations

import json
from typing import Any

import pytest

from threatcode.config import ThreatCodeConfig
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.llm.client import BaseLLMClient, DryRunLLMClient
from threatcode.engine.llm.phase import run_llm_phase
from threatcode.exceptions import LLMError
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id


class FakeClient(BaseLLMClient):
    """Returns a canned reply or raises, and records the prompts it receives."""

    def __init__(self, reply: str = '{"threats": []}', error: Exception | None = None) -> None:
        self.reply = reply
        self.error = error
        self.prompts: list[str] = []

    def analyze(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self.error is not None:
            raise self.error
        return self.reply


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
        client = FakeClient(_reply(_raw()))
        threats, status = run_llm_phase(simple_s3_graph, [], client, None)

        assert len(threats) == 1
        t = threats[0]
        assert t.source == ThreatSource.LLM
        assert t.severity == Severity.HIGH
        assert t.stride_category == "elevation_of_privilege"
        assert t.resource_address == "aws_s3_bucket.public_assets"
        assert t.confidence == 0.9
        assert t.id == hash_id(f"LLM_aws_s3_bucket.public_assets_{t.title}")
        assert status["status"] == "ran"
        assert status["threat_count"] == 1
        assert status["error"] == ""

    def test_unknown_resource_caps_confidence_at_half(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeClient(
            _reply(
                _raw(title="Known", confidence=0.9),
                _raw(title="Unknown", resource_address="aws_s3_bucket.nope", confidence=0.9),
                _raw(title="Low", resource_address="aws_s3_bucket.nope", confidence=0.2),
            )
        )
        threats, _ = run_llm_phase(simple_s3_graph, [], client, None)
        by_title = {t.title: t for t in threats}

        assert by_title["Known"].confidence == 0.9
        assert by_title["Unknown"].confidence == 0.5
        assert by_title["Low"].confidence == 0.2

    def test_tactics_derived_from_techniques_when_absent(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeClient(_reply(_raw(mitre_techniques=["T1190"])))
        threats, _ = run_llm_phase(simple_s3_graph, [], client, None)
        assert threats[0].mitre_techniques == ["T1190"]
        assert threats[0].mitre_tactics == ["TA0001"]

    def test_prompt_lists_the_ids_of_findings_gathered_so_far(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        existing = [
            Threat(
                id="r1",
                title="t",
                description="d",
                stride_category="tampering",
                severity=Severity.LOW,
                source=ThreatSource.RULE,
                resource_type="aws_s3_bucket",
                resource_address="aws_s3_bucket.data",
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
                resource_address="aws_s3_bucket.data",
            ),
        ]
        client = FakeClient()
        run_llm_phase(simple_s3_graph, existing, client, None)

        assert len(client.prompts) == 1
        assert "S3_NO_ENCRYPTION" in client.prompts[0]

    def test_empty_reply_is_a_successful_run_with_no_threats(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        threats, status = run_llm_phase(simple_s3_graph, [], FakeClient("not json"), None)
        assert threats == []
        assert status["status"] == "ran"
        assert status["threat_count"] == 0

    def test_dry_run_client_reports_its_provider(
        self, simple_s3_graph: InfraGraph, capsys: pytest.CaptureFixture[str]
    ) -> None:
        threats, status = run_llm_phase(simple_s3_graph, [], DryRunLLMClient(), None)
        assert threats == []
        assert status["status"] == "ran"
        assert status["provider"] == "dry-run"
        assert "DRY RUN" in capsys.readouterr().err

    def test_provider_and_model_come_from_config_for_other_clients(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        config = ThreatCodeConfig()
        config.llm.provider = "openai"
        config.llm.model = "some-model"
        _, status = run_llm_phase(simple_s3_graph, [], FakeClient(), config)
        assert status["provider"] == "openai"
        assert status["model"] == "some-model"


class TestFailures:
    def test_llm_error_returns_failed_status_without_raising(
        self, simple_s3_graph: InfraGraph, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = FakeClient(error=LLMError("server unreachable"))
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
        client = FakeClient(error=RuntimeError("kaboom"))
        with caplog.at_level("ERROR", logger="threatcode.engine.llm.phase"):
            threats, status = run_llm_phase(simple_s3_graph, [], client, None)

        assert threats == []
        assert status["status"] == "failed"
        assert status["error"] == "RuntimeError: kaboom"
        assert any(r.exc_info is not None for r in caplog.records)

    def test_error_text_is_bounded(self, simple_s3_graph: InfraGraph) -> None:
        client = FakeClient(error=LLMError("x" * 5000))
        _, status = run_llm_phase(simple_s3_graph, [], client, None)
        assert len(status["error"]) == 500

    def test_invalid_threat_is_dropped_but_the_rest_survive(
        self, simple_s3_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The parser normally filters unknown categories; force one through.
        from threatcode.engine.llm import parser

        def bad_parse(response: str) -> list[dict[str, Any]]:
            return [_raw(title="Bad", stride_category="made_up"), _raw(title="Good")]

        monkeypatch.setattr(parser, "parse_llm_threats", bad_parse)
        threats, status = run_llm_phase(simple_s3_graph, [], FakeClient(), None)

        assert [t.title for t in threats] == ["Good"]
        assert status["status"] == "ran"
        assert status["threat_count"] == 1


class TestThroughTheEngine:
    def test_llm_threats_are_appended_last_and_status_is_recorded(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        engine = HybridEngine(llm_client=FakeClient(_reply(_raw())))
        report = engine.analyze(simple_s3_graph)

        assert report.threats[-1].source == ThreatSource.LLM
        assert [t.source for t in report.threats].count(ThreatSource.LLM) == 1
        assert report.llm is not None
        assert report.llm["status"] == "ran"
        assert report.to_dict()["llm"]["threat_count"] == 1

    def test_failed_llm_keeps_rule_results(self, simple_s3_graph: InfraGraph) -> None:
        baseline = HybridEngine().analyze(simple_s3_graph)
        engine = HybridEngine(llm_client=FakeClient(error=LLMError("down")))
        report = engine.analyze(simple_s3_graph)

        assert [t.id for t in report.threats] == [t.id for t in baseline.threats]
        assert report.llm is not None
        assert report.llm["status"] == "failed"
        assert report.llm["error"] == "down"
        assert report.to_dict()["llm"]["status"] == "failed"
