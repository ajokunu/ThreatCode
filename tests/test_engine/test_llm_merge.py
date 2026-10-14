"""Tests for merging model findings: attribution, deduplication, stable ids and provenance."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.test_engine.llm_fakes import FakeLLMClient, canary_graph, raw_threat, threats_reply
from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.llm.context import AddressMap
from threatcode.engine.llm.merge import MAX_UNATTRIBUTED, merge_llm_threats
from threatcode.engine.llm.redactor import Redactor
from threatcode.formatters.diff import compute_diff
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.parsers.base import ParsedOutput, ParsedResource

BUCKET = "aws_s3_bucket.data"
ROLE = "aws_iam_role.app"


def _graph() -> InfraGraph:
    resources = [
        ParsedResource("aws_s3_bucket", BUCKET, "data", "aws", {"acl": "private"}),
        ParsedResource("aws_iam_role", ROLE, "app", "aws", {}, evidence="design"),
    ]
    return InfraGraph.from_parsed(ParsedOutput(resources=resources, source_path="x.tf"))


def _item(**overrides: Any) -> dict[str, Any]:
    item: dict[str, Any] = {
        "title": "The role can read every bucket",
        "description": "d",
        "stride_category": "information_disclosure",
        "severity": "high",
        "resource_type": "wrong_type_from_the_model",
        "resource_address": BUCKET,
        "mitigation": "m",
        "confidence": 0.8,
        "mitre_techniques": [],
        "mitre_tactics": [],
    }
    item.update(overrides)
    return item


def _existing(address: str = BUCKET, **overrides: Any) -> Threat:
    fields: dict[str, Any] = {
        "id": "rule-1",
        "title": "S3 bucket is not encrypted",
        "description": "d",
        "stride_category": "information_disclosure",
        "severity": Severity.HIGH,
        "source": ThreatSource.RULE,
        "resource_type": "aws_s3_bucket",
        "resource_address": address,
        "rule_id": "S3_NO_ENCRYPTION",
        "mitre_techniques": ["T1530"],
    }
    fields.update(overrides)
    return Threat(**fields)


def _merge(
    items: list[dict[str, Any]], existing: list[Threat] | None = None, graph: Any = None
) -> Any:
    graph = graph or _graph()
    return merge_llm_threats(items, graph, existing or [], AddressMap(graph), Redactor())


class TestAttribution:
    def test_an_empty_address_is_set_aside(self) -> None:
        result = _merge([_item(resource_address="")])
        assert result.threats == []
        assert result.unattributed_count == 1
        assert result.unattributed[0]["reason"] == "no resource address"

    def test_an_address_that_is_not_in_the_graph_is_set_aside(self) -> None:
        result = _merge([_item(resource_address="aws_s3_bucket.invented")])
        assert result.threats == []
        assert result.unattributed[0]["resource_address"] == "aws_s3_bucket.invented"
        assert result.unattributed[0]["reason"] == "address is not in the graph"

    def test_a_handle_and_a_real_address_both_attribute(self) -> None:
        result = _merge([_item(resource_address="aws_s3_bucket.n1")])
        assert [t.resource_address for t in result.threats] == [BUCKET]
        assert _merge([_item()]).threats[0].resource_address == BUCKET

    def test_the_resource_type_comes_from_the_graph(self) -> None:
        assert _merge([_item()]).threats[0].resource_type == "aws_s3_bucket"

    def test_evidence_follows_the_resource(self) -> None:
        result = _merge([_item(resource_address=ROLE, title="Other role problem")])
        assert result.threats[0].evidence == "design"
        assert _merge([_item()]).threats[0].evidence == "config"

    def test_the_unattributed_list_is_bounded_but_counted(self) -> None:
        items = [_item(resource_address="", title=f"T{i}") for i in range(MAX_UNATTRIBUTED + 20)]
        result = _merge(items)
        assert result.unattributed_count == MAX_UNATTRIBUTED + 20
        assert len(result.unattributed) == MAX_UNATTRIBUTED

    def test_findings_are_never_kept_at_full_confidence_for_a_made_up_resource(self) -> None:
        result = _merge([_item(resource_address="nothing", confidence=1.0)])
        assert result.threats == []


class TestTechniquesAndTactics:
    def test_tactics_are_derived_and_the_models_are_ignored(self) -> None:
        result = _merge([_item(mitre_techniques=["T1530"], mitre_tactics=["TA0001", "TA0040"])])
        assert result.threats[0].mitre_tactics == ["TA0009"]

    def test_the_models_tactics_are_kept_only_without_techniques(self) -> None:
        result = _merge([_item(mitre_tactics=["TA0001"])])
        assert result.threats[0].mitre_tactics == ["TA0001"]
        assert result.threats[0].mitre_techniques == []


class TestDeduplication:
    def test_a_rule_finding_with_the_same_technique_wins(self) -> None:
        result = _merge(
            [_item(title="Totally different words", mitre_techniques=["T1530"])], [_existing()]
        )
        assert result.threats == [] and result.duplicates == 1

    def test_a_rule_finding_with_a_similar_title_wins(self) -> None:
        result = _merge([_item(title="S3 bucket is not encrypted at rest")], [_existing()])
        assert result.threats == [] and result.duplicates == 1

    def test_a_different_category_is_not_a_duplicate(self) -> None:
        result = _merge(
            [_item(stride_category="tampering", title="S3 bucket is not encrypted")], [_existing()]
        )
        assert len(result.threats) == 1

    def test_a_different_resource_is_not_a_duplicate(self) -> None:
        result = _merge(
            [_item(resource_address=ROLE, title="S3 bucket is not encrypted")], [_existing()]
        )
        assert len(result.threats) == 1

    def test_a_dissimilar_title_without_a_shared_technique_is_kept(self) -> None:
        result = _merge([_item(title="Cross account access through the role chain")], [_existing()])
        assert len(result.threats) == 1 and result.duplicates == 0

    def test_a_boundary_finding_counts_through_its_target_too(self) -> None:
        crossing = _existing(
            ROLE,
            id="b1",
            source=ThreatSource.BOUNDARY,
            rule_id="",
            title="Trust boundary crossing: data -> management",
            mitre_techniques=["T1040"],
        )
        crossing.target_address = BUCKET
        result = _merge([_item(mitre_techniques=["T1040"])], [crossing])
        assert result.threats == [] and result.duplicates == 1

    def test_two_identical_model_items_give_one_finding(self) -> None:
        result = _merge([_item(), _item()])
        assert len(result.threats) == 1 and result.duplicates == 1

    def test_two_model_items_with_a_shared_technique_give_one_finding(self) -> None:
        result = _merge(
            [
                _item(title="First phrasing about role reach", mitre_techniques=["T1190"]),
                _item(title="Wholly separate wording here", mitre_techniques=["T1190"]),
            ]
        )
        assert len(result.threats) == 1

    def test_two_different_model_items_both_survive_with_distinct_ids(self) -> None:
        result = _merge(
            [_item(title="Alpha lateral path"), _item(title="Bravo exfiltration route")]
        )
        assert len(result.threats) == 2
        first, second = result.threats
        assert first.id != second.id  # same address and category, no techniques: a counter

    def test_a_clash_with_an_existing_id_gets_a_counter(self) -> None:
        first = _merge([_item()]).threats[0]
        clash = _existing(id=first.id, title="unrelated words only", mitre_techniques=[])
        clash.resource_address = ROLE
        result = _merge([_item(title="Another thing entirely")], [clash])
        assert result.threats[0].id != first.id


class TestStableIds:
    def test_rewording_does_not_change_the_id(self) -> None:
        one = _merge([_item(title="Wording one", mitre_techniques=["T1190", "T1530"])])
        two = _merge([_item(title="Entirely new words", mitre_techniques=["T1530", "T1190"])])
        assert one.threats[0].id == two.threats[0].id

    def test_a_different_technique_set_changes_the_id(self) -> None:
        one = _merge([_item(mitre_techniques=["T1190"])]).threats[0].id
        two = _merge([_item(mitre_techniques=["T1530"])]).threats[0].id
        assert one != two

    def test_the_id_depends_on_the_resource_and_the_category(self) -> None:
        base = _merge([_item()]).threats[0].id
        assert _merge([_item(resource_address=ROLE)]).threats[0].id != base
        assert _merge([_item(stride_category="tampering")]).threats[0].id != base

    def test_a_diff_of_two_reworded_runs_is_empty(self, tmp_path: Path) -> None:
        graph = canary_graph()

        def run(title: str) -> Path:
            reply = threats_reply(
                raw_threat(
                    title=title,
                    resource_address="aws_db_instance.n1",
                    stride_category="elevation_of_privilege",
                    mitre_techniques=["T1078"],
                )
            )
            report = HybridEngine(llm_client=FakeLLMClient(reply)).analyze(graph)
            path = tmp_path / f"{abs(hash(title))}.json"
            path.write_text(json.dumps(report.to_dict()), encoding="utf-8")
            return path

        diff = compute_diff(
            str(run("Public database exposes customer rows")),
            str(run("A reachable database leaks data")),
        )
        assert diff["added"] == [] and diff["removed"] == []
        assert diff["changed"] and all(c["id"] for c in diff["changed"])  # only the wording differs


class TestTextRestoration:
    def test_handles_in_text_become_addresses(self) -> None:
        graph = canary_graph()
        result = merge_llm_threats(
            [
                _item(
                    resource_address="aws_db_instance.n1",
                    description="Reached from aws_security_group.n2",
                )
            ],
            graph,
            [],
            AddressMap(graph),
            Redactor(),
        )
        assert result.threats[0].description.startswith("Reached from aws_security_group.")

    def test_a_placeholder_is_restored_only_for_the_findings_own_resource(self) -> None:
        graph = _graph()
        redactor = Redactor()
        with redactor.scope(BUCKET):
            own = redactor.redact({"note": "10.0.0.1"})["note"]
        with redactor.scope(ROLE):
            other = redactor.redact({"note": "10.0.0.2"})["note"]
        result = merge_llm_threats(
            [_item(description=f"own {own} other {other}")], graph, [], AddressMap(graph), redactor
        )
        assert result.threats[0].description == f"own 10.0.0.1 other {other}"

    def test_a_secret_placeholder_is_never_restored(self) -> None:
        graph = _graph()
        redactor = Redactor()
        with redactor.scope(BUCKET):
            secret = redactor.redact({"password": "hunter2hunter2"})["password"]
        result = merge_llm_threats(
            [_item(mitigation=f"Rotate {secret}")], graph, [], AddressMap(graph), redactor
        )
        assert "hunter2" not in result.threats[0].mitigation
        assert secret in result.threats[0].mitigation


class TestSeverityAndFields:
    def test_an_invalid_severity_becomes_medium(self) -> None:
        assert _merge([_item(severity="catastrophic")]).threats[0].severity is Severity.MEDIUM

    def test_source_and_confidence_are_set(self) -> None:
        threat = _merge([_item(confidence=0.42)]).threats[0]
        assert threat.source is ThreatSource.LLM
        assert threat.confidence == pytest.approx(0.42)

    def test_a_blank_title_after_restoring_is_invalid_not_a_crash(self) -> None:
        result = _merge([_item(title="")])
        assert result.threats == [] and result.invalid == 1
