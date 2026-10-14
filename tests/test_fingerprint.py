"""Tests for threatcode.fingerprint."""

from __future__ import annotations

import re

from tests.helpers.scan import scan_text
from threatcode.fingerprint import FINGERPRINT_LENGTH, assign_fingerprints, compute_fingerprint
from threatcode.models.threat import Threat, ThreatSource

BUCKET = 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n'


def _threat(**overrides: object) -> Threat:
    fields: dict[str, object] = {
        "id": "abc123abc123",
        "title": "T",
        "description": "d",
        "stride_category": "tampering",
        "severity": "high",
        "source": ThreatSource.RULE,
        "resource_type": "aws_s3_bucket",
        "resource_address": "aws_s3_bucket.logs",
        "rule_id": "S3_NO_ENCRYPTION",
        "location_file": "main.tf",
    }
    fields.update(overrides)
    from threatcode.models.threat import Severity

    fields["severity"] = Severity(str(fields["severity"]))
    return Threat(**fields)  # type: ignore[arg-type]


class TestComputeFingerprint:
    def test_is_sixteen_lowercase_hex_characters(self) -> None:
        value = compute_fingerprint(_threat())
        assert len(value) == FINGERPRINT_LENGTH == 16
        assert re.fullmatch(r"[0-9a-f]{16}", value)

    def test_is_stable_for_the_same_finding(self) -> None:
        assert compute_fingerprint(_threat()) == compute_fingerprint(_threat())

    def test_changes_with_the_rule_the_address_the_file_and_the_kind(self) -> None:
        base = compute_fingerprint(_threat())
        assert compute_fingerprint(_threat(rule_id="S3_NO_LOGGING")) != base
        assert compute_fingerprint(_threat(resource_address="aws_s3_bucket.other")) != base
        assert compute_fingerprint(_threat(location_file="other.tf")) != base
        assert compute_fingerprint(_threat(source=ThreatSource.SECRET)) != base

    def test_ignores_text_severity_and_the_threat_id(self) -> None:
        base = compute_fingerprint(_threat())
        reworded = _threat(title="Another title", description="other", id="ffffffffffff")
        assert compute_fingerprint(reworded) == base
        assert compute_fingerprint(_threat(severity="low")) == base

    def test_a_hint_replaces_the_address_part(self) -> None:
        hinted = _threat(metadata={"fingerprint_hint": "attr:password"})
        moved = _threat(metadata={"fingerprint_hint": "attr:password"}, resource_address="x.y")
        assert compute_fingerprint(hinted) == compute_fingerprint(moved)
        assert compute_fingerprint(hinted) != compute_fingerprint(_threat())

    def test_a_finding_without_a_rule_id_uses_its_boundary_key_or_id(self) -> None:
        a = _threat(rule_id="", source=ThreatSource.BOUNDARY, id="aaaaaaaaaaaa")
        b = _threat(rule_id="", source=ThreatSource.BOUNDARY, id="bbbbbbbbbbbb")
        keyed = _threat(
            rule_id="",
            source=ThreatSource.BOUNDARY,
            id="cccccccccccc",
            metadata={"boundary_key": "internet->private"},
        )
        assert compute_fingerprint(a) != compute_fingerprint(b)
        assert compute_fingerprint(keyed) not in (compute_fingerprint(a), compute_fingerprint(b))

    def test_an_explicit_source_file_overrides_the_threats_location(self) -> None:
        threat = _threat(location_file="")
        assert compute_fingerprint(threat, "main.tf") == compute_fingerprint(_threat())

    def test_windows_separators_do_not_change_the_fingerprint(self) -> None:
        assert compute_fingerprint(_threat(location_file="a\\main.tf")) == compute_fingerprint(
            _threat(location_file="a/main.tf")
        )


class TestAssignFingerprints:
    def test_sets_one_on_every_threat_using_the_node_source_file(self) -> None:
        result = scan_text(BUCKET, "main.tf")
        assert result.threats
        for threat in result.threats:
            threat.fingerprint = ""
        assign_fingerprints(result.threats, result.graph)
        assert all(len(t.fingerprint) == 16 for t in result.threats)
        node = result.graph.get_node("aws_s3_bucket.logs")
        assert node is not None
        for threat in result.threats:
            if threat.resource_address == "aws_s3_bucket.logs":
                assert threat.fingerprint == compute_fingerprint(threat, node.source_file)

    def test_the_same_rule_on_two_resources_gets_two_fingerprints(self) -> None:
        text = BUCKET + BUCKET.replace("logs", "data")
        result = scan_text(text, "main.tf")
        assign_fingerprints(result.threats, result.graph)
        by_rule: dict[str, set[str]] = {}
        for threat in result.threats:
            by_rule.setdefault(threat.rule_id, set()).add(threat.fingerprint)
        assert len(by_rule["S3_NO_ENCRYPTION"]) == 2

    def test_threat_ids_are_not_touched(self) -> None:
        result = scan_text(BUCKET, "main.tf")
        ids = [t.id for t in result.threats]
        assign_fingerprints(result.threats, result.graph)
        assert [t.id for t in result.threats] == ids

    def test_works_without_a_graph(self) -> None:
        threat = _threat()
        assign_fingerprints([threat])
        assert threat.fingerprint == compute_fingerprint(threat)
