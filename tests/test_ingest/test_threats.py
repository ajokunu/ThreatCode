"""The threats a placed finding becomes."""

from __future__ import annotations

import json

import pytest

from tests.test_ingest.conftest import Ingest, by_rule
from threatcode.fingerprint import compute_fingerprint
from threatcode.ingest.attach import Placement
from threatcode.ingest.model import ExternalFinding, PackageInfo
from threatcode.ingest.threats import STRIDE_BY_KIND, to_threats
from threatcode.models.threat import Severity, ThreatSource


class TestShape:
    def test_a_finding_becomes_a_scanner_threat_with_the_rule_id_tool_and_aliases(
        self, ingest: Ingest
    ) -> None:
        threats = by_rule(ingest("grype-image.json"))["grype:GHSA-35jh-r3h4-6jhm"]
        (threat,) = threats
        assert threat.source is ThreatSource.SCANNER
        assert threat.evidence == "scanner"
        assert threat.tool == "grype"
        assert threat.severity is Severity.HIGH
        assert threat.aliases == ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"]
        assert threat.mitre_techniques == []
        assert threat.title.startswith("GHSA-35jh-r3h4-6jhm")
        assert threat.resource_address == "kubernetes_deployment.shop.worker"
        assert threat.resource_type == "kubernetes_deployment"

    def test_the_description_names_the_package_both_versions_and_the_cvss(
        self, ingest: Ingest
    ) -> None:
        (threat,) = by_rule(ingest("trivy-image.json"))["trivy:CVE-2023-4911"]
        text = threat.description
        assert "Trivy reports CVE-2023-4911 in package libc6 2.36-9+deb12u3" in text
        assert "Fixed in 2.36-9+deb12u4" in text
        assert "CVSS base score 7.8" in text
        assert "Image: ghcr.io/acme/api:1.4.2" in text
        assert threat.mitigation == (
            "Upgrade libc6 to 2.36-9+deb12u4, or rebuild the image on a patched base."
        )

    def test_an_unfixed_vulnerability_says_so(self, ingest: Ingest) -> None:
        (threat,) = by_rule(ingest("trivy-image.json"))["trivy:CVE-2024-0001"]
        assert "No fixed version is reported" in threat.description
        assert threat.mitigation.startswith("No fixed version is reported")

    def test_metadata_records_the_join_the_package_and_the_ingested_file(
        self, ingest: Ingest
    ) -> None:
        (threat,) = by_rule(ingest("trivy-image.json"))["trivy:CVE-2023-4911"]
        meta = threat.metadata
        assert meta["join"] == "image"
        assert meta["kind"] == "vulnerability"
        assert meta["ingest_file"] == "trivy-image.json" or meta["ingest_file"].endswith(
            "trivy-image.json"
        )
        assert meta["package"]["name"] == "libc6"
        assert meta["fixed_version"] == "2.36-9+deb12u4"
        assert meta["cvss_score"] == 7.8
        json.dumps(meta)  # every value is JSON-safe

    def test_stride_follows_the_kind(self, ingest: Ingest) -> None:
        grouped = by_rule(ingest("trivy-fs.json"))
        assert grouped["trivy:CVE-2021-23337"][0].stride_category == "elevation_of_privilege"
        assert grouped["trivy:aws-secret-access-key"][0].stride_category == "information_disclosure"
        assert grouped["trivy:KSV001"][0].stride_category == "tampering"
        assert STRIDE_BY_KIND["other"] == "tampering"

    def test_a_secret_never_carries_the_matched_text(self, ingest: Ingest) -> None:
        for name in ("trivy-image.json", "trivy-fs.json", "sarif-gitleaks.json"):
            blob = json.dumps([t.to_dict() for t in ingest(name).threats])
            assert "AWS_ACCESS_KEY_ID=" not in blob
            assert "echo ****" not in blob
            assert "REDACTED" not in blob

    def test_every_threat_serializes(self, ingest: Ingest) -> None:
        names = [
            "trivy-image.json",
            "trivy-fs.json",
            "grype-image.json",
            "osv-lockfile.json",
            "sarif-trivy.json",
        ]
        for threat in ingest(*names).threats:
            json.dumps(threat.to_dict())


class TestIdentity:
    def test_a_finding_on_two_nodes_gets_two_threats_with_distinct_ids_and_fingerprints(
        self,
    ) -> None:
        finding = ExternalFinding(
            tool="trivy",
            kind="vulnerability",
            id="CVE-1",
            severity="high",
            package=PackageInfo(name="zlib", version="1"),
            target="img",
        )
        from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone

        def node(name: str) -> InfraNode:
            return InfraNode(
                id=name,
                resource_type="aws_instance",
                name=name,
                category=NodeCategory.COMPUTE,
                trust_zone=TrustZone.PRIVATE,
            )

        placement = Placement("image", [node("aws_instance.a"), node("aws_instance.b")])
        a, b = to_threats(finding, placement, "r.json")
        assert a.id != b.id
        assert compute_fingerprint(a) != compute_fingerprint(b)

    def test_unattached_findings_of_one_rule_do_not_share_a_fingerprint(self) -> None:
        def build(target: str, package: str) -> ExternalFinding:
            return ExternalFinding(
                tool="trivy",
                kind="vulnerability",
                id="CVE-1",
                severity="high",
                package=PackageInfo(name=package),
                target=target,
            )

        placement = Placement("unattached")
        threats = [
            to_threats(build("img-a", "zlib"), placement, "r.json")[0],
            to_threats(build("img-b", "zlib"), placement, "r.json")[0],
            to_threats(build("img-a", "openssl"), placement, "r.json")[0],
        ]
        assert len({compute_fingerprint(t) for t in threats}) == 3
        assert len({t.id for t in threats}) == 3

    def test_the_fingerprint_survives_a_new_installed_version(self) -> None:
        def build(version: str) -> ExternalFinding:
            return ExternalFinding(
                tool="trivy",
                kind="vulnerability",
                id="CVE-1",
                severity="high",
                package=PackageInfo(name="zlib", version=version),
                target="img",
            )

        placement = Placement("unattached")
        one = to_threats(build("1.0"), placement, "r.json")[0]
        two = to_threats(build("1.1"), placement, "r.json")[0]
        assert compute_fingerprint(one) == compute_fingerprint(two)
        assert one.id != two.id


class TestLocation:
    def test_a_file_and_line_finding_is_located_at_that_line(self, ingest: Ingest) -> None:
        (threat,) = by_rule(ingest("sarif-gitleaks.json"))["gitleaks:aws-access-token"]
        assert (threat.location_file, threat.location_start_line) == ("infra/main.tf", 20)
        assert threat.metadata["join"] == "file_line"
        assert threat.confidence == 1.0

    def test_an_image_finding_leaves_the_location_to_the_workload(self, ingest: Ingest) -> None:
        (threat,) = by_rule(ingest("trivy-image.json"))["trivy:CVE-2023-4911"]
        assert threat.location_file == ""
        assert threat.location_start_line is None

    def test_a_directory_join_is_a_guess_about_ownership_and_says_so(self, ingest: Ingest) -> None:
        threats = by_rule(ingest("osv-lockfile.json"))["osv-scanner:GHSA-35jh-r3h4-6jhm"]
        (threat,) = threats
        assert threat.metadata["join"] == "directory"
        assert threat.confidence == pytest.approx(0.7)
        assert threat.location_file == "services/api/package-lock.json"
