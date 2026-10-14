"""Format detection by content, clean reports and the errors a bad file raises."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.test_ingest.conftest import INGEST_FIXTURES, REPO, Ingest, write_json
from threatcode.exceptions import UsageError
from threatcode.ingest import grype, load_and_attach, osv, sarif, trivy
from threatcode.ir.graph import InfraGraph

FORMATS = {
    "trivy-image.json": "trivy",
    "trivy-fs.json": "trivy",
    "grype-image.json": "grype",
    "grype-dir.json": "grype",
    "osv-lockfile.json": "osv-scanner",
    "sarif-checkov.json": "sarif",
    "sarif-gitleaks.json": "sarif",
    "sarif-trivy.json": "sarif",
}
CLEAN = [
    "trivy-clean.json",
    "grype-clean.json",
    "osv-clean.json",
    "sarif-empty.json",
]


@pytest.mark.parametrize(("name", "expected"), sorted(FORMATS.items()))
def test_each_sample_is_detected_by_its_content(ingest: Ingest, name: str, expected: str) -> None:
    (source, *_) = ingest(name).sources
    assert source["format"] == expected


@pytest.mark.parametrize("name", CLEAN)
def test_a_clean_report_is_a_source_with_zero_findings_not_an_error(
    ingest: Ingest, name: str
) -> None:
    result = ingest(name)
    assert result.threats == []
    (source,) = result.sources
    assert (source["findings"], source["attached"], source["unattached"]) == (0, 0, 0)
    assert result.diagnostics == []


def test_detection_does_not_depend_on_the_file_name(
    ingest: Ingest, tmp_path: Path, repo_graph: InfraGraph
) -> None:
    renamed = tmp_path / "scan-output.txt"
    renamed.write_text((INGEST_FIXTURES / "grype-image.json").read_text(), encoding="utf-8")
    result = load_and_attach([renamed], repo_graph, REPO)
    assert result.sources[0]["tool"] == "grype"
    assert result.sources[0]["file"] == "scan-output.txt"


def test_a_byte_order_mark_is_accepted(tmp_path: Path, repo_graph: InfraGraph) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + (INGEST_FIXTURES / "trivy-clean.json").read_bytes())
    result = load_and_attach([path], repo_graph, REPO)
    assert result.sources[0]["tool"] == "trivy"


def test_the_same_file_named_twice_is_read_once(repo_graph: InfraGraph) -> None:
    name = INGEST_FIXTURES / "trivy-image.json"
    result = load_and_attach([name, name], repo_graph, REPO)
    assert len(result.sources) == 1


def test_no_files_is_an_empty_result(repo_graph: InfraGraph) -> None:
    result = load_and_attach([], repo_graph, REPO)
    assert (result.threats, result.diagnostics, result.sources) == ([], [], [])


class TestDetectors:
    @pytest.mark.parametrize(
        "document",
        [
            {},
            [],
            "text",
            None,
            {"results": []},
            {"matches": []},
            {"runs": []},
            {"SchemaVersion": 2},
            {"SchemaVersion": "2", "Results": []},
            {"version": "2.1.0", "runs": [{"results": []}]},
            {"results": [{"source": {}, "packages": "no"}]},
        ],
    )
    def test_documents_that_are_not_scanner_results_match_no_reader(self, document: object) -> None:
        for reader in (trivy, grype, osv, sarif):
            assert not reader.detect(document), (reader.__name__, document)

    def test_a_results_list_alone_is_ambiguous_but_one_with_osv_config_is_a_report(self) -> None:
        assert not osv.detect({"results": []})
        assert osv.detect({"results": [], "experimental_config": {}})

    def test_sarif_needs_the_version_or_the_schema(self) -> None:
        run = {"tool": {"driver": {"name": "x"}}, "results": []}
        assert sarif.detect({"version": "2.1.0", "runs": [run]})
        assert sarif.detect({"$schema": "https://example/sarif-schema-2.1.0.json", "runs": [run]})
        assert not sarif.detect({"runs": [run]})
        assert not sarif.detect({"version": "1.0.0", "runs": [run]})


class TestErrors:
    def load(self, path: Path, graph: InfraGraph) -> None:
        load_and_attach([path], graph, REPO)

    def test_an_unrecognized_json_document_names_the_file_and_the_formats(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        junk = write_json(tmp_path / "junk.json", {"hello": "world"})
        with pytest.raises(UsageError) as info:
            self.load(junk, repo_graph)
        message = str(info.value)
        assert str(junk) in message
        for name in ("Trivy", "Grype", "OSV-Scanner", "SARIF"):
            assert name in message

    def test_text_that_is_not_json_names_the_file(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        path = tmp_path / "report.txt"
        path.write_text("CVE-2021-0001 lodash\n", encoding="utf-8")
        with pytest.raises(UsageError, match="report.txt.*not valid JSON"):
            self.load(path, repo_graph)

    def test_a_file_that_is_not_utf8_is_an_error_not_a_crash(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        path = tmp_path / "binary.json"
        path.write_bytes(b"\xff\xfe\x00\x01{")
        with pytest.raises(UsageError, match="binary.json"):
            self.load(path, repo_graph)

    def test_a_missing_file_is_an_error(self, tmp_path: Path, repo_graph: InfraGraph) -> None:
        with pytest.raises(UsageError, match="nope.json"):
            self.load(tmp_path / "nope.json", repo_graph)

    def test_a_directory_is_an_error(self, tmp_path: Path, repo_graph: InfraGraph) -> None:
        with pytest.raises(UsageError, match="is a directory"):
            self.load(tmp_path, repo_graph)

    def test_a_file_over_the_size_limit_is_an_error(
        self, tmp_path: Path, repo_graph: InfraGraph, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.ingest.MAX_INGEST_BYTES", 10)
        with pytest.raises(UsageError, match="limit"):
            self.load(INGEST_FIXTURES / "trivy-image.json", repo_graph)

    def test_deeply_nested_json_is_an_error_not_a_crash(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        path = tmp_path / "deep.json"
        path.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
        with pytest.raises(UsageError, match="deep.json"):
            self.load(path, repo_graph)

    def test_one_bad_file_among_good_ones_fails_the_whole_ingestion(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        junk = write_json(tmp_path / "junk.json", [1, 2])
        with pytest.raises(UsageError, match="junk.json"):
            load_and_attach(
                [INGEST_FIXTURES / "trivy-image.json", junk],
                repo_graph,
                REPO,
            )

    def test_malformed_entries_inside_a_recognized_report_are_skipped_not_fatal(
        self, tmp_path: Path, repo_graph: InfraGraph
    ) -> None:
        document = json.loads((INGEST_FIXTURES / "trivy-image.json").read_text())
        document["Results"].insert(0, "garbage")
        document["Results"][1]["Vulnerabilities"].insert(0, 7)
        path = write_json(tmp_path / "messy.json", document)
        result = load_and_attach([path], repo_graph, REPO)
        assert result.sources[0]["findings"] == 4
