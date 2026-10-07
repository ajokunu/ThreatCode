"""Tests for threatcode.pipeline: one graph per scan, coverage and the exit contract."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

import pytest

from threatcode.diagnostics import Diagnostic
from threatcode.engine.llm.client import BaseLLMClient
from threatcode.exceptions import ConfigError, UsageError
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import Coverage
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.pipeline import (
    EXIT_FINDINGS,
    EXIT_OK,
    EXIT_USAGE,
    ScanResult,
    compute_exit_code,
    prepare_request,
    run_scan,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
TF_BUCKET = 'resource "aws_s3_bucket" "{name}" {{\n  bucket = "{name}"\n}}\n'
BAD_TF = 'resource "aws_s3_bucket" "broken" {\n  bucket = \n'


@pytest.fixture(autouse=True)
def hermetic_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    for name in (
        "THREATCODE_FAIL_ON",
        "THREATCODE_MIN_SEVERITY",
        "THREATCODE_FORMAT",
        "THREATCODE_LLM",
    ):
        monkeypatch.delenv(name, raising=False)


def fixture_text(relative: str) -> str:
    return (FIXTURES / relative).read_text(encoding="utf-8")


def bucket(name: str) -> str:
    return TF_BUCKET.format(name=name)


def write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def scan(*paths: str | Path, **options: Any) -> ScanResult:
    return run_scan(prepare_request([str(p) for p in paths], **options).request)


def make_threat(severity: Severity, source: ThreatSource = ThreatSource.RULE) -> Threat:
    return Threat(
        id="abcdefabcdef",
        title="t",
        description="d",
        stride_category="tampering",
        severity=severity,
        source=source,
        resource_type="x",
        resource_address="x.y",
    )


class TestOneGraphPerScan:
    def test_several_paths_and_a_directory_make_one_graph(self, tmp_path: Path) -> None:
        write(tmp_path, "infra/main.tf", bucket("one"))
        write(
            tmp_path,
            "k8s/deploy.yaml",
            (FIXTURES / "kubernetes/insecure_deployment.yml").read_text(),
        )
        write(
            tmp_path, "stack/cfn.yml", (FIXTURES / "cloudformation/insecure_stack.yml").read_text()
        )
        result = scan(tmp_path)
        separate = [
            scan(tmp_path / "infra"),
            scan(tmp_path / "k8s"),
            scan(tmp_path / "stack"),
        ]
        assert result.graph.node_count == sum(r.graph.node_count for r in separate)
        assert result.coverage.units_parsed == 3
        assert {t.location_file for t in result.report.threats} >= {
            "infra/main.tf",
            "k8s/deploy.yaml",
            "stack/cfn.yml",
        }

    def test_several_named_files_are_one_scan_rooted_at_their_common_parent(
        self, tmp_path: Path
    ) -> None:
        a = write(tmp_path, "a/main.tf", bucket("a"))
        b = write(tmp_path, "b/other.tf", bucket("b"))
        result = scan(a, b)
        assert result.root == tmp_path
        assert result.report.input_file == "a/main.tf, b/other.tf"
        assert result.graph.node_count == 2

    def test_files_of_one_terraform_directory_share_a_graph_with_cross_file_edges(
        self, tmp_path: Path
    ) -> None:
        vpc = 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'
        subnet = (
            'resource "aws_subnet" "a" {\n  vpc_id = aws_vpc.main.id\n'
            '  cidr_block = "10.0.1.0/24"\n}\n'
        )
        write(tmp_path, "network.tf", vpc)
        write(tmp_path, "subnets.tf", subnet)
        result = scan(tmp_path)
        assert result.coverage.units_parsed == 1
        edges = {(e.source, e.target, e.edge_type.value) for e in result.graph.edges}
        assert ("aws_subnet.a", "aws_vpc.main", "containment") in edges
        sources = {n.id: n.source_file for n in result.graph.nodes.values()}
        assert sources["aws_vpc.main"] == "network.tf"
        assert sources["aws_subnet.a"] == "subnets.tf"

    def test_a_named_terraform_file_is_parsed_alone_not_as_its_directory(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        write(tmp_path, "other.tf", bucket("two"))
        result = scan(tmp_path / "main.tf")
        assert [n.id for n in result.graph.nodes.values()] == ["aws_s3_bucket.one"]

    def test_the_same_address_in_two_units_is_qualified_by_the_unit_path(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "a/main.tf", bucket("shared"))
        write(tmp_path, "b/main.tf", bucket("shared"))
        ids = sorted(scan(tmp_path).graph.nodes)
        assert ids == ["a::aws_s3_bucket.shared", "b::aws_s3_bucket.shared"]
        assert ids == sorted(scan(tmp_path).graph.nodes)

    def test_a_plan_replaces_the_module_in_its_directory(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("from_hcl") + bucket("second"))
        shutil.copy(FIXTURES / "terraform/simple_s3.plan.json", tmp_path / "plan.json")
        result = scan(tmp_path)
        plan_only = scan(tmp_path / "plan.json")
        assert sorted(result.graph.nodes) == sorted(plan_only.graph.nodes)
        assert "aws_s3_bucket.from_hcl" not in result.graph.nodes
        assert result.coverage.units_parsed == 1
        assert result.coverage.files_discovered == 2
        codes = [d.code for d in result.graph.diagnostics]
        assert "graph.unit_superseded" in codes
        superseded = next(d for d in result.graph.diagnostics if d.code == "graph.unit_superseded")
        assert superseded.level == "info"
        assert result.coverage.gaps == []

    def test_a_plan_that_fails_leaves_the_module_in_place(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("kept"))
        shutil.copy(FIXTURES / "input_shapes/terraform_state.json", tmp_path / "state.json")
        result = scan(tmp_path)
        assert "aws_s3_bucket.kept" in result.graph.nodes
        assert [e["file"] for e in result.coverage.errors] == ["state.json"]

    def test_a_helm_chart_is_one_unit_and_its_templates_are_not_scanned_raw(self) -> None:
        result = scan(FIXTURES / "helm")
        assert result.coverage.units_parsed == 1
        assert result.coverage.errors == []
        assert result.coverage.not_iac_count == 0
        assert result.coverage.files_discovered == 1
        assert result.graph.node_count > 0


class TestCoverage:
    def test_a_broken_file_is_an_error_and_the_rest_is_still_analysed(self, tmp_path: Path) -> None:
        write(tmp_path, "good/main.tf", bucket("fine"))
        write(tmp_path, "bad/main.tf", BAD_TF)
        result = scan(tmp_path)
        assert "aws_s3_bucket.fine" in result.graph.nodes
        (error,) = result.coverage.errors
        assert error["file"] == "bad"
        assert error["code"] == "parse.failed"
        assert error["message"]
        assert result.exit_code == EXIT_USAGE
        assert result.report.to_dict()["coverage"]["errors"] == [error]

    def test_a_broken_dockerfile_name_or_mcp_config_is_an_error_not_not_iac(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "ok.tf", bucket("fine"))
        (tmp_path / "Dockerfile").write_bytes(b"\x80\x81\x82" * 50)
        write(tmp_path, ".mcp.json", "{ nope")
        result = scan(tmp_path)
        assert sorted(e["file"] for e in result.coverage.errors) == ["Dockerfile"]
        assert result.coverage.not_iac_count == 1
        assert result.coverage.not_iac_paths == [".mcp.json"]

    def test_candidates_no_parser_claims_are_counted_not_errors(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("fine"))
        write(tmp_path, "tsconfig.json", '{"compilerOptions": {}}')
        write(tmp_path, ".gitlab/ci.yml", "stages: [build]\n")
        write(tmp_path, "docs/ci.yml", "stages: [build]\n")
        write(tmp_path, "package.json", '{"name": "x"}')
        result = scan(tmp_path)
        assert result.coverage.errors == []
        assert result.coverage.not_iac_count == 3
        assert result.coverage.not_iac_paths == ["docs/ci.yml", "package.json", "tsconfig.json"]
        assert result.coverage.units_parsed == 1

    def test_invalid_json_and_yaml_and_empty_and_binary_generic_files_are_not_infrastructure(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", bucket("fine"))
        write(tmp_path, "broken.json", "{not json")
        write(tmp_path, "broken.yaml", "a: [unclosed\n")
        write(tmp_path, "empty.yaml", "")
        (tmp_path / "blob.json").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x01")
        result = scan(tmp_path)
        assert result.coverage.errors == []
        assert result.coverage.not_iac_count == 4

    def test_a_named_file_that_nothing_claims_is_an_error(self, tmp_path: Path) -> None:
        other = write(tmp_path, "notes.xml", "<root/>")
        result = scan(other)
        assert result.exit_code == EXIT_USAGE
        assert result.coverage.errors[0]["file"] == "notes.xml"
        assert "Cannot detect format" in result.coverage.errors[0]["message"]
        assert result.coverage.not_iac_count == 0

    def test_a_named_empty_file_is_an_error(self, tmp_path: Path) -> None:
        empty = write(tmp_path, "empty.yaml", "")
        result = scan(empty)
        assert result.exit_code == EXIT_USAGE
        assert "file is empty" in result.coverage.errors[0]["message"]

    def test_symlinks_are_skipped_and_counted_and_never_read(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        write(outside, "secret.tf", bucket("leaked_outside"))
        scan_root = tmp_path / "scan"
        write(scan_root, "main.tf", bucket("inside"))
        (scan_root / "escape.tf").symlink_to(outside / "secret.tf")
        (scan_root / "escape-dir").symlink_to(outside)
        (scan_root / "loop").symlink_to(".")
        result = scan(scan_root)
        assert result.coverage.symlinks_skipped == 3
        assert list(result.graph.nodes) == ["aws_s3_bucket.inside"]
        assert "leaked_outside" not in json.dumps(result.to_dict())

    def test_a_warning_diagnostic_is_a_gap_and_an_info_one_is_not(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._add_diagnostics(monkeypatch, "warning", "info")
        result = scan(write(tmp_path, "main.tf", bucket("one")))
        assert [g["code"] for g in result.coverage.gaps] == ["hcl.module_call_skipped"]
        gap = result.coverage.gaps[0]
        assert gap["level"] == "warning"
        assert gap["file"] == "main.tf"
        assert gap["message"].startswith("module call")

    @staticmethod
    def _add_diagnostics(monkeypatch: pytest.MonkeyPatch, *levels: str) -> None:
        import threatcode.parsers as parsers

        real = parsers.detect_and_parse
        codes = {"warning": "hcl.module_call_skipped", "info": "graph.unit_superseded"}

        def patched(path: str | Path) -> Any:
            parsed = real(path)
            for level in levels:
                parsed.diagnostics.append(
                    Diagnostic(level, codes[level], f"module call vpc ({level})", file=str(path))  # type: ignore[arg-type]
                )
            return parsed

        monkeypatch.setattr(parsers, "detect_and_parse", patched)

    def test_diagnostic_files_are_made_root_relative(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self._add_diagnostics(monkeypatch, "warning")
        result = scan(write(tmp_path, "sub/main.tf", bucket("one")))
        assert result.coverage.gaps[0]["file"] == "main.tf"
        assert str(tmp_path) not in json.dumps(result.to_dict())

    def test_a_rule_that_raises_is_counted_and_listed(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import threatcode.engine.hybrid as hybrid

        real = hybrid.matches_rule

        def flaky(rule: Any, node: Any) -> Any:
            if rule.id == "S3_NO_LOGGING":
                raise RuntimeError("boom")
            return real(rule, node)

        monkeypatch.setattr(hybrid, "matches_rule", flaky)
        monkeypatch.delenv("THREATCODE_STRICT_RULES", raising=False)
        result = scan(write(tmp_path, "main.tf", bucket("one")))
        assert result.coverage.rule_errors == len(result.report.rule_errors) == 1
        assert result.coverage.has_gaps

    def test_files_discovered_counts_every_candidate_file(self, tmp_path: Path) -> None:
        write(tmp_path, "a.tf", bucket("a"))
        write(tmp_path, "b.tf", bucket("b"))
        write(tmp_path, "c.json", "{}")
        write(tmp_path, "notes.txt", "x")
        assert scan(tmp_path).coverage.files_discovered == 3


class TestExitContract:
    @pytest.mark.parametrize(
        ("fail_on", "expected"),
        [
            ("critical", EXIT_OK),
            ("high", EXIT_FINDINGS),
            ("medium", EXIT_FINDINGS),
            ("low", EXIT_FINDINGS),
            ("info", EXIT_FINDINGS),
            ("none", EXIT_OK),
        ],
    )
    def test_findings_gate_at_and_below_the_threshold(self, fail_on: str, expected: int) -> None:
        # simple.tf has one high and no critical finding
        assert scan(FIXTURES / "terraform/simple.tf", fail_on=fail_on).exit_code == expected

    def test_default_threshold_is_high(self, tmp_path: Path) -> None:
        # one medium-or-lower finding set: a Kubernetes manifest with only mediums
        result = scan(FIXTURES / "terraform/simple.tf")
        assert result.exit_code == EXIT_FINDINGS
        assert max(t.severity for t in result.report.threats) is Severity.HIGH

    def test_a_clean_input_exits_zero(self, tmp_path: Path) -> None:
        # the secure Dockerfile fixture has no finding at or above high
        assert scan(FIXTURES / "docker/secure.Dockerfile", fail_on="high").exit_code == EXIT_OK

    def test_nothing_found_is_a_usage_error(self, tmp_path: Path) -> None:
        write(tmp_path, "README.md", "# nothing here\n")
        result = scan(tmp_path)
        assert result.exit_code == EXIT_USAGE
        assert [e["code"] for e in result.coverage.errors] == ["discovery.nothing_to_model"]
        assert result.graph.node_count == 0

    def test_only_not_iac_files_is_nothing_found(self, tmp_path: Path) -> None:
        write(tmp_path, "package.json", '{"name": "x"}')
        result = scan(tmp_path)
        assert result.exit_code == EXIT_USAGE
        assert "1 candidate file(s) were not infrastructure" in result.coverage.errors[0]["message"]

    def test_zero_resources_overall_is_a_usage_error(self, tmp_path: Path) -> None:
        write(tmp_path, "vars.tf", 'variable "region" {\n  default = "us-east-1"\n}\n')
        result = scan(tmp_path)
        assert result.exit_code == EXIT_USAGE
        assert [e["code"] for e in result.coverage.errors] == ["parse.zero_resources"]

    def test_a_parse_failure_beats_findings(self, tmp_path: Path) -> None:
        write(tmp_path, "good/main.tf", bucket("fine"))
        write(tmp_path, "bad/main.tf", BAD_TF)
        assert scan(tmp_path, fail_on="none").exit_code == EXIT_USAGE

    def test_a_missing_path_raises_a_usage_error(self, tmp_path: Path) -> None:
        with pytest.raises(UsageError, match="path not found"):
            scan(tmp_path / "nope")

    def test_strict_turns_any_gap_into_exit_two(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        TestCoverage._add_diagnostics(monkeypatch, "warning")
        path = write(tmp_path, "main.tf", bucket("one"))
        assert scan(path, fail_on="none").exit_code == EXIT_OK
        assert scan(path, fail_on="none", strict=True).exit_code == EXIT_USAGE
        assert scan(path, strict=True).exit_code == EXIT_USAGE

    def test_strict_without_gaps_changes_nothing(self) -> None:
        assert scan(FIXTURES / "terraform/simple.tf", strict=True).exit_code == EXIT_FINDINGS
        assert scan(FIXTURES / "terraform/simple.tf", strict=True, fail_on="none").exit_code == 0

    def test_a_suppressed_gate_exits_zero(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        rules = sorted({t.rule_id for t in scan(tmp_path, fail_on="none").report.threats})
        (tmp_path / ".threatcodeignore").write_text("\n".join(rules) + "\n", encoding="utf-8")
        result = scan(tmp_path)
        assert result.exit_code == EXIT_OK
        assert result.report.threats == []
        assert result.coverage.suppressed > 0

    def test_ingest_errors_surface_as_usage_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def reject(paths: Any, graph: Any, root: Any) -> Any:
            raise UsageError(f"cannot ingest {paths[0]}: unrecognized format")

        monkeypatch.setattr("threatcode.ingest.load_and_attach", reject)
        junk = write(tmp_path, "junk.json", "{}")
        with pytest.raises(UsageError, match="junk.json"):
            scan(FIXTURES / "terraform/simple.tf", ingest=[junk])


class TestComputeExitCode:
    def call(self, **overrides: Any) -> int:
        args: dict[str, Any] = {
            "errors": [],
            "strict": False,
            "coverage": Coverage(),
            "threats": [],
            "attack_paths": [],
            "fail_on": "high",
        }
        args.update(overrides)
        return compute_exit_code(**args)

    def test_nothing_is_zero(self) -> None:
        assert self.call() == EXIT_OK

    def test_errors_win_over_everything(self) -> None:
        err = [{"file": "x", "code": "parse.failed", "message": "m"}]
        assert self.call(errors=err, threats=[make_threat(Severity.CRITICAL)]) == EXIT_USAGE
        assert self.call(errors=err, write_baseline=True, fail_on="none") == EXIT_USAGE

    def test_strict_gaps_win_over_findings_but_strict_alone_does_not(self) -> None:
        gappy = Coverage(gaps=[{"level": "warning", "code": "k8s.skipped_document"}])
        high = [make_threat(Severity.HIGH)]
        assert self.call(strict=True, coverage=gappy, threats=high) == EXIT_USAGE
        assert self.call(strict=False, coverage=gappy, threats=high) == EXIT_FINDINGS
        assert self.call(strict=True, threats=high) == EXIT_FINDINGS

    def test_failed_rules_count_as_a_gap_under_strict(self) -> None:
        assert self.call(strict=True, coverage=Coverage(rule_errors=1)) == EXIT_USAGE

    def test_write_baseline_exits_zero_whatever_was_found(self) -> None:
        assert self.call(threats=[make_threat(Severity.CRITICAL)], write_baseline=True) == EXIT_OK

    def test_none_never_fails_on_findings_or_paths(self) -> None:
        path = AttackPath(id="p", entry="internet", target="db", severity=Severity.CRITICAL)
        threats = [make_threat(Severity.CRITICAL)]
        assert self.call(fail_on="none", threats=threats, attack_paths=[path]) == EXIT_OK

    def test_an_attack_path_at_or_above_the_threshold_gates(self) -> None:
        path = AttackPath(id="p", entry="internet", target="db", severity=Severity.HIGH)
        assert self.call(attack_paths=[path]) == EXIT_FINDINGS
        assert self.call(attack_paths=[path], fail_on="critical") == EXIT_OK

    def test_llm_findings_are_advisory_and_never_gate(self) -> None:
        llm = make_threat(Severity.CRITICAL, ThreatSource.LLM)
        assert self.call(threats=[llm]) == EXIT_OK
        assert self.call(threats=[llm, make_threat(Severity.HIGH)]) == EXIT_FINDINGS

    def test_the_effective_severity_decides_and_the_base_is_the_fallback(self) -> None:
        raised = make_threat(Severity.LOW)
        raised.effective_severity = Severity.CRITICAL
        lowered = make_threat(Severity.CRITICAL)
        lowered.effective_severity = Severity.LOW
        assert self.call(threats=[raised]) == EXIT_FINDINGS
        assert self.call(threats=[lowered]) == EXIT_OK
        assert self.call(threats=[make_threat(Severity.HIGH)]) == EXIT_FINDINGS


class TestLocationsFingerprintsAndOrder:
    def test_threats_are_sorted_by_severity_address_rule_and_id(self) -> None:
        threats = scan(FIXTURES / "terraform/multi_service_insecure.plan.json").report.threats
        keys = [
            (-(t.effective_severity or t.severity).rank, t.resource_address, t.rule_id, t.id)
            for t in threats
        ]
        assert keys == sorted(keys)
        assert len(threats) > 10

    def test_every_threat_has_a_fingerprint_and_ids_are_the_engines(self, tmp_path: Path) -> None:
        from tests.helpers.scan import scan_files

        path = write(tmp_path, "main.tf", bucket("one"))
        piped = scan(path).report.threats
        direct = scan_files([path]).threats
        assert sorted(t.id for t in piped) == sorted(t.id for t in direct)
        assert all(len(t.fingerprint) == 16 for t in piped)
        assert len({t.fingerprint for t in piped}) == len(piped)

    def test_locations_are_root_relative_posix_everywhere(self, tmp_path: Path) -> None:
        write(tmp_path, "deep/er/main.tf", bucket("one"))
        write(tmp_path, "k8s/d.yaml", fixture_text("kubernetes/insecure_deployment.yml"))
        result = scan(tmp_path)
        text = json.dumps(result.to_dict())
        assert str(tmp_path) not in text
        assert "\\\\" not in text
        files = {t.location_file for t in result.report.threats}
        assert files == {"deep/er/main.tf", "k8s/d.yaml"}
        assert {n.source_file for n in result.graph.nodes.values()} == files

    def test_output_does_not_depend_on_where_the_tree_lives(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        outputs = []
        for name in ("first", "second/nested"):
            root = tmp_path / name
            write(root, "infra/main.tf", bucket("one"))
            write(root, "k8s/d.yaml", fixture_text("kubernetes/secure_deployment.yml"))
            outputs.append(json.dumps(scan(root).to_dict(), indent=2))
        assert outputs[0] == outputs[1]

    def test_a_threat_without_a_location_gets_its_nodes_file(self, tmp_path: Path) -> None:
        result = scan(write(tmp_path, "main.tf", bucket("one")))
        assert all(t.location_file == "main.tf" for t in result.report.threats)

    def test_an_absolute_location_from_a_producer_is_made_relative(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "proj"
        path = write(root, "main.tf", bucket("one"))
        absolute = str(path)

        def secrets(units: Any, graph: Any) -> list[Threat]:
            threat = make_threat(Severity.HIGH, ThreatSource.SECRET)
            threat.id = "5ec5ec5ec5ec"
            threat.rule_id = "SECRET_TEST"
            threat.location_file = absolute
            return [threat]

        monkeypatch.setattr("threatcode.engine.secrets.iac.find_secrets", secrets)
        result = scan(root)
        found = next(t for t in result.report.threats if t.rule_id == "SECRET_TEST")
        assert found.location_file == "main.tf"
        assert len(found.fingerprint) == 16


class TestSeams:
    def test_find_secrets_gets_the_units_with_their_parse_outputs_and_the_graph(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: dict[str, Any] = {}

        def spy(units: Any, graph: Any) -> list[Threat]:
            seen["units"] = list(units)
            seen["graph"] = graph
            return []

        monkeypatch.setattr("threatcode.engine.secrets.iac.find_secrets", spy)
        write(tmp_path, "main.tf", bucket("one"))
        write(tmp_path, "plan.json", "{}")
        result = scan(tmp_path)
        by_rel = {u.relpath: u for u in seen["units"]}
        assert by_rel["."].parsed is not None
        assert by_rel["."].path == tmp_path
        assert seen["graph"] is result.graph

    def test_secret_findings_join_the_report_and_the_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def secrets(units: Any, graph: Any) -> list[Threat]:
            threat = make_threat(Severity.CRITICAL, ThreatSource.SECRET)
            threat.id = "5ec5ec5ec5ec"
            threat.rule_id = "SECRET_TEST"
            threat.resource_address = "aws_s3_bucket.one"
            return [threat]

        monkeypatch.setattr("threatcode.engine.secrets.iac.find_secrets", secrets)
        result = scan(write(tmp_path, "main.tf", bucket("one")), fail_on="critical")
        assert any(t.rule_id == "SECRET_TEST" for t in result.report.threats)
        assert result.exit_code == EXIT_FINDINGS

    def test_ingested_findings_and_diagnostics_are_merged(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from threatcode.ingest import IngestResult

        calls: list[Any] = []

        def ingest(paths: Any, graph: Any, root: Any) -> IngestResult:
            calls.append((list(paths), root))
            threat = make_threat(Severity.CRITICAL, ThreatSource.SCANNER)
            threat.id = "1111111111aa"
            threat.rule_id = "trivy:CVE-2024-1"
            threat.evidence = "scanner"
            diag = Diagnostic("warning", "ingest.unattached", "1 finding matched no node")
            return IngestResult([threat], [diag], [{"tool": "trivy", "attached": 0}])

        monkeypatch.setattr("threatcode.ingest.load_and_attach", ingest)
        report_file = write(tmp_path, "scan/trivy.json", "{}")
        result = scan(write(tmp_path, "main.tf", bucket("one")), ingest=[report_file])
        assert calls == [([report_file], tmp_path)]
        assert any(t.rule_id == "trivy:CVE-2024-1" for t in result.report.threats)
        assert [g["code"] for g in result.coverage.gaps] == ["ingest.unattached"]
        assert result.ingest_sources == [{"tool": "trivy", "attached": 0}]

    def test_ingest_is_not_touched_without_ingest_files(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def explode(paths: Any, graph: Any, root: Any) -> Any:
            raise AssertionError("ingest must not run")

        monkeypatch.setattr("threatcode.ingest.load_and_attach", explode)
        scan(write(tmp_path, "main.tf", bucket("one")))

    def test_the_ingest_stub_refuses_files_and_names_the_first(self, tmp_path: Path) -> None:
        junk = write(tmp_path, "report.json", "{}")
        with pytest.raises(UsageError, match="report.json"):
            scan(FIXTURES / "terraform/simple.tf", ingest=[junk])


class TestSuppressionsAndBaseline:
    def test_suppression_is_counted_and_reported_before_the_gate(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        (tmp_path / ".threatcodeignore").write_text("S3_NO_ENCRYPTION\nGHOST_RULE\n")
        result = scan(tmp_path)
        assert result.ignore_file == tmp_path / ".threatcodeignore"
        assert result.ignore_entries == 2
        assert result.coverage.suppressed == 1
        assert not any(t.rule_id == "S3_NO_ENCRYPTION" for t in result.report.threats)
        assert any("GHOST_RULE matched no finding" in n for n in result.notices)
        # the one high finding was suppressed, so the default gate no longer trips
        assert result.exit_code == EXIT_OK

    def test_no_ignore_reads_no_file(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        (tmp_path / ".threatcodeignore").write_text("S3_NO_ENCRYPTION\n")
        result = scan(tmp_path, no_ignore=True)
        assert result.ignore_file is None
        assert result.coverage.suppressed == 0
        assert result.exit_code == EXIT_FINDINGS

    def test_an_explicit_ignore_file_is_used_and_a_missing_one_is_an_error(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path / "src", "main.tf", bucket("one"))
        custom = write(tmp_path, "custom.ignore", "S3_NO_ENCRYPTION\n")
        assert scan(tmp_path / "src", ignore_file=custom).coverage.suppressed == 1
        with pytest.raises(ConfigError, match="Ignore file not found"):
            scan(tmp_path / "src", ignore_file=tmp_path / "missing")

    def test_the_ignore_file_at_the_root_is_only_read_from_the_root(self, tmp_path: Path) -> None:
        write(tmp_path, "infra/main.tf", bucket("one"))
        (tmp_path / ".threatcodeignore").write_text("S3_NO_ENCRYPTION\n")
        assert scan(tmp_path / "infra").coverage.suppressed == 0

    def test_an_expired_entry_does_not_suppress(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        (tmp_path / ".threatcodeignore").write_text("S3_NO_ENCRYPTION exp:2020-01-01\n")
        result = scan(tmp_path)
        assert result.coverage.suppressed == 0
        assert any("expired" in n for n in result.notices)

    def test_a_suppression_by_fingerprint_works(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        first = scan(tmp_path, fail_on="none")
        target = next(t for t in first.report.threats if t.rule_id == "S3_NO_ENCRYPTION")
        (tmp_path / ".threatcodeignore").write_text(f"{target.fingerprint}\n")
        second = scan(tmp_path, fail_on="none")
        assert [
            t.rule_id
            for t in first.report.threats
            if t.rule_id not in {t2.rule_id for t2 in second.report.threats}
        ] == ["S3_NO_ENCRYPTION"]
        assert second.coverage.suppressed == 1

    def test_baseline_round_trip(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        baseline = tmp_path / "out" / "baseline.json"
        written = scan(tmp_path, write_baseline=baseline, fail_on="info")
        assert written.exit_code == EXIT_OK
        assert written.baseline_written == baseline
        entries = json.loads(baseline.read_text())["entries"]
        assert len(entries) == len(written.report.threats) > 0
        assert entries == sorted(
            entries, key=lambda e: (e["fingerprint"], e["rule_id"], e["resource"])
        )

        again = scan(tmp_path, baseline=baseline, fail_on="info")
        assert again.exit_code == EXIT_OK
        assert again.report.threats == []
        assert again.coverage.baselined == len(entries)

        write(tmp_path, "more.tf", bucket("two"))
        grown = scan(tmp_path, baseline=baseline, fail_on="info")
        assert grown.exit_code == EXIT_FINDINGS
        assert {t.resource_address for t in grown.report.threats} == {"aws_s3_bucket.two"}
        assert grown.coverage.baselined == len(entries)

    def test_the_baseline_survives_a_move_of_the_tree(self, tmp_path: Path) -> None:
        for name in ("a", "b/deep"):
            write(tmp_path / name, "main.tf", bucket("one"))
        baseline = tmp_path / "baseline.json"
        scan(tmp_path / "a", write_baseline=baseline)
        moved = scan(tmp_path / "b" / "deep", baseline=baseline, fail_on="info")
        assert moved.report.threats == []
        assert moved.exit_code == EXIT_OK

    def test_a_baseline_is_not_written_when_the_scan_had_input_errors(self, tmp_path: Path) -> None:
        write(tmp_path, "good/main.tf", bucket("one"))
        write(tmp_path, "bad/main.tf", BAD_TF)
        baseline = tmp_path / "baseline.json"
        result = scan(tmp_path, write_baseline=baseline)
        assert result.exit_code == EXIT_USAGE
        assert not baseline.exists()
        assert result.baseline_written is None
        assert any("was not written" in n for n in result.notices)

    def test_a_bad_baseline_file_fails_before_scanning(self, tmp_path: Path) -> None:
        bad = write(tmp_path, "b.json", '{"hello": 1}')
        with pytest.raises(ConfigError, match="not a ThreatCode baseline"):
            scan(FIXTURES / "terraform/simple.tf", baseline=bad)

    def test_writing_a_baseline_into_a_directory_is_an_error(self, tmp_path: Path) -> None:
        from threatcode.exceptions import ThreatCodeError

        with pytest.raises(ThreatCodeError, match="cannot write .*directory"):
            scan(FIXTURES / "terraform/simple.tf", write_baseline=tmp_path)

    def test_min_severity_filters_the_listing_but_not_the_gate(self) -> None:
        full = scan(FIXTURES / "terraform/simple.tf", fail_on="high")
        filtered = scan(FIXTURES / "terraform/simple.tf", fail_on="high", min_severity="critical")
        assert filtered.report.threats == []
        assert filtered.exit_code == full.exit_code == EXIT_FINDINGS
        assert filtered.report.to_dict()["total_threats"] == 0

    def test_min_severity_keeps_what_is_at_or_above_it(self) -> None:
        result = scan(FIXTURES / "terraform/simple.tf", min_severity="medium", fail_on="none")
        assert result.report.threats
        assert all(t.severity >= Severity.MEDIUM for t in result.report.threats)
        assert len(result.report.threats) == 4


class TestStdin:
    @staticmethod
    def feed(monkeypatch: pytest.MonkeyPatch, data: bytes) -> None:
        monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(data), encoding="utf-8"))

    def test_text_with_a_name_is_parsed_by_that_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, bucket("piped").encode())
        result = scan("-", stdin_name="main.tf")
        assert list(result.graph.nodes) == ["aws_s3_bucket.piped"]
        assert result.report.input_file == "main.tf"
        assert {t.location_file for t in result.report.threats} == {"main.tf"}
        assert result.root == Path.cwd()

    def test_a_plan_is_recognized_without_a_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, (FIXTURES / "terraform/simple_s3.plan.json").read_bytes())
        result = scan("-")
        assert result.report.input_file == "stdin.json"
        assert (
            result.graph.node_count
            == scan(FIXTURES / "terraform/simple_s3.plan.json").graph.node_count
        )

    def test_yaml_without_a_name_is_read_as_yaml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, (FIXTURES / "kubernetes/insecure_deployment.yml").read_bytes())
        result = scan("-")
        assert result.report.input_file == "stdin.yaml"
        assert result.graph.node_count >= 1

    def test_the_saved_copy_is_removed_afterwards(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scratch = tmp_path / "scratch"
        scratch.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(scratch))
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, bucket("piped").encode())
        result = scan("-", stdin_name="main.tf")
        assert result.graph.node_count == 1
        assert list(scratch.iterdir()) == []

    def test_empty_standard_input_is_a_usage_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, b"  \n")
        with pytest.raises(UsageError, match="standard input is empty"):
            scan("-")

    @pytest.mark.parametrize("name", ["../x.tf", "a/b.tf", "/abs.tf", "..", "a\\b.tf"])
    def test_a_stdin_name_must_be_a_plain_file_name(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, bucket("piped").encode())
        with pytest.raises(UsageError, match="--stdin-name must be a plain file name"):
            scan("-", stdin_name=name)

    def test_standard_input_next_to_a_file_is_one_scan(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        path = write(tmp_path, "main.tf", bucket("on_disk"))
        self.feed(monkeypatch, bucket("piped").replace("piped", "from_stdin").encode())
        result = scan(path, "-", stdin_name="extra.tf")
        assert sorted(result.graph.nodes) == ["aws_s3_bucket.from_stdin", "aws_s3_bucket.on_disk"]

    def test_stdin_that_is_a_state_file_gets_the_corrective_message(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        self.feed(monkeypatch, (FIXTURES / "input_shapes/terraform_state.json").read_bytes())
        result = scan("-")
        assert result.exit_code == EXIT_USAGE
        assert "This is Terraform state, not a plan" in result.coverage.errors[0]["message"]
        assert result.coverage.errors[0]["file"] == "stdin.json"


class TestDeterminismAndTimestamps:
    def test_two_runs_with_source_date_epoch_are_byte_identical(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        write(tmp_path, "main.tf", bucket("one"))
        first = json.dumps(scan(tmp_path).to_dict(), indent=2)
        second = json.dumps(scan(tmp_path).to_dict(), indent=2)
        assert first == second
        assert json.loads(first)["timestamp"] == "2023-11-14T22:13:20+00:00"

    def test_no_timestamp_leaves_the_key_out_even_with_an_epoch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        write(tmp_path, "main.tf", bucket("one"))
        assert "timestamp" not in scan(tmp_path, no_timestamp=True).to_dict()

    def test_two_runs_without_a_clock_are_identical_with_no_timestamp(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        a = json.dumps(scan(tmp_path, no_timestamp=True).to_dict())
        b = json.dumps(scan(tmp_path, no_timestamp=True).to_dict())
        assert a == b

    def test_a_bad_source_date_epoch_is_a_config_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "yesterday")
        write(tmp_path, "main.tf", bucket("one"))
        with pytest.raises(ConfigError, match="SOURCE_DATE_EPOCH"):
            scan(tmp_path)


class _RecordingClient(BaseLLMClient):
    def __init__(self, reply: str = '{"threats": []}') -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def analyze(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.reply


class TestLlmWiring:
    @pytest.fixture
    def factory_calls(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        calls: list[Any] = []

        def build(settings: Any) -> BaseLLMClient:
            calls.append(settings)
            return _RecordingClient()

        monkeypatch.setattr("threatcode.engine.llm.factory.build_client", build)
        return calls

    def test_no_client_is_built_without_a_request(
        self, tmp_path: Path, factory_calls: list[Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        result = scan(write(tmp_path, "main.tf", bucket("one")))
        assert factory_calls == []
        assert (result.report.llm or {}).get("status") == "skipped"

    @pytest.mark.parametrize("option", [{"llm": True}, {"dry_run": True}])
    def test_a_client_is_built_when_the_llm_or_a_dry_run_is_requested(
        self, tmp_path: Path, factory_calls: list[Any], option: dict[str, Any]
    ) -> None:
        result = scan(write(tmp_path, "main.tf", bucket("one")), **option)
        assert len(factory_calls) == 1
        assert factory_calls[0].use_llm is True
        assert (result.report.llm or {}).get("status") == "ran"

    def test_an_explicit_config_can_enable_the_llm(
        self, tmp_path: Path, factory_calls: list[Any]
    ) -> None:
        config = write(tmp_path, "c.yml", "llm:\n  enabled: true\n")
        scan(write(tmp_path / "src", "main.tf", bucket("one")), config_path=config)
        assert len(factory_calls) == 1

    def test_no_llm_overrides_the_config(self, tmp_path: Path, factory_calls: list[Any]) -> None:
        config = write(tmp_path, "c.yml", "llm:\n  enabled: true\n")
        scan(write(tmp_path / "src", "main.tf", bucket("one")), config_path=config, llm=False)
        assert factory_calls == []

    def test_no_client_is_built_when_there_is_nothing_to_send(
        self, tmp_path: Path, factory_calls: list[Any]
    ) -> None:
        write(tmp_path, "README.md", "x")
        scan(tmp_path, llm=True)
        assert factory_calls == []

    def test_llm_findings_are_advisory_and_never_gate(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        reply = json.dumps(
            {
                "threats": [
                    {
                        "title": "Model found something terrible",
                        "description": "d",
                        "stride_category": "tampering",
                        "severity": "critical",
                        "resource_address": "aws_s3_bucket.one",
                    }
                ]
            }
        )
        monkeypatch.setattr(
            "threatcode.engine.llm.factory.build_client", lambda settings: _RecordingClient(reply)
        )
        result = scan(write(tmp_path, "main.tf", bucket("one")), llm=True, fail_on="critical")
        llm_threats = [t for t in result.report.threats if t.source is ThreatSource.LLM]
        assert llm_threats
        assert llm_threats[0].severity is Severity.CRITICAL
        assert result.exit_code == EXIT_OK
        assert all(len(t.fingerprint) == 16 for t in llm_threats)


class TestPrepareRequest:
    def test_no_path_is_a_usage_error(self) -> None:
        with pytest.raises(UsageError, match="no input"):
            prepare_request([])

    def test_contradictory_ignore_options_are_a_usage_error(self) -> None:
        with pytest.raises(UsageError, match="contradict"):
            prepare_request(["x"], ignore_file="a", no_ignore=True)

    @pytest.mark.parametrize(
        ("options", "message"),
        [
            ({"fail_on": "sometimes"}, "fail_on must be one of"),
            ({"min_severity": "none"}, "min_severity must be one of"),
            ({"output_format": "yaml"}, "unknown output format"),
        ],
    )
    def test_invalid_option_values_are_usage_errors(
        self, options: dict[str, Any], message: str
    ) -> None:
        with pytest.raises(UsageError, match=message):
            prepare_request(["x"], **options)

    def test_a_config_in_the_scan_root_is_auto_discovered_and_untrusted(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        write(tmp_path, ".threatcode.yml", "fail_on: none\nmin_severity: high\n")
        prepared = prepare_request([str(tmp_path)])
        assert prepared.config.auto_discovered
        assert prepared.config.path == tmp_path / ".threatcode.yml"
        assert prepared.request.settings.fail_on == "high"
        assert prepared.request.settings.min_severity == "high"

    def test_the_request_carries_every_option(self, tmp_path: Path) -> None:
        prepared = prepare_request(
            [str(tmp_path)],
            strict=True,
            ignore_file="i",
            baseline="b",
            write_baseline="w",
            ingest=["x.json", "y.json"],
            stdin_name="n",
            no_timestamp=True,
            extra_rule_paths=["r.yml"],
        )
        request = prepared.request
        assert request.strict and request.no_timestamp
        assert request.ignore_file == Path("i")
        assert request.baseline == Path("b") and request.write_baseline == Path("w")
        assert request.ingest == (Path("x.json"), Path("y.json"))
        assert request.stdin_name == "n"
        assert request.settings.extra_rule_paths == (Path("r.yml"),)
        assert request.root == tmp_path

    def test_the_environment_is_read_through_the_same_resolver(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_FAIL_ON", "critical")
        write(tmp_path, "main.tf", bucket("one"))
        assert prepare_request([str(tmp_path)]).request.settings.fail_on == "critical"
        assert prepare_request([str(tmp_path)], fail_on="low").request.settings.fail_on == "low"

    def test_graph_limits_reach_the_graph(self, tmp_path: Path) -> None:
        from threatcode.exceptions import ThreatCodeError

        write(tmp_path, "main.tf", bucket("one") + bucket("two") + bucket("three"))
        with pytest.raises(ThreatCodeError, match="2 node limit"):
            scan(tmp_path, max_nodes=2)
        assert scan(tmp_path, max_nodes=3).graph.node_count == 3


class TestScanResult:
    def test_the_result_exposes_the_analysis_report_graph_and_coverage(
        self, tmp_path: Path
    ) -> None:
        result = scan(write(tmp_path, "main.tf", bucket("one")))
        assert result.report is result.analysis.report
        assert result.graph is result.analysis.graph
        assert result.coverage is result.report.coverage
        assert result.to_dict() == result.report.to_dict()
        assert result.to_dict()["coverage"]["units_parsed"] == 1
