"""The pipeline's reports are one fact once and carry no trace of the machine they ran on.

RW-10: a coverage gap is listed once, and the two gaps one cause makes are one.
RW-12: every location is a POSIX path relative to the scan root (``..`` where a module sits
outside it), a finding names its resource type, and fingerprints do not depend on where the tree
lives.
A local module directory is in the graph once, as the call that uses it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from threatcode.diagnostics import Diagnostic
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.pipeline import (
    ScanResult,
    _coverage_gaps,
    _posix_relative,
    _unique_errors,
    prepare_request,
    run_scan,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
BUCKET = 'resource "aws_s3_bucket" "{name}" {{\n  bucket = "{name}"\n}}\n'


@pytest.fixture(autouse=True)
def hermetic_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")


def write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def scan(*paths: str | Path, **options: Any) -> ScanResult:
    return run_scan(prepare_request([str(p) for p in paths], **options).request)


def gap(code: str, message: str, file: str = "", line: int | None = None) -> Diagnostic:
    return Diagnostic("warning", code, message, file, line)


class TestGapsAreListedOnce:
    def test_a_repeated_diagnostic_is_one_gap(self) -> None:
        repeated = gap("hcl.module_call_skipped", "module.a is not analysed", "main.tf", 399)
        gaps = _coverage_gaps([repeated, repeated, repeated])
        assert [g["code"] for g in gaps] == ["hcl.module_call_skipped"]

    def test_the_same_message_on_another_line_or_in_another_file_is_another_gap(self) -> None:
        gaps = _coverage_gaps(
            [
                gap("hcl.unresolved_reference", "var.x is unknown", "a.tf", 3),
                gap("hcl.unresolved_reference", "var.x is unknown", "a.tf", 4),
                gap("hcl.unresolved_reference", "var.x is unknown", "b.tf", 3),
                gap("hcl.unresolved_reference", "var.y is unknown", "a.tf", 3),
            ]
        )
        assert len(gaps) == 4

    def test_order_is_the_order_of_first_appearance(self) -> None:
        a = gap("hcl.unresolved_reference", "a", "a.tf", 1)
        b = gap("hcl.unresolved_reference", "b", "b.tf", 1)
        assert [g["message"] for g in _coverage_gaps([b, a, b, a])] == ["b", "a"]

    def test_only_warnings_and_errors_are_gaps(self) -> None:
        info = Diagnostic("info", "graph.unit_superseded", "replaced", "x.tf")
        error = Diagnostic("error", "parse.failed", "broken", "y.tf")
        assert [
            g["level"] for g in _coverage_gaps([info, error, gap("k8s.skipped_document", "m")])
        ] == [
            "error",
            "warning",
        ]

    def test_errors_are_unique_by_file_code_and_message(self) -> None:
        one = {"file": "child/bad.tf", "code": "parse.failed", "message": "syntax error"}
        other = {"file": "child/bad.tf", "code": "parse.failed", "message": "another error"}
        assert _unique_errors([one, dict(one), other]) == [one, other]


class TestOneCauseOneGap:
    FOR_EACH = (
        "AWSTemplateFormatVersion: '2010-09-09'\n"
        "Transform: AWS::LanguageExtensions\n"
        "Resources:\n"
        "  Fn::ForEach::Buckets:\n"
        "    - Name\n"
        "    - [a, b]\n"
        "    - 'Bucket${Name}':\n"
        "        Type: AWS::S3::Bucket\n"
    )

    def test_a_for_each_template_reports_its_skip_and_not_a_second_gap_for_the_same_cause(
        self, tmp_path: Path
    ) -> None:
        path = write(tmp_path, "t.yaml", self.FOR_EACH)
        result = scan(path)
        codes = [g["code"] for g in result.coverage.gaps]
        assert codes == ["cfn.skipped_resource"]
        assert "Fn::ForEach" in result.coverage.gaps[0]["message"]
        # The input error that makes the scan exit 2 is a different fact and stays
        assert result.exit_code == 2
        assert [e["code"] for e in result.coverage.errors] == ["parse.zero_resources"]

    def test_a_zero_resources_gap_that_no_skip_explains_stays(self) -> None:
        alone = gap("parse.zero_resources", "none could be modelled", "t.yaml")
        assert [g["code"] for g in _coverage_gaps([alone])] == ["parse.zero_resources"]

    def test_a_skip_in_another_file_does_not_explain_the_gap(self) -> None:
        skip = gap("cfn.skipped_resource", "Resource 'X' was skipped", "other.yaml", 4)
        zero = gap("parse.zero_resources", "none could be modelled", "t.yaml")
        codes = [g["code"] for g in _coverage_gaps([skip, zero])]
        assert codes == ["cfn.skipped_resource", "parse.zero_resources"]

    def test_a_skip_in_the_same_file_explains_the_gap(self) -> None:
        skip = gap("cfn.skipped_resource", "Resource 'X' was skipped", "t.yaml", 4)
        zero = gap("parse.zero_resources", "none could be modelled", "t.yaml")
        assert [g["code"] for g in _coverage_gaps([skip, zero])] == ["cfn.skipped_resource"]

    def test_the_pair_is_merged_in_the_json_report_too(self, tmp_path: Path) -> None:
        path = write(tmp_path, "t.yaml", self.FOR_EACH)
        data = scan(path).to_dict()
        assert [g["code"] for g in data["coverage"]["gaps"]] == ["cfn.skipped_resource"]


class TestPathsAreRelativeToTheScanRoot:
    def test_a_path_outside_the_root_is_relative_with_dot_dot_segments(
        self, tmp_path: Path
    ) -> None:
        root = tmp_path / "repo" / "infra"
        root.mkdir(parents=True)
        outside = tmp_path / "repo" / "modules" / "net" / "main.tf"
        assert _posix_relative(str(outside), root) == "../modules/net/main.tf"

    def test_a_path_inside_the_root_has_no_dot_dot(self, tmp_path: Path) -> None:
        assert _posix_relative(str(tmp_path / "a" / "b.tf"), tmp_path) == "a/b.tf"

    def test_a_root_named_through_a_symlink_still_finds_the_files_below_it(
        self, tmp_path: Path
    ) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are not available")
        assert _posix_relative(str(real / "m" / "main.tf"), link) == "m/main.tf"

    def _tree(self, base: Path) -> Path:
        write(base, "repo/modules/net/main.tf", BUCKET.format(name="net"))
        write(
            base,
            "repo/infra/main.tf",
            'module "net" {\n  source = "../modules/net"\n}\n' + BUCKET.format(name="own"),
        )
        return base / "repo" / "infra"

    def test_a_module_outside_the_scan_root_is_a_posix_path_with_dot_dot(
        self, tmp_path: Path
    ) -> None:
        result = scan(self._tree(tmp_path))
        files = {t.location_file for t in result.report.threats}
        assert files == {"main.tf", "../modules/net/main.tf"}
        text = json.dumps(result.to_dict())
        assert str(tmp_path) not in text
        assert "\\\\" not in text

    def test_gaps_and_errors_never_carry_an_absolute_path(self, tmp_path: Path) -> None:
        base = tmp_path / "repo"
        write(
            base, "modules/net/main.tf", 'resource "aws_s3_bucket" "n" {\n  bucket = var.name\n}\n'
        )
        write(base, "infra/main.tf", 'module "net" {\n  source = "../modules/net"\n}\n')
        result = scan(base / "infra")
        assert result.coverage.gaps
        for item in [*result.coverage.gaps, *result.coverage.errors]:
            assert not Path(item.get("file", "")).is_absolute(), item
        assert str(tmp_path) not in json.dumps(result.to_dict())

    def test_fingerprints_and_locations_do_not_depend_on_where_the_tree_lives(
        self, tmp_path: Path
    ) -> None:
        first = scan(self._tree(tmp_path / "one"))
        second = scan(self._tree(tmp_path / "deeper" / "two"))
        keyed = [
            sorted(
                (t.rule_id, t.resource_address, t.location_file, t.fingerprint)
                for t in r.report.threats
            )
            for r in (first, second)
        ]
        assert keyed[0] == keyed[1]
        assert keyed[0]
        assert all(len(item[3]) == 16 for item in keyed[0])

    def test_a_real_scan_has_no_absolute_location_in_any_finding(self) -> None:
        result = scan(REPO_ROOT / "tests/fixtures/terraform/multi_service_insecure.plan.json")
        assert result.report.threats
        for threat in result.report.threats:
            assert threat.location_file
            assert not Path(threat.location_file).is_absolute()
            assert "\\" not in threat.location_file


class TestEveryFindingNamesItsResourceType:
    def test_a_secret_finding_carries_the_type_of_the_resource_it_exposes(
        self, tmp_path: Path
    ) -> None:
        write(
            tmp_path,
            "main.tf",
            'resource "aws_db_instance" "orders" {\n'
            '  engine   = "mysql"\n'
            '  password = "Sup3rS3cretPassw0rd!x9"\n'
            "}\n",
        )
        result = scan(tmp_path)
        (secret,) = [t for t in result.report.threats if t.source is ThreatSource.SECRET]
        assert secret.resource_address == "aws_db_instance.orders"
        assert secret.resource_type == "aws_db_instance"

    def test_a_secret_finding_on_no_known_resource_keeps_an_empty_type(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Nothing to take the type from: it stays unset rather than being guessed
        def secrets(units: Any, graph: Any) -> list[Threat]:
            return [
                Threat(
                    id="5ec5ec5ec5ec",
                    title="Hardcoded secret",
                    description="d",
                    stride_category="information_disclosure",
                    severity=Severity.HIGH,
                    source=ThreatSource.SECRET,
                    resource_type="",
                    resource_address="nowhere.x",
                    rule_id="SECRET_TEST",
                )
            ]

        monkeypatch.setattr("threatcode.engine.secrets.iac.find_secrets", secrets)
        write(tmp_path, "main.tf", BUCKET.format(name="one"))
        found = next(t for t in scan(tmp_path).report.threats if t.rule_id == "SECRET_TEST")
        assert found.resource_type == ""

    def test_boundary_findings_have_a_resource_type_and_a_kind_in_the_json_report(self) -> None:
        data = scan(REPO_ROOT / "examples/aws-webapp/tfplan.json").to_dict()
        boundary = [t for t in data["threats"] if t["source"] == "boundary"]
        assert boundary
        for threat in boundary:
            assert threat["resource_type"], threat["title"]
            assert threat["metadata"]["boundary_rule"].startswith("BOUNDARY_"), threat["title"]

    def test_no_finding_of_a_real_scan_lacks_a_resource_type_it_could_have(self) -> None:
        for example in ("aws-webapp/tfplan.json", "k8s-platform"):
            result = scan(REPO_ROOT / "examples" / example)
            for threat in result.report.threats:
                if result.graph.get_node(threat.resource_address) is not None:
                    assert threat.resource_type, (example, threat.title)


class TestAModuleDirectoryIsInTheGraphOnce:
    def _tree(self, root: Path, *, secret: bool = False) -> Path:
        write(root, "main.tf", 'module "vpc" {\n  source = "./modules/vpc"\n}\n')
        body = BUCKET.format(name="m")
        if secret:
            body += (
                'resource "aws_db_instance" "orders" {\n'
                '  engine   = "mysql"\n'
                '  password = "Sup3rS3cretPassw0rd!x9"\n'
                "}\n"
            )
        write(root, "modules/vpc/main.tf", body)
        return root

    def test_the_directory_is_not_scanned_again_as_its_own_unit(self, tmp_path: Path) -> None:
        result = scan(self._tree(tmp_path))
        addresses = {t.resource_address for t in result.report.threats}
        assert addresses == {"module.vpc.aws_s3_bucket.m"}
        assert "aws_s3_bucket.m" not in result.graph.nodes
        assert result.graph.node_count == 1
        assert result.coverage.units_parsed == 1
        ids = [t.id for t in result.report.threats]
        assert len(ids) == len(set(ids))

    def test_each_finding_appears_once(self, tmp_path: Path) -> None:
        result = scan(self._tree(tmp_path))
        keys = [(t.rule_id, t.location_file, t.location_start_line) for t in result.report.threats]
        assert len(keys) == len(set(keys))

    def test_a_secret_in_the_covered_directory_is_still_found(self, tmp_path: Path) -> None:
        result = scan(self._tree(tmp_path, secret=True))
        secrets = [t for t in result.report.threats if t.source is ThreatSource.SECRET]
        assert secrets
        assert {t.location_file for t in secrets} == {"modules/vpc/main.tf"}

    def test_the_report_says_why_the_directory_has_no_unit_of_its_own(self, tmp_path: Path) -> None:
        result = scan(self._tree(tmp_path))
        notes = [d for d in result.graph.diagnostics if d.code == "graph.unit_superseded"]
        assert len(notes) == 1
        assert "modules/vpc" in notes[0].message
        assert "module call" in notes[0].message
        assert notes[0].level == "info"
        # Not a coverage gap: nothing was left unanalysed
        assert not result.coverage.gaps

    def test_scanning_the_module_directory_alone_still_scans_it(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        result = scan(tmp_path / "modules" / "vpc")
        assert {t.resource_address for t in result.report.threats} == {"aws_s3_bucket.m"}

    def test_two_directories_that_no_call_connects_are_both_scanned(self, tmp_path: Path) -> None:
        write(tmp_path, "a/main.tf", BUCKET.format(name="one"))
        write(tmp_path, "b/main.tf", BUCKET.format(name="two"))
        result = scan(tmp_path)
        assert {t.resource_address for t in result.report.threats} == {
            "aws_s3_bucket.one",
            "aws_s3_bucket.two",
        }

    def test_a_directory_whose_call_cannot_be_followed_is_scanned_on_its_own(
        self, tmp_path: Path
    ) -> None:
        # A remote source is not read, so the sibling directory is the only reading there is
        write(
            tmp_path,
            "main.tf",
            'module "vpc" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n',
        )
        write(tmp_path, "modules/vpc/main.tf", BUCKET.format(name="m"))
        result = scan(tmp_path)
        assert {t.resource_address for t in result.report.threats} == {"aws_s3_bucket.m"}

    def test_a_module_that_calls_another_covers_the_nested_directory_once(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", 'module "outer" {\n  source = "./modules/outer"\n}\n')
        write(
            tmp_path,
            "modules/outer/main.tf",
            'module "inner" {\n  source = "./inner"\n}\n',
        )
        write(tmp_path, "modules/outer/inner/main.tf", BUCKET.format(name="deep"))
        result = scan(tmp_path)
        assert {t.resource_address for t in result.report.threats} == {
            "module.outer.module.inner.aws_s3_bucket.deep"
        }

    def test_a_parse_error_in_the_covered_directory_is_one_error(self, tmp_path: Path) -> None:
        self._tree(tmp_path)
        write(tmp_path, "modules/vpc/bad.tf", 'resource "aws_s3_bucket" "broken" {\n  bucket = \n')
        result = scan(tmp_path)
        broken = [e for e in result.coverage.errors if e["file"].endswith("bad.tf")]
        assert len(broken) == 1
        assert result.exit_code == 2


class TestKubernetesFindingsPointAtTheirKey:
    """FV-08, FR-19: ``daemonset.yaml:1`` for every finding is no location."""

    def _lines(self, result: ScanResult) -> dict[tuple[str, str], int | None]:
        return {
            (t.rule_id, t.location_file): t.location_start_line
            for t in result.report.threats
            if t.rule_id
        }

    def test_the_demo_stack_findings_are_at_the_key_that_causes_them(self) -> None:
        result = scan(REPO_ROOT / "examples/k8s-platform")
        lines = self._lines(result)
        # privileged: true is on line 23 of daemonset.yaml, hostNetwork on 17, hostPID on 18
        assert lines[("K8S_PRIVILEGED_CONTAINER", "daemonset.yaml")] == 23
        assert lines[("K8S_HOST_NETWORK", "daemonset.yaml")] == 17
        assert lines[("K8S_HOST_PID", "daemonset.yaml")] == 18
        assert lines[("K8S_HOST_PATH_VOLUME", "daemonset.yaml")] == 30
        # The rule that reads Secrets is the third rule of the second document
        assert lines[("K8S_RBAC_SECRETS_READ", "rbac.yaml")] == 13

    def test_few_findings_of_the_demo_stack_still_say_line_1(self) -> None:
        result = scan(REPO_ROOT / "examples/k8s-platform")
        threats = [t for t in result.report.threats if t.location_file.endswith(".yaml")]
        assert threats
        assert not [t for t in threats if t.location_start_line == 1]

    def test_a_finding_on_the_whole_object_points_at_its_kind_line(self) -> None:
        result = scan(REPO_ROOT / "examples/k8s-platform")
        by_rule = {
            (t.rule_id, t.location_file): t.location_start_line for t in result.report.threats
        }
        # No network policy exists anywhere: the workload as a whole is what is wrong
        assert by_rule[("K8S_NO_NETWORK_POLICY", "daemonset.yaml")] == 2
        boundary = [t for t in result.report.threats if t.source is ThreatSource.BOUNDARY]
        assert boundary
        assert {t.location_start_line for t in boundary} == {2}

    def test_a_secret_keeps_the_line_the_secret_is_on(self, tmp_path: Path) -> None:
        write(
            tmp_path,
            "secret.yaml",
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: db\n"
            "stringData:\n"
            "  password: Sup3rS3cretPassw0rd!x9\n",
        )
        result = scan(tmp_path)
        secrets = [t for t in result.report.threats if t.source is ThreatSource.SECRET]
        assert secrets
        assert {t.location_start_line for t in secrets} == {6}

    def test_a_terraform_finding_keeps_the_start_of_its_block(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", "\n\n" + BUCKET.format(name="one"))
        result = scan(tmp_path)
        assert {t.location_start_line for t in result.report.threats} == {3}

    def test_two_documents_of_one_file_get_their_own_lines(self, tmp_path: Path) -> None:
        text = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: a\nspec:\n  hostNetwork: true\n"
            "  containers:\n    - name: c\n      image: x:1\n"
            "---\n"
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: b\nspec:\n  hostPID: true\n"
            "  containers:\n    - name: c\n      image: x:1\n"
        )
        write(tmp_path, "pods.yaml", text)
        lines = {
            (t.rule_id, t.resource_address): t.location_start_line
            for t in scan(tmp_path).report.threats
        }
        assert lines[("K8S_HOST_NETWORK", "kubernetes_pod.default.a")] == 6
        assert lines[("K8S_HOST_PID", "kubernetes_pod.default.b")] == 16

    def test_the_text_of_a_json_manifest_is_used_too(self, tmp_path: Path) -> None:
        manifest = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "a"},
            "spec": {
                "hostNetwork": True,
                "containers": [{"name": "c", "image": "x:1"}],
            },
        }
        write(tmp_path, "pod.json", json.dumps(manifest, indent=2))
        lines = {t.rule_id: t.location_start_line for t in scan(tmp_path).report.threats}
        assert lines["K8S_HOST_NETWORK"] == 8
