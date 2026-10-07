"""Secrets in infrastructure code, placed on the resource that holds them."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest

from threatcode.discovery import ScanUnit, discover
from threatcode.engine.secrets.config import SecretScanConfig
from threatcode.engine.secrets.iac import find_secrets, find_secrets_in_file
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput
from threatcode.pipeline import ScanRequest, _parse_units, _start_coverage, run_scan

FIXTURES = Path(__file__).parent.parent / "fixtures" / "secrets" / "iac"
PASSWORD = "Zx9fQ2mLp7Tr0ub4"
LEGACY_CONFIG_MAP = "kubernetes_config_map.default.release-legacy"


@pytest.fixture(autouse=True)
def _no_helm_binary(monkeypatch: pytest.MonkeyPatch) -> None:
    """The fallback renderer gives the same resources on every machine."""
    monkeypatch.setenv("THREATCODE_HELM", "off")


def _scan_tree(
    target: Path, config: SecretScanConfig | None = None
) -> tuple[list[Threat], InfraGraph]:
    root = target if target.is_dir() else target.parent
    discovery = discover([str(target)], root=root)
    _parse_units(discovery, root, _start_coverage(discovery), [])
    graph = InfraGraph.from_units([u.parsed for u in discovery.units if u.parsed is not None])
    return find_secrets(discovery.units, graph, config), graph


def _where(threats: list[Threat]) -> list[tuple[str, str, int | None, str]]:
    return [
        (t.rule_id, t.location_file, t.location_start_line, t.resource_address) for t in threats
    ]


class TestFindingShape:
    def test_a_finding_is_a_secret_threat_with_a_redacted_preview(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "warehouse.yaml")
        (threat,) = threats
        assert threat.source is ThreatSource.SECRET
        assert threat.rule_id == "SECRET_GENERIC_PASSWORD"
        assert threat.stride_category == "information_disclosure"
        assert threat.mitre_techniques == ["T1552.001"]
        assert threat.severity is Severity.MEDIUM
        assert threat.location_file == "warehouse.yaml"
        assert threat.location_start_line == threat.location_end_line == 14
        assert threat.metadata["preview"] == "[REDACTED SECRET_GENERIC_PASSWORD len=17]"
        assert threat.metadata["attribute"] == "MasterUserPassword"
        assert threat.metadata["fingerprint_hint"]

    def test_no_text_of_a_finding_holds_the_secret(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "warehouse.yaml")
        blob = json.dumps([t.to_dict() for t in threats])
        for secret in ("WarehouseP@ss2026", "WarehouseP@ss", "ss2026", "P@ss2"):
            assert secret not in blob

    def test_fingerprint_hint_does_not_depend_on_the_value(self) -> None:
        text = (FIXTURES / "warehouse.yaml").read_text(encoding="utf-8")
        hints = []
        for password in ("WarehouseP@ss2026", "Different#Value99"):
            hints.append(_hint_for(text.replace("WarehouseP@ss2026", password)))
        assert hints[0] == hints[1]

    def test_the_hint_survives_a_moved_secret(self, tmp_path: Path) -> None:
        text = (FIXTURES / "warehouse.yaml").read_text(encoding="utf-8")
        shifted = text.replace("Resources:\n", "# one more comment\nResources:\n")
        assert _hint_for(text) == _hint_for(shifted)


def _hint_for(text: str) -> str:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "stack.yaml"
        path.write_text(text, encoding="utf-8")
        threats, _ = _scan_tree(path)
    (threat,) = threats
    return str(threat.metadata["fingerprint_hint"])


class TestPlacedOnTheResource:
    def test_cloudformation_master_password_attaches_to_the_redshift_cluster(self) -> None:
        threats, graph = _scan_tree(FIXTURES / "warehouse.yaml")
        (threat,) = threats
        assert threat.resource_address == "WarehouseCluster"
        assert threat.resource_type == "aws_redshift_cluster"
        assert graph.get_node("WarehouseCluster") is not None

    def test_a_dynamic_reference_on_the_database_is_not_a_secret(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "warehouse.yaml")
        assert all(t.resource_address != "OrdersDatabase" for t in threats)

    def test_cloudformation_rds_instance_with_a_literal_password(self, tmp_path: Path) -> None:
        template = tmp_path / "db.yaml"
        template.write_text(
            "Resources:\n  Db:\n    Type: AWS::RDS::DBInstance\n    Properties:\n"
            "      Engine: mysql\n      DBInstanceClass: db.t3.micro\n"
            f'      MasterUserPassword: "{PASSWORD}"\n  Other:\n    Type: AWS::S3::Bucket\n',
            encoding="utf-8",
        )
        threats, _ = _scan_tree(template)
        assert [(t.resource_address, t.resource_type) for t in threats] == [
            ("Db", "aws_db_instance")
        ]

    def test_terraform_literal_password_attaches_and_a_variable_reference_does_not(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "terraform")
        by_file = {(t.location_file, t.location_start_line): t for t in threats}
        main = by_file[("main.tf", 7)]
        assert main.resource_address == "aws_db_instance.main"
        assert main.metadata["attribute"] == "password"
        assert not any(t.resource_address == "aws_db_instance.replica" for t in threats), (
            "password = var.replica_password is a reference"
        )

    def test_tfvars_beside_a_module_are_scanned_without_a_resource(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "terraform")
        tfvars = [t for t in threats if t.location_file.endswith(".tfvars")]
        assert [(t.location_file, t.location_start_line, t.resource_address) for t in tfvars] == [
            ("terraform.tfvars", 1, "")
        ]
        assert tfvars[0].metadata["attribute"] == "replica_password"

    def test_terraform_plan_json_attaches_once_per_resource(self, tmp_path: Path) -> None:
        plan = _plan_with_password(PASSWORD)
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        threats, _ = _scan_tree(path)
        assert [t.resource_address for t in threats] == ["aws_db_instance.main"]
        assert threats[0].metadata["occurrences"] >= 2

    def test_the_same_literal_in_two_resources_is_two_findings(self, tmp_path: Path) -> None:
        plan = _plan_with_password(PASSWORD, names=("main", "replica"))
        path = tmp_path / "plan.json"
        path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
        threats, _ = _scan_tree(path)
        assert sorted(t.resource_address for t in threats) == [
            "aws_db_instance.main",
            "aws_db_instance.replica",
        ]

    def test_kubernetes_secret_data_is_decoded_and_attached(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "k8s_secret.yaml")
        found = {(t.metadata.get("attribute"), t.location_start_line): t for t in threats}
        assert set(found) == {("data.password", 8), ("api_key", 11)}
        for threat in found.values():
            assert threat.resource_address == "kubernetes_secret.shop.db-credentials"
            assert threat.resource_type == "kubernetes_secret"
        assert found[("data.password", 8)].metadata["preview"].endswith("len=16]")

    def test_the_base64_text_itself_is_not_reported(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "k8s_secret.yaml")
        assert not any(
            t.location_start_line == 8 and t.metadata.get("attribute") == "password"
            for t in threats
        )

    def test_a_deployment_in_the_same_file_gets_nothing(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "k8s_secret.yaml")
        assert all("deployment" not in t.resource_address for t in threats)

    def test_helm_values_and_templates(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "helm" / "chart")
        assert sorted(_where(threats)) == [
            ("SECRET_GENERIC_PASSWORD", "templates/deployment.yaml", 31, LEGACY_CONFIG_MAP),
            ("SECRET_GENERIC_PASSWORD", "values.yaml", 5, ""),
        ]

    def test_helm_template_markers_are_never_secrets(self) -> None:
        threats, _ = _scan_tree(FIXTURES / "helm" / "chart")
        assert all(t.location_start_line != 22 for t in threats)  # value: "{{ .Values... }}"

    def test_a_secret_outside_every_resource_has_no_address(self, tmp_path: Path) -> None:
        template = tmp_path / "stack.yaml"
        template.write_text(
            "Parameters:\n  DbPassword:\n    Type: String\n"
            f'    Default: "{PASSWORD}"\n    NoEcho: true\n    AdminPassword: "{PASSWORD}"\n'
            "Resources:\n  Bucket:\n    Type: AWS::S3::Bucket\n",
            encoding="utf-8",
        )
        threats, _ = _scan_tree(template)
        assert [t.resource_address for t in threats] == [""]
        assert threats[0].resource_type == ""


def _plan_with_password(password: str, names: tuple[str, ...] = ("main",)) -> dict[str, Any]:
    values = {
        "engine": "postgres",
        "instance_class": "db.t3.micro",
        "allocated_storage": 20,
        "username": "orders",
        "password": password,
    }
    resources = [
        {
            "address": f"aws_db_instance.{name}",
            "mode": "managed",
            "type": "aws_db_instance",
            "name": name,
            "provider_name": "registry.terraform.io/hashicorp/aws",
            "values": dict(values),
        }
        for name in names
    ]
    return {
        "format_version": "1.2",
        "terraform_version": "1.9.0",
        "planned_values": {"root_module": {"resources": resources}},
        "resource_changes": [
            {
                "address": r["address"],
                "mode": "managed",
                "type": "aws_db_instance",
                "name": r["name"],
                "change": {"actions": ["create"], "before": None, "after": dict(values)},
            }
            for r in resources
        ],
        "configuration": {
            "root_module": {
                "resources": [
                    {
                        "address": r["address"],
                        "mode": "managed",
                        "type": "aws_db_instance",
                        "name": r["name"],
                        "expressions": {"password": {"constant_value": password}},
                    }
                    for r in resources
                ]
            }
        },
    }


class TestNotReportedTwice:
    def test_dockerfiles_and_mcp_configs_are_left_to_their_own_rules(self, tmp_path: Path) -> None:
        shutil.copytree(FIXTURES / "docker", tmp_path / "docker")
        shutil.copytree(FIXTURES / "mcp", tmp_path / "mcp")
        threats, _ = _scan_tree(tmp_path)
        assert threats == []

    def test_their_own_rules_do_report_the_secret(self) -> None:
        result = run_scan(ScanRequest(paths=(str(FIXTURES / "docker"), str(FIXTURES / "mcp"))))
        rule_ids = {t.rule_id for t in result.report.threats}
        assert "MCP_SECRET_IN_CONFIG" in rule_ids
        assert any(r.startswith("DOCKER_") and "SECRET" in r for r in rule_ids)
        assert not any(t.source is ThreatSource.SECRET for t in result.report.threats)

    def test_single_file_form_skips_the_same_formats(self) -> None:
        for relative in ("docker/Dockerfile", "mcp/.mcp.json"):
            path = FIXTURES / relative
            parsed = detect_and_parse(path)
            graph = InfraGraph.from_parsed(parsed)
            text = path.read_text(encoding="utf-8")
            assert find_secrets_in_file(path, text, parsed, graph, FIXTURES) == []


class TestSingleFileForm:
    def test_matches_the_pipeline_for_a_template(self) -> None:
        path = FIXTURES / "warehouse.yaml"
        parsed = detect_and_parse(path)
        graph = InfraGraph.from_parsed(parsed)
        text = path.read_text(encoding="utf-8")
        single = find_secrets_in_file(path, text, parsed, graph, FIXTURES)
        piped, _ = _scan_tree(path)
        assert [t.id for t in single] == [t.id for t in piped]
        assert [t.resource_address for t in single] == ["WarehouseCluster"]

    def test_a_chart_pulls_in_its_values_and_templates(self) -> None:
        path = FIXTURES / "helm" / "chart" / "Chart.yaml"
        parsed = detect_and_parse(path)
        graph = InfraGraph.from_parsed(parsed)
        found = find_secrets_in_file(
            path, path.read_text(encoding="utf-8"), parsed, graph, FIXTURES
        )
        assert sorted(t.location_file for t in found) == [
            "helm/chart/templates/deployment.yaml",
            "helm/chart/values.yaml",
        ]


class TestDeterminism:
    def test_two_runs_give_the_same_ids_and_fingerprints(self) -> None:
        first = run_scan(ScanRequest(paths=(str(FIXTURES),)))
        second = run_scan(ScanRequest(paths=(str(FIXTURES),)))

        def snapshot(result: Any) -> list[tuple[str, str]]:
            return [
                (t.id, t.fingerprint)
                for t in result.report.threats
                if t.source is ThreatSource.SECRET
            ]

        assert snapshot(first) and snapshot(first) == snapshot(second)

    def test_ids_do_not_depend_on_where_the_tree_lives(self, tmp_path: Path) -> None:
        copy = tmp_path / "elsewhere" / "deeper"
        shutil.copytree(FIXTURES, copy)
        here, _ = _scan_tree(FIXTURES)
        there, _ = _scan_tree(copy)
        assert [t.id for t in here] == [t.id for t in there]
        assert [t.metadata["fingerprint_hint"] for t in here] == [
            t.metadata["fingerprint_hint"] for t in there
        ]

    def test_ids_are_unique_and_a_moved_line_changes_the_id(self, tmp_path: Path) -> None:
        threats, _ = _scan_tree(FIXTURES)
        assert len({t.id for t in threats}) == len(threats)
        text = (FIXTURES / "warehouse.yaml").read_text(encoding="utf-8")
        original = _ids_of(text, tmp_path / "a")
        moved = _ids_of("# comment\n" + text, tmp_path / "b")
        assert original != moved


def _ids_of(text: str, directory: Path) -> list[str]:
    directory.mkdir()
    path = directory / "warehouse.yaml"
    path.write_text(text, encoding="utf-8")
    return [t.id for t in _scan_tree(path)[0]]


class TestFilesAreReadSafely:
    @pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
    def test_a_symlink_that_leaves_the_tree_is_never_read(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "creds.tf").write_text(
            f'resource "aws_db_instance" "x" {{\n  password = "{PASSWORD}"\n}}\n', encoding="utf-8"
        )
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n}\n', encoding="utf-8")
        (repo / "creds.tf").symlink_to(outside / "creds.tf")
        threats, _ = _scan_tree(repo)
        assert threats == []

    @pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
    def test_a_unit_that_is_swapped_for_a_link_after_discovery_is_not_followed(
        self, tmp_path: Path
    ) -> None:
        secret = tmp_path / "outside.yaml"
        secret.write_text(f'password: "{PASSWORD}"\n', encoding="utf-8")
        link = tmp_path / "repo" / "swap.yaml"
        link.parent.mkdir()
        link.symlink_to(secret)
        unit = ScanUnit(path=link, relpath="swap.yaml", files=("swap.yaml",))
        unit.parsed = ParsedOutput(format_type="kubernetes")
        graph = InfraGraph.from_units([])
        assert find_secrets([unit], graph) == []
        assert any(d.code == "secrets.file_skipped" for d in graph.diagnostics)

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
    def test_a_named_pipe_is_never_opened_for_reading(self, tmp_path: Path) -> None:
        fifo = tmp_path / "stuck.yaml"
        os.mkfifo(fifo)
        unit = ScanUnit(path=fifo, relpath="stuck.yaml", files=("stuck.yaml",))
        unit.parsed = ParsedOutput(format_type="kubernetes")
        assert find_secrets([unit], InfraGraph.from_units([])) == []

    def test_a_user_named_symlink_is_followed(self, tmp_path: Path) -> None:
        if os.name == "nt":
            pytest.skip("needs symlinks")
        real = tmp_path / "real.yaml"
        real.write_text((FIXTURES / "warehouse.yaml").read_text(encoding="utf-8"), encoding="utf-8")
        link = tmp_path / "link.yaml"
        link.symlink_to(real)
        threats, _ = _scan_tree(link)
        assert [t.location_file for t in threats] == ["link.yaml"]


class TestSizeEncodingAndCaps:
    def test_a_file_over_the_limit_is_skipped_and_reported(self) -> None:
        threats, graph = _scan_tree(
            FIXTURES / "warehouse.yaml", SecretScanConfig(max_file_size=100)
        )
        assert threats == []
        skipped = [d for d in graph.diagnostics if d.code == "secrets.file_skipped"]
        assert [(d.level, d.file) for d in skipped] == [("warning", "warehouse.yaml")]
        assert "limit" in skipped[0].message

    def test_utf16_template_is_scanned(self, tmp_path: Path) -> None:
        text = (FIXTURES / "warehouse.yaml").read_text(encoding="utf-8")
        path = tmp_path / "warehouse.yaml"
        path.write_bytes(text.encode("utf-16"))
        threats, _ = _scan_tree(path)
        assert [(t.resource_address, t.location_start_line) for t in threats] == [
            ("WarehouseCluster", 14)
        ]

    @pytest.mark.parametrize("separator", ["\x0c", "\u2028", "\x1c"])
    def test_odd_line_separators_do_not_shift_the_line(
        self, tmp_path: Path, separator: str
    ) -> None:
        path = tmp_path / "main.tf"
        path.write_text(
            f'# header{separator}comment\n\nresource "aws_db_instance" "main" {{\n'
            f'  password = "{PASSWORD}"\n}}\n',
            encoding="utf-8",
        )
        threats, _ = _scan_tree(path)
        assert [(t.resource_address, t.location_start_line) for t in threats] == [
            ("aws_db_instance.main", 4)
        ]

    def test_many_secrets_are_capped_with_a_truncated_marker(self, tmp_path: Path) -> None:
        lines = "".join(f'  db{n}_password: "Zx9fQ2mLp7Tr0ub{n:03d}"\n' for n in range(400))
        path = tmp_path / "config.yaml"
        path.write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\ndata:\n" + lines,
            encoding="utf-8",
        )
        threats, graph = _scan_tree(path)
        assert 0 < len(threats) <= 25
        assert threats[-1].metadata["truncated"] is True
        assert any(d.code == "secrets.truncated" for d in graph.diagnostics)


class TestConfig:
    def test_default_scan_ignores_any_configuration_in_the_tree(self, tmp_path: Path) -> None:
        shutil.copy(FIXTURES / "warehouse.yaml", tmp_path / "warehouse.yaml")
        (tmp_path / ".threatcode.yml").write_text(
            "secrets:\n  disabled_rules: [SECRET_GENERIC_PASSWORD]\n", encoding="utf-8"
        )
        threats, _ = _scan_tree(tmp_path)
        assert len(threats) == 1

    def test_an_explicit_configuration_is_honored(self) -> None:
        config = SecretScanConfig.from_mapping({"disabled_rules": ["SECRET_GENERIC_PASSWORD"]})
        threats, _ = _scan_tree(FIXTURES / "warehouse.yaml", config)
        assert threats == []

    def test_allow_patterns_apply_to_the_value(self) -> None:
        config = SecretScanConfig.from_mapping({"allow_patterns": [r"^Warehouse"]})
        threats, _ = _scan_tree(FIXTURES / "warehouse.yaml", config)
        assert threats == []
