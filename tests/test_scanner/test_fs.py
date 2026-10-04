"""Tests for filesystem scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from threatcode.scanner.fs import (
    _is_dockerfile,
    _is_iac_candidate,
    scan_filesystem,
)


class TestHelpers:
    def test_is_dockerfile(self) -> None:
        assert _is_dockerfile("Dockerfile")
        assert _is_dockerfile("dockerfile")
        assert _is_dockerfile("Dockerfile.prod")
        assert _is_dockerfile("app.dockerfile")
        assert not _is_dockerfile("README.md")
        assert not _is_dockerfile("main.py")

    def test_is_iac_candidate(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.touch()
        assert _is_iac_candidate(tf)

        yml = tmp_path / "deploy.yml"
        yml.touch()
        assert _is_iac_candidate(yml)

        py = tmp_path / "main.py"
        py.touch()
        assert not _is_iac_candidate(py)


class TestScanFilesystem:
    def test_discovers_lockfiles(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("flask==2.3.0\n")

        # Only run vuln scanner (will warn about missing DB but still returns structure)
        result = scan_filesystem(tmp_path, scanners=("vuln",))
        assert result["lockfiles_found"] == 1
        assert result["target"] == str(tmp_path.resolve())

    def test_discovers_iac_files(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text('resource "aws_s3_bucket" "b" { bucket = "test" }\n')

        result = scan_filesystem(tmp_path, scanners=("misconfig",))
        assert result["iac_files_found"] >= 1

    def test_skips_configured_dirs(self, tmp_path: Path) -> None:
        # Create a file inside node_modules — should be skipped
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "package-lock.json").write_text("{}")

        # Create a file outside — should be found
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")

        result = scan_filesystem(tmp_path, scanners=("vuln",))
        assert result["lockfiles_found"] == 1  # only requirements.txt

    def test_not_a_directory_raises(self, tmp_path: Path) -> None:
        f = tmp_path / "file.txt"
        f.write_text("hello")
        with pytest.raises(Exception, match="not a directory"):
            scan_filesystem(f)

    def test_empty_directory(self, tmp_path: Path) -> None:
        result = scan_filesystem(tmp_path, scanners=("vuln",))
        assert result["files_scanned"] == 0
        assert result["lockfiles_found"] == 0

    def test_secret_scanner_runs(self, tmp_path: Path) -> None:
        # Create a file with a potential secret
        f = tmp_path / "config.py"
        f.write_text('AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')

        result = scan_filesystem(tmp_path, scanners=("secret",))
        assert "secret" in result
        assert isinstance(result["secret"]["findings"], list)

    def test_multiple_scanners(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==2.3.0\n")
        result = scan_filesystem(tmp_path, scanners=("vuln", "secret"))
        assert "vuln" in result
        assert "secret" in result


class TestMcpConfigDiscovery:
    def test_same_pass_as_iac_threat_model(self) -> None:
        """A Cursor MCP config inside a dot-directory is scanned with the Kubernetes manifest."""
        project = Path(__file__).parent.parent / "fixtures" / "mcp" / "project"
        result = scan_filesystem(project, scanners=("misconfig",))
        findings = result["misconfig"]["findings"]
        rule_ids = {f["rule_id"] for f in findings}
        assert {"MCP_PLAINTEXT_TRANSPORT", "MCP_SECRET_IN_CONFIG"} <= rule_ids
        assert any(f["resource_type"].startswith("kubernetes_") for f in findings)
        assert result["iac_files_found"] == 2

    @pytest.mark.parametrize("client_dir", [".cursor", ".vscode"])
    def test_discovers_project_mcp_json(self, tmp_path: Path, client_dir: str) -> None:
        (tmp_path / client_dir).mkdir()
        (tmp_path / client_dir / "mcp.json").write_text(
            '{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"]}}}'
        )
        # Other files in the client directory are not treated as IaC
        (tmp_path / client_dir / "settings.json").write_text('{"editor.tabSize": 2}')
        result = scan_filesystem(tmp_path, scanners=("misconfig",))
        assert result["iac_files_found"] == 1
        assert [f["rule_id"] for f in result["misconfig"]["findings"]] == ["MCP_UNPINNED_PACKAGE"]

    def test_other_dot_directories_still_skipped(self, tmp_path: Path) -> None:
        (tmp_path / ".idea").mkdir()
        (tmp_path / ".idea" / "mcp.json").write_text('{"mcpServers": {"a": {"command": "x"}}}')
        result = scan_filesystem(tmp_path, scanners=("misconfig",))
        assert result["iac_files_found"] == 0


class TestMultiDocumentManifests:
    def test_fs_reports_findings_in_multi_document_manifest(self, tmp_path: Path) -> None:
        """Regression: a multi-document manifest was skipped and the scan reported no issues."""
        fixture = Path(__file__).parent.parent / "fixtures" / "kubernetes" / "multi_resource.yml"
        (tmp_path / "multi_resource.yml").write_text(fixture.read_text())
        result = scan_filesystem(tmp_path, scanners=("misconfig",), no_llm=True)
        assert result["misconfig"]["total_threats"] > 0
        rule_ids = {f["rule_id"] for f in result["misconfig"]["findings"]}
        assert {"K8S_CLUSTER_ADMIN_BINDING", "K8S_WILDCARD_RBAC_VERBS"} <= rule_ids
