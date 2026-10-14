"""Self-tests for the library-path scan helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.scan import scan_files, scan_text

PUBLIC_BUCKET_TF = """
resource "aws_s3_bucket" "assets" {
  bucket = "assets"
  acl    = "public-read"
}
"""

ROOT_DOCKERFILE = 'FROM ubuntu:22.04\nRUN apt-get update\nCMD ["app"]\n'


class TestScanText:
    def test_hcl_text_runs_the_whole_pipeline(self) -> None:
        result = scan_text(PUBLIC_BUCKET_TF, "main.tf")
        assert "aws_s3_bucket.assets" in result.graph.nodes
        assert result.fired("S3_PUBLIC_ACCESS", "aws_s3_bucket.assets")
        assert "S3_PUBLIC_ACCESS" in result.rule_ids
        assert result.rule_ids_for("aws_s3_bucket.assets") >= {"S3_PUBLIC_ACCESS"}

    def test_the_file_name_selects_the_parser(self) -> None:
        result = scan_text(ROOT_DOCKERFILE, "Dockerfile")
        assert result.parsed[0].format_type == "dockerfile"
        assert any(n.startswith("dockerfile.") for n in result.graph.nodes)

    def test_dotfile_names_reach_the_mcp_parser(self) -> None:
        text = '{"mcpServers": {"fetch": {"command": "npx", "args": ["-y", "mcp-fetch"]}}}'
        result = scan_text(text, ".mcp.json")
        assert result.parsed[0].format_type == "mcp_config"
        assert any(node.resource_type == "mcp_server" for node in result.graph.nodes.values())

    def test_clean_input_yields_no_rule_on_the_resource(self) -> None:
        clean = 'resource "aws_s3_bucket" "assets" {\n  bucket = "assets"\n  acl = "private"\n}\n'
        result = scan_text(clean, "main.tf")
        assert not result.fired("S3_PUBLIC_ACCESS")

    def test_rejects_names_that_escape_the_scan_directory(self) -> None:
        with pytest.raises(ValueError, match="relative name"):
            scan_text("x", "../outside.tf")
        with pytest.raises(ValueError, match="relative name"):
            scan_text("x", "/abs/main.tf")

    def test_an_explicit_directory_keeps_the_file(self, tmp_path: Path) -> None:
        scan_text(PUBLIC_BUCKET_TF, "modules/main.tf", directory=tmp_path)
        assert (tmp_path / "modules" / "main.tf").is_file()


class TestScanFiles:
    def test_several_files_share_one_graph(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text(PUBLIC_BUCKET_TF, encoding="utf-8")
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(ROOT_DOCKERFILE, encoding="utf-8")
        result = scan_files([tf, dockerfile])
        assert len(result.parsed) == 2
        assert "aws_s3_bucket.assets" in result.graph.nodes
        assert any(n.startswith("dockerfile.") for n in result.graph.nodes)

    def test_no_paths_is_an_error(self) -> None:
        with pytest.raises(ValueError, match="at least one path"):
            scan_files([])

    def test_missing_file_surfaces_the_parser_error(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            scan_files([tmp_path / "absent.tf"])
