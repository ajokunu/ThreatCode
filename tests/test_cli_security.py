"""Security regression tests for the command line.

Moved from tests/test_security.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from threatcode.cli import cli


class TestCLIHardening:
    def test_output_dir_rejected(self, tmp_path: Path) -> None:
        """A01-04: an output path that is a directory is rejected without a traceback."""
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "test" { bucket = "test" }')
        result = CliRunner().invoke(cli, ["scan", str(tf_file), "-o", str(tmp_path)])
        assert result.exit_code == 2
        assert "directory" in result.stderr.lower()
        assert "Traceback" not in result.output

    def test_a_symlink_in_the_scanned_tree_is_never_read(self, tmp_path: Path) -> None:
        """SEC-02: a link that leaves the scan root cannot expose a host file."""
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.tf").write_text('resource "aws_s3_bucket" "leaked_outside" {}')
        root = tmp_path / "scan"
        root.mkdir()
        (root / "main.tf").write_text('resource "aws_s3_bucket" "inside" { bucket = "inside" }')
        (root / "escape.tf").symlink_to(outside / "secret.tf")
        (root / "escape-dir").symlink_to(outside)
        result = CliRunner().invoke(cli, ["scan", str(root), "--fail-on", "none"])
        assert result.exit_code == 0
        assert "inside" in result.stdout
        assert "leaked_outside" not in result.stdout
        assert "leaked_outside" not in result.stderr

    def test_a_repository_cannot_turn_off_its_own_gate_with_a_config_file(
        self, tmp_path: Path
    ) -> None:
        """A01-01: fail_on in an auto-discovered config is ignored and announced."""
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" { bucket = "b" }')
        (tmp_path / ".threatcode.yml").write_text("fail_on: none\n")
        result = CliRunner().invoke(cli, ["scan", str(tmp_path)])
        assert result.exit_code == 1
        assert "fail_on" in result.stderr

    def test_an_api_key_in_the_environment_does_not_send_anything_by_itself(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """LLM02: egress needs an explicit --llm, llm.enabled or THREATCODE_LLM."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        built: list[object] = []
        monkeypatch.setattr(
            "threatcode.engine.llm.factory.build_client", lambda settings: built.append(settings)
        )
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "b" { bucket = "b" }')
        CliRunner().invoke(cli, ["scan", str(tf_file)])
        assert built == []
