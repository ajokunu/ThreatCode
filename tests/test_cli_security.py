"""Security regression tests for the command line.

Moved from tests/test_security.py.
"""

from __future__ import annotations

from pathlib import Path


class TestCLIHardening:
    def test_output_dir_rejected(self, tmp_path: Path) -> None:
        """A01-04: Output path that is a directory is rejected."""
        from click.testing import CliRunner

        from threatcode.cli import scan

        runner = CliRunner()
        # Create a minimal input file
        tf_file = tmp_path / "main.tf"
        tf_file.write_text('resource "aws_s3_bucket" "test" { bucket = "test" }')
        result = runner.invoke(
            scan,
            [str(tf_file), "-o", str(tmp_path), "--no-llm"],
        )
        assert result.exit_code != 0
        stderr = (result.stderr_bytes or b"").decode().lower()
        assert "directory" in result.output.lower() or "directory" in stderr
