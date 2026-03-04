"""Tests for secret scanner."""

from pathlib import Path

import pytest

from threatcode.engine.secrets.scanner import SecretScanner


@pytest.fixture
def scanner() -> SecretScanner:
    return SecretScanner()


class TestSecretScanner:
    def test_scan_file_with_secrets(self, scanner: SecretScanner) -> None:
        findings = scanner.scan("tests/fixtures/secrets/has_secrets.py")
        assert len(findings) > 0
        rule_ids = {f.rule_id for f in findings}
        # Should detect AWS key, GitHub token, private key, etc.
        assert "SECRET_AWS_ACCESS_KEY" in rule_ids
        assert "SECRET_GITHUB_PAT" in rule_ids
        assert "SECRET_PRIVATE_KEY" in rule_ids

    def test_scan_clean_file(self, scanner: SecretScanner) -> None:
        findings = scanner.scan("tests/fixtures/secrets/clean_file.py")
        # Clean file should have zero or very few findings
        # (allow-list should catch placeholder/example values)
        assert len(findings) == 0

    def test_scan_directory(self, scanner: SecretScanner) -> None:
        findings = scanner.scan("tests/fixtures/secrets")
        # Should find secrets in has_secrets.py
        assert len(findings) > 0
        files = {f.file_path for f in findings}
        assert any("has_secrets" in f for f in files)

    def test_finding_has_redacted_match(self, scanner: SecretScanner) -> None:
        findings = scanner.scan("tests/fixtures/secrets/has_secrets.py")
        for f in findings:
            # Redacted match should contain asterisks
            assert "****" in f.match

    def test_finding_has_line_number(self, scanner: SecretScanner) -> None:
        findings = scanner.scan("tests/fixtures/secrets/has_secrets.py")
        for f in findings:
            assert f.line_number > 0

    def test_binary_files_skipped(self, scanner: SecretScanner, tmp_path: Path) -> None:
        binary_file = tmp_path / "test.bin"
        binary_file.write_bytes(b"\x00\x01\x02AKIA1234567890123456\x00")
        findings = scanner.scan(str(binary_file))
        assert len(findings) == 0

    def test_large_files_skipped(self, scanner: SecretScanner, tmp_path: Path) -> None:
        large_file = tmp_path / "large.txt"
        large_file.write_text("AKIA1234567890123456\n" * 100000)
        findings = scanner.scan(str(large_file))
        assert len(findings) == 0  # File exceeds 1MB limit


class TestSecretScannerConfig:
    def test_custom_skip_paths(self) -> None:
        from threatcode.engine.secrets.config import SecretScanConfig

        config = SecretScanConfig(skip_paths=["has_secrets"])
        scanner = SecretScanner(config=config)
        findings = scanner.scan("tests/fixtures/secrets")
        assert len(findings) == 0
