"""Tests for repository scanner."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from threatcode.exceptions import ThreatCodeError
from threatcode.scanner.repo import _clone_repo, scan_repository


class TestScanRepository:
    def test_rejects_unsupported_url(self) -> None:
        with pytest.raises(ThreatCodeError, match="Unsupported repository URL"):
            scan_repository("ftp://example.com/repo.git")

    def test_rejects_missing_git(self) -> None:
        with patch("threatcode.scanner.repo.shutil.which", return_value=None):
            with pytest.raises(ThreatCodeError, match="git is not installed"):
                scan_repository("https://github.com/user/repo.git")

    def test_clone_failure_raises(self, tmp_path: str) -> None:
        import subprocess

        with patch("threatcode.scanner.repo.shutil.which", return_value="/usr/bin/git"):
            with patch(
                "threatcode.scanner.repo.subprocess.run",
                side_effect=subprocess.CalledProcessError(128, "git", stderr="not found"),
            ):
                with pytest.raises(ThreatCodeError, match="Failed to clone"):
                    scan_repository("https://github.com/user/repo.git")

    def test_valid_url_schemes(self) -> None:
        # Just validate URL parsing — don't actually clone
        with patch("threatcode.scanner.repo.shutil.which", return_value="/usr/bin/git"):
            with patch("threatcode.scanner.repo._clone_repo"):
                with patch(
                    "threatcode.scanner.repo.scan_filesystem",
                    return_value={
                        "target": "/tmp/test",
                        "scanners": ["vuln"],
                        "files_scanned": 0,
                        "lockfiles_found": 0,
                        "iac_files_found": 0,
                        "has_issues": False,
                    },
                ):
                    # HTTPS
                    result = scan_repository(
                        "https://github.com/user/repo.git",
                        scanners=("vuln",),
                    )
                    assert result["repository"] == "https://github.com/user/repo.git"

    def test_ssh_url_accepted(self) -> None:
        with patch("threatcode.scanner.repo.shutil.which", return_value="/usr/bin/git"):
            with patch("threatcode.scanner.repo._clone_repo"):
                with patch(
                    "threatcode.scanner.repo.scan_filesystem",
                    return_value={
                        "target": "/tmp/test",
                        "scanners": ["vuln"],
                        "files_scanned": 0,
                        "lockfiles_found": 0,
                        "iac_files_found": 0,
                        "has_issues": False,
                    },
                ):
                    result = scan_repository(
                        "git@github.com:user/repo.git",
                        scanners=("vuln",),
                    )
                    assert result["repository"] == "git@github.com:user/repo.git"
