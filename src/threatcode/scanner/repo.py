"""Repository scanner — clone a Git repo and scan it."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from threatcode.exceptions import ThreatCodeError
from threatcode.scanner.fs import scan_filesystem

logger = logging.getLogger(__name__)

# Max clone depth for shallow clones
_DEFAULT_DEPTH = 1

# Timeout for git clone (seconds)
_CLONE_TIMEOUT = 300


def scan_repository(
    repo_url: str,
    *,
    branch: str | None = None,
    scanners: tuple[str, ...] = ("vuln", "secret", "misconfig", "license"),
    ignore_unfixed: bool = False,
    min_severity: str = "info",
    no_llm: bool = True,
    config_path: str | Path | None = None,
    extra_rule_paths: list[str | Path] | None = None,
) -> dict[str, Any]:
    """Clone a Git repository and scan it for security issues.

    Performs a shallow clone (depth=1) of the repository into a temporary
    directory, then delegates to the filesystem scanner.

    Args:
        repo_url: Git repository URL (HTTPS or SSH).
        branch: Branch to clone. Defaults to the repo's default branch.
        scanners: Scanner types to run.
        ignore_unfixed: Skip vulnerabilities without a fix.
        min_severity: Minimum severity to include.
        no_llm: Disable LLM analysis for misconfig scanner.
        config_path: Path to .threatcode.yml config file.
        extra_rule_paths: Additional rule files for misconfig scanner.

    Returns:
        Dict with scan results plus repository metadata.

    Raises:
        ThreatCodeError: If git is not installed or clone fails.
    """
    # Validate git is available
    if not shutil.which("git"):
        raise ThreatCodeError("git is not installed or not in PATH")

    # Validate URL (basic check)
    if not (
        repo_url.startswith("https://")
        or repo_url.startswith("git@")
        or repo_url.startswith("ssh://")
    ):
        raise ThreatCodeError(
            f"Unsupported repository URL scheme: {repo_url}. "
            "Use https://, git@, or ssh:// URLs."
        )

    tmpdir = tempfile.mkdtemp(prefix="threatcode-repo-")
    try:
        _clone_repo(repo_url, tmpdir, branch=branch)

        result = scan_filesystem(
            tmpdir,
            scanners=scanners,
            ignore_unfixed=ignore_unfixed,
            min_severity=min_severity,
            no_llm=no_llm,
            config_path=config_path,
            extra_rule_paths=extra_rule_paths,
        )

        # Add repo metadata
        result["repository"] = repo_url
        if branch:
            result["branch"] = branch
        result["target"] = repo_url  # Override tmpdir path with URL

        return result
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def _clone_repo(url: str, dest: str, *, branch: str | None = None) -> None:
    """Shallow-clone a Git repository."""
    cmd = ["git", "clone", "--depth", str(_DEFAULT_DEPTH)]

    if branch:
        cmd.extend(["--branch", branch])

    cmd.extend(["--", url, dest])

    logger.info("Cloning %s ...", url)
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=_CLONE_TIMEOUT,
        )
    except subprocess.CalledProcessError as e:
        stderr = e.stderr.strip() if e.stderr else "unknown error"
        raise ThreatCodeError(f"Failed to clone {url}: {stderr}") from e
    except subprocess.TimeoutExpired as e:
        raise ThreatCodeError(
            f"Clone of {url} timed out after {_CLONE_TIMEOUT}s"
        ) from e
