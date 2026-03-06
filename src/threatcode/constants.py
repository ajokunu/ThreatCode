"""Single source of truth for validation constants."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threatcode.models.threat import Severity

VALID_STRIDE_CATEGORIES: frozenset[str] = frozenset(
    {
        "spoofing",
        "tampering",
        "repudiation",
        "information_disclosure",
        "denial_of_service",
        "elevation_of_privilege",
    }
)

VALID_SEVERITIES: frozenset[str] = frozenset(
    {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    }
)


def _severity_map() -> dict[str, Severity]:
    """Lazy-load SEVERITY_MAP to avoid circular import with models.threat."""
    from threatcode.models.threat import Severity

    return {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }


def cvss_to_severity(score: float) -> Severity:
    """Convert a CVSS score to a Severity enum value."""
    from threatcode.models.threat import Severity

    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


LOCKFILE_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "requirements.txt",
        "Pipfile.lock",
        "poetry.lock",
        "go.sum",
        "Cargo.lock",
        "Gemfile.lock",
        "composer.lock",
    }
)
