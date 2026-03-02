"""Single source of truth for validation constants."""

from __future__ import annotations

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
