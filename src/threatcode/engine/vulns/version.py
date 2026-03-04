"""Version comparison utilities for vulnerability matching."""

from __future__ import annotations

import re


def compare_versions(v1: str, v2: str, ecosystem: str) -> int:
    """Compare two version strings. Returns -1, 0, or 1.

    -1: v1 < v2
     0: v1 == v2
     1: v1 > v2
    """
    if ecosystem == "pypi":
        return _compare_pep440(v1, v2)
    elif ecosystem in ("npm", "crates.io", "go"):
        return _compare_semver(v1, v2)
    else:
        return _compare_generic(v1, v2)


def is_vulnerable(
    pkg_version: str,
    introduced: str,
    fixed: str,
    ecosystem: str,
) -> bool:
    """Check if a package version falls within a vulnerable range.

    Vulnerable if: introduced <= pkg_version < fixed
    If introduced is empty, assume all versions before fixed are vulnerable.
    If fixed is empty, assume all versions after introduced are vulnerable.
    """
    if not pkg_version:
        return False

    if introduced and fixed:
        return (
            compare_versions(pkg_version, introduced, ecosystem) >= 0
            and compare_versions(pkg_version, fixed, ecosystem) < 0
        )
    elif introduced:
        return compare_versions(pkg_version, introduced, ecosystem) >= 0
    elif fixed:
        return compare_versions(pkg_version, fixed, ecosystem) < 0
    return False


def _compare_semver(v1: str, v2: str) -> int:
    """Compare semver versions."""
    p1 = _parse_semver(v1)
    p2 = _parse_semver(v2)

    for a, b in zip(p1, p2):
        if a < b:
            return -1
        if a > b:
            return 1
    return 0


def _parse_semver(v: str) -> tuple[int, ...]:
    """Parse a semver string into numeric tuple."""
    v = v.lstrip("v")
    # Strip pre-release suffixes
    v = re.split(r"[-+]", v)[0]
    parts: list[int] = []
    for p in v.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    # Pad to at least 3 parts
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _compare_pep440(v1: str, v2: str) -> int:
    """Compare PEP 440 Python versions."""
    try:
        from packaging.version import Version

        pv1 = Version(v1)
        pv2 = Version(v2)
        if pv1 < pv2:
            return -1
        if pv1 > pv2:
            return 1
        return 0
    except Exception:
        return _compare_generic(v1, v2)


def _compare_generic(v1: str, v2: str) -> int:
    """Generic version comparison using numeric segments."""
    return _compare_semver(v1, v2)
