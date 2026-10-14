"""Lockfile dependency resource categories and trust zones."""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "dependency_npm": NodeCategory.UNKNOWN,
    "dependency_pypi": NodeCategory.UNKNOWN,
    "dependency_go": NodeCategory.UNKNOWN,
    "dependency_crates.io": NodeCategory.UNKNOWN,
    "dependency_rubygems": NodeCategory.UNKNOWN,
    "dependency_packagist": NodeCategory.UNKNOWN,
}

ZONES: dict[str, TrustZone] = {}
