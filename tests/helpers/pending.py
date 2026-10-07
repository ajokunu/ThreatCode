"""The ``pending`` marker: write an expectation now, switch it on when its package delivers.

A test that describes behavior a later work package will add carries
``pending("WP-2-1", "instances inherit the references of their resource")``.
The test is skipped with that reason, so it never flips between pass and fail
because of an unrelated merge, which is the failure mode of ``xfail(strict=True)``.
The package named in the marker removes it when it delivers the behavior.

Usage::

    from tests.helpers.pending import pending

    @pending("WP-3-1", "security group attachments become dependency edges")
    def test_attachment() -> None: ...

    pytestmark = pending("WP-4-1", "attack paths")   # a whole module

Environment switches (read by the hook below):

``THREATCODE_RUN_PENDING``
    ``all`` or a package id such as ``WP-2-1``.
    Pending tests of that package run instead of skipping, so the package author
    can see which expectations hold before removing the markers.

``THREATCODE_FAIL_ON_PENDING``
    ``1`` turns every pending marker into a collection error.
    The final quality gate (WP-5-2) sets it so no marker survives to release.

The pytest hooks live in this module and tests/conftest.py loads it as a plugin.
Later packages never edit tests/conftest.py.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable
from typing import Any

import pytest

# Every package of the rework plan. A marker naming anything else is a typo and
# would leave a marker that no package ever removes.
KNOWN_PACKAGE_IDS: frozenset[str] = frozenset(
    [f"WP-1-{n}" for n in range(1, 7)]
    + [f"WP-2-{n}" for n in range(1, 9)]
    + [f"WP-3-{n}" for n in range(1, 9)]
    + [f"WP-4-{n}" for n in range(1, 7)]
    + [f"WP-5-{n}" for n in range(1, 3)]
)

_PACKAGE_ID_RE = re.compile(r"^WP-[1-5]-[1-9]\d*$")

MARKER_NAME = "pending"


def validate_pending(package_id: object, reason: object) -> tuple[str, str]:
    """Return the cleaned ``(package_id, reason)`` or raise ``ValueError``."""
    if not isinstance(package_id, str) or not _PACKAGE_ID_RE.match(package_id):
        raise ValueError(
            f"pending() needs a package id like 'WP-2-1', got {package_id!r}. "
            "Name the package whose work makes this test pass."
        )
    if package_id not in KNOWN_PACKAGE_IDS:
        raise ValueError(
            f"pending() names {package_id!r}, which is not a package of the rework plan."
        )
    if not isinstance(reason, str) or not reason.strip():
        raise ValueError(
            f"pending({package_id!r}, ...) needs a reason naming the specific deliverable."
        )
    return package_id, reason.strip()


def pending(package_id: str, reason: str) -> Any:
    """Build the marker. Validation happens here, so a bad id fails at import time."""
    package_id, reason = validate_pending(package_id, reason)
    return getattr(pytest.mark, MARKER_NAME)(package_id, reason)


def pending_markers(item: pytest.Item) -> list[tuple[str, str]]:
    """Every ``(package_id, reason)`` pending marker on a test item, validated."""
    found: list[tuple[str, str]] = []
    for marker in item.iter_markers(name=MARKER_NAME):
        args = list(marker.args)
        package_id = args[0] if args else marker.kwargs.get("package_id")
        reason = args[1] if len(args) > 1 else marker.kwargs.get("reason")
        found.append(validate_pending(package_id, reason))
    return found


def collect_pending(items: Iterable[pytest.Item]) -> dict[str, list[str]]:
    """Map package id to the node ids of its pending tests, for reports and gates."""
    by_package: dict[str, list[str]] = {}
    for item in items:
        for package_id, _reason in pending_markers(item):
            by_package.setdefault(package_id, []).append(item.nodeid)
    return by_package


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "pending(package_id, reason): skip this test until the named work package delivers "
        "the behavior it describes. THREATCODE_RUN_PENDING=<id|all> runs it anyway.",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run = os.environ.get("THREATCODE_RUN_PENDING", "").strip()
    fail = os.environ.get("THREATCODE_FAIL_ON_PENDING") == "1"
    for item in items:
        try:
            markers = pending_markers(item)
        except ValueError as exc:
            raise pytest.UsageError(f"{item.nodeid}: {exc}") from exc
        if not markers:
            continue
        if fail:
            ids = ", ".join(sorted({m[0] for m in markers}))
            raise pytest.UsageError(
                f"{item.nodeid}: pending marker still present ({ids}) and "
                "THREATCODE_FAIL_ON_PENDING=1."
            )
        if run == "all" or (run and all(package_id == run for package_id, _ in markers)):
            continue
        reason = "; ".join(f"pending {package_id}: {why}" for package_id, why in markers)
        item.add_marker(pytest.mark.skip(reason=reason))
