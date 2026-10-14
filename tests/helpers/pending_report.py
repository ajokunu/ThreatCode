"""A pytest plugin that records every pending marker of a collection to a JSON file.

The final quality gate (tests/test_meta.py) runs a throwaway ``pytest --collect-only`` over the
whole suite with this plugin and reads the file back.
Collecting is what finds the markers: many of them are built from data (the ``pending`` blocks
of ``examples/*/expected.yml``, the ``EXPECTED_DIFFERENCES`` table of the parity test, the
``pending.yml`` files beside rule cases), so a text search for ``pending(`` would both miss them
and match the strings the marker's own self-tests carry.

The plugin writes nothing unless ``THREATCODE_PENDING_REPORT`` names a file.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tests.helpers.pending import pending_markers

REPORT_ENV = "THREATCODE_PENDING_REPORT"


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    target = os.environ.get(REPORT_ENV)
    if not target:
        return
    found: list[dict[str, str]] = []
    for item in items:
        for package_id, reason in pending_markers(item):
            found.append({"test": item.nodeid, "package": package_id, "reason": reason})
    Path(target).write_text(json.dumps(found, indent=2), encoding="utf-8")
