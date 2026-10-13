"""Fixtures for the engine tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def built_in_rule_failures_fail_the_test(monkeypatch: pytest.MonkeyPatch) -> None:
    """Re-raise an exception from a built-in rule instead of recording it in ``rule_errors``.

    A built-in rule that raises on a node is a bug of the rule, and the engine's own isolation
    (the failure goes to ``report.rule_errors`` and the scan goes on) would hide it from a test.
    A test of that isolation sets ``THREATCODE_STRICT_RULES`` itself.
    """
    monkeypatch.setenv("THREATCODE_STRICT_RULES", "1")
