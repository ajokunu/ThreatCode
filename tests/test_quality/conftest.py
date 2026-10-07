"""Print the planted-issue benchmark in the terminal summary, where capture cannot hide it."""

from __future__ import annotations

import pytest

from tests.test_quality.harness import REPORT_KEY


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, config: pytest.Config
) -> None:
    report = config.stash.get(REPORT_KEY, None)
    if report:
        terminalreporter.section("planted-issue benchmark")
        terminalreporter.write_line(report)
