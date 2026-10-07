"""Print the planted-issue benchmark in the terminal summary, where capture cannot hide it."""

from __future__ import annotations

import os

import pytest

from tests.test_quality.harness import REPORT_KEY


def pytest_terminal_summary(
    terminalreporter: pytest.TerminalReporter, config: pytest.Config
) -> None:
    report = config.stash.get(REPORT_KEY, None)
    if not report:
        return
    table, detail = report
    terminalreporter.section("planted-issue benchmark")
    terminalreporter.write_line(table)
    if detail and (config.getoption("verbose") > 0 or os.environ.get("THREATCODE_QUALITY_DETAIL")):
        terminalreporter.write_line("")
        terminalreporter.write_line(detail)
