"""Run a scan of a hostile input in a child process, under a wall-clock budget.

A hostile input can hang the scanner, exhaust its stack or its memory. Running it in a child
keeps the test process alive in every case: a hang becomes a timeout, a stack overflow becomes an
exception type in the outcome, and the child's peak memory is measured.

``scan_in_child`` goes through the library path (``detect_and_parse``, the graph and the engine),
which exists in every version of the tool. ``cli_scan`` goes through ``threatcode scan PATH`` for
inputs that only the directory walker handles.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

from tests.helpers.cli import CliRun, run_cli

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"

# Generous: the point is to separate "milliseconds" from "minutes", on a slow CI machine as well
DEFAULT_BUDGET_SECONDS = 10.0
DEFAULT_MEMORY_BUDGET_MB = 1500.0

_CHILD = textwrap.dedent(
    """
    import json, sys, time
    sys.path.insert(0, {repo!r})
    sys.path.insert(0, {src!r})
    from pathlib import Path
    from threatcode.exceptions import ThreatCodeError
    from tests.helpers.scan import scan_files
    from tests.hostile.memory import peak_memory_mb

    started = time.monotonic()
    outcome = {{"status": "ok", "exception": None, "threatcode_error": False, "nodes": 0}}
    try:
        result = scan_files([Path(sys.argv[1])])
        outcome["nodes"] = result.graph.node_count
    except BaseException as exc:  # the child reports every failure by type
        outcome["status"] = "error"
        outcome["exception"] = type(exc).__name__
        outcome["message"] = str(exc)[:200]
        outcome["threatcode_error"] = isinstance(exc, (ThreatCodeError, FileNotFoundError))
    outcome["seconds"] = time.monotonic() - started
    outcome["peak_mb"] = peak_memory_mb()
    print("OUTCOME " + json.dumps(outcome))
    """
).format(repo=str(REPO_ROOT), src=str(SRC))


@dataclass(frozen=True)
class Outcome:
    status: str  # "ok", "error" or "timeout"
    seconds: float
    exception: str | None = None
    threatcode_error: bool = False
    nodes: int = 0
    peak_mb: float = 0.0
    message: str = ""

    @property
    def timed_out(self) -> bool:
        return self.status == "timeout"

    @property
    def clean(self) -> bool:
        """Finished in budget with either a graph or an error the tool itself raises on purpose."""
        return self.status == "ok" or (self.status == "error" and self.threatcode_error)


def scan_in_child(path: Path, budget: float = DEFAULT_BUDGET_SECONDS) -> Outcome:
    """Scan one file through the library path in a child process."""
    try:
        done = subprocess.run(
            [sys.executable, "-c", _CHILD, str(path)],
            capture_output=True,
            text=True,
            timeout=budget,
            env={**os.environ, "PYTHONPATH": str(SRC)},
        )
    except subprocess.TimeoutExpired:
        return Outcome("timeout", budget)
    for line in reversed(done.stdout.splitlines()):
        if line.startswith("OUTCOME "):
            data = json.loads(line[len("OUTCOME ") :])
            return Outcome(
                status=data["status"],
                seconds=data["seconds"],
                exception=data.get("exception"),
                threatcode_error=data.get("threatcode_error", False),
                nodes=data.get("nodes", 0),
                peak_mb=data.get("peak_mb", 0.0),
                message=data.get("message", ""),
            )
    return Outcome("error", 0.0, exception="ChildCrashed", message=done.stderr[-300:])


def cli_scan(
    path: Path, budget: float = DEFAULT_BUDGET_SECONDS, extra_args: tuple[str, ...] = ()
) -> CliRun:
    """Run ``threatcode scan PATH -f json --fail-on none`` in a child process."""
    args = ["scan", str(path), "-f", "json", "--fail-on", "none", *extra_args]
    return run_cli(args, budget, cwd=path if path.is_dir() else path.parent)


def run_python(code: str, budget: float) -> Outcome:
    """Run a snippet in a child; used to prove the budget machinery itself catches a hang."""
    import time

    started = time.monotonic()
    try:
        done = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, timeout=budget
        )
    except subprocess.TimeoutExpired:
        return Outcome("timeout", time.monotonic() - started)
    status = "ok" if done.returncode == 0 else "error"
    return Outcome(status, time.monotonic() - started, exception=None if status == "ok" else "Exit")
