"""Run ``python -m threatcode`` in a child process and read its JSON output.

The CLI is the public contract, so tests that check what a user sees go through it, in a child
process with a wall-clock budget: a hang becomes a timeout and a crash becomes an exit code.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src"
DEFAULT_BUDGET_SECONDS = 30.0


@dataclass(frozen=True)
class CliRun:
    exit_code: int | None  # None when the run timed out
    stdout: str
    stderr: str
    seconds: float

    @property
    def timed_out(self) -> bool:
        return self.exit_code is None

    def json(self) -> Any:
        """The stdout parsed as JSON; fails with the stderr tail when it is not JSON."""
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(
                f"stdout is not JSON (exit {self.exit_code}): {exc}\nstderr: {self.stderr[-400:]}"
            ) from exc


def run_cli(
    args: list[str], budget: float = DEFAULT_BUDGET_SECONDS, cwd: Path | None = None
) -> CliRun:
    """Run ``python -m threatcode <args>`` with ``src`` on the path."""
    started = time.monotonic()
    try:
        done = subprocess.run(
            [sys.executable, "-m", "threatcode", *args],
            capture_output=True,
            text=True,
            timeout=budget,
            env={**os.environ, "PYTHONPATH": str(SRC)},
            cwd=str(cwd or REPO_ROOT),
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return CliRun(None, out, err, time.monotonic() - started)
    return CliRun(done.returncode, done.stdout, done.stderr, time.monotonic() - started)


def scan_json(
    paths: list[Path],
    ingest: list[Path] | None = None,
    budget: float = DEFAULT_BUDGET_SECONDS,
) -> CliRun:
    """``threatcode scan PATH... [--ingest FILE]... -f json --fail-on none``."""
    args = ["scan", *map(str, paths), "-f", "json", "--fail-on", "none"]
    for file in ingest or []:
        args += ["--ingest", str(file)]
    return run_cli(args, budget)


def find_key(data: Any, key: str) -> Any:
    """The first value stored under ``key`` anywhere in nested dicts and lists, else ``None``."""
    if isinstance(data, dict):
        if key in data:
            return data[key]
        for value in data.values():
            found = find_key(value, key)
            if found is not None:
                return found
    elif isinstance(data, list):
        for value in data:
            found = find_key(value, key)
            if found is not None:
                return found
    return None
