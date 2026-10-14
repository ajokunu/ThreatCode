#!/usr/bin/env python3
"""Fail when a golden recording outside the globs a package owns has changed.

Packages that run in parallel each re-record only their own part of
``tests/fixtures/golden/`` (see the docstring of ``tests/test_ir/test_golden.py``).
After ``THREATCODE_UPDATE_GOLDEN=1 pytest tests/test_ir/test_golden.py`` and before
committing, run::

    python scripts/check_golden_scope.py --allow 'tests/fixtures/golden/*/findings/aws__s3.json'

The script compares the working tree, the index and untracked files under the golden
directory with a base revision and exits 1, naming every changed, added or deleted file
that no ``--allow`` glob covers.
A change outside the allowed scope means the package's change leaked into another
package's territory; fix it or escalate it, never commit it.

The base revision is ``--base``, else the ``THREATCODE_GOLDEN_BASE`` environment variable,
else ``HEAD``.
Against ``HEAD`` the comparison only sees changes you have not committed yet, so a package
that commits as it goes should pass the commit its worktree started from.
The base that was used is always printed.

Quote every glob.
An unquoted one is expanded by the shell before the script sees it, and only into the files that
exist now, so a recording the change deleted is then reported as out of scope.
Globs are matched against paths relative to the repository root:
``*`` matches within one path segment, ``?`` one character other than ``/``,
``**/`` any number of directories (including none) and a trailing or lone ``**`` anything.

Exit codes: 0 every change is in scope, 1 a change is out of scope, 2 usage or git error.
Only the standard library is used.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Sequence

DEFAULT_GOLDEN_DIR = "tests/fixtures/golden"
BASE_ENV = "THREATCODE_GOLDEN_BASE"


class ScopeError(Exception):
    """A usage or git problem (exit code 2)."""


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate a path glob to a regex that must match the whole path."""
    pattern = pattern.removeprefix("./")
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        elif pattern[i] == "[" and (end := pattern.find("]", i + 2)) != -1:
            body = pattern[i + 1 : end]
            negate = body.startswith(("!", "^"))
            body = body[1:] if negate else body
            out.append("[" + ("^/" if negate else "") + body.replace("\\", "\\\\") + "]")
            i = end + 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("".join(out))


def _git(repo: str, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", repo, *args],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        raise ScopeError(f"cannot run git: {e}") from e
    if result.returncode != 0:
        raise ScopeError(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def repo_root(start: str) -> str:
    try:
        return _git(start, "rev-parse", "--show-toplevel").strip()
    except ScopeError as e:
        raise ScopeError(f"{start} is not inside a git repository ({e})") from e


def resolve_base(repo: str, base: str) -> str:
    try:
        return _git(repo, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}").strip()
    except ScopeError as e:
        raise ScopeError(f"base revision {base!r} does not exist ({e})") from e


def changed_golden_files(repo: str, base: str, golden_dir: str) -> dict[str, str]:
    """Map path to a status letter (M, A, D) for golden files that differ from ``base``."""
    changes: dict[str, str] = {}
    diff = _git(repo, "diff", "-z", "--name-status", "--no-renames", base, "--", golden_dir)
    fields = [f for f in diff.split("\0") if f]
    for status, path in zip(fields[0::2], fields[1::2], strict=True):
        changes[path] = status[0]
    untracked = _git(repo, "ls-files", "-z", "--others", "--exclude-standard", "--", golden_dir)
    for path in untracked.split("\0"):
        if path:
            changes.setdefault(path, "A")
    return changes


def out_of_scope(changes: dict[str, str], allowed: Iterable[str]) -> dict[str, str]:
    patterns = [glob_to_regex(g) for g in allowed]
    return {
        path: status
        for path, status in sorted(changes.items())
        if not any(p.fullmatch(path) for p in patterns)
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fail if a golden recording outside the allowed globs changed.",
    )
    parser.add_argument(
        "--allow",
        metavar="GLOB",
        nargs="+",
        action="extend",
        default=[],
        help="glob of golden files the package may change (repeatable); with none, "
        "no golden file may change",
    )
    parser.add_argument(
        "--base",
        metavar="REF",
        default=None,
        help=f"revision to compare with (default: ${BASE_ENV}, then HEAD)",
    )
    parser.add_argument(
        "--golden-dir",
        default=DEFAULT_GOLDEN_DIR,
        help=f"golden directory relative to the repository root (default: {DEFAULT_GOLDEN_DIR})",
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="a directory inside the repository to check (default: the current directory)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    base_name = args.base or os.environ.get(BASE_ENV) or "HEAD"
    golden_dir = args.golden_dir.strip("/")
    try:
        repo = repo_root(args.repo)
        base = resolve_base(repo, base_name)
        changes = changed_golden_files(repo, base, golden_dir)
    except ScopeError as e:
        print(f"check_golden_scope: {e}", file=sys.stderr)
        return 2

    print(f"golden scope: comparing {golden_dir} with {base_name} ({base[:12]})")
    outside = out_of_scope(changes, args.allow)
    if outside:
        print(
            f"{len(outside)} golden file(s) changed outside the allowed scope:",
            file=sys.stderr,
        )
        names = {"M": "modified", "A": "added", "D": "deleted"}
        for path, status in outside.items():
            print(f"  {names.get(status, status)}: {path}", file=sys.stderr)
        print(
            "Fix the change so it stays in your scope, or escalate it; do not commit it.",
            file=sys.stderr,
        )
        return 1
    print(f"ok: {len(changes)} golden file(s) changed, all within the allowed scope")
    return 0


if __name__ == "__main__":
    sys.exit(main())
