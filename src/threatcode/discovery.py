"""Input discovery: which files of a scan are read, and as which units.

``discover`` turns the paths a user names into ``ScanUnit`` objects, the things a parser reads:

* a Terraform module: every directory that holds ``.tf``, ``.tofu`` or ``.tf.json`` files is one
  ``hcl_module`` unit, so resources in separate files of one directory share a graph;
* a Helm chart: every ``Chart.yaml`` is one ``helm_chart`` unit that owns its directory, so its
  ``templates/`` and ``charts/`` subtrees are never scanned as raw manifests and nested subcharts
  are not separate units;
* everything else that may be infrastructure (``.json``, ``.yml``, ``.yaml``, ``.template``,
  ``.cfn``, Dockerfile-family names, MCP config names) is its own ``file`` unit.

The walker is built for repositories you did not write.
It uses ``os.walk`` without following links and ``lstat`` on every entry, so only regular files are
ever opened: a symlink is skipped and counted, a named pipe or device is skipped and counted, and a
link cycle cannot loop.
The one exception is a symlink the user names directly, which is explicit intent and is followed.
Dependency and tool directories (``.git``, ``node_modules``, ``.terraform``, ``vendor``,
virtualenvs, build output, caches) and every dot-directory except ``.cursor`` and ``.vscode``
(where MCP configs live) are pruned.

A candidate that no parser recognises is not an error, because a repository holds many JSON and YAML
files that are not infrastructure; the pipeline counts those as "not infrastructure".
This module only finds candidates, it never reads them.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from threatcode.constants import is_dockerfile_name, is_terraform_name
from threatcode.diagnostics import register_code
from threatcode.exceptions import UsageError
from threatcode.parsers._text import MAX_INPUT_SIZE_BYTES

if TYPE_CHECKING:
    from threatcode.parsers.base import ParsedOutput

__all__ = [
    "SKIP_DIRS",
    "STDIN_PATH",
    "Discovery",
    "ScanUnit",
    "discover",
    "scan_root",
]

register_code("discovery.unreadable", "A path could not be read during discovery")
register_code("discovery.not_regular", "A named input is not a regular file or a directory")
register_code("discovery.not_iac", "A candidate file is not infrastructure code a parser knows")
register_code("discovery.nothing_to_model", "The scan found nothing to model")

STDIN_PATH = "-"
"""The path argument that means "read standard input"."""

HCL_MODULE = "hcl_module"
HELM_CHART = "helm_chart"
FILE = "file"

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".terraform",
        ".terragrunt-cache",
        "vendor",
        "__pycache__",
        ".venv",
        "venv",
        "site-packages",
        "dist",
        "build",
        ".tox",
        ".nox",
        ".eggs",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".hypothesis",
        ".cache",
        ".gradle",
        ".idea",
    }
)
"""Directory names that are never entered."""

# Dot-directories that hold MCP client configs and are therefore entered.
_ENTERED_DOT_DIRS: frozenset[str] = frozenset({".cursor", ".vscode"})

_CANDIDATE_SUFFIXES: frozenset[str] = frozenset({".json", ".yml", ".yaml", ".template", ".cfn"})
_HELM_CHART_FILE = "Chart.yaml"
_HELM_SUBTREES: frozenset[str] = frozenset({"templates", "charts"})
_HELM_OWNED_FILES: frozenset[str] = frozenset(
    {
        "values.schema.json",
        "chart.lock",
        "requirements.yaml",
        "requirements.yml",
        "requirements.lock",
    }
)

# File names whose JSON is an MCP client config. The parser owns the list.
_MCP_NAMES_CACHE: frozenset[str] | None = None


def _mcp_names() -> frozenset[str]:
    global _MCP_NAMES_CACHE
    if _MCP_NAMES_CACHE is None:
        from threatcode.parsers.mcp_config import MCP_CONFIG_FILENAMES

        _MCP_NAMES_CACHE = frozenset(MCP_CONFIG_FILENAMES)
    return _MCP_NAMES_CACHE


@dataclass
class ScanUnit:
    """One thing a parser reads, and (after parsing) what it produced.

    ``path`` is absolute and is what ``detect_and_parse`` receives; ``relpath`` is the POSIX path
    relative to the scan root that every report location uses.
    ``files`` lists the root-relative POSIX paths of the regular files the unit is made of (the
    ``.tf`` files of a module, the single file of any other unit).
    ``by_name`` is true when the file name alone identifies infrastructure (Terraform, Dockerfile,
    Chart.yaml, MCP config names), so a failure to read it is an error, not "not infrastructure".
    ``explicit`` is true when the user named the path on the command line.
    ``parsed`` is set by the pipeline once the unit has been parsed.
    """

    path: Path
    relpath: str
    kind: str = FILE
    files: tuple[str, ...] = ()
    by_name: bool = False
    explicit: bool = False
    stdin: bool = False
    parsed: ParsedOutput | None = field(default=None, repr=False, compare=False)

    @property
    def base_dir(self) -> Path:
        """The directory the unit's own paths are under: itself for a module, else its parent."""
        return self.path if self.kind == HCL_MODULE else self.path.parent

    @property
    def base_rel(self) -> PurePosixPath:
        """``base_dir`` as a root-relative POSIX path."""
        rel = PurePosixPath(self.relpath)
        return rel if self.kind == HCL_MODULE else rel.parent


@dataclass
class Discovery:
    """What discovery found: the units plus everything it declined to read."""

    root: Path
    units: list[ScanUnit] = field(default_factory=list)
    symlinks_skipped: int = 0
    special_skipped: int = 0
    # Walked JSON and YAML candidates over the size cap; they are almost always data dumps.
    oversized: list[str] = field(default_factory=list)
    # Paths that could not be read: {file, code, message}.
    errors: list[dict[str, str]] = field(default_factory=list)

    @property
    def files_discovered(self) -> int:
        return sum(len(unit.files) for unit in self.units) + len(self.oversized)


def classify_name(name: str) -> tuple[bool, bool]:
    """Return ``(is_candidate, by_name)`` for a file name that is not a Terraform file."""
    if name == _HELM_CHART_FILE or is_dockerfile_name(name) or name in _mcp_names():
        return True, True
    suffix = PurePosixPath(name).suffix.lower()
    return suffix in _CANDIDATE_SUFFIXES, False


def scan_root(paths: Sequence[str], *, cwd: Path | None = None) -> Path:
    """The common parent directory of the named paths; the current directory for stdin.

    A directory is its own root candidate and a file contributes its parent, so
    ``scan infra/`` reports ``main.tf`` and ``scan a/x.tf b/y.tf`` reports ``a/x.tf`` and
    ``b/y.tf`` relative to their common parent.
    """
    here = Path(os.path.abspath(cwd or Path.cwd()))
    candidates: list[str] = []
    for raw in paths:
        if raw == STDIN_PATH:
            candidates.append(str(here))
            continue
        absolute = os.path.abspath(raw)
        candidates.append(absolute if os.path.isdir(absolute) else os.path.dirname(absolute))
    if not candidates:
        return here
    try:
        return Path(os.path.commonpath(candidates))
    except ValueError as exc:
        raise UsageError("the paths are on different drives, so they have no common root") from exc


def _posix_relative(path: str | Path, root: Path) -> str:
    return Path(os.path.relpath(path, root)).as_posix()


def discover(
    paths: Sequence[str],
    *,
    root: Path | None = None,
    stdin_path: Path | None = None,
    stdin_name: str = "",
    max_file_bytes: int = MAX_INPUT_SIZE_BYTES,
) -> Discovery:
    """Find the units of a scan.

    ``paths`` are file or directory paths, or ``-`` for standard input, whose text the caller has
    already saved at ``stdin_path`` under the name ``stdin_name``.
    Units come back sorted by root-relative path, so everything downstream is deterministic.

    Raises:
        UsageError: A named path does not exist or standard input was named without content.
    """
    if not paths:
        raise UsageError("no input: name at least one file or directory, or - for standard input")
    scan_root_path = root or scan_root(paths)
    result = Discovery(root=scan_root_path)
    units: dict[tuple[str, str], ScanUnit] = {}

    def add(unit: ScanUnit) -> None:
        key = (unit.kind, str(unit.path))
        known = units.get(key)
        if known is None:
            units[key] = unit
        elif unit.explicit:
            known.explicit = True

    for raw in paths:
        if raw == STDIN_PATH:
            if stdin_path is None:
                raise UsageError("standard input was named (-) but none was provided")
            add(_stdin_unit(stdin_path, stdin_name))
            continue
        absolute = os.path.abspath(raw)
        try:
            mode = os.stat(absolute).st_mode  # a named symlink is followed on purpose
        except FileNotFoundError as exc:
            raise UsageError(f"path not found: {raw}") from exc
        except OSError as exc:
            raise UsageError(f"cannot read {raw}: {exc.strerror or exc}") from exc
        if stat.S_ISDIR(mode):
            _walk(Path(absolute), scan_root_path, result, add, max_file_bytes)
        elif stat.S_ISREG(mode):
            add(_named_file_unit(Path(absolute), scan_root_path))
        else:
            result.errors.append(
                {
                    "file": _posix_relative(absolute, scan_root_path),
                    "code": "discovery.not_regular",
                    "message": f"{raw} is not a regular file or a directory, so it was not read",
                }
            )

    ordered = sorted(units.values(), key=lambda u: (u.relpath, u.kind))
    result.units = _drop_covered_files(ordered)
    return result


def _stdin_unit(stdin_path: Path, name: str) -> ScanUnit:
    label = name or stdin_path.name
    _candidate, by_name = classify_name(label)
    by_name = by_name or is_terraform_name(label)
    kind = HELM_CHART if label == _HELM_CHART_FILE else FILE
    return ScanUnit(
        path=stdin_path,
        relpath=label,
        kind=kind,
        files=(label,),
        by_name=by_name,
        explicit=True,
        stdin=True,
    )


def _named_file_unit(path: Path, root: Path) -> ScanUnit:
    """A file the user named: it is parsed on its own, whatever its name."""
    relpath = _posix_relative(path, root)
    _candidate, by_name = classify_name(path.name)
    by_name = by_name or is_terraform_name(path.name)
    kind = HELM_CHART if path.name == _HELM_CHART_FILE else FILE
    return ScanUnit(
        path=path, relpath=relpath, kind=kind, files=(relpath,), by_name=by_name, explicit=True
    )


def _drop_covered_files(units: list[ScanUnit]) -> list[ScanUnit]:
    """Drop a named ``.tf`` file whose directory is already a module unit."""
    modules = {unit.path for unit in units if unit.kind == HCL_MODULE}
    return [
        unit
        for unit in units
        if not (
            unit.kind == FILE
            and not unit.stdin
            and is_terraform_name(unit.path.name)
            and unit.path.parent in modules
        )
    ]


def _walk(
    top: Path,
    root: Path,
    result: Discovery,
    add: Callable[[ScanUnit], None],
    max_file_bytes: int,
) -> None:
    def on_error(exc: OSError) -> None:
        name = exc.filename if isinstance(exc.filename, str) else str(top)
        result.errors.append(
            {
                "file": _posix_relative(name, root),
                "code": "discovery.unreadable",
                "message": f"cannot read {_posix_relative(name, root)}: {exc.strerror or exc}",
            }
        )

    walker = os.walk(top, topdown=True, followlinks=False, onerror=on_error)
    for dirpath, dirnames, filenames in walker:
        directory = Path(dirpath)
        kept: list[str] = []
        for name in sorted(dirnames):
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                result.symlinks_skipped += 1
            elif name in SKIP_DIRS or (name.startswith(".") and name not in _ENTERED_DOT_DIRS):
                continue
            else:
                kept.append(name)

        regular: list[tuple[str, int]] = []
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            try:
                info = os.lstat(full)
            except OSError as exc:
                result.errors.append(
                    {
                        "file": _posix_relative(full, root),
                        "code": "discovery.unreadable",
                        "message": f"cannot read {_posix_relative(full, root)}: "
                        f"{exc.strerror or exc}",
                    }
                )
                continue
            if stat.S_ISLNK(info.st_mode):
                result.symlinks_skipped += 1
            elif stat.S_ISREG(info.st_mode):
                regular.append((name, info.st_size))
            else:
                result.special_skipped += 1

        names = {name for name, _size in regular}
        chart_here = _HELM_CHART_FILE in names
        if chart_here:
            # The chart owns its directory: templates and subcharts are not scanned as raw files.
            kept = [name for name in kept if name not in _HELM_SUBTREES]
        dirnames[:] = kept

        _collect_directory(directory, regular, chart_here, root, result, add, max_file_bytes)


def _collect_directory(
    directory: Path,
    regular: Iterable[tuple[str, int]],
    chart_here: bool,
    root: Path,
    result: Discovery,
    add: Callable[[ScanUnit], None],
    max_file_bytes: int,
) -> None:
    tf_files: list[str] = []
    for name, size in regular:
        path = directory / name
        relpath = _posix_relative(path, root)
        if is_terraform_name(name):
            tf_files.append(relpath)
            continue
        if chart_here and _is_chart_owned(name):
            continue
        candidate, by_name = classify_name(name)
        if not candidate:
            continue
        if size > max_file_bytes and not by_name:
            result.oversized.append(relpath)
            continue
        kind = HELM_CHART if name == _HELM_CHART_FILE else FILE
        add(ScanUnit(path=path, relpath=relpath, kind=kind, files=(relpath,), by_name=by_name))
    if tf_files:
        add(
            ScanUnit(
                path=directory,
                relpath=_posix_relative(directory, root),
                kind=HCL_MODULE,
                files=tuple(tf_files),
                by_name=True,
            )
        )


def _is_chart_owned(name: str) -> bool:
    """Files next to Chart.yaml that the chart itself reads (values and lock files)."""
    lowered = name.lower()
    if lowered in _HELM_OWNED_FILES:
        return True
    return lowered.startswith("values") and lowered.endswith((".yaml", ".yml", ".json"))
