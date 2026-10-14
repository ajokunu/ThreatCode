"""Output formats: one registry for the CLI, the Python API and the config file.

``FORMATTERS`` maps a format name to a ``FormatterSpec``: the function that renders an
``AnalysisResult`` to text, the file extension of its output and a one-line description.
The CLI builds its ``--format`` choices from it, the config validates ``output_format`` against it
and ``render`` is the one call that turns an analysis into text.
Formatter modules are imported on first use, so listing the formats costs nothing.

``write_text_file`` is the one way output reaches a file: it rejects a directory and turns every
``OSError`` into a single ``ThreatCodeError`` line that names the absolute path and the reason.

``RepoPaths`` is how SARIF and Bitbucket name files: relative to the repository root (the git
top level of the scan root, or an explicit ``repo_root``), which is what GitHub and Bitbucket
resolve a path against, whatever directory the scan was started from.

``format_for_extension`` and ``extension_mismatch`` let a caller that is given only an output
file name pick, or check, the format; ``DEPRECATED_FORMATS`` names the aliases that still work but
that ``visible_format_names`` leaves out.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import TYPE_CHECKING, NamedTuple
from urllib.parse import quote

from threatcode._paths import WINDOWS_DRIVE_PATH, inside, is_windows_flavor, relative_posix
from threatcode.exceptions import ThreatCodeError, UsageError

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult

__all__ = [
    "DEPRECATED_FORMATS",
    "DIAGRAM_DETAILS",
    "FORMATTERS",
    "FormatterSpec",
    "RenderOptions",
    "RepoPaths",
    "deprecation_notice",
    "extension_mismatch",
    "find_repo_root",
    "format_for_extension",
    "format_names",
    "get_formatter",
    "render",
    "visible_format_names",
    "write_text_file",
]

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RenderOptions:
    """Presentation switches a renderer may honor; formats that are data ignore them."""

    # Use ANSI colors. The CLI sets it for a terminal when NO_COLOR is unset and --no-color is off.
    color: bool = False
    # Terminal width for the text report; 0 means find it (COLUMNS, else the terminal, else 100).
    width: int = 0
    # Put the graph (nodes and edges, no properties), the summary by base severity and the ingested
    # sources in the JSON report. Off by default so the JSON is exactly the report.
    include_graph: bool = False
    # The repository root SARIF and Bitbucket paths are relative to. None means the git top level
    # of the scan root; a path overrides it (a monorepo checkout without a .git directory).
    repo_root: str | None = None
    # The gate (`--fail-on`) of the scan. Bitbucket's report result follows it: FAILED when a
    # finding or attack path at or above it remains. None means the default gate, `high`.
    fail_on: str | None = None
    # SVG diagram only (`--diagram-*`). The findings rows kept in the table: None is the renderer's
    # own limit, 0 keeps every row.
    diagram_max_rows: int | None = None
    # Draw every Dockerfile instruction instead of one node per large build stage.
    diagram_expand_docker: bool = False
    # How much detail the diagram draws: "auto" collapses nodes by zone and type once the graph is
    # large, "full" never collapses and "collapsed" always does.
    diagram_detail: str = "auto"


DIAGRAM_DETAILS: tuple[str, ...] = ("auto", "full", "collapsed")


class FormatterSpec(NamedTuple):
    render: Callable[[AnalysisResult, RenderOptions], str]
    extension: str
    description: str


def _json(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.json_out import format_json

    return format_json(analysis, include_graph=options.include_graph)


def _sarif(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.sarif import format_sarif

    return format_sarif(
        analysis.report,
        analysis.graph,
        source_root=analysis.root,
        repo_root=options.repo_root,
        ingest_sources=analysis.ingest_sources,
    )


def _markdown(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.markdown import format_markdown

    return format_markdown(analysis.report, analysis.graph)


def _bitbucket(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.bitbucket import format_bitbucket

    return format_bitbucket(
        analysis.report,
        analysis.graph,
        source_root=analysis.root,
        repo_root=options.repo_root,
        fail_on=options.fail_on,
    )


def _navigator(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.attack_navigator import format_attack_navigator

    return format_attack_navigator(analysis.report)


def _mermaid(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.mermaid import format_mermaid

    return format_mermaid(analysis)


def _diagram(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.diagram import (
        DEFAULT_LOD_THRESHOLD,
        DEFAULT_MAX_ROWS,
        format_diagram,
    )

    if options.diagram_detail not in DIAGRAM_DETAILS:
        raise UsageError(
            f"diagram_detail must be one of {', '.join(DIAGRAM_DETAILS)}, "
            f"got '{options.diagram_detail}'"
        )
    if options.diagram_max_rows is not None and options.diagram_max_rows < 0:
        raise UsageError(f"diagram_max_rows must be 0 or more, got {options.diagram_max_rows}")
    max_rows: int | None = DEFAULT_MAX_ROWS
    if options.diagram_max_rows is not None:
        max_rows = options.diagram_max_rows or None
    lod_threshold: int | None = {
        "auto": DEFAULT_LOD_THRESHOLD,
        "full": None,
        "collapsed": 0,
    }[options.diagram_detail]
    return format_diagram(
        analysis.report,
        analysis.graph,
        max_rows=max_rows,
        expand_docker=options.diagram_expand_docker,
        lod_threshold=lod_threshold,
    )


def _text(analysis: AnalysisResult, options: RenderOptions) -> str:
    from threatcode.formatters.text import format_text

    return format_text(analysis, options)


FORMATTERS: dict[str, FormatterSpec] = {
    "json": FormatterSpec(_json, ".json", "Machine-readable report with coverage"),
    "sarif": FormatterSpec(_sarif, ".sarif", "SARIF 2.1.0 for GitHub code scanning"),
    "markdown": FormatterSpec(_markdown, ".md", "Markdown for pull request comments"),
    "bitbucket": FormatterSpec(_bitbucket, ".json", "Bitbucket Code Insights report"),
    "navigator": FormatterSpec(_navigator, ".json", "MITRE ATT&CK Navigator layer"),
    "mermaid": FormatterSpec(_mermaid, ".mmd", "Mermaid flowchart by trust zone with attack paths"),
    "diagram": FormatterSpec(_diagram, ".svg", "SVG diagram of the infrastructure"),
    "text": FormatterSpec(_text, ".txt", "Human summary for a terminal"),
    # The old name of "navigator", kept so scripts and configs that use it keep working.
    "matrix": FormatterSpec(_navigator, ".json", "Deprecated alias of navigator"),
}


# Names that still work but are not advertised: the alias and the format it stands for.
DEPRECATED_FORMATS: dict[str, str] = {"matrix": "navigator"}


def format_names() -> list[str]:
    """Every name the CLI, the config file and the API accept, in display order.

    That includes the deprecated aliases; ``visible_format_names`` leaves them out.
    """
    return list(FORMATTERS)


def visible_format_names() -> list[str]:
    """The formats to advertise (in ``--help``, docs and error messages): no deprecated alias."""
    return [name for name in FORMATTERS if name not in DEPRECATED_FORMATS]


def deprecation_notice(name: str) -> str:
    """One line to tell a person that format ``name`` is deprecated, or ``""`` when it is not."""
    replacement = DEPRECATED_FORMATS.get(name)
    if replacement is None:
        return ""
    return f"-f {name} is deprecated, use -f {replacement}"


def get_formatter(name: str) -> FormatterSpec:
    """The spec of format ``name``.

    Raises:
        UsageError: ``name`` is not a registered format.
    """
    try:
        return FORMATTERS[name]
    except KeyError:
        raise UsageError(
            f"unknown output format '{name}'; choose one of {', '.join(FORMATTERS)}"
        ) from None


def render(
    name: str,
    analysis: AnalysisResult,
    options: RenderOptions | None = None,
    *,
    warn_deprecated: bool = True,
) -> str:
    """Render ``analysis`` in format ``name``.

    A deprecated alias still renders; it logs one warning on the ``threatcode`` logger, which the
    CLI shows on stderr.
    A caller that tells the person itself (the CLI does, even with ``--quiet``) passes
    ``warn_deprecated=False`` so the notice is not printed twice.
    """
    spec = get_formatter(name)
    notice = deprecation_notice(name)
    if notice and warn_deprecated:
        logger.warning(notice)
    return spec.render(analysis, options or RenderOptions())


# ── choosing a format from a file name ────────────────────────────────


def _extension_formats() -> dict[str, str]:
    """Output extension -> the format a file with it holds, for the extensions that say one.

    ``.json`` is shared by json, bitbucket and navigator, so it names the plain report.
    """
    found: dict[str, str] = {}
    for name, spec in FORMATTERS.items():
        if name not in DEPRECATED_FORMATS:
            found.setdefault(spec.extension, name)
    return found


def format_for_extension(path: str | os.PathLike[str]) -> str | None:
    """The format a file named ``path`` is meant to hold, from its extension, else None.

    ``results.sarif`` is sarif, ``report.md`` markdown, ``flow.mmd`` mermaid, ``map.svg`` the
    diagram and ``out.json`` the plain JSON report.
    A file with no extension, or one no format claims, says nothing.
    """
    suffix = PurePosixPath(os.fspath(path).replace("\\", "/")).suffix.lower()
    return _extension_formats().get(suffix) if suffix else None


def extension_mismatch(name: str, path: str | os.PathLike[str]) -> str:
    """A warning when writing format ``name`` to ``path`` contradicts the file's extension.

    ``-f json -o results.sarif`` would leave a JSON report in a file that looks like SARIF.
    Returns ``""`` when the extension fits the format or says nothing.
    """
    spec = FORMATTERS.get(name)
    inferred = format_for_extension(path)
    if spec is None or inferred is None:
        return ""
    if PurePosixPath(os.fspath(path).replace("\\", "/")).suffix.lower() == spec.extension:
        return ""
    return (
        f"{os.fspath(path)} has the extension of the {inferred} format but the {name} format "
        f"is written to it; pass -f {inferred} to write {inferred}"
    )


# ── paths relative to the repository ──────────────────────────────────


def find_repo_root(start: str | os.PathLike[str]) -> Path | None:
    """The nearest directory at or above ``start`` that holds a ``.git`` entry, else None.

    ``.git`` is a directory in a clone and a file in a worktree or a submodule; either marks the
    top of the checkout.
    """
    here = Path(os.path.realpath(start))
    for candidate in (here, *here.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _clamp(path: str) -> str:
    """``path`` with no empty, ``.`` or ``..`` segment, so it cannot name a place above the root."""
    segments: list[str] = []
    for segment in path.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/".join(segments)


@dataclass
class RepoPaths:
    """Where a report's files sit in the repository, for the formats that must say it.

    A report names files relative to the scan root (``infra/main.tf`` when ``infra`` was
    scanned), but GitHub and Bitbucket resolve a path against the repository root.
    ``locate`` joins the two, so ``threatcode scan infra`` run from ``infra``, from a
    subdirectory of it or from the repository root puts alerts on the same files.

    The repository root is, in order: ``repo_root`` when given, the git top level above the scan
    root, the current directory when the scan root is inside it, and else the scan root itself,
    in which case ``anchored`` is False and the paths are only relative to the scan.
    A file that is outside the repository root cannot be placed; it is named by its file name
    alone (never with ``..``) and counted in ``outside``.
    ``source_root`` is None for a report built by hand, whose paths are relative to the current
    directory.
    """

    scan_root: str
    base: str
    anchored: bool
    outside: set[str] = field(default_factory=set)
    # The path rules the paths follow: those of this machine, unless a test checks another's
    pathmod: ModuleType = field(default=os.path, repr=False, compare=False)
    _cache: dict[str, str] = field(default_factory=dict, repr=False)

    @classmethod
    def resolve(
        cls,
        source_root: str | os.PathLike[str] | None = None,
        repo_root: str | os.PathLike[str] | None = None,
    ) -> RepoPaths:
        cwd = os.path.realpath(os.getcwd())
        scan = os.path.realpath(source_root) if source_root is not None else cwd
        if repo_root:
            return cls(scan, os.path.realpath(repo_root), anchored=True)
        git = find_repo_root(scan)
        if git is not None:
            return cls(scan, str(git), anchored=True)
        if _inside(scan, cwd):
            return cls(scan, cwd, anchored=True)
        return cls(scan, scan, anchored=False)

    def locate(self, path: str) -> str:
        """``path`` as a POSIX path relative to the repository root; ``.`` for the root itself."""
        cached = self._cache.get(path)
        if cached is None:
            cached = self._cache[path] = self._locate(path)
        return cached

    def uri(self, path: str) -> str:
        """``locate`` percent-encoded as a URI reference (space, ``@``, ``:``, ``%``, ...)."""
        return quote(self.locate(path), safe="/")

    def _locate(self, path: str) -> str:
        mod = self.pathmod
        text = path.replace("\\", "/")
        drive_path = bool(WINDOWS_DRIVE_PATH.match(text))
        if drive_path and not is_windows_flavor(mod):
            # A path from a report made on Windows is not a place on this machine
            self.outside.add(path)
            return PurePosixPath(text).name or "."
        rooted = drive_path or text.startswith("/")
        absolute = str(
            mod.realpath(text) if rooted else mod.normpath(mod.join(self.scan_root, text))
        )
        relative = relative_posix(absolute, self.base, pathmod=mod)
        if relative is not None and inside(relative):
            return relative
        self.outside.add(path)
        if rooted:
            return PurePosixPath(absolute.replace(str(mod.sep), "/")).name or "."
        return _clamp(text) or "."


def _inside(path: str, base: str) -> bool:
    """Whether ``path`` is ``base`` or below it."""
    relative = relative_posix(path, base)  # None: another drive on Windows
    return relative is not None and inside(relative)


def write_text_file(path: str | os.PathLike[str], text: str) -> Path:
    """Write ``text`` to ``path`` (UTF-8), creating parent directories; return the absolute path.

    Raises:
        ThreatCodeError: ``path`` is a directory or cannot be written. The message is one line:
            ``cannot write <absolute path>: <reason>``.
    """
    target = Path(os.path.abspath(path))
    try:
        if target.is_dir():
            raise ThreatCodeError(f"cannot write {target}: it is a directory, not a file")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    except OSError as exc:
        raise ThreatCodeError(f"cannot write {target}: {exc.strerror or exc}") from exc
    return target
