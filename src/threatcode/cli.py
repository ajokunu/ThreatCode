"""Click CLI for ThreatCode: ``threatcode scan`` and ``threatcode diff``.

The CLI parses options, calls ``threatcode.pipeline.run_scan`` and renders the result.
It owns everything a person sees: the report on stdout or in a file, and the messages on stderr.
Errors and coverage gaps are always printed on stderr, even with ``--quiet``, because a scan that
looks clean while part of the input was not analysed is worse than a failed scan.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from threatcode import __version__
from threatcode.exceptions import ThreatCodeError, UsageError
from threatcode.formatters import (
    DIAGRAM_DETAILS,
    RenderOptions,
    deprecation_notice,
    extension_mismatch,
    format_for_extension,
    format_names,
    render,
    visible_format_names,
    write_text_file,
)
from threatcode.formatters._utils import set_aside_phrase, terminal_safe
from threatcode.formatters.terminal_coverage import (
    error_text,
    gap_lines,
    gap_summary,
    unique_gaps,
)
from threatcode.formatters.terminal_layout import hanging
from threatcode.formatters.text import plural
from threatcode.models.threat import Severity

if TYPE_CHECKING:
    from threatcode.config import LoadedConfig
    from threatcode.models.report import Coverage
    from threatcode.pipeline import ScanResult

logger = logging.getLogger("threatcode.cli")

# Derived from the Severity enum so importing the CLI does not import the config model (pydantic).
SEVERITY_CHOICES: tuple[str, ...] = tuple(s.value for s in Severity)
FAIL_ON_CHOICES: tuple[str, ...] = (*SEVERITY_CHOICES, "none")

DEBUG_ENV = "THREATCODE_DEBUG"
# Errors and gaps beyond this many are summarised on stderr; the JSON report lists them all.
_LISTED_LIMIT = 10
_MIN_STDERR_WIDTH = 40
_DEFAULT_STDERR_WIDTH = 100

# The environment variables the CLI reads, in one list: (names, what they do).
# Both the group help and the help of every command print it, so they cannot disagree.
_ENVIRONMENT: tuple[tuple[str, str], ...] = (
    (
        "THREATCODE_FAIL_ON, THREATCODE_MIN_SEVERITY, THREATCODE_FORMAT, THREATCODE_LLM",
        "defaults below the flags and above a config file",
    ),
    ("THREATCODE_MAX_NODES, THREATCODE_MAX_EDGES", "graph size limits"),
    ("THREATCODE_DEBUG=1", "show tracebacks for unexpected errors"),
    ("ANTHROPIC_API_KEY", "read only when the LLM is requested with --llm"),
    ("SOURCE_DATE_EPOCH", "fixed report timestamp for reproducible output"),
    ("NO_COLOR", "plain text output"),
    ("CI", "skips the home directory when looking for a config file"),
)
_ENVIRONMENT_COLUMN = 25


def _environment_block() -> str:
    """The ``Environment:`` section of a help page, built from ``_ENVIRONMENT``."""
    lines = ["\b", "Environment:"]
    for names, meaning in _ENVIRONMENT:
        if len(names) + 2 < _ENVIRONMENT_COLUMN:
            lines.append(f"  {names.ljust(_ENVIRONMENT_COLUMN - 2)}{meaning}")
        else:
            lines.append(f"  {names}")
            lines.append(f"{' ' * _ENVIRONMENT_COLUMN}{meaning}")
    return "\n".join(lines) + "\n"


_GROUP_EPILOG = """\b
Examples:
  threatcode scan infra/
  threatcode scan main.tf modules/ -f sarif -o threatcode.sarif --fail-on high
  terraform show -json tfplan | threatcode scan - --stdin-name plan.json
  threatcode diff base.json current.json --fail-on-new high

\b
Exit codes:
  0  clean: nothing at or above --fail-on survived suppressions and the baseline
  1  at least one finding or attack path at or above --fail-on
  2  usage or input error: an unreadable path, a file that failed to parse, nothing to
     scan, a bad option, or --strict with a coverage gap

""" + _environment_block()

_SCAN_EPILOG = """\b
Examples:
  threatcode scan infra/                       a directory: one graph across every file
  threatcode scan a.tf b.yaml k8s/             several files and directories
  terraform show -json tfplan | threatcode scan - --stdin-name plan.json
  threatcode scan infra/ --fail-on critical --min-severity medium -f markdown
  threatcode scan infra/ -o threatcode.sarif   the .sarif extension picks the SARIF format
  threatcode scan infra/ --write-baseline .threatcode-baseline.json
  threatcode scan infra/ --baseline .threatcode-baseline.json

\b
Exit codes:
  0  clean            nothing at or above --fail-on (default: high)
  1  findings         a finding or attack path at or above --fail-on survived
                      suppressions and the baseline (LLM findings never count)
  2  usage or input   unreadable path, file that failed to parse, nothing to scan,
                      bad option, or --strict with any coverage gap

""" + _environment_block()

_DIFF_EPILOG = """\b
Examples:
  threatcode scan infra/ -f json -o current.json
  threatcode diff base.json current.json
  threatcode diff base.json current.json -f markdown --fail-on-new high

\b
Exit codes:
  0  no new or worsened threat at or above --fail-on-new (or the flag was not given)
  1  a threat was added, or got worse, at or above --fail-on-new
  2  an input is not a ThreatCode JSON report, or another usage error

""" + _environment_block()

# Defaults the help states; tests check them against the modules that own the values.
DEFAULT_MAX_NODES = 10_000
DEFAULT_MAX_EDGES = 50_000
DEFAULT_DIAGRAM_MAX_ROWS = 200
# Names that mean standard output where a file name is expected.
_STDOUT_NAMES = frozenset({"-", "/dev/stdout", "/dev/fd/1"})
# Formats that are not meant to be read in a terminal, with what to do instead.
_NOT_FOR_A_TERMINAL = {
    "diagram": "diagram output is SVG; pass -o file.svg instead of printing it",
    "navigator": (
        "navigator output is an ATT&CK Navigator layer (JSON); "
        "pass -o layer.json instead of printing it"
    ),
    "matrix": (
        "matrix output is an ATT&CK Navigator layer (JSON); "
        "pass -o layer.json instead of printing it"
    ),
}


def _stderr_is_tty() -> bool:
    try:
        return sys.stderr.isatty()
    except (AttributeError, ValueError):
        return False


def echo_err(message: str, *, hang: int = 0) -> None:
    """One message on stderr, safe for a terminal.

    Messages quote the scanned input (a file name, a resource address, a parser's complaint), and
    that text is hostile: an escape sequence in a server name must not clear the screen or retitle
    the window.
    Every message the CLI prints on stderr goes through here.
    On a terminal a long message wraps at the terminal width with ``hang`` spaces of hanging
    indent; into a pipe or a log it stays one line, because tools that read the stream
    (a CI step that quotes the last line) read lines.
    """
    safe = terminal_safe(message, keep_lines=True)
    if hang and _stderr_is_tty():
        safe = _wrap_for_terminal(safe, hang)
    click.echo(safe, err=True)


def _stderr_width() -> int:
    """The width of the terminal standard error is on: ``COLUMNS``, else the terminal, else 100.

    Standard output may be a pipe while standard error is the terminal (``scan -f json > out``),
    so the width of standard output says nothing about it.
    """
    columns = os.environ.get("COLUMNS", "")
    if columns.isdigit() and int(columns) > 0:
        return max(int(columns), _MIN_STDERR_WIDTH)
    try:
        return max(os.get_terminal_size(sys.stderr.fileno()).columns, _MIN_STDERR_WIDTH)
    except (OSError, ValueError, AttributeError):
        return _DEFAULT_STDERR_WIDTH


def _wrap_for_terminal(message: str, hang: int) -> str:
    """``message`` wrapped at the terminal width, continuation lines ``hang`` spaces further in."""
    width = _stderr_width()
    out: list[str] = []
    for line in message.split("\n"):
        lead = line[: len(line) - len(line.lstrip(" "))]
        out.extend(hanging(line.lstrip(" "), width, first=lead, rest=" " * (len(lead) + hang)))
    return "\n".join(out)


@dataclass
class CliState:
    """Group-level settings that every command reads."""

    quiet: bool = False
    verbose: int = 0
    debug: bool = False
    color: bool = True

    def info(self, message: str, *, hang: int = 0) -> None:
        """A message that ``--quiet`` hides."""
        if not self.quiet:
            echo_err(message, hang=hang)

    def warn(self, message: str, *, hang: int = 0) -> None:
        """A message that is always shown."""
        echo_err(message, hang=hang)


def _state(ctx: click.Context) -> CliState:
    found = ctx.find_object(CliState)
    return found if found is not None else CliState()


class _ThreatCodeGroup(click.Group):
    """A group that turns every ThreatCodeError, and any unexpected error, into one line.

    ThreatCodeErrors are messages written for people: ``Error: <message>`` and exit 2.
    An unexpected exception prints one line and exits 2; the traceback appears only with
    ``--debug`` or ``THREATCODE_DEBUG=1``.
    """

    def invoke(self, ctx: click.Context) -> Any:
        try:
            return super().invoke(ctx)
        except (click.exceptions.ClickException, click.exceptions.Abort, click.exceptions.Exit):
            raise
        except ThreatCodeError as exc:
            echo_err(f"Error: {exc}")
            ctx.exit(2)
        except Exception as exc:  # noqa: BLE001 - last resort: any crash must exit 2, never 1
            echo_err(
                f"Error: unexpected {type(exc).__name__}: {exc} (run with --debug for a traceback)"
            )
            if bool(ctx.params.get("debug")) or os.environ.get(DEBUG_ENV) == "1":
                # The traceback is for the person debugging; the exit status stays 2 so a crash
                # can never be read as "findings" (1).
                traceback.print_exc(file=sys.stderr)
            ctx.exit(2)


class _SafeFormatter(logging.Formatter):
    """A log formatter whose output cannot carry a control sequence from the scanned input."""

    def format(self, record: logging.LogRecord) -> str:
        return terminal_safe(super().format(record), keep_lines=True)


def _configure_logging(ctx: click.Context, state: CliState) -> None:
    """Send ThreatCode's log records to stderr at the level ``state`` asks for.

    The handler is installed once per invocation; ``-q`` and ``-v`` given after the command call
    this again, which only moves the level.
    """
    if state.debug or state.verbose >= 2:
        level = logging.DEBUG
    elif state.verbose == 1:
        level = logging.INFO
    elif state.quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING
    target = logging.getLogger("threatcode")
    if _LOG_HANDLER_KEY in ctx.meta:
        target.setLevel(level)
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_SafeFormatter("%(levelname)s: %(message)s"))
    previous = target.level
    target.addHandler(handler)
    target.setLevel(level)
    ctx.meta[_LOG_HANDLER_KEY] = handler

    def restore() -> None:
        target.removeHandler(handler)
        target.setLevel(previous)

    ctx.call_on_close(restore)


_LOG_HANDLER_KEY = "threatcode.log_handler"


@click.group(
    cls=_ThreatCodeGroup,
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=_GROUP_EPILOG,
)
@click.version_option(version=__version__, prog_name="threatcode")
@click.option("-v", "--verbose", count=True, help="More log detail on stderr (-vv for debug).")
@click.option("-q", "--quiet", is_flag=True, help="Hide progress and notices; errors stay.")
@click.option("--debug", is_flag=True, help="Debug logging and tracebacks for unexpected errors.")
@click.option("--no-color", is_flag=True, help="Never use colors (NO_COLOR does the same).")
@click.pass_context
def cli(ctx: click.Context, verbose: int, quiet: bool, debug: bool, no_color: bool) -> None:
    """ThreatCode: STRIDE threat models and attack paths from infrastructure code and agent configs.

    scan reads Terraform, CloudFormation, Kubernetes, Helm, Dockerfiles and MCP configs and models
    them as one graph.
    diff compares two JSON reports.
    -v, -q and --no-color work before or after the command; --debug goes before it:
    threatcode --debug scan infra/.
    """
    state = CliState(quiet=quiet, verbose=verbose, debug=debug, color=not no_color)
    ctx.obj = state
    _configure_logging(ctx, state)


def _command_state(ctx: click.Context) -> CliState:
    """The state of the group, created when a command runs without one (``scan.main()``)."""
    found = ctx.find_object(CliState)
    if found is None:
        found = CliState()
        ctx.obj = found
    return found


def _set_quiet(ctx: click.Context, _param: click.Parameter, value: bool) -> bool:
    state = _command_state(ctx)
    if value:
        state.quiet = True
        _configure_logging(ctx, state)
    return value


def _set_verbose(ctx: click.Context, _param: click.Parameter, value: int) -> int:
    state = _command_state(ctx)
    if value:
        state.verbose += value
        _configure_logging(ctx, state)
    return value


def _set_no_color(ctx: click.Context, _param: click.Parameter, value: bool) -> bool:
    if value:
        _command_state(ctx).color = False
    return value


def _global_options(func: Callable[..., Any]) -> Callable[..., Any]:
    """``-q``, ``-v`` and ``--no-color`` on a command, the same options the group has.

    They act on the shared ``CliState`` while the command line is parsed, so a command never sees
    them as arguments, and ``threatcode scan -q infra/`` means what ``threatcode -q scan infra/``
    does.
    """
    options = (
        click.option(
            "-v",
            "--verbose",
            count=True,
            expose_value=False,
            callback=_set_verbose,
            help="More log detail on stderr (-vv for debug). Also works before the command.",
        ),
        click.option(
            "-q",
            "--quiet",
            is_flag=True,
            expose_value=False,
            callback=_set_quiet,
            help="Hide progress and notices; errors and coverage gaps stay. "
            "Also works before the command.",
        ),
        click.option(
            "--no-color",
            is_flag=True,
            expose_value=False,
            callback=_set_no_color,
            help="Never use colors (NO_COLOR does the same). Also works before the command.",
        ),
    )
    for option in reversed(options):
        func = option(func)
    return func


# ── Shared helpers ────────────────────────────────────────────────────


def _stdout_is_tty() -> bool:
    try:
        return sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _check_output_path(path: str | None) -> None:
    """Fail before scanning when ``-o`` names a directory."""
    if path is not None and Path(path).is_dir():
        target = Path(os.path.abspath(path))
        raise ThreatCodeError(f"cannot write {target}: it is a directory, not a file")


def write_output(
    path: str | None, text: str, *, label: str = "Output", quiet: bool = False
) -> None:
    """Write ``text`` to ``path``, or to stdout when ``path`` is None.

    A directory or an unwritable path is one ``ThreatCodeError`` line naming the absolute path and
    the reason. ``<label> written to <path>`` goes to stderr so stdout stays clean.
    """
    body = text if text.endswith("\n") else text + "\n"
    if path is None:
        click.echo(body, nl=False)
        return
    target = write_text_file(path, body)
    if not quiet:
        echo_err(f"{label} written to {target}")


def _output_target(path: str | None) -> str | None:
    """``path`` for ``-o``, or None when it means standard output (``-``, ``/dev/stdout``).

    ``/dev/stdout`` is not a file to create: a pipe or a terminal cannot be rewritten, and opening
    it again would also truncate a file the shell redirected standard output to.
    """
    return None if path in _STDOUT_NAMES else path


def _default_format(output_path: str | None) -> str:
    """The format when nothing chose one: the output file's extension, else text on a terminal."""
    if output_path is not None:
        return format_for_extension(output_path) or "json"
    return "text" if _stdout_is_tty() else "json"


def _use_color(state: CliState, output_path: str | None) -> bool:
    return (
        state.color and output_path is None and _stdout_is_tty() and not os.environ.get("NO_COLOR")
    )


def _first_line(text: str) -> str:
    return text.splitlines()[0] if text else text


class _FormatChoice(click.Choice):  # type: ignore[type-arg]
    """The ``--format`` choice: advertises the current formats, still accepts a deprecated alias.

    ``--help`` and the invalid-value error list ``visible_format_names()``; ``matrix`` is accepted
    but never offered.
    """

    def __init__(self) -> None:
        super().__init__(visible_format_names())

    def convert(self, value: Any, param: click.Parameter | None, ctx: click.Context | None) -> Any:
        if isinstance(value, str) and value in format_names() and value not in self.choices:
            return value
        return super().convert(value, param, ctx)


# ── scan ──────────────────────────────────────────────────────────────


@cli.command(
    epilog=_SCAN_EPILOG, short_help="Build a threat model from files, directories or stdin."
)
@click.argument("paths", nargs=-1, required=True, metavar="PATH...")
@click.option(
    "--format",
    "-f",
    "output_format",
    default=None,
    type=_FormatChoice(),
    metavar="FORMAT",
    help=f"Output format: {', '.join(visible_format_names())}. "
    "Default: THREATCODE_FORMAT or the config's format, else the one the -o extension names "
    "(.sarif, .md, .mmd, .svg, .json), else text on a terminal and json otherwise.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(readable=False),
    default=None,
    help="Write the report to this file instead of stdout. - means stdout.",
)
@click.option(
    "--min-severity",
    default=None,
    type=click.Choice(SEVERITY_CHOICES),
    help="Hide findings below this severity. Display only: the gate is --fail-on.",
)
@click.option(
    "--fail-on",
    default=None,
    type=click.Choice(FAIL_ON_CHOICES),
    help="Exit 1 when a finding or attack path at or above this severity remains. "
    "'none' never fails on findings. Default: high.",
)
@click.option(
    "--strict",
    is_flag=True,
    help="Exit 2 when any coverage gap was reported (unanalysed module, fallback render, "
    "unknown value, unresolved intrinsic, skipped document).",
)
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(),
    default=None,
    help="Path to a .threatcode.yml. Only an explicit config can set fail_on, rules or the LLM.",
)
@click.option(
    "--rules",
    "-r",
    "extra_rules",
    type=click.Path(exists=True),
    multiple=True,
    help="Additional rule file (repeatable).",
)
@click.option(
    "--ignore-file",
    type=click.Path(dir_okay=False),
    default=None,
    help="Suppressions file. Default: .threatcodeignore in the scan root.",
)
@click.option("--no-ignore", is_flag=True, help="Do not read any suppressions file.")
@click.option(
    "--baseline",
    type=click.Path(dir_okay=False),
    default=None,
    help="Hide findings already in this baseline from the gate and the listings.",
)
@click.option(
    "--write-baseline",
    type=click.Path(),
    default=None,
    help="Write every finding's fingerprint to this file. Exits 0 unless an input error occurred.",
)
@click.option(
    "--ingest",
    type=click.Path(),
    multiple=True,
    help="A scanner result (Trivy, Grype, OSV-Scanner or SARIF) to join to the graph (repeatable).",
)
@click.option(
    "--llm/--no-llm",
    "llm",
    default=None,
    help="Send a redacted graph to an LLM for extra findings. Off by default.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Build the LLM request without sending it. Implies --llm; nothing leaves the machine.",
)
@click.option(
    "--dry-run-output",
    type=click.Path(dir_okay=False),
    default=None,
    help="Where --dry-run writes the request. Default: stdout.",
)
@click.option(
    "--no-timestamp",
    is_flag=True,
    help="Leave the timestamp out of the report. SOURCE_DATE_EPOCH fixes it instead.",
)
@click.option(
    "--stdin-name",
    default=None,
    help="File name for standard input (main.tf, Dockerfile, plan.json) so its format is found.",
)
@click.option(
    "--include-graph",
    is_flag=True,
    help="Add the graph (nodes and edges, no properties) to the JSON report.",
)
@click.option(
    "--source-root",
    type=click.Path(exists=True, file_okay=False),
    default=None,
    help="The repository root that SARIF and Bitbucket paths are relative to, for a checkout "
    "with no .git directory. Default: the git top level above the scan root.",
)
@click.option(
    "--diagram-max-rows",
    type=click.IntRange(min=0),
    metavar="N",
    default=None,
    help=f"-f diagram: findings rows drawn in the table (default {DEFAULT_DIAGRAM_MAX_ROWS}; "
    "0 draws every row).",
)
@click.option(
    "--diagram-expand-docker",
    is_flag=True,
    help="-f diagram: draw every Dockerfile instruction, not one node per large build stage.",
)
@click.option(
    "--diagram-detail",
    type=click.Choice(DIAGRAM_DETAILS),
    default=None,
    help="-f diagram: auto collapses nodes by zone and type once the graph is large (default), "
    "full never collapses, collapsed always does.",
)
@click.option(
    "--max-nodes",
    type=click.IntRange(min=1),
    metavar="N",
    default=None,
    help=f"Graph node limit (default {DEFAULT_MAX_NODES:,}).",
)
@click.option(
    "--max-edges",
    type=click.IntRange(min=1),
    metavar="N",
    default=None,
    help=f"Graph edge limit (default {DEFAULT_MAX_EDGES:,}).",
)
@_global_options
@click.pass_context
def scan(
    ctx: click.Context,
    paths: tuple[str, ...],
    output_format: str | None,
    output_path: str | None,
    min_severity: str | None,
    fail_on: str | None,
    strict: bool,
    config_path: str | None,
    extra_rules: tuple[str, ...],
    ignore_file: str | None,
    no_ignore: bool,
    baseline: str | None,
    write_baseline: str | None,
    ingest: tuple[str, ...],
    llm: bool | None,
    dry_run: bool,
    dry_run_output: str | None,
    no_timestamp: bool,
    stdin_name: str | None,
    include_graph: bool,
    source_root: str | None,
    diagram_max_rows: int | None,
    diagram_expand_docker: bool,
    diagram_detail: str | None,
    max_nodes: int | None,
    max_edges: int | None,
) -> None:
    """Scan files, directories and standard input and build one STRIDE threat model.

    PATH is a Terraform plan JSON, a .tf file or a directory of them, a CloudFormation template,
    a Kubernetes manifest, a Helm chart, a Dockerfile, an MCP client config, or a directory of
    any of these. Use - to read standard input. Everything found is modeled in one graph, so
    attack paths can cross files.
    """
    from threatcode.pipeline import prepare_request, run_scan

    state = _state(ctx)
    output_path = _output_target(output_path)
    prepared = prepare_request(
        paths,
        config_path=config_path,
        fail_on=fail_on,
        min_severity=min_severity,
        output_format=output_format,
        llm=llm,
        dry_run=dry_run,
        dry_run_output=dry_run_output,
        extra_rule_paths=extra_rules,
        strict=strict,
        ignore_file=ignore_file,
        no_ignore=no_ignore,
        baseline=baseline,
        write_baseline=write_baseline,
        ingest=ingest,
        stdin_name=stdin_name,
        no_timestamp=no_timestamp,
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
    settings = prepared.request.settings
    chosen = settings.output_format or _default_format(output_path)
    _check_format_choice(
        chosen,
        output_path,
        explicit=settings.output_format is not None,
        state=state,
        diagram_options=diagram_max_rows is not None
        or diagram_expand_docker
        or diagram_detail is not None,
    )
    _check_output_path(output_path)
    _check_output_path(write_baseline)
    _announce_config(prepared.config, state)
    llm_ready = _check_llm(settings)
    if llm_ready:
        _announce_llm(settings, state)

    result = run_scan(prepared.request)
    # A parser that meets one cause twice reports it twice; the count and the listing are of causes
    result.coverage.gaps[:] = unique_gaps(result.coverage.gaps)
    _warn_on_duplicate_ids(result.report)

    options = RenderOptions(
        color=_use_color(state, output_path),
        include_graph=include_graph,
        repo_root=source_root,
        fail_on=settings.fail_on,
        diagram_max_rows=diagram_max_rows,
        diagram_expand_docker=diagram_expand_docker,
        diagram_detail=diagram_detail or "auto",
    )
    # The deprecation notice was printed above, where -q cannot hide it
    text = render(chosen, result.analysis, options, warn_deprecated=False)
    write_output(output_path, text, label="Report", quiet=state.quiet)
    if result.baseline_written is not None:
        state.info(f"Baseline written to {result.baseline_written}")
    _report_to_stderr(
        result,
        state,
        # The text report on standard output already lists every gap and error
        listed_in_report=chosen == "text" and output_path is None,
        fail_on=settings.fail_on,
    )
    ctx.exit(result.exit_code)


def _check_format_choice(
    chosen: str,
    output_path: str | None,
    *,
    explicit: bool,
    state: CliState,
    diagram_options: bool,
) -> None:
    """Refuse or warn about a format and destination that do not fit, before the scan runs."""
    if diagram_options and chosen != "diagram":
        raise UsageError(f"--diagram-* options only apply to -f diagram, not -f {chosen}")
    if output_path is None and chosen in _NOT_FOR_A_TERMINAL and _stdout_is_tty():
        raise UsageError(_NOT_FOR_A_TERMINAL[chosen])
    notice = deprecation_notice(chosen)
    if notice:
        state.warn(f"Warning: {notice}")
    if explicit and output_path is not None:
        mismatch = extension_mismatch(chosen, output_path)
        if mismatch:
            state.warn(f"Warning: {mismatch}")


def _check_llm(settings: Any) -> bool:
    """Whether the LLM can run, checked before the scan says it will send anything.

    Without the anthropic SDK this raises one error that names the extra, whether or not a key
    is set: the SDK is checked first, because a key does not help without it.
    Without a key the scan goes on with rules only (the client factory warns), so nothing is said
    about sending.
    A dry run needs neither.
    """
    if not settings.use_llm or settings.dry_run:
        return bool(settings.use_llm)
    llm = settings.config.llm
    if llm.provider != "anthropic":
        return True
    # Looked for, not imported: only the model client touches the SDK.
    if importlib.util.find_spec("anthropic") is None:
        raise ThreatCodeError(
            "the LLM needs the anthropic SDK, which is not installed; "
            "install it with: pip install 'threatcode[llm]'"
        )
    from threatcode.engine.llm.factory import resolve_api_key

    return bool(resolve_api_key(llm))


def _warn_on_duplicate_ids(report: Any) -> None:
    """Log the warning ``threatcode.scan()`` logs when two threats share an id."""
    repeated = report.duplicate_ids()
    if repeated:
        # An id names one finding in a diff and in an ignore entry; a repeat would merge two.
        logging.getLogger("threatcode").warning(
            "the report holds %d threat id(s) more than once, so a diff or an ignore entry "
            "cannot tell the threats apart: %s",
            len(repeated),
            ", ".join(repeated[:5]),
        )


def _announce_config(loaded: LoadedConfig, state: CliState) -> None:
    if loaded.path is None:
        return
    for notice in loaded.notices:
        state.warn(f"Warning: {notice}")
    if loaded.auto_discovered:
        used = ", ".join(loaded.used) or "nothing"
        state.info(f"Using config {loaded.path} (auto-discovered); fields used: {used}")


def _announce_llm(settings: Any, state: CliState) -> None:
    if not settings.use_llm:
        return
    if settings.dry_run:
        state.info("Dry run: the LLM request is built and nothing is sent")
        return
    llm = settings.config.llm
    state.info(f"LLM enrichment enabled: sending a redacted graph to {llm.provider}/{llm.model}")


def _report_input_errors(coverage: Coverage, state: CliState, *, listed_in_report: bool) -> None:
    """Every input error once, when the report does not list them; the exit-2 line comes last."""
    if listed_in_report or len(coverage.errors) < 2:
        # One error is named by the exit line; the text report lists them all itself
        return
    for error in coverage.errors[:_LISTED_LIMIT]:
        state.warn(f"Error: {error_text(error)}", hang=7)
    if len(coverage.errors) > _LISTED_LIMIT:
        state.warn(f"Error: ... and {len(coverage.errors) - _LISTED_LIMIT} more input errors")


def _report_coverage_gaps(coverage: Coverage, state: CliState, *, listed_in_report: bool) -> None:
    """The parts of the input the scan did not analyse: the list, or one line pointing to it."""
    if not coverage.gaps:
        return
    if listed_in_report:
        state.warn(
            f"Warning: part of the input was not analysed: {gap_summary(coverage.gaps)}; "
            "the report lists them",
            hang=9,
        )
        return
    lines = gap_lines(coverage.gaps)
    state.warn(
        f"Coverage gaps ({len(unique_gaps(coverage.gaps))}): part of the input was not analysed"
    )
    for gap in lines[:_LISTED_LIMIT]:
        state.warn(f"  {gap.text()}", hang=4)
    if len(lines) > _LISTED_LIMIT:
        state.warn(
            f"  ... and {len(lines) - _LISTED_LIMIT} more (see coverage.gaps in the JSON report)"
        )


def _gate_line(result: ScanResult, fail_on: str) -> str:
    gated = set_aside_phrase(result.gate_findings, result.gate_paths)
    return f"Gate failed: {gated} at or above {fail_on} (--fail-on {fail_on}), exiting 1"


def _summary_extras(result: ScanResult) -> str:
    """What the ``Scanned`` line says was left out, set aside or not read."""
    coverage = result.coverage
    extras = []
    if coverage.baselined:
        baselined = set_aside_phrase(
            coverage.baselined - coverage.baselined_paths, coverage.baselined_paths
        )
        extras.append(f"{baselined} baselined")
    if coverage.suppressed:
        suppressed = set_aside_phrase(
            coverage.suppressed - coverage.suppressed_paths, coverage.suppressed_paths
        )
        extras.append(f"{suppressed} suppressed")
    if coverage.hidden_findings or coverage.hidden_paths:
        hidden = set_aside_phrase(coverage.hidden_findings, coverage.hidden_paths)
        extras.append(f"{hidden} below {coverage.min_severity} hidden by --min-severity")
    incomplete = _incomplete_phrase(coverage)
    if incomplete:
        extras.append(f"incomplete: {incomplete}")
    return f" ({', '.join(extras)})" if extras else ""


def _incomplete_phrase(coverage: Coverage) -> str:
    """What makes the scan incomplete: input errors, error-level gaps and skipped Helm templates.

    A Helm template that was skipped or only approximated leaves resources out of the model, so a
    ``found 0 findings`` over it must not read as clean.
    Other coverage gaps (an unresolved value, a capped search) are listed on their own and do not
    make the scan incomplete.
    """
    parts = []
    if coverage.errors:
        parts.append(plural(len(coverage.errors), "input error"))
    unique = unique_gaps(coverage.gaps)
    helm = [gap for gap in unique if gap.get("code") == "helm.render_warning"]
    other = [gap for gap in unique if gap.get("level") == "error" and gap not in helm]
    if other:
        parts.append(plural(len(other), "error-level coverage gap"))
    if helm:
        parts.append(f"{plural(len(helm), 'Helm template')} skipped or approximated")
    return ", ".join(parts)


def _report_to_stderr(
    result: ScanResult, state: CliState, *, listed_in_report: bool = False, fail_on: str = "high"
) -> None:
    """Print what a person must know about the scan; errors and gaps are never hidden.

    When the text report went to standard output it already lists every error and gap and says
    how many findings there are, so stderr keeps one line per kind instead of repeating them.
    Whatever is printed last explains the exit code.
    """
    coverage = result.coverage
    report = result.report

    _report_input_errors(coverage, state, listed_in_report=listed_in_report)
    _report_coverage_gaps(coverage, state, listed_in_report=listed_in_report)
    if coverage.rule_errors:
        state.warn(
            f"{plural(coverage.rule_errors, 'rule evaluation')} failed and "
            "were skipped; see rule_errors in the JSON report"
        )

    llm = report.llm or {}
    if llm.get("status") == "failed":
        reason = _first_line(str(llm.get("error") or "unknown error"))
        state.warn(f"Warning: LLM analysis failed ({reason}); rule results are unaffected", hang=9)

    if result.ignore_file is not None:
        suppressed = plural(coverage.suppressed - result.suppressed_paths, "finding")
        if result.suppressed_paths:
            suppressed += f" and {plural(result.suppressed_paths, 'attack path')}"
        state.info(
            f"Using ignore file {result.ignore_file} "
            f"({plural(result.ignore_entries, 'active entry', 'active entries')}); "
            f"suppressed {suppressed}",
            hang=2,
        )
    for notice in result.notices:
        state.info(f"Warning: {notice}", hang=9)

    if state.verbose and coverage.not_iac_count:
        shown = ", ".join(coverage.not_iac_paths[:5])
        state.info(f"{coverage.not_iac_count} file(s) are not infrastructure: {shown}")
    if coverage.units_parsed and not listed_in_report:
        shown_findings = len(report.threats)
        found = plural(shown_findings, "finding")
        if coverage.hidden_findings:
            found = f"{shown_findings} of {shown_findings + coverage.hidden_findings} findings"
        state.info(
            f"Scanned {plural(report.scanned_resources, 'resource')} in "
            f"{plural(coverage.units_parsed, 'unit')}, found {found}{_summary_extras(result)}.",
            hang=2,
        )

    # The last line says why the exit code is not 0
    if result.exit_code == 2:
        if coverage.errors:
            problem = plural(len(coverage.errors), "input error")
            state.warn(
                f"Error: scan incomplete ({problem}), exiting 2: {error_text(coverage.errors[0])}",
                hang=7,
            )
        elif coverage.has_gaps:
            state.warn("--strict: coverage gaps make this scan fail, exiting 2")
    elif result.exit_code == 1:
        state.warn(_gate_line(result, fail_on), hang=13)


# ── diff ──────────────────────────────────────────────────────────────


@cli.command(epilog=_DIFF_EPILOG, short_help="Compare two JSON reports.")
@click.argument("baseline", type=click.Path(exists=True, dir_okay=False))
@click.argument("current", type=click.Path(exists=True, dir_okay=False))
@click.option(
    "--format",
    "-f",
    "output_format",
    default=None,
    type=click.Choice(["json", "markdown", "text"]),
    help="Output format. Default: text on a terminal, else json.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(readable=False),
    default=None,
    help="Write the diff to this file instead of stdout. - means stdout.",
)
@click.option(
    "--fail-on-new",
    default=None,
    type=click.Choice(FAIL_ON_CHOICES),
    help="Exit 1 when a threat at or above this severity was added or got worse. "
    "'none' never fails. Default: never fail.",
)
@_global_options
@click.pass_context
def diff(
    ctx: click.Context,
    baseline: str,
    current: str,
    output_format: str | None,
    output_path: str | None,
    fail_on_new: str | None,
) -> None:
    """Compare two ThreatCode JSON reports: what was added, resolved, changed or kept.

    Both files must be reports written by 'threatcode scan -f json'. Threats are matched by id,
    counting duplicates, and a threat whose severity or title changed is reported as changed.
    """
    from threatcode.formatters.diff import compute_diff, format_diff, gating_threats

    state = _state(ctx)
    output_path = _output_target(output_path)
    _check_output_path(output_path)
    result = compute_diff(baseline, current)
    chosen = output_format or ("text" if _stdout_is_tty() and output_path is None else "json")
    write_output(output_path, format_diff(result, chosen), label="Diff", quiet=state.quiet)

    summary = _diff_summary(result)
    state.info(summary)
    if fail_on_new is not None and fail_on_new != "none":
        offenders = gating_threats(result, fail_on_new)
        if offenders:
            state.warn(
                f"{plural(len(offenders), 'threat')} added or worsened at or above "
                f"{fail_on_new}, exiting 1"
            )
            ctx.exit(1)
    ctx.exit(0)


def _diff_summary(result: dict[str, Any]) -> str:
    added = result["added"]
    counts: dict[str, int] = {}
    for threat in added:
        sev = str(threat.get("effective_severity") or threat.get("severity"))
        counts[sev] = counts.get(sev, 0) + 1
    detail = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_CHOICES if counts.get(s))
    detail = f" ({detail})" if detail else ""
    return (
        f"{plural(len(added), 'new threat')}{detail}, "
        f"{len(result['removed'])} resolved, {len(result['changed'])} changed."
    )


# ── Removed commands ──────────────────────────────────────────────────

# The 0.9 commands that no longer exist, and what replaces each. They are registered hidden so
# that a script or a habit gets a pointer to the migration page instead of "No such command".
_REMOVED_COMMANDS: dict[str, str] = {
    "fs": "use 'threatcode scan DIR', which reads every supported file under DIR into one graph",
    "repo": "clone the repository, then use 'threatcode scan DIR'",
    "image": (
        "run Trivy or Grype on the image and pass its JSON to 'threatcode scan DIR --ingest FILE'"
    ),
    "vuln": (
        "run OSV-Scanner, Grype or Trivy and pass its JSON to 'threatcode scan DIR --ingest FILE'"
    ),
    "db": "there is no vulnerability database any more; pass scanner results to --ingest",
    "secret": (
        "'threatcode scan DIR' runs the secret detectors over the files it models; for a "
        "whole-repository secret scan, run Gitleaks and pass its SARIF to --ingest"
    ),
    "sbom": "use Syft or Trivy",
    "license": "use Syft or Trivy",
}


class _RemovedCommandError(click.UsageError):
    """A removed command was run: one ``Error:`` line, exit 2, like every other usage error."""

    def show(self, file: Any = None) -> None:  # noqa: ARG002 - click's signature
        echo_err(f"Error: {self.message}")


class _RemovedCommand(click.Command):
    """A command that no longer exists, kept so that it can say what replaced it.

    It fails while the command line is parsed, whatever follows its name, so a tool that only
    parses a command line (the check of the documentation's examples) refuses it too.
    """

    def __init__(self, name: str, replacement: str) -> None:
        super().__init__(
            name,
            hidden=True,
            add_help_option=False,
            context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
            params=[click.Argument(["arguments"], nargs=-1, type=click.UNPROCESSED)],
        )
        self.message = (
            f"'threatcode {name}' was removed in 1.0: {replacement}. See docs/migrating.md"
        )

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:  # noqa: ARG002
        raise _RemovedCommandError(self.message, ctx=ctx)


for _name, _replacement in _REMOVED_COMMANDS.items():
    cli.add_command(_RemovedCommand(_name, _replacement))
