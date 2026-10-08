"""Click CLI for ThreatCode: ``threatcode scan`` and ``threatcode diff``.

The CLI parses options, calls ``threatcode.pipeline.run_scan`` and renders the result.
It owns everything a person sees: the report on stdout or in a file, and the messages on stderr.
Errors and coverage gaps are always printed on stderr, even with ``--quiet``, because a scan that
looks clean while part of the input was not analysed is worse than a failed scan.
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import click

from threatcode import __version__
from threatcode.exceptions import ThreatCodeError, UsageError
from threatcode.formatters import RenderOptions, format_names, render, write_text_file
from threatcode.formatters._utils import set_aside_phrase, terminal_safe
from threatcode.formatters.terminal_coverage import (
    error_text,
    gap_lines,
    gap_summary,
    unique_gaps,
)
from threatcode.formatters.terminal_layout import hanging
from threatcode.formatters.text import plural, terminal_width
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

\b
Environment:
  THREATCODE_FAIL_ON, THREATCODE_MIN_SEVERITY, THREATCODE_FORMAT, THREATCODE_LLM
                         defaults below the flags and above a config file
  THREATCODE_DEBUG=1     show tracebacks for unexpected errors
  THREATCODE_MAX_NODES, THREATCODE_MAX_EDGES   graph size limits
  ANTHROPIC_API_KEY      read only when the LLM is requested with --llm
  SOURCE_DATE_EPOCH      fixed report timestamp for reproducible output
  NO_COLOR               plain text output
  CI                     skips the home directory when looking for a config file
"""

_SCAN_EPILOG = """\b
Examples:
  threatcode scan infra/                       a directory: one graph across every file
  threatcode scan a.tf b.yaml k8s/             several files and directories
  terraform show -json tfplan | threatcode scan - --stdin-name plan.json
  threatcode scan infra/ --fail-on critical --min-severity medium -f markdown
  threatcode scan infra/ --write-baseline .threatcode-baseline.json
  threatcode scan infra/ --baseline .threatcode-baseline.json

\b
Exit codes:
  0  clean            nothing at or above --fail-on (default: high)
  1  findings         a finding or attack path at or above --fail-on survived
                      suppressions and the baseline (LLM findings never count)
  2  usage or input   unreadable path, file that failed to parse, nothing to scan,
                      bad option, or --strict with any coverage gap

\b
Environment:
  THREATCODE_FAIL_ON, THREATCODE_MIN_SEVERITY, THREATCODE_FORMAT, THREATCODE_LLM,
  ANTHROPIC_API_KEY (with --llm), SOURCE_DATE_EPOCH, NO_COLOR, CI
"""

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
"""


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


def _wrap_for_terminal(message: str, hang: int) -> str:
    """``message`` wrapped at the terminal width, continuation lines ``hang`` spaces further in."""
    width = terminal_width()
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


def _configure_logging(ctx: click.Context, verbose: int, quiet: bool, debug: bool) -> None:
    """Send ThreatCode's log records to stderr, once per invocation, at the requested level."""
    if debug or verbose >= 2:
        level = logging.DEBUG
    elif verbose == 1:
        level = logging.INFO
    elif quiet:
        level = logging.ERROR
    else:
        level = logging.WARNING
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_SafeFormatter("%(levelname)s: %(message)s"))
    target = logging.getLogger("threatcode")
    previous = target.level
    target.addHandler(handler)
    target.setLevel(level)

    def restore() -> None:
        target.removeHandler(handler)
        target.setLevel(previous)

    ctx.call_on_close(restore)


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
    The options above go before the command: threatcode -q scan infra/.
    """
    ctx.obj = CliState(quiet=quiet, verbose=verbose, debug=debug, color=not no_color)
    _configure_logging(ctx, verbose, quiet, debug)


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


def _default_format(output_path: str | None) -> str:
    return "text" if _stdout_is_tty() and output_path is None else "json"


def _use_color(state: CliState, output_path: str | None) -> bool:
    return (
        state.color and output_path is None and _stdout_is_tty() and not os.environ.get("NO_COLOR")
    )


def _first_line(text: str) -> str:
    return text.splitlines()[0] if text else text


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
    type=click.Choice(format_names()),
    help="Output format. Default: the config's output_format, else text on a terminal, else json.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(),
    default=None,
    help="Write the report to this file instead of stdout.",
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
@click.option("--max-nodes", type=click.IntRange(min=1), default=None, help="Graph node limit.")
@click.option("--max-edges", type=click.IntRange(min=1), default=None, help="Graph edge limit.")
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
    if chosen == "diagram" and output_path is None and _stdout_is_tty():
        raise UsageError("diagram output is SVG; pass -o file.svg instead of printing it")
    _check_output_path(output_path)
    _check_output_path(write_baseline)
    _announce_config(prepared.config, state)
    _announce_llm(settings, state)

    result = run_scan(prepared.request)
    # A parser that meets one cause twice reports it twice; the count and the listing are of causes
    result.coverage.gaps[:] = unique_gaps(result.coverage.gaps)

    options = RenderOptions(color=_use_color(state, output_path), include_graph=include_graph)
    text = render(chosen, result.analysis, options)
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
    if coverage.errors:
        extras.append(f"incomplete: {plural(len(coverage.errors), 'input error')}")
    return f" ({', '.join(extras)})" if extras else ""


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
    type=click.Path(),
    default=None,
    help="Write the diff to this file instead of stdout.",
)
@click.option(
    "--fail-on-new",
    default=None,
    type=click.Choice(SEVERITY_CHOICES),
    metavar="SEVERITY",
    help="Exit 1 when a threat at or above SEVERITY was added or got worse "
    f"({', '.join(SEVERITY_CHOICES)}).",
)
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
    _check_output_path(output_path)
    result = compute_diff(baseline, current)
    chosen = output_format or ("text" if _stdout_is_tty() and output_path is None else "json")
    write_output(output_path, format_diff(result, chosen), label="Diff", quiet=state.quiet)

    summary = _diff_summary(result)
    state.info(summary)
    if fail_on_new is not None:
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
