"""The scan pipeline: the one orchestration path of the CLI, the Python API and the Action.

``run_scan(request)`` turns a ``ScanRequest`` into a ``ScanResult``:

1. discovery: files, directories and standard input become units (``threatcode.discovery``);
2. parse every unit, collecting errors and diagnostics without stopping at one bad file;
3. one graph across all units (``InfraGraph.from_units``), so edges can cross files;
4. secret findings (``engine.secrets.iac.find_secrets``) and ingested scanner findings
   (``ingest.load_and_attach``) go into an ``AnalysisContext``;
5. ``HybridEngine.analyze`` runs the rules, boundaries, severity, paths and, only when asked for,
   the LLM phase;
6. root-relative locations, fingerprints and a deterministic order;
7. suppressions, then the baseline, then the gate, then the ``--min-severity`` display filter;
8. the exit code.

The pipeline never prints.
Everything a person should see (input errors, coverage gaps, notices) is in the result, and the CLI
renders it.

Exit contract (``compute_exit_code``), in order of precedence:

* 2: a usage or input error occurred: an unreadable path, a file a parser claimed but could not
  parse, an unreadable or unrecognized ingest file, nothing to model (no supported files, or zero
  resources overall), or ``--strict`` with any coverage gap;
* 1: a non-LLM finding or attack path whose effective severity (the base severity when there is no
  effective one) is at or above ``--fail-on`` survives suppressions and the baseline;
* 0: otherwise.

LLM findings are advisory and never gate.
With ``--write-baseline`` the exit is 0 unless an input error occurred.
"""

from __future__ import annotations

import contextlib
import dataclasses
import logging
import os
import sys
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any

from threatcode.config import (
    FAIL_ON_CHOICES,
    SEVERITY_CHOICES,
    LoadedConfig,
    ResolvedSettings,
    discover_config,
    resolve_settings,
)
from threatcode.diagnostics import Diagnostic
from threatcode.discovery import (
    HCL_MODULE,
    STDIN_PATH,
    Discovery,
    ScanUnit,
    discover,
    scan_root,
)
from threatcode.exceptions import ParseError, ThreatCodeError, UnsupportedFormatError, UsageError
from threatcode.fingerprint import assign_fingerprints
from threatcode.ir.addressing import split_location
from threatcode.models.analysis import AnalysisResult
from threatcode.models.report import (
    Coverage,
    ThreatReport,
    current_timestamp,
    threat_severity,
)
from threatcode.models.threat import Severity, Threat, ThreatSource

if TYPE_CHECKING:
    from threatcode.engine.llm.client import BaseLLMClient
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.attack_path import AttackPath
    from threatcode.parsers.base import ParsedOutput

logger = logging.getLogger(__name__)

__all__ = [
    "EXIT_FINDINGS",
    "EXIT_OK",
    "EXIT_USAGE",
    "PreparedScan",
    "ScanRequest",
    "ScanResult",
    "compute_exit_code",
    "prepare_request",
    "run_scan",
]

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2

_MAX_STDIN_BYTES = 50 * 1024 * 1024


@dataclass(frozen=True)
class ScanRequest:
    """Everything one scan needs: the paths and the resolved settings.

    ``paths`` are file or directory paths, or ``-`` for standard input.
    ``root`` overrides the scan root (the common parent of the paths) for the whole scan.
    """

    paths: tuple[str, ...]
    settings: ResolvedSettings = field(default_factory=ResolvedSettings)
    strict: bool = False
    ignore_file: Path | None = None
    no_ignore: bool = False
    baseline: Path | None = None
    write_baseline: Path | None = None
    ingest: tuple[Path, ...] = ()
    stdin_name: str | None = None
    no_timestamp: bool = False
    root: Path | None = None


@dataclass
class ScanResult:
    """The outcome of ``run_scan``.

    ``coverage`` is the same object as ``analysis.report.coverage``.
    ``notices`` are warnings for the user about suppressions and baselines, one line each.
    """

    analysis: AnalysisResult
    exit_code: int
    coverage: Coverage
    root: Path = field(default_factory=Path.cwd)
    notices: list[str] = field(default_factory=list)
    # The ignore file that was used and how many of its entries are active.
    ignore_file: Path | None = None
    ignore_entries: int = 0
    # The baseline file written by --write-baseline, when one was.
    baseline_written: Path | None = None
    # One mapping per ingested file, for the report.
    ingest_sources: list[dict[str, Any]] = field(default_factory=list)

    @property
    def report(self) -> ThreatReport:
        return self.analysis.report

    @property
    def graph(self) -> InfraGraph:
        return self.analysis.graph

    def to_dict(self) -> dict[str, Any]:
        """The report as a dict, exactly what ``--format json`` prints."""
        return self.report.to_dict()


@dataclass(frozen=True)
class PreparedScan:
    """A request plus the config it was resolved from, so the caller can announce the config."""

    request: ScanRequest
    config: LoadedConfig


def prepare_request(
    paths: Sequence[str | os.PathLike[str]],
    *,
    config_path: str | os.PathLike[str] | None = None,
    fail_on: str | None = None,
    min_severity: str | None = None,
    output_format: str | None = None,
    llm: bool | None = None,
    dry_run: bool = False,
    dry_run_output: str | None = None,
    extra_rule_paths: Iterable[str | os.PathLike[str]] = (),
    strict: bool = False,
    ignore_file: str | os.PathLike[str] | None = None,
    no_ignore: bool = False,
    baseline: str | os.PathLike[str] | None = None,
    write_baseline: str | os.PathLike[str] | None = None,
    ingest: Iterable[str | os.PathLike[str]] = (),
    stdin_name: str | None = None,
    no_timestamp: bool = False,
    max_nodes: int | None = None,
    max_edges: int | None = None,
    env: Mapping[str, str] | None = None,
) -> PreparedScan:
    """Resolve options, environment and config into a ``ScanRequest``.

    Every option is ``None`` (or false) when not given, which lets the environment and the config
    file supply it.
    The CLI and the Python API both come through here, so they cannot disagree.

    Raises:
        UsageError: No path, an invalid option value or contradictory options.
        ConfigError: The config file or an environment variable is invalid.
    """
    named = tuple(os.fspath(p) for p in paths)
    if not named:
        raise UsageError("no input: name at least one file or directory, or - for standard input")
    if ignore_file is not None and no_ignore:
        raise UsageError("--ignore-file and --no-ignore contradict each other")
    if fail_on is not None and fail_on not in FAIL_ON_CHOICES:
        raise UsageError(f"fail_on must be one of {', '.join(FAIL_ON_CHOICES)}, got '{fail_on}'")
    if min_severity is not None and min_severity not in SEVERITY_CHOICES:
        raise UsageError(
            f"min_severity must be one of {', '.join(SEVERITY_CHOICES)}, got '{min_severity}'"
        )
    if output_format is not None:
        from threatcode.formatters import get_formatter

        get_formatter(output_format)

    root = scan_root(named)
    loaded = discover_config(
        Path(config_path) if config_path is not None else None,
        search_dirs=[root, Path.cwd()],
    )
    settings = resolve_settings(
        {
            "fail_on": fail_on,
            "min_severity": min_severity,
            "output_format": output_format,
            "llm": llm,
            "dry_run": dry_run,
            "dry_run_output": dry_run_output,
            "rules": [os.fspath(p) for p in extra_rule_paths],
            "max_nodes": max_nodes,
            "max_edges": max_edges,
        },
        loaded,
        env,
    )
    request = ScanRequest(
        paths=named,
        settings=settings,
        strict=strict,
        ignore_file=Path(ignore_file) if ignore_file is not None else None,
        no_ignore=no_ignore,
        baseline=Path(baseline) if baseline is not None else None,
        write_baseline=Path(write_baseline) if write_baseline is not None else None,
        ingest=tuple(Path(p) for p in ingest),
        stdin_name=stdin_name,
        no_timestamp=no_timestamp,
        root=root,
    )
    return PreparedScan(request=request, config=loaded)


# ── Exit code ─────────────────────────────────────────────────────────


def compute_exit_code(
    *,
    errors: Sequence[Mapping[str, str]],
    strict: bool,
    coverage: Coverage,
    threats: Iterable[Threat],
    attack_paths: Iterable[AttackPath],
    fail_on: str,
    write_baseline: bool = False,
) -> int:
    """The exit code of a scan: 2 for an input error, else 1 for a gating finding, else 0.

    ``threats`` and ``attack_paths`` are what is left after suppressions and the baseline.
    LLM findings never gate.
    """
    if errors:
        return EXIT_USAGE
    if strict and coverage.has_gaps:
        return EXIT_USAGE
    if write_baseline or fail_on == "none":
        return EXIT_OK
    threshold = Severity(fail_on)
    for threat in threats:
        if threat.source is not ThreatSource.LLM and threat_severity(threat) >= threshold:
            return EXIT_FINDINGS
    for path in attack_paths:
        if path.severity >= threshold:
            return EXIT_FINDINGS
    return EXIT_OK


# ── The pipeline ──────────────────────────────────────────────────────


def run_scan(request: ScanRequest) -> ScanResult:
    """Run one scan end to end. The pipeline never prints and never exits.

    Raises:
        UsageError: A named path does not exist, standard input is unusable or an ingest file is
            rejected.
        ConfigError: The ignore file or the baseline cannot be used.
        ThreatCodeError: The graph limits are exceeded or a rule file is invalid.
    """
    from threatcode import suppressions
    from threatcode.engine.context import AnalysisContext
    from threatcode.engine.hybrid import HybridEngine
    from threatcode.engine.secrets.iac import find_secrets
    from threatcode.ir.graph import InfraGraph

    settings = request.settings
    baseline_fingerprints = (
        suppressions.load_baseline(request.baseline) if request.baseline is not None else None
    )

    with contextlib.ExitStack() as stack:
        stdin_path: Path | None = None
        stdin_name = ""
        if STDIN_PATH in request.paths:
            tmp = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="threatcode-stdin-")))
            stdin_name, stdin_path = _save_stdin(request.stdin_name, tmp)

        root = request.root or scan_root(request.paths)
        discovery = discover(request.paths, root=root, stdin_path=stdin_path, stdin_name=stdin_name)
        coverage = _start_coverage(discovery)
        errors: list[dict[str, str]] = list(discovery.errors)
        for relpath in discovery.oversized:
            coverage.note_not_iac(relpath)

        _parse_units(discovery, root, coverage, errors)
        outputs = [unit.parsed for unit in discovery.units if unit.parsed is not None]
        coverage.units_parsed = len(outputs)
        if not outputs and not errors:
            errors.append(_nothing_to_model(coverage))

        graph = InfraGraph.from_units(
            outputs,
            max_nodes=settings.max_nodes,
            max_edges=settings.max_edges,
            strict_edges=settings.strict_edges,
        )
        if outputs and graph.node_count == 0 and not errors:
            errors.append(
                {
                    "file": ".",
                    "code": "parse.zero_resources",
                    "message": f"{len(outputs)} input(s) were parsed but produced no resources "
                    "to model, so there is nothing to scan",
                }
            )

        secret_findings = find_secrets(discovery.units, graph)
        external, sources = _ingest(request, graph, root)

        label = _input_label(request, discovery, stdin_name)
        client = _build_client(settings, graph)
        engine = HybridEngine(
            config=settings.config,
            extra_rule_paths=list(settings.extra_rule_paths),
            llm_client=client,
        )
        context = AnalysisContext(
            input_label=label, secret_findings=secret_findings, external_findings=external
        )
        report = engine.analyze(graph, input_file=label, context=context)

        return _finish(
            request,
            discovery=discovery,
            graph=graph,
            report=report,
            coverage=coverage,
            errors=errors,
            sources=sources,
            baseline_fingerprints=baseline_fingerprints,
            stdin_dir=stdin_path.parent if stdin_path else None,
            stdin_name=stdin_name,
        )


def _start_coverage(discovery: Discovery) -> Coverage:
    return Coverage(
        files_discovered=discovery.files_discovered,
        symlinks_skipped=discovery.symlinks_skipped,
        special_files_skipped=discovery.special_skipped,
    )


def _nothing_to_model(coverage: Coverage) -> dict[str, str]:
    skipped = coverage.not_iac_count
    detail = f" ({skipped} candidate file(s) were not infrastructure)" if skipped else ""
    return {
        "file": ".",
        "code": "discovery.nothing_to_model",
        "message": f"no supported infrastructure files found{detail}; supported inputs are "
        "Terraform, CloudFormation, Kubernetes, Helm, Dockerfile and MCP configs",
    }


def _save_stdin(name: str | None, directory: Path) -> tuple[str, Path]:
    """Read standard input into ``directory`` under a name the format detection can use."""
    stream = sys.stdin
    buffer = getattr(stream, "buffer", None)
    raw: bytes
    if buffer is not None:
        raw = buffer.read(_MAX_STDIN_BYTES + 1)
    else:
        raw = stream.read().encode("utf-8")
    if len(raw) > _MAX_STDIN_BYTES:
        raise UsageError(f"standard input is larger than {_MAX_STDIN_BYTES // (1024 * 1024)} MB")
    if not raw.strip():
        raise UsageError(
            "standard input is empty; pipe a plan or manifest into 'threatcode scan -'"
        )
    if name is None:
        name = "stdin.json" if raw.lstrip()[:1] in (b"{", b"[") else "stdin.yaml"
    if not name or name in (".", "..") or "/" in name or "\\" in name or os.path.isabs(name):
        raise UsageError(
            f"--stdin-name must be a plain file name such as main.tf or Dockerfile, got '{name}'"
        )
    target = directory / name
    target.write_bytes(raw)
    return name, target


def _input_label(request: ScanRequest, discovery: Discovery, stdin_name: str) -> str:
    """The inputs as the report names them: root-relative POSIX, sorted, comma separated."""
    labels: list[str] = []
    for raw in request.paths:
        if raw == STDIN_PATH:
            labels.append(stdin_name)
        else:
            labels.append(Path(os.path.relpath(os.path.abspath(raw), discovery.root)).as_posix())
    return ", ".join(sorted(set(labels)))


# ── Parsing ───────────────────────────────────────────────────────────


def _parse_units(
    discovery: Discovery, root: Path, coverage: Coverage, errors: list[dict[str, str]]
) -> None:
    """Parse every unit, setting ``unit.parsed``. A bad file is recorded and skipped.

    A Terraform plan in the same directory as a module replaces the module: the plan is the
    resolved truth and the ``.tf`` files would model the same resources twice.
    """
    units = discovery.units
    for unit in units:
        if unit.kind != HCL_MODULE:
            unit.parsed = _parse_unit(unit, root, coverage, errors)
    plans: dict[Path, ScanUnit] = {
        unit.path.parent: unit
        for unit in units
        if unit.parsed is not None and unit.parsed.format_type == "terraform_plan"
    }
    for unit in units:
        if unit.kind != HCL_MODULE:
            continue
        plan = plans.get(unit.path)
        if plan is not None and plan.parsed is not None:
            plan.parsed.diagnostics.append(
                Diagnostic(
                    "info",
                    "graph.unit_superseded",
                    f"Terraform module {unit.relpath} is replaced by the plan {plan.relpath} in "
                    "the same directory; its .tf files were not read",
                    file=unit.relpath,
                )
            )
            continue
        unit.parsed = _parse_unit(unit, root, coverage, errors)


def _parse_unit(
    unit: ScanUnit, root: Path, coverage: Coverage, errors: list[dict[str, str]]
) -> ParsedOutput | None:
    from threatcode.parsers import detect_and_parse

    try:
        parsed = detect_and_parse(unit.path)
    except UnsupportedFormatError as exc:
        # Nothing claimed the file: for a file found by walking, that is "not infrastructure".
        if unit.explicit or unit.kind == HCL_MODULE:
            errors.append(_parse_error(unit, exc))
        else:
            coverage.note_not_iac(unit.relpath)
        return None
    except ParseError as exc:
        # A generic JSON or YAML file that cannot even be read as text was never claimed.
        if not (unit.explicit or unit.by_name) and not _readable_text(unit.path):
            coverage.note_not_iac(unit.relpath)
        else:
            errors.append(_parse_error(unit, exc))
        return None
    except (ThreatCodeError, OSError) as exc:
        errors.append(_parse_error(unit, exc))
        return None
    except Exception as exc:
        # A parser bug must not look like a clean file.
        logger.debug("Unexpected failure parsing %s", unit.relpath, exc_info=True)
        errors.append(_parse_error(unit, exc, unexpected=True))
        return None
    return _localize_parsed(parsed, unit, root)


def _readable_text(path: Path) -> bool:
    from threatcode.parsers._text import decode_input

    try:
        decode_input(path)
    except (ParseError, OSError):
        return False
    return True


def _parse_error(unit: ScanUnit, exc: BaseException, *, unexpected: bool = False) -> dict[str, str]:
    message = f"{type(exc).__name__}: {exc}" if unexpected else str(exc)
    return {"file": unit.relpath, "code": "parse.failed", "message": message}


# ── Root-relative paths ───────────────────────────────────────────────


def _map_path(value: str, unit: ScanUnit, root: Path) -> str:
    """Rewrite one absolute path a parser reported to a root-relative POSIX path."""
    if not value or not os.path.isabs(value):
        return value
    path = Path(value)
    try:
        sub = path.relative_to(unit.base_dir)
    except ValueError:
        try:
            return Path(os.path.relpath(value, root)).as_posix() if _under(path, root) else value
        except ValueError:
            return value
    if str(sub) == ".":
        return unit.base_rel.as_posix()
    return (unit.base_rel / PurePosixPath(sub.as_posix())).as_posix()


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _map_location(value: str, unit: ScanUnit, root: Path) -> str:
    """Like ``_map_path`` for a ``path`` or legacy ``path:line`` location."""
    file_part, line = split_location(value)
    mapped = _map_path(file_part, unit, root)
    if mapped == file_part:
        return value
    return f"{mapped}:{line}" if line is not None else mapped


def _localize_parsed(parsed: ParsedOutput, unit: ScanUnit, root: Path) -> ParsedOutput:
    """Make every path in a parse output root-relative POSIX, in place.

    The graph qualifies colliding addresses with ``source_path`` and every report location comes
    from ``source_location``, so absolute paths must never get past this point.
    """
    parsed.source_path = unit.relpath
    for resource in parsed.resources:
        resource.source_location = _map_location(resource.source_location, unit, root)
    parsed.diagnostics = [
        dataclasses.replace(d, file=_map_path(d.file, unit, root)) if d.file else d
        for d in parsed.diagnostics
    ]
    return parsed


# ── Analysis helpers ──────────────────────────────────────────────────


def _ingest(
    request: ScanRequest, graph: InfraGraph, root: Path
) -> tuple[list[Threat], list[dict[str, Any]]]:
    if not request.ingest:
        return [], []
    from threatcode import ingest

    result = ingest.load_and_attach(list(request.ingest), graph, root)
    graph.diagnostics.extend(result.diagnostics)
    return list(result.threats), list(result.sources)


def _build_client(settings: ResolvedSettings, graph: InfraGraph) -> BaseLLMClient | None:
    """The LLM client, built only when the LLM was requested and there is something to send."""
    if not settings.use_llm or graph.node_count == 0:
        return None
    from threatcode.engine.llm import factory

    return factory.build_client(settings)


def _finish(
    request: ScanRequest,
    *,
    discovery: Discovery,
    graph: InfraGraph,
    report: ThreatReport,
    coverage: Coverage,
    errors: list[dict[str, str]],
    sources: list[dict[str, Any]],
    baseline_fingerprints: frozenset[str] | None,
    stdin_dir: Path | None,
    stdin_name: str,
) -> ScanResult:
    from threatcode import suppressions

    settings = request.settings
    root = discovery.root

    _localize_threats(report.threats, graph, root, stdin_dir, stdin_name)
    assign_fingerprints(report.threats, graph)
    report.threats.sort(key=_threat_order)
    report.timestamp = "" if request.no_timestamp else current_timestamp()

    notices: list[str] = []
    ignore = suppressions.load(request.ignore_file, root, no_ignore=request.no_ignore)
    outcome = suppressions.apply(report.threats, ignore)
    report.threats = outcome.kept
    notices.extend(outcome.notices)
    coverage.suppressed = len(outcome.suppressed)

    snapshot = list(report.threats)
    baselined: list[Threat] = []
    if baseline_fingerprints is not None:
        report.threats, baselined = suppressions.apply_baseline(
            report.threats, baseline_fingerprints
        )
    coverage.baselined = len(baselined)

    coverage.errors = [dict(e) for e in errors]
    coverage.gaps = [d.to_dict() for d in graph.diagnostics if d.level in ("warning", "error")]
    coverage.rule_errors = len(report.rule_errors)

    exit_code = compute_exit_code(
        errors=errors,
        strict=request.strict,
        coverage=coverage,
        threats=report.threats,
        attack_paths=report.attack_paths,
        fail_on=settings.fail_on,
        write_baseline=request.write_baseline is not None,
    )

    baseline_written: Path | None = None
    if request.write_baseline is not None:
        if errors:
            notices.append(
                f"baseline {request.write_baseline} was not written because the scan had "
                "input errors; a baseline of a partial scan would hide findings later"
            )
        else:
            baseline_written = suppressions.write_baseline(request.write_baseline, snapshot)

    _apply_display_filter(report, settings.min_severity)
    report.coverage = coverage
    analysis = AnalysisResult(graph=graph, report=report)
    return ScanResult(
        analysis=analysis,
        exit_code=exit_code,
        coverage=coverage,
        root=root,
        notices=notices,
        ignore_file=ignore.path if ignore is not None else None,
        ignore_entries=sum(1 for e in ignore.entries if not e.expired) if ignore else 0,
        baseline_written=baseline_written,
        ingest_sources=sources,
    )


def _threat_order(threat: Threat) -> tuple[int, str, str, str]:
    return (-threat_severity(threat).rank, threat.resource_address, threat.rule_id, threat.id)


def _localize_threats(
    threats: Iterable[Threat],
    graph: InfraGraph,
    root: Path,
    stdin_dir: Path | None,
    stdin_name: str,
) -> None:
    """Give every finding a root-relative POSIX location, from the node it sits on when unset."""
    for threat in threats:
        if threat.location_file:
            threat.location_file = _relative_to_root(
                threat.location_file, root, stdin_dir, stdin_name
            )
            continue
        node = graph.get_node(threat.resource_address)
        if node is not None and node.source_file:
            threat.location_file = node.source_file
            threat.location_start_line = node.start_line
            threat.location_end_line = node.end_line


def _relative_to_root(value: str, root: Path, stdin_dir: Path | None, stdin_name: str) -> str:
    if not os.path.isabs(value):
        return value.replace("\\", "/")
    path = Path(value)
    if stdin_dir is not None and _under(path, stdin_dir):
        return stdin_name
    if _under(path, root):
        return Path(os.path.relpath(value, root)).as_posix()
    return value


def _apply_display_filter(report: ThreatReport, min_severity: str) -> None:
    """Hide findings and paths below ``min_severity``; the gate already ran on the full set."""
    if min_severity == "info":
        return
    threshold = Severity(min_severity)
    report.threats = report.filter_by_severity(threshold)
    report.attack_paths = [p for p in report.attack_paths if p.severity >= threshold]
