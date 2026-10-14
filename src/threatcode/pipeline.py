"""The scan pipeline: the one orchestration path of the CLI, the Python API and the Action.

``run_scan(request)`` turns a ``ScanRequest`` into a ``ScanResult``:

1. discovery: files, directories and standard input become units (``threatcode.discovery``);
2. parse every unit, collecting errors and diagnostics without stopping at one bad file;
3. one graph across all units (``InfraGraph.from_units``), so edges can cross files;
4. secret findings (``engine.secrets.iac.find_secrets``) and ingested scanner findings
   (``ingest.load_and_attach``) go into an ``AnalysisContext``;
5. ``HybridEngine.analyze`` runs the rules, boundaries, severity, paths and, only when asked for,
   the LLM phase;
6. root-relative locations, scanner findings that ThreatCode's own finding at the same file and
   line already reports dropped (``ingest.reconcile_native``), fingerprints and a deterministic
   order;
7. suppressions, then the baseline (both cover findings and attack paths), then the gate, then the
   ``--min-severity`` display filter;
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

from threatcode._paths import ReportPaths
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
from threatcode.formatters._utils import display_path, plural
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
    from threatcode.ir.nodes import InfraNode
    from threatcode.models.attack_path import AttackPath
    from threatcode.parsers.base import ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)

__all__ = [
    "EXIT_FINDINGS",
    "EXIT_OK",
    "EXIT_USAGE",
    "PreparedScan",
    "ScanRequest",
    "ScanResult",
    "compute_exit_code",
    "gating",
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
    # Attack paths set aside; ``coverage.suppressed`` and ``coverage.baselined`` already count them.
    suppressed_paths: int = 0
    baselined_paths: int = 0
    # What --fail-on counted, before --min-severity hid anything: the findings and attack paths at
    # or above the threshold. Exit code 1 means at least one of them is not zero.
    gate_findings: int = 0
    gate_paths: int = 0
    # One mapping per ingested file, for the report.
    ingest_sources: list[dict[str, Any]] = field(default_factory=list)

    @property
    def report(self) -> ThreatReport:
        return self.analysis.report

    @property
    def graph(self) -> InfraGraph:
        return self.analysis.graph

    def to_dict(self) -> dict[str, Any]:
        """The report as a dict, exactly what ``--format json`` prints.

        When scanner results were ingested the document also lists them under ``ingest``.
        """
        data = self.report.to_dict()
        if self.ingest_sources:
            data["ingest"] = [dict(source) for source in self.ingest_sources]
        return data


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
    if stdin_name is not None and STDIN_PATH not in named:
        raise UsageError("--stdin-name only applies when reading standard input (-)")
    if dry_run_output is not None and not dry_run:
        raise UsageError("--dry-run-output only applies together with --dry-run")
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
    if write_baseline:
        return EXIT_OK
    findings, paths = gating(threats, attack_paths, fail_on)
    return EXIT_FINDINGS if findings or paths else EXIT_OK


def gating(
    threats: Iterable[Threat], attack_paths: Iterable[AttackPath], fail_on: str
) -> tuple[int, int]:
    """How many findings and attack paths are at or above ``fail_on``: what the gate counts.

    LLM findings are advisory and never count; ``none`` counts nothing.
    """
    if fail_on == "none":
        return 0, 0
    threshold = Severity(fail_on)
    findings = sum(
        1
        for threat in threats
        if threat.source is not ThreatSource.LLM and threat_severity(threat) >= threshold
    )
    return findings, sum(1 for path in attack_paths if path.severity >= threshold)


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

        label = _input_label(request, stdin_name, root)
        covered = _parse_units(discovery, coverage, errors, label)
        # A module directory read through the call that uses it is in the graph once, as that
        # call; its files are still scanned for secrets, so its parse output is kept on the unit
        outputs = [
            unit.parsed
            for unit in discovery.units
            if unit.parsed is not None and unit.relpath not in covered
        ]
        coverage.units_parsed = len(outputs)
        if not outputs and not errors:
            errors.append(_nothing_to_model(coverage, label))

        graph = InfraGraph.from_units(
            outputs,
            max_nodes=settings.max_nodes,
            max_edges=settings.max_edges,
            strict_edges=settings.strict_edges,
        )
        if outputs and graph.node_count == 0 and not errors:
            errors.append(
                {
                    "file": label,
                    "code": "parse.zero_resources",
                    "message": f"{plural(len(outputs), 'input')} "
                    f"{'was' if len(outputs) == 1 else 'were'} parsed but produced no "
                    "resources to model, so there is nothing to scan",
                }
            )

        secret_findings = find_secrets(discovery.units, graph)
        external, sources = _ingest(request, graph, root)

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
        report.input_paths = _input_paths(request, discovery, stdin_name)

        return _finish(
            request,
            discovery=discovery,
            graph=graph,
            report=report,
            coverage=coverage,
            errors=errors,
            sources=sources,
            external=external,
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


def _nothing_to_model(coverage: Coverage, label: str) -> dict[str, str]:
    skipped = coverage.not_iac_count
    detail = f" ({skipped} candidate file(s) were not infrastructure)" if skipped else ""
    return {
        "file": label,
        "code": "discovery.nothing_to_model",
        "message": f"no supported infrastructure files found{detail}; supported inputs are "
        "Terraform, CloudFormation, Kubernetes, Helm, Dockerfile and MCP configs",
    }


def _save_stdin(name: str | None, directory: Path) -> tuple[str, Path]:
    """Read standard input into ``directory`` under a name the format detection can use."""
    stream = sys.stdin
    buffer = getattr(stream, "buffer", None)
    raw: bytes = (
        buffer.read(_MAX_STDIN_BYTES + 1) if buffer is not None else stream.read().encode("utf-8")
    )
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


def _input_label(request: ScanRequest, stdin_name: str, root: Path) -> str:
    """The inputs as the report names them: as typed, never absolute, sorted, comma separated.

    ``scan infra/`` is ``infra`` and ``scan ./deploy/app.yaml`` is ``deploy/app.yaml``, so the
    report says what was scanned and a file keeps the directory it sits in.
    The current directory is named by its directory name, never ``.``.
    """
    labels = [
        stdin_name if raw == STDIN_PATH else display_path(raw, root=root) for raw in request.paths
    ]
    return ", ".join(sorted(set(labels)))


def _input_paths(request: ScanRequest, discovery: Discovery, stdin_name: str) -> list[str]:
    """The inputs relative to the scan root, POSIX, sorted: where SARIF anchors a result."""
    paths: list[str] = []
    for raw in request.paths:
        if raw == STDIN_PATH:
            paths.append(stdin_name)
        else:
            paths.append(discovery.paths.posix(os.path.abspath(raw)))
    return sorted(set(paths))


# ── Parsing ───────────────────────────────────────────────────────────


def _parse_units(
    discovery: Discovery,
    coverage: Coverage,
    errors: list[dict[str, str]],
    label: str = "",
) -> set[str]:
    """Parse every unit, setting ``unit.parsed``. A bad file is recorded and skipped.

    A Terraform plan in the same directory as a module replaces the module: the plan is the
    resolved truth and the ``.tf`` files would model the same resources twice.
    Returns the relative paths of the module directories that another module read through the
    call that uses them; those units keep their parse output, but the graph takes the call.
    """
    units = discovery.units
    for unit in units:
        if unit.kind != HCL_MODULE:
            unit.parsed = _parse_unit(unit, discovery.paths, coverage, errors, label)
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
        unit.parsed = _parse_unit(unit, discovery.paths, coverage, errors, label)
    return _covered_modules(units)


_BlockKey = tuple[str, int | None, str]


def _block(resource: ParsedResource) -> _BlockKey:
    """Which block of which file a resource comes from, whatever module path it was reached by."""
    return (
        split_location(resource.source_location)[0],
        resource.start_line,
        resource.resource_type,
    )


def _module_resources(unit: ScanUnit) -> dict[_BlockKey, set[str]]:
    """The addresses of the resources ``unit`` reached through its module calls, by block."""
    found: dict[_BlockKey, set[str]] = {}
    if unit.parsed is not None:
        for resource in unit.parsed.resources:
            if resource.module:
                found.setdefault(_block(resource), set()).add(resource.address)
    return found


def _is_read_through(resource: ParsedResource, reached: Mapping[_BlockKey, set[str]]) -> bool:
    """Whether the block of ``resource`` was also read through a module call, one level deeper.

    ``aws_s3_bucket.m`` is read through ``module.vpc.aws_s3_bucket.m``, and
    ``module.inner.aws_s3_bucket.m`` through ``module.outer.module.inner.aws_s3_bucket.m``.
    """
    if resource.start_line is None:
        return False
    return any(
        address != resource.address and address.endswith(f".{resource.address}")
        for address in reached.get(_block(resource), ())
    )


def _covered_modules(units: list[ScanUnit]) -> set[str]:
    """The module directories whose every resource another module reads through a call.

    The directory ``modules/vpc`` is a Terraform module of its own, and ``module "vpc"`` in a
    parent reads the same files with the arguments of the call.
    Putting both in the graph gives every resource twice (``aws_s3_bucket.m`` and
    ``module.vpc.aws_s3_bucket.m``) and so every finding.
    The call is the better reading, because it knows what the caller passes in, so a directory
    that the calls of the other modules reach in full is not analysed on its own.
    A directory with a resource no call reaches (a call with ``count = 0``, a call that could
    not be followed) stays, and so does one whose only caller was itself set aside for the same
    reason.
    """
    modules = {u.relpath: u for u in units if u.kind == HCL_MODULE and u.parsed is not None}
    reached = {path: _module_resources(unit) for path, unit in modules.items()}
    kept = set(modules)
    covered: set[str] = set()
    for path in sorted(modules):
        parsed = modules[path].parsed
        if parsed is None or not parsed.resources:
            continue
        others = sorted(c for c in kept if c != path)
        merged: dict[_BlockKey, set[str]] = {}
        for other in others:
            for block, addresses in reached[other].items():
                merged.setdefault(block, set()).update(addresses)
        if not all(_is_read_through(r, merged) for r in parsed.resources):
            continue
        callers = [
            c for c in others if any(_is_read_through(r, reached[c]) for r in parsed.resources)
        ]
        owner = modules[callers[0]].parsed
        if owner is not None:
            owner.diagnostics.append(
                Diagnostic(
                    "info",
                    "graph.unit_superseded",
                    f"Terraform module {path} is read through the module call that uses it in "
                    f"{callers[0]}, so its directory is not analysed on its own",
                    file=path,
                )
            )
        covered.add(path)
        kept.discard(path)
    return covered


def _parse_unit(
    unit: ScanUnit,
    paths: ReportPaths,
    coverage: Coverage,
    errors: list[dict[str, str]],
    label: str = "",
) -> ParsedOutput | None:
    from threatcode.parsers import detect_and_parse, looks_like_infrastructure

    try:
        parsed = detect_and_parse(unit.path)
    except UnsupportedFormatError as exc:
        # Nothing claimed the file. For a file found by walking that is "not infrastructure",
        # unless its name says it should be (Chart.yaml, an MCP config, plan.json) or the start
        # of it reads like a plan, template or manifest, and it is so broken that no parser could
        # have told: then it is an input error, because a truncated plan must never pass as a
        # clean scan.
        if (
            unit.explicit
            or unit.kind == HCL_MODULE
            or (
                (unit.by_name or looks_like_infrastructure(unit.path))
                and not _well_formed(unit.path)
            )
        ):
            errors.append(_parse_error(unit, exc, label))
        else:
            coverage.note_not_iac(unit.relpath)
        return None
    except ParseError as exc:
        # A generic JSON or YAML file that cannot even be read as text was never claimed.
        if not (unit.explicit or unit.by_name) and not _readable_text(unit.path):
            coverage.note_not_iac(unit.relpath)
        else:
            errors.append(_parse_error(unit, exc, label))
        return None
    except (ThreatCodeError, OSError) as exc:
        errors.append(_parse_error(unit, exc, label))
        return None
    except Exception as exc:
        # A parser bug must not look like a clean file.
        logger.debug("Unexpected failure parsing %s", unit.relpath, exc_info=True)
        errors.append(_parse_error(unit, exc, label, unexpected=True))
        return None
    parsed = _localize_parsed(parsed, unit, paths)
    _promote_parse_failures(parsed, errors)
    return parsed


def _promote_parse_failures(parsed: ParsedOutput, errors: list[dict[str, str]]) -> None:
    """Make a file that failed inside a unit an input error, like the same file named alone.

    A Terraform module reads its other files when one cannot be parsed and records the failure
    as an error-level ``parse.failed`` diagnostic.
    The exit contract does not depend on what sits beside a broken file, so each of those is an
    input error (exit 2, "incomplete" in the summary) and is no longer also listed as a gap.
    """
    kept: list[Diagnostic] = []
    for diagnostic in parsed.diagnostics:
        if diagnostic.level == "error" and diagnostic.code == "parse.failed":
            errors.append(
                {"file": diagnostic.file, "code": diagnostic.code, "message": diagnostic.message}
            )
        else:
            kept.append(diagnostic)
    parsed.diagnostics = kept


def _readable_text(path: Path) -> bool:
    from threatcode.parsers._text import decode_input

    try:
        decode_input(path)
    except (ParseError, OSError):
        return False
    return True


def _well_formed(path: Path) -> bool:
    """Whether a JSON or YAML file is readable text with valid syntax."""
    import json

    from threatcode.parsers._text import decode_input

    try:
        text = decode_input(path)
    except (ParseError, OSError):
        return False
    suffix = path.suffix.lower()
    if suffix in (".template", ".cfn"):
        suffix = ".json" if text.lstrip().startswith(("{", "[")) else ".yaml"
    try:
        if suffix == ".json":
            try:
                json.loads(text)
            except json.JSONDecodeError:
                # MCP configs may carry comments and trailing commas (VS Code JSONC).
                from threatcode.parsers.mcp_config import strip_jsonc

                json.loads(strip_jsonc(text))
        elif suffix in (".yml", ".yaml"):
            from threatcode.parsers._yaml import load_yaml_documents

            load_yaml_documents(text, source=path.name)
        else:
            return False
    except (ValueError, ParseError, RecursionError):
        return False
    return True


def _parse_error(
    unit: ScanUnit, exc: BaseException, label: str = "", *, unexpected: bool = False
) -> dict[str, str]:
    """The ``parse.failed`` error of a unit, naming the file that failed.

    A Terraform module is a directory, so its parser says which file inside it failed; a module
    at the scan root that does not say is named by the input label, never ``.``.
    """
    message = f"{type(exc).__name__}: {exc}" if unexpected else str(exc)
    where = unit.relpath
    if unit.kind == HCL_MODULE:
        inner = getattr(exc, "file", "")
        where = (unit.base_rel / inner).as_posix() if inner else where
    if where == ".":
        where = label or where
    return {"file": where, "code": "parse.failed", "message": message}


# ── Root-relative paths ───────────────────────────────────────────────


def _map_path(value: str, unit: ScanUnit, paths: ReportPaths) -> str:
    """Rewrite one absolute path a parser reported to a root-relative POSIX path.

    A path outside the scan root (a local module in a parent directory) keeps its place as a
    relative path with ``..`` segments, and one on another drive is named like the files of that
    drive (``ReportPaths``), so no report carries a path from the machine it ran on.
    """
    if not value or not os.path.isabs(value):
        return value
    path = Path(value)
    try:
        sub = path.relative_to(unit.base_dir)
    except ValueError:
        return _posix_relative(value, paths)
    if str(sub) == ".":
        return unit.base_rel.as_posix()
    return (unit.base_rel / PurePosixPath(sub.as_posix())).as_posix()


def _posix_relative(value: str, paths: ReportPaths) -> str:
    """The absolute path ``value`` as the report names it: relative to the root, ``..`` allowed.

    A path that sits under the root only by its real location (the root names a symlink) is
    relative to the real root, and likewise for the anchor of another drive.
    """
    if not paths.holds(value):
        real_path = os.path.realpath(value)
        if paths.resolved.holds(real_path):
            return paths.resolved.posix(real_path)
    return paths.posix(value)


def _under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _map_location(value: str, unit: ScanUnit, paths: ReportPaths) -> str:
    """Like ``_map_path`` for a ``path`` or legacy ``path:line`` location."""
    file_part, line = split_location(value)
    mapped = _map_path(file_part, unit, paths)
    if mapped == file_part:
        return value
    return f"{mapped}:{line}" if line is not None else mapped


def _localize_parsed(parsed: ParsedOutput, unit: ScanUnit, paths: ReportPaths) -> ParsedOutput:
    """Make every path in a parse output root-relative POSIX, in place.

    The graph qualifies colliding addresses with ``source_path`` and every report location comes
    from ``source_location``, so absolute paths must never get past this point.
    """
    parsed.source_path = unit.relpath
    for resource in parsed.resources:
        resource.source_location = _map_location(resource.source_location, unit, paths)
    parsed.diagnostics = [
        dataclasses.replace(d, file=_map_path(d.file, unit, paths)) if d.file else d
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
    external: list[Threat],
    baseline_fingerprints: frozenset[str] | None,
    stdin_dir: Path | None,
    stdin_name: str,
) -> ScanResult:
    from threatcode import suppressions

    settings = request.settings
    root = discovery.root

    _localize_threats(
        report.threats,
        graph,
        discovery.paths,
        stdin_dir,
        stdin_name,
        _manifest_lines(discovery, list(settings.extra_rule_paths)),
    )
    _reconcile_ingested(report, graph, external, sources)
    assign_fingerprints(report.threats, graph)
    report.threats.sort(key=_threat_order)
    report.timestamp = "" if request.no_timestamp else current_timestamp()

    notices: list[str] = []
    ignore = suppressions.load(
        request.ignore_file,
        root,
        no_ignore=request.no_ignore,
        extra_rule_paths=list(settings.extra_rule_paths),
    )
    outcome = suppressions.apply(report.threats, ignore, attack_paths=report.attack_paths)
    report.threats = outcome.kept
    report.attack_paths = outcome.kept_paths
    notices.extend(outcome.notices)
    suppressed_paths = len(outcome.suppressed_paths)
    coverage.suppressed = len(outcome.suppressed) + suppressed_paths
    coverage.suppressed_paths = suppressed_paths

    # The baseline records what is left after suppressions, findings and attack paths alike.
    snapshot = list(report.threats)
    snapshot_paths = list(report.attack_paths)
    baselined: list[Threat] = []
    baselined_paths: list[AttackPath] = []
    if baseline_fingerprints is not None:
        report.threats, baselined = suppressions.apply_baseline(
            report.threats, baseline_fingerprints
        )
        report.attack_paths, baselined_paths = suppressions.apply_baseline_paths(
            report.attack_paths, baseline_fingerprints
        )
    coverage.baselined = len(baselined) + len(baselined_paths)
    coverage.baselined_paths = len(baselined_paths)

    errors = _unique_errors(errors)
    coverage.errors = [dict(e) for e in errors]
    coverage.gaps = _coverage_gaps(graph.diagnostics)
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
            baseline_written = suppressions.write_baseline(
                request.write_baseline, snapshot, snapshot_paths
            )

    gate_findings, gate_paths = gating(report.threats, report.attack_paths, settings.fail_on)
    _apply_display_filter(report, settings.min_severity, coverage)
    report.coverage = coverage
    analysis = AnalysisResult(
        graph=graph,
        report=report,
        root=root,
        ingest_sources=sources,
        other_drives=discovery.paths.other_drives,
    )
    return ScanResult(
        analysis=analysis,
        exit_code=exit_code,
        coverage=coverage,
        root=root,
        notices=notices,
        ignore_file=ignore.path if ignore is not None else None,
        ignore_entries=sum(1 for e in ignore.entries if not e.expired) if ignore else 0,
        baseline_written=baseline_written,
        suppressed_paths=suppressed_paths,
        baselined_paths=len(baselined_paths),
        gate_findings=gate_findings,
        gate_paths=gate_paths,
        ingest_sources=sources,
    )


def _unique_errors(errors: Iterable[Mapping[str, str]]) -> list[dict[str, str]]:
    """The input errors with a repeat of the same file, code and message left out.

    A file that is read twice (a module directory scanned on its own and through the call that
    uses it) fails twice with the same words, and one cause is one error.
    """
    seen: set[tuple[str, str, str]] = set()
    unique: list[dict[str, str]] = []
    for error in errors:
        key = (error.get("file", ""), error.get("code", ""), error.get("message", ""))
        if key not in seen:
            seen.add(key)
            unique.append(dict(error))
    return unique


def _coverage_gaps(diagnostics: Iterable[Diagnostic]) -> list[dict[str, Any]]:
    """What the scan did not analyse: the warnings and errors, each cause listed once.

    A diagnostic repeated with the same code, file, line and message is one gap (a module read
    through several calls reports its unresolved references each time).
    A template that skips resources and then finds none left to model says why in the skip, so
    the second gap, which says only that nothing could be modelled, is the same cause (RW-10).
    """
    seen: set[tuple[str, str, int | None, str]] = set()
    gaps: list[dict[str, Any]] = []
    for diagnostic in diagnostics:
        if diagnostic.level not in ("warning", "error"):
            continue
        key = (diagnostic.code, diagnostic.file, diagnostic.line, diagnostic.message)
        if key in seen:
            continue
        seen.add(key)
        gaps.append(diagnostic.to_dict())
    explained = {g["file"] for g in gaps if g["code"] == "cfn.skipped_resource" and "file" in g}
    return [
        g
        for g in gaps
        if not (g["code"] == "parse.zero_resources" and g.get("file", "") in explained)
    ]


def _reconcile_ingested(
    report: ThreatReport,
    graph: InfraGraph,
    external: list[Threat],
    sources: list[dict[str, Any]],
) -> None:
    """Drop scanner findings that ThreatCode's own finding at the same file and line reports.

    Needs root-relative locations, so it runs after ``_localize_threats``.
    The dropped finding's diagnostic goes to the graph and its count to the source it came from.
    Attack path hops and findings that referred to it are repointed at the native finding that
    stands in for it, so no reference is left to a finding the report no longer holds.
    """
    from threatcode.ingest import reconcile_native

    ingested = {id(threat) for threat in external}
    scanner = [t for t in report.threats if id(t) in ingested]
    if not scanner:
        return
    native = [t for t in report.threats if id(t) not in ingested]
    twins: dict[str, Threat] = {}
    remaining, diagnostics = reconcile_native(scanner, native, twins=twins)
    if not diagnostics:
        return
    graph.diagnostics.extend(diagnostics)
    kept = {id(t) for t in remaining}
    for threat in scanner:
        if id(threat) in kept:
            continue
        twin = twins[threat.id]
        twin.path_ids = sorted({*twin.path_ids, *threat.path_ids})
        for source in sources:
            if source.get("file") == threat.metadata.get("ingest_file") and (
                source.get("tool") == threat.tool
            ):
                source["duplicates"] = int(source.get("duplicates", 0)) + 1
                break
    report.threats = [t for t in report.threats if id(t) not in ingested or id(t) in kept]
    for path in report.attack_paths:
        for hop in path.hops:
            hop.enabled_by = list(
                dict.fromkeys(twins[i].id if i in twins else i for i in hop.enabled_by)
            )


def _threat_order(threat: Threat) -> tuple[int, str, str, str]:
    return (-threat_severity(threat).rank, threat.resource_address, threat.rule_id, threat.id)


def _localize_threats(
    threats: Iterable[Threat],
    graph: InfraGraph,
    paths: ReportPaths,
    stdin_dir: Path | None,
    stdin_name: str,
    lines: _ManifestLines | None = None,
) -> None:
    """Give every finding a root-relative POSIX location and a resource type.

    The location comes from the node the finding sits on when the finding has none of its own.
    A finding that names a resource but not its type (a secret) takes the type of the node.
    A finding that sits on the whole of a Kubernetes object points at the line of the key it is
    about, when the manifest says which (``lines``).
    """
    for threat in threats:
        node = graph.get_node(threat.resource_address)
        if node is not None and not threat.resource_type:
            threat.resource_type = node.resource_type
        if threat.location_file:
            threat.location_file = _relative_to_root(
                threat.location_file, paths, stdin_dir, stdin_name
            )
        elif node is not None and node.source_file:
            threat.location_file = node.source_file
            threat.location_start_line = node.start_line
            threat.location_end_line = node.end_line
        if lines is not None and node is not None:
            line = lines.line_for(threat, node)
            if line is not None:
                threat.location_start_line = line


@dataclass
class _ManifestLines:
    """Where in its manifest each property of a Kubernetes object comes from.

    A node carries one line, the start of its document, which for a manifest that opens with
    ``apiVersion`` is line 1 for every finding on it.
    The Kubernetes parser records for each object the line of the key behind every property a
    rule reads (``ParsedResource.meta['lines']``), and this index joins those lines to the nodes
    by file, line, type and name.
    A finding on a property points at that key; a finding on the whole object points at its
    ``kind:`` line.
    """

    by_object: dict[tuple[str, int | None, str, str], Mapping[str, int] | None]
    reads: Mapping[str, tuple[str, ...]]

    def line_for(self, threat: Threat, node: InfraNode) -> int | None:
        if threat.source not in (ThreatSource.RULE, ThreatSource.BOUNDARY):
            return None
        # Only a line that is the node's own default is refined; a producer's line stands
        if (
            threat.location_file != node.source_file
            or threat.location_start_line != node.start_line
        ):
            return None
        lines = self.by_object.get(
            (node.source_file, node.start_line, node.resource_type, node.name)
        )
        if not lines:
            return None
        named = [lines[p] for p in self.reads.get(threat.rule_id, ()) if p in lines]
        return min(named) if named else lines.get("kind")


def _manifest_lines(discovery: Discovery, rule_paths: Sequence[Path]) -> _ManifestLines | None:
    """The line index of the Kubernetes objects of a scan, or None when no parser recorded one."""
    by_object: dict[tuple[str, int | None, str, str], Mapping[str, int] | None] = {}
    for unit in discovery.units:
        if unit.parsed is None:
            continue
        for resource in unit.parsed.resources:
            lines = resource.meta.get("lines")
            if not resource.resource_type.startswith("kubernetes_") or not isinstance(
                lines, Mapping
            ):
                continue
            key = (
                split_location(resource.source_location)[0],
                resource.start_line,
                resource.resource_type,
                resource.name,
            )
            # Two objects that look alike to the index are not told apart: neither is refined
            by_object[key] = None if key in by_object else lines
    if not any(by_object.values()):
        return None
    from threatcode.engine.rules.loader import load_all_rules

    reads = {rule.id: rule.properties_read for rule in load_all_rules(list(rule_paths))}
    return _ManifestLines(by_object, reads)


def _relative_to_root(
    value: str, paths: ReportPaths, stdin_dir: Path | None, stdin_name: str
) -> str:
    """A finding's file as the report names it: relative to the scan root, ``..`` allowed."""
    if not os.path.isabs(value):
        return value.replace("\\", "/")
    path = Path(value)
    if stdin_dir is not None and _under(path, stdin_dir):
        return stdin_name
    return _posix_relative(value, paths)


def _apply_display_filter(report: ThreatReport, min_severity: str, coverage: Coverage) -> None:
    """Hide findings and paths below ``min_severity``; the gate already ran on the full set.

    What was hidden is counted in ``coverage``, so a report that shows 5 of 12 findings says so.
    """
    if min_severity == "info":
        return
    threshold = Severity(min_severity)
    shown = report.filter_by_severity(threshold)
    shown_paths = [p for p in report.attack_paths if p.severity >= threshold]
    coverage.hidden_findings = len(report.threats) - len(shown)
    coverage.hidden_paths = len(report.attack_paths) - len(shown_paths)
    coverage.min_severity = min_severity
    report.threats = shown
    report.attack_paths = shown_paths
