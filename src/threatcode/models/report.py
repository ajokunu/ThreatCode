"""Threat report aggregate and the coverage block that says what a scan did not analyse."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, ClassVar

from threatcode.exceptions import ConfigError
from threatcode.models.attack_path import AttackPath
from threatcode.models.threat import Severity, Threat

SOURCE_DATE_EPOCH_ENV = "SOURCE_DATE_EPOCH"

# How many not-infrastructure paths a coverage block lists; the count is always complete.
NOT_IAC_PATH_LIMIT = 20


def current_timestamp() -> str:
    """ISO 8601 UTC time of now, or of ``SOURCE_DATE_EPOCH`` when that variable is set.

    ``SOURCE_DATE_EPOCH`` is the reproducible-builds convention: set it and two scans of the same
    input write byte-identical reports.

    Raises:
        ConfigError: ``SOURCE_DATE_EPOCH`` is set but is not an integer number of seconds.
    """
    raw = os.environ.get(SOURCE_DATE_EPOCH_ENV, "").strip()
    if not raw:
        return datetime.now(timezone.utc).isoformat()
    try:
        moment = datetime.fromtimestamp(int(raw), tz=timezone.utc)
    except (ValueError, OverflowError, OSError) as exc:
        raise ConfigError(
            f"{SOURCE_DATE_EPOCH_ENV} must be an integer number of seconds, got '{raw}'"
        ) from exc
    return moment.isoformat()


def threat_severity(threat: Threat) -> Severity:
    """The severity gates, filters and reports use: effective when set, else the base severity."""
    return threat.effective_severity if threat.effective_severity is not None else threat.severity


@dataclass
class Coverage:
    """What a scan read, what it could not analyse and what it set aside.

    A scan that looks clean while a file failed to parse is worse than a failed scan, so this block
    is part of every report.
    ``errors`` are input errors (each makes the scan exit 2); ``gaps`` are warning diagnostics the
    parsers and the graph recorded (an unanalysed module call, a Helm fallback render, unknown plan
    values, an unresolved intrinsic, a skipped document).
    """

    files_discovered: int = 0
    units_parsed: int = 0
    not_iac_count: int = 0
    # The first NOT_IAC_PATH_LIMIT root-relative paths of candidates no parser recognised.
    not_iac_paths: list[str] = field(default_factory=list)
    symlinks_skipped: int = 0
    # Named pipes, sockets and devices met while walking; they are never opened.
    special_files_skipped: int = 0
    # Input errors: {file, code, message}.
    errors: list[dict[str, str]] = field(default_factory=list)
    # Warning diagnostics as dicts: {level, code, message, file?, line?}.
    gaps: list[dict[str, Any]] = field(default_factory=list)
    # How many rule evaluations raised; the detail is in the report's rule_errors.
    rule_errors: int = 0
    # Findings and attack paths removed by .threatcodeignore entries.
    suppressed: int = 0
    # Findings and attack paths removed because the baseline already contains them.
    baselined: int = 0
    # How many of ``suppressed`` and ``baselined`` are attack paths; the rest are findings.
    suppressed_paths: int = 0
    baselined_paths: int = 0
    # What ``--min-severity`` left out of ``threats`` and ``attack_paths``, and the severity it cut
    # at. The gate saw all of it, so a report that hides findings has to say so.
    hidden_findings: int = 0
    hidden_paths: int = 0
    min_severity: str = ""

    @property
    def has_gaps(self) -> bool:
        """True when part of the input was not analysed in full (gaps or failed rules)."""
        return bool(self.gaps) or self.rule_errors > 0

    def note_not_iac(self, relpath: str) -> None:
        self.not_iac_count += 1
        if len(self.not_iac_paths) < NOT_IAC_PATH_LIMIT:
            self.not_iac_paths.append(relpath)

    def to_dict(self) -> dict[str, Any]:
        data = self._base_dict()
        # Emitted only when they differ from their defaults, so a report that sets nothing aside
        # and hides nothing is byte-identical to one from before these fields existed
        if self.suppressed_paths:
            data["suppressed_paths"] = self.suppressed_paths
        if self.baselined_paths:
            data["baselined_paths"] = self.baselined_paths
        if self.hidden_findings or self.hidden_paths:
            data["hidden"] = {
                "min_severity": self.min_severity,
                "findings": self.hidden_findings,
                "attack_paths": self.hidden_paths,
            }
        return data

    def _base_dict(self) -> dict[str, Any]:
        return {
            "files_discovered": self.files_discovered,
            "units_parsed": self.units_parsed,
            "not_iac": {"count": self.not_iac_count, "paths": list(self.not_iac_paths)},
            "symlinks_skipped": self.symlinks_skipped,
            "special_files_skipped": self.special_files_skipped,
            "errors": [dict(e) for e in self.errors],
            "gaps": [dict(g) for g in self.gaps],
            "rule_errors": self.rule_errors,
            "suppressed": self.suppressed,
            "baselined": self.baselined,
        }


@dataclass
class ThreatReport:
    # Version of the report document contract, written to every report as schema_version.
    SCHEMA_VERSION: ClassVar[str] = "2"

    threats: list[Threat] = field(default_factory=list)
    scanned_resources: int = 0
    input_file: str = ""
    # ISO 8601 UTC; the empty string means "leave it out" (scan --no-timestamp).
    timestamp: str = field(default_factory=current_timestamp)
    version: str = ""
    attack_paths: list[AttackPath] = field(default_factory=list)
    # LLM phase status: provider, model, status (ran, skipped or failed), error
    # and threat_count. None until the LLM phase has been evaluated.
    llm: dict[str, Any] | None = None
    # Rule evaluations that raised: {rule_id, node_id, error}.
    rule_errors: list[dict[str, str]] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    # The inputs relative to the scan root, as they were before ``input_file`` became the paths as
    # typed. SARIF and Bitbucket anchor a result that has no location of its own at the first one,
    # and SARIF names its alert category after them. Not serialized.
    input_paths: list[str] = field(default_factory=list)

    def add(self, threat: Threat) -> None:
        self.threats.append(threat)

    def filter_by_severity(self, min_severity: Severity) -> list[Threat]:
        return [t for t in self.threats if threat_severity(t) >= min_severity]

    def duplicate_ids(self) -> list[str]:
        """Ids that more than one threat carries, sorted; empty when every id is unique.

        A threat id names one finding in the diff, in ``enabled_by`` and in a suppression, so two
        threats that share one would be merged or hidden together.
        """
        seen: set[str] = set()
        repeated: set[str] = set()
        for threat in self.threats:
            (repeated if threat.id in seen else seen).add(threat.id)
        return sorted(repeated)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for t in self.threats:
            key = threat_severity(t).value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.SCHEMA_VERSION,
            "version": self.version,
        }
        if self.timestamp:
            data["timestamp"] = self.timestamp
        data.update(
            {
                "input_file": self.input_file,
                "scanned_resources": self.scanned_resources,
                "summary": self.summary,
                "total_threats": len(self.threats),
                "threats": [t.to_dict() for t in self.threats],
                "attack_paths": [p.to_dict() for p in self.attack_paths],
                "coverage": self.coverage.to_dict(),
            }
        )
        # A skipped LLM phase is tracked in memory but not serialized.
        if self.llm is not None and self.llm.get("status") != "skipped":
            data["llm"] = dict(self.llm)
        if self.rule_errors:
            data["rule_errors"] = [dict(e) for e in self.rule_errors]
        return data
