"""The normalized scanner finding and the severity tables every reader maps through.

Each reader (Trivy, Grype, OSV-Scanner, SARIF) turns its tool's report into the same
``ExternalFinding`` list inside a ``ScannerReport``, so joining a finding to the graph and turning
it into a ``Threat`` never depends on which tool produced it.

Severity vocabulary
-------------------
Every tool severity maps to one of ``critical``, ``high``, ``medium``, ``low`` or ``info``.
A tool that says it does not know (Trivy ``UNKNOWN``, Grype ``Unknown``) or that a finding is
negligible (Grype ``Negligible``) maps to ``info``, and so does an advisory that carries no rating
at all: the report never invents a severity the data does not have.
A numeric score (CVSS base score, SARIF ``security-severity``) maps through the bands 9.0, 7.0 and
4.0: 9.0 and above is critical, 7.0 and above high, 4.0 and above medium, anything above zero low,
and zero is info.
A SARIF result with no score maps through its level: ``error`` is high, ``warning`` medium,
``note`` low and ``none`` info.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

__all__ = [
    "SEVERITY_LEVELS",
    "ExternalFinding",
    "PackageInfo",
    "ScannerReport",
    "clean_text",
    "severity_from_label",
    "severity_from_level",
    "severity_from_score",
    "to_float",
]

Kind = Literal["vulnerability", "misconfiguration", "secret", "other"]
Scope = Literal["image", "path"]

SEVERITY_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_LABELS: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "important": "high",
    "medium": "medium",
    "moderate": "medium",
    "low": "low",
    "minor": "low",
    "negligible": "info",
    "info": "info",
    "informational": "info",
    "unknown": "info",
    "none": "info",
    "unspecified": "info",
}

_LEVELS: dict[str, str] = {"error": "high", "warning": "medium", "note": "low", "none": "info"}

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def severity_from_label(label: object, default: str = "info") -> str:
    """The severity a tool's word stands for (``MODERATE`` -> ``medium``), or ``default``."""
    if not isinstance(label, str):
        return default
    return _LABELS.get(label.strip().lower(), default)


def severity_from_score(score: float | None, default: str = "info") -> str:
    """The severity of a 0-10 score through the bands 9.0, 7.0 and 4.0."""
    if score is None:
        return default
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def severity_from_level(level: object, default: str = "medium") -> str:
    """The severity of a SARIF result level; a missing level is ``warning`` per the SARIF spec."""
    if not isinstance(level, str):
        return default
    return _LEVELS.get(level.strip().lower(), default)


def to_float(value: object) -> float | None:
    """A number out of a JSON value that may be a number or a numeric string, else ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def clean_text(value: object, limit: int = 0) -> str:
    """A string out of a JSON value with control characters removed, shortened to ``limit``."""
    if not isinstance(value, str):
        return ""
    text = _CONTROL.sub("", value).strip()
    if limit and len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


@dataclass(frozen=True)
class PackageInfo:
    """The package a vulnerability is in."""

    name: str = ""
    version: str = ""
    purl: str = ""
    ecosystem: str = ""

    def to_dict(self) -> dict[str, str]:
        pairs = (
            ("name", self.name),
            ("version", self.version),
            ("purl", self.purl),
            ("ecosystem", self.ecosystem),
        )
        return {key: value for key, value in pairs if value}


@dataclass
class ExternalFinding:
    """One finding of a scanner, in the vocabulary of every reader.

    ``scope`` says how the finding is joined to the graph.
    A finding of ``image`` scope belongs to a container image, named by the ``image_refs`` of its
    report, and joins the workloads that run that image.
    A finding of ``path`` scope sits in a file (``file`` and ``line``) and joins the resource whose
    source span holds the line, or for a package vulnerability the workloads beside the lockfile.
    ``aliases`` are the other identifiers of the same issue (CVE and GHSA ids); the finding's own
    ``id`` is added when the finding becomes a ``Threat``, so a bare CVE id suppresses it.
    """

    tool: str
    kind: Kind
    id: str
    severity: str
    title: str = ""
    description: str = ""
    aliases: list[str] = field(default_factory=list)
    cvss_score: float | None = None
    cvss_vector: str = ""
    package: PackageInfo | None = None
    fixed_version: str = ""
    target: str = ""
    file: str = ""
    line: int | None = None
    end_line: int | None = None
    scope: Scope = "path"
    image_refs: tuple[str, ...] = ()
    mitigation: str = ""
    references: list[str] = field(default_factory=list)
    status: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> tuple[str, str, str, str, str, str, int | None]:
        """What makes two findings of one tool the same finding."""
        pkg = self.package
        return (
            self.tool,
            self.id,
            pkg.name if pkg else "",
            pkg.version if pkg else "",
            self.target,
            self.file,
            self.line,
        )


@dataclass
class ScannerReport:
    """One tool run read from one file: who ran, what it found and what it left out."""

    tool: str
    version: str = ""
    findings: list[ExternalFinding] = field(default_factory=list)
    # How many entries were deliberately not turned into findings, by reason.
    skipped: dict[str, int] = field(default_factory=dict)

    def skip(self, reason: str, count: int = 1) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + count
