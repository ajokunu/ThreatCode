"""Two scanners, or a scanner and ThreatCode itself, reporting the same finding.

Within the ingested files (``merge_across_tools``): the same advisory on the same package of the
same node reported by two different tools is one finding.
The first tool in command-line order keeps its threat, takes the other's ids as aliases and lists
the other tool in ``metadata['corroborated_by']``.
The same tool repeating a finding at another target (a second lockfile) is not a duplicate.

Against ThreatCode's own findings (``reconcile_native``): a scanner finding at the same file and
line as a native finding of the same family is dropped in favor of the native one, whose
``metadata['corroborated_by']`` then lists the tool.
The families are secrets (scanner secrets against the secret detectors, ``source`` ``secret``) and
misconfigurations (scanner misconfigurations against rule findings, ``source`` ``rule``).
Vulnerabilities have no native family.
Each dropped finding yields an ``ingest.duplicate`` info diagnostic.

``reconcile_native`` needs the native findings, which exist only once the rule engine has run and
root-relative locations are set, so the pipeline calls it after that point.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from threatcode.diagnostics import Diagnostic
from threatcode.models.threat import Threat, ThreatSource

__all__ = ["merge_across_tools", "reconcile_native"]

_NATIVE_SOURCE_BY_KIND = {
    "secret": ThreatSource.SECRET,
    "misconfiguration": ThreatSource.RULE,
}


def _note(kept: Threat, tool: str) -> None:
    corroborated = kept.metadata.setdefault("corroborated_by", [])
    if tool and tool not in corroborated and tool != kept.tool:
        corroborated.append(tool)


def _diagnostic(dropped: Threat, kept: Threat) -> Diagnostic:
    return Diagnostic(
        "info",
        "ingest.duplicate",
        f"{dropped.rule_id} duplicates {kept.rule_id or kept.title} at "
        f"{dropped.resource_address or dropped.location_file}, so only one is reported",
        file=dropped.location_file,
        line=dropped.location_start_line,
    )


def merge_across_tools(threats: Sequence[Threat]) -> tuple[list[Threat], list[Threat]]:
    """Fold vulnerabilities that two tools report on the same package of the same node.

    Returns the kept threats in their original order and the threats that were folded into another.
    """
    kept: list[Threat] = []
    folded: list[Threat] = []
    seen: dict[tuple[str, str], list[Threat]] = {}
    for threat in threats:
        if (
            threat.metadata.get("kind") != "vulnerability"
            or not threat.resource_address
            or not threat.metadata.get("package")
        ):
            kept.append(threat)
            continue
        name = str(threat.metadata["package"].get("name", "")).lower()
        key = (threat.resource_address, name)
        ids = {a.casefold() for a in threat.aliases}
        twin = next(
            (
                other
                for other in seen.get(key, ())
                if other.tool != threat.tool and ids & {a.casefold() for a in other.aliases}
            ),
            None,
        )
        if twin is None:
            seen.setdefault(key, []).append(threat)
            kept.append(threat)
            continue
        _note(twin, threat.tool)
        twin.aliases = list(dict.fromkeys([*twin.aliases, *threat.aliases]))
        folded.append(threat)
    return kept, folded


def reconcile_native(
    external: Iterable[Threat],
    native: Iterable[Threat],
    *,
    twins: dict[str, Threat] | None = None,
) -> tuple[list[Threat], list[Diagnostic]]:
    """Drop scanner findings that a native finding already reports at the same file and line.

    ``external`` are the ingested threats and ``native`` the other findings of the report, both
    with root-relative ``location_file``.
    Returns the external threats that remain and one ``ingest.duplicate`` diagnostic per dropped
    one; the native findings are updated in place.
    When ``twins`` is given it is filled with ``{dropped threat id: the native threat that stands
    in for it}``, so a caller can repoint what referred to the dropped finding.
    """
    index: dict[tuple[ThreatSource, str, int], Threat] = {}
    for threat in native:
        if (
            threat.source in _NATIVE_SOURCE_BY_KIND.values()
            and threat.location_file
            and threat.location_start_line is not None
        ):
            index.setdefault(
                (threat.source, threat.location_file, threat.location_start_line), threat
            )
    remaining: list[Threat] = []
    diagnostics: list[Diagnostic] = []
    for threat in external:
        family = _NATIVE_SOURCE_BY_KIND.get(str(threat.metadata.get("kind")))
        twin = None
        if family is not None and threat.location_file and threat.location_start_line is not None:
            twin = index.get((family, threat.location_file, threat.location_start_line))
        if twin is None:
            remaining.append(threat)
            continue
        _note(twin, threat.tool)
        diagnostics.append(_diagnostic(threat, twin))
        if twins is not None:
            twins[threat.id] = twin
    return remaining, diagnostics
