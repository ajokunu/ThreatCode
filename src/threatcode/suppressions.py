""".threatcodeignore suppressions and baselines.

Suppressions
------------
A ``.threatcodeignore`` file at the scan root (or the file named with ``--ignore-file``) lists one
suppression per line::

    # an accepted CVE
    CVE-2023-12345
    # a rule, until a date
    S3_NO_ENCRYPTION exp:2027-06-30
    # one exact finding, with the reason it is accepted
    9f2c4a7e1b3d5c80 reason:"covered by the bucket policy in infra/policy.tf"

An entry matches a finding by its rule id, threat id, fingerprint or any alias (a CVE or GHSA id),
case-insensitively.
``exp:YYYY-MM-DD`` ends the suppression; a malformed date is treated as already expired and warned,
so a typo can never suppress forever.
An entry with a token this version does not understand is skipped and warned, never applied more
widely than written.
Suppression happens before the gate, so a fully suppressed scan exits 0.
Every active entry is counted; entries that matched nothing and entries that expired are reported
once.

Baselines
---------
``--write-baseline FILE`` records the fingerprint of every finding as ``{schema, entries}`` sorted
for stable diffs, and ``--baseline FILE`` removes the findings it already contains from the gate and
the listings, so a pull request fails only on new findings.

The module API the scan pipeline uses is ``load``, ``apply``, ``baseline_document``,
``write_baseline``, ``load_baseline`` and ``apply_baseline``.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from threatcode.exceptions import ConfigError
from threatcode.models.report import threat_severity
from threatcode.models.threat import Threat, ThreatSource

__all__ = [
    "BASELINE_SCHEMA",
    "IGNORE_FILE_NAME",
    "Entry",
    "IgnoreFile",
    "SuppressionResult",
    "apply",
    "apply_baseline",
    "baseline_document",
    "load",
    "load_baseline",
    "write_baseline",
]

IGNORE_FILE_NAME = ".threatcodeignore"
BASELINE_SCHEMA = "threatcode-baseline/1"

# Tokens that scope an entry; they are not supported yet, so such an entry is skipped.
_SCOPE_TOKENS = ("resource=", "file=")


@dataclass(frozen=True)
class Entry:
    """One suppression line."""

    id: str
    line: int
    expires: date | None = None
    # True when the entry is past its date or its date could not be read.
    expired: bool = False
    reason: str = ""


@dataclass
class IgnoreFile:
    """A parsed ignore file: where it came from, its entries and what was wrong with it."""

    path: Path
    entries: list[Entry] = field(default_factory=list)
    # Problems found while reading: malformed dates, unknown tokens, unreadable lines.
    notices: list[str] = field(default_factory=list)


@dataclass
class SuppressionResult:
    """The outcome of ``apply``."""

    kept: list[Threat] = field(default_factory=list)
    suppressed: list[Threat] = field(default_factory=list)
    # Findings matched per active entry, in file order, as (entry, count).
    matches: list[tuple[Entry, int]] = field(default_factory=list)
    # Active entries that matched no finding.
    unmatched: list[Entry] = field(default_factory=list)
    # Entries past their date (or with an unreadable one); they suppress nothing.
    expired: list[Entry] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)


def load(
    path: Path | None,
    root: Path,
    *,
    no_ignore: bool = False,
    today: date | None = None,
) -> IgnoreFile | None:
    """Read the ignore file: ``path`` when given, else ``root/.threatcodeignore`` if it exists.

    Returns None when suppressions are off (``no_ignore``) or no file applies.

    Raises:
        ConfigError: A file named explicitly does not exist or cannot be read.
    """
    if no_ignore:
        return None
    explicit = path is not None
    target = path if path is not None else root / IGNORE_FILE_NAME
    if not target.is_file():
        if explicit:
            raise ConfigError(f"Ignore file not found: {target}")
        return None
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Cannot read ignore file {target}: {exc}") from exc
    return parse(text, target, today or date.today())


def parse(text: str, path: Path, today: date) -> IgnoreFile:
    """Parse ignore-file ``text``; ``path`` names it in messages."""
    result = IgnoreFile(path=path)
    for number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        where = f"{path}:{number}"
        try:
            tokens = shlex.split(stripped, comments=True)
        except ValueError as exc:
            result.notices.append(f"{where}: cannot read the line ({exc}); skipped")
            continue
        if not tokens:
            continue
        entry_id, options = tokens[0], tokens[1:]
        expires: date | None = None
        expired = False
        reason = ""
        usable = True
        for option in options:
            if option.startswith("exp:"):
                try:
                    expires = date.fromisoformat(option[4:])
                except ValueError:
                    expired = True
                    result.notices.append(
                        f"{where}: invalid expiration date '{option[4:]}' for {entry_id}; "
                        "treating the entry as expired"
                    )
                else:
                    expired = today > expires
            elif option.startswith(("reason:", "reason=")):
                reason = option[len("reason:") :]
            elif option.startswith(_SCOPE_TOKENS):
                usable = False
                result.notices.append(
                    f"{where}: scoped entries ({option.split('=')[0]}=) are not supported yet; "
                    f"{entry_id} skipped so it cannot suppress more than written"
                )
            else:
                usable = False
                result.notices.append(f"{where}: unknown option '{option}'; {entry_id} skipped")
        if usable:
            result.entries.append(
                Entry(id=entry_id, line=number, expires=expires, expired=expired, reason=reason)
            )
    return result


def _keys(threat: Threat) -> set[str]:
    values = [threat.rule_id, threat.id, threat.fingerprint, *threat.aliases]
    return {v.casefold() for v in values if v}


def apply(threats: Iterable[Threat], ignore: IgnoreFile | None) -> SuppressionResult:
    """Split ``threats`` into the ones kept and the ones ``ignore`` suppresses.

    Which entries are expired was decided when the file was loaded.
    """
    result = SuppressionResult()
    if ignore is None:
        result.kept = list(threats)
        return result
    active = [e for e in ignore.entries if not e.expired]
    result.expired = [e for e in ignore.entries if e.expired]
    counts = [0] * len(active)
    for threat in threats:
        keys = _keys(threat)
        matched = False
        for index, entry in enumerate(active):
            if entry.id.casefold() in keys:
                counts[index] += 1
                matched = True
        (result.suppressed if matched else result.kept).append(threat)
    result.matches = [(entry, counts[i]) for i, entry in enumerate(active)]
    result.unmatched = [entry for entry, count in result.matches if count == 0]
    result.notices.extend(ignore.notices)
    for entry in result.expired:
        when = f" on {entry.expires.isoformat()}" if entry.expires else ""
        result.notices.append(
            f"{ignore.path}:{entry.line}: {entry.id} expired{when}; it suppresses nothing"
        )
    for entry in result.unmatched:
        result.notices.append(f"{ignore.path}:{entry.line}: {entry.id} matched no finding")
    return result


def baseline_document(threats: Iterable[Threat]) -> dict[str, Any]:
    """The baseline of ``threats``: one entry per fingerprint, sorted, LLM findings left out.

    LLM findings are advisory and their wording is not stable, so they are never baselined.
    """
    entries: dict[str, dict[str, str]] = {}
    for threat in threats:
        if threat.source is ThreatSource.LLM or not threat.fingerprint:
            continue
        entries.setdefault(
            threat.fingerprint,
            {
                "fingerprint": threat.fingerprint,
                "rule_id": threat.rule_id,
                "resource": threat.resource_address,
                "severity": threat_severity(threat).value,
            },
        )
    ordered = sorted(
        entries.values(), key=lambda e: (e["fingerprint"], e["rule_id"], e["resource"])
    )
    return {"schema": BASELINE_SCHEMA, "entries": ordered}


def write_baseline(path: Path, threats: Iterable[Threat]) -> Path:
    """Write the baseline of ``threats`` to ``path`` and return the absolute path.

    Raises:
        ThreatCodeError: ``path`` is a directory or cannot be written.
    """
    from threatcode.formatters import write_text_file

    text = json.dumps(baseline_document(threats), indent=2) + "\n"
    return write_text_file(path, text)


def load_baseline(path: Path) -> frozenset[str]:
    """The fingerprints a baseline file lists.

    Raises:
        ConfigError: The file is missing, is not JSON or is not a ThreatCode baseline.
    """
    if not path.is_file():
        raise ConfigError(f"Baseline file not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"Cannot read baseline {path}: {exc}") from exc
    entries = data.get("entries") if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("schema") != BASELINE_SCHEMA
        or not isinstance(entries, list)
    ):
        raise ConfigError(
            f"{path} is not a ThreatCode baseline (expected schema '{BASELINE_SCHEMA}'); "
            "write one with --write-baseline"
        )
    fingerprints = {
        str(e["fingerprint"]) for e in entries if isinstance(e, dict) and e.get("fingerprint")
    }
    return frozenset(fingerprints)


def apply_baseline(
    threats: Iterable[Threat], fingerprints: frozenset[str]
) -> tuple[list[Threat], list[Threat]]:
    """Split ``threats`` into ``(kept, baselined)``; LLM findings are always kept."""
    kept: list[Threat] = []
    baselined: list[Threat] = []
    for threat in threats:
        if threat.source is not ThreatSource.LLM and threat.fingerprint in fingerprints:
            baselined.append(threat)
        else:
            kept.append(threat)
    return kept, baselined
