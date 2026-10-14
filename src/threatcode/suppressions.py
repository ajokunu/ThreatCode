""".threatcodeignore suppressions and baselines.

Suppressions
------------
A ``.threatcodeignore`` file at the scan root (or the file named with ``--ignore-file``) lists one
suppression per line::

    <ID> [resource=GLOB] [file=GLOB] [exp:YYYY-MM-DD] [reason="text"]

``ID`` is a rule id, a threat id, a fingerprint, a CVE or GHSA alias, the kind of a trust boundary
crossing, or an attack path id.
The kind of a crossing is ``BOUNDARY_GENERIC_FLOW``, ``BOUNDARY_UNENCRYPTED_FLOW``,
``BOUNDARY_UNAUTHENTICATED_FLOW`` or ``BOUNDARY_UNVALIDATED_FLOW``, which is what the RULE column of
the text report prints for one::

    # an accepted CVE, with the reason and a date to look at it again
    CVE-2023-12345 exp:2027-03-31 reason="no network path to the parser"
    # one rule, on the resources that match a glob, in one directory
    S3_NO_ENCRYPTION resource="aws_s3_bucket.logs*" file="infra/prod/*" exp:2027-06-30 reason="SSE"
    # one exact finding
    9f2c4a7e1b3d5c80 reason="covered by the bucket policy in infra/policy.tf"
    # one attack path
    3c8d1f0a92be exp:2027-01-31 reason="the gateway is intentionally public"

``resource=`` is an ``fnmatch`` glob over the resource address and ``file=`` one over the
root-relative POSIX path of the file the finding sits in, so a scoped entry never reaches further
than it is written.
A finding with no location never matches a ``file=`` scope.
An attack path is matched by ``resource=`` against any resource on its route, and a ``file=`` scope
never matches one, because a route has no single file.
Quote a glob that has spaces or quote characters in it.

``exp:YYYY-MM-DD`` ends the suppression after that date.
A malformed date is treated as already expired and warned, so a typo can never suppress forever.
An entry with an option this version does not understand is skipped and warned, never applied more
widely than written.

Warnings, never errors: an entry without a ``reason``; a global entry (no fingerprint and no scope)
without an ``exp``; an entry that names a rule listed in a rule file's ``deprecated_ids`` (the rule
was removed or renamed, so the line no longer does anything).
When the ``CI`` environment variable is set and the ignore file lives inside the scanned tree, a
notice explains that a pull request can edit that file and recommends ``--ignore-file`` with a path
the pull request cannot change.

Suppression happens before the gate, so a fully suppressed scan exits 0.
``SuppressionResult.report()`` lists what was applied (id, reason, expiry, file and line of the
entry, matched count), the entries that matched nothing and the entries that expired.

Baselines
---------
``--write-baseline FILE`` records the fingerprint of every finding and the id of every attack path
as ``{schema, entries, attack_paths}`` sorted for stable diffs, and ``--baseline FILE`` removes
what it already contains from the gate and the listings, so a pull request fails only on new
findings and new attack paths.
A baseline written before attack paths were recorded has no ``attack_paths`` key and baselines no
path.

The module API the scan pipeline uses is ``load``, ``apply``, ``baseline_document``,
``write_baseline``, ``load_baseline`` and ``apply_baseline``.
Attack paths are passed to ``apply`` with ``attack_paths=``, to ``write_baseline`` and
``baseline_document`` with ``attack_paths=``, and split by ``apply_baseline_paths``.
"""

from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from threatcode.exceptions import ConfigError
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import threat_severity
from threatcode.models.threat import Threat, ThreatSource

__all__ = [
    "BASELINE_SCHEMA",
    "IGNORE_FILE_NAME",
    "Baseline",
    "Entry",
    "IgnoreFile",
    "SuppressionResult",
    "apply",
    "apply_baseline",
    "apply_baseline_paths",
    "baseline_document",
    "ci_notice",
    "load",
    "load_baseline",
    "write_baseline",
]

IGNORE_FILE_NAME = ".threatcodeignore"
BASELINE_SCHEMA = "threatcode-baseline/1"

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{16}$")
_FALSE_VALUES = frozenset({"", "0", "false", "no", "off"})


@dataclass(frozen=True)
class Entry:
    """One suppression line."""

    id: str
    line: int
    expires: date | None = None
    # True when the entry is past its date or its date could not be read.
    expired: bool = False
    reason: str = ""
    # fnmatch glob over the resource address; empty means any resource.
    resource: str = ""
    # fnmatch glob over the root-relative POSIX file; empty means any file.
    file: str = ""

    @property
    def scoped(self) -> bool:
        """True when the entry is limited to a resource or a file."""
        return bool(self.resource or self.file)

    @property
    def is_fingerprint(self) -> bool:
        """True when ``id`` has the shape of a fingerprint, which names one finding in one file."""
        return _FINGERPRINT_RE.match(self.id.casefold()) is not None


@dataclass
class IgnoreFile:
    """A parsed ignore file: where it came from, its entries and what was wrong with it."""

    path: Path
    entries: list[Entry] = field(default_factory=list)
    # Problems found while reading: malformed dates, unknown tokens, unreadable lines, missing
    # reasons, global entries without an expiry, removed rules and the CI trust notice.
    notices: list[str] = field(default_factory=list)


@dataclass
class SuppressionResult:
    """The outcome of ``apply``."""

    kept: list[Threat] = field(default_factory=list)
    suppressed: list[Threat] = field(default_factory=list)
    # Attack paths, when ``apply`` was given some.
    kept_paths: list[AttackPath] = field(default_factory=list)
    suppressed_paths: list[AttackPath] = field(default_factory=list)
    # Matches per active entry, in file order, as (entry, count); the count covers findings and
    # attack paths together.
    matches: list[tuple[Entry, int]] = field(default_factory=list)
    # Active entries that matched nothing.
    unmatched: list[Entry] = field(default_factory=list)
    # Entries past their date (or with an unreadable one); they suppress nothing.
    expired: list[Entry] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    # The ignore file the entries came from; None when there was none.
    ignore_file: Path | None = None

    def report(self) -> dict[str, Any]:
        """What the ignore file did, for the report.

        ``applied`` lists every active entry that suppressed something, ``unmatched`` the active
        ones that did not, and ``expired`` the ones past their date.
        Each item carries the id, reason, expiry, the ignore file and line, its scope and (for
        applied and unmatched) the matched count.
        """
        applied = [self._item(entry, count) for entry, count in self.matches if count > 0]
        unmatched = [self._item(entry, 0) for entry in self.unmatched]
        expired = [self._item(entry, None) for entry in self.expired]
        return {"applied": applied, "unmatched": unmatched, "expired": expired}

    def _item(self, entry: Entry, matched: int | None) -> dict[str, Any]:
        item: dict[str, Any] = {
            "id": entry.id,
            "reason": entry.reason,
            "expires": entry.expires.isoformat() if entry.expires else None,
            "ignore_file": self.ignore_file.as_posix() if self.ignore_file else "",
            "line": entry.line,
            "scope": {"resource": entry.resource, "file": entry.file},
        }
        if matched is not None:
            item["matched"] = matched
        return item


class Baseline(frozenset[str]):
    """The fingerprints a baseline lists; ``path_ids`` holds the attack path ids it lists.

    It is a plain ``frozenset`` of fingerprints for every caller that only knows findings.
    """

    path_ids: frozenset[str]

    def __new__(cls, fingerprints: Iterable[str] = (), path_ids: Iterable[str] = ()) -> Baseline:
        self = super().__new__(cls, fingerprints)
        self.path_ids = frozenset(path_ids)
        return self


# ── Reading the ignore file ───────────────────────────────────────────


def _ci_is_set(env: Mapping[str, str]) -> bool:
    return env.get("CI", "").strip().casefold() not in _FALSE_VALUES


def _inside(path: Path, root: Path) -> bool:
    def contained(p: Path, r: Path) -> bool:
        return p == r or r in p.parents

    lexical = contained(Path(os.path.abspath(path)), Path(os.path.abspath(root)))
    try:
        real = contained(path.resolve(), root.resolve())
    except OSError:
        real = False
    return lexical or real


def ci_notice(ignore_path: Path, root: Path, env: Mapping[str, str] | None = None) -> str | None:
    """The CI trust notice for ``ignore_path``, or None.

    It applies when the ``CI`` environment variable is set and the ignore file lives inside the
    scanned tree ``root``, because a pull request can edit a file in the tree and suppress its own
    findings.
    """
    environment = os.environ if env is None else env
    if not _ci_is_set(environment) or not _inside(ignore_path, root):
        return None
    return (
        f"{ignore_path} lives inside the scanned tree, so a pull request can edit it and suppress "
        "its own findings; in CI pass --ignore-file with a path a pull request cannot change "
        "(a file outside the checkout, or one read from the base branch)"
    )


def load(
    path: Path | None,
    root: Path,
    *,
    no_ignore: bool = False,
    today: date | None = None,
    env: Mapping[str, str] | None = None,
    extra_rule_paths: list[Path] | None = None,
) -> IgnoreFile | None:
    """Read the ignore file: ``path`` when given, else ``root/.threatcodeignore`` if it exists.

    Returns None when suppressions are off (``no_ignore``) or no file applies.
    ``env`` is the environment the CI notice reads (default ``os.environ``) and
    ``extra_rule_paths`` are rule files whose ``deprecated_ids`` count with the built-in ones.

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
        text = target.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Cannot read ignore file {target}: {exc}") from exc
    from threatcode.engine.rules.loader import deprecated_rule_ids

    ignore = parse(
        text,
        target,
        today or date.today(),
        deprecated_ids=deprecated_rule_ids(extra_rule_paths),
    )
    notice = ci_notice(target, root, env)
    if notice is not None:
        ignore.notices.append(notice)
    return ignore


def _lines(text: str) -> list[str]:
    """Split on newlines only, so a stray form feed or line separator cannot shift line numbers."""
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def parse(
    text: str,
    path: Path,
    today: date,
    *,
    deprecated_ids: frozenset[str] = frozenset(),
) -> IgnoreFile:
    """Parse ignore-file ``text``; ``path`` names it in messages.

    ``deprecated_ids`` are rule ids that were removed or renamed; an entry naming one warns.
    """
    result = IgnoreFile(path=path)
    deprecated = {d.casefold() for d in deprecated_ids}
    for number, raw in enumerate(_lines(text), start=1):
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
        notices: list[str] = []
        entry = _parse_entry(entry_id, options, number, today, where, notices)
        result.notices.extend(notices)
        if entry is None:
            continue
        result.entries.append(entry)
        result.notices.extend(_entry_warnings(entry, options, where, deprecated))
    return result


def _parse_entry(
    entry_id: str,
    options: list[str],
    number: int,
    today: date,
    where: str,
    notices: list[str],
) -> Entry | None:
    """The entry for one line, or None (with the reason in ``notices``) when it must be skipped."""
    expires: date | None = None
    expired = False
    reason = ""
    resource = ""
    file_glob = ""
    seen: set[str] = set()
    for option in options:
        key, sep, value = _split_option(option)
        if key is None:
            notices.append(f"{where}: unknown option '{option}'; {entry_id} skipped")
            return None
        if key in seen:
            notices.append(
                f"{where}: option '{key}' appears twice for {entry_id}; entry skipped so it "
                "cannot suppress more than written"
            )
            return None
        seen.add(key)
        if key == "exp":
            try:
                expires = date.fromisoformat(value)
            except ValueError:
                expired = True
                notices.append(
                    f"{where}: invalid expiration date '{value}' for {entry_id}; "
                    "treating the entry as expired"
                )
            else:
                expired = today > expires
        elif key == "reason":
            reason = value
        else:
            if sep != "=" or not value:
                notices.append(
                    f"{where}: '{key}' needs a glob, as {key}=GLOB; {entry_id} skipped so it "
                    "cannot suppress more than written"
                )
                return None
            if key == "resource":
                resource = value
            else:
                file_glob = value.replace("\\", "/").removeprefix("./")
    return Entry(
        id=entry_id,
        line=number,
        expires=expires,
        expired=expired,
        reason=reason,
        resource=resource,
        file=file_glob,
    )


def _split_option(option: str) -> tuple[str | None, str, str]:
    """``(key, separator, value)`` of an option, or ``(None, '', '')`` when it is not one."""
    for key in ("exp", "reason"):
        for sep in (":", "="):
            if option.startswith(key + sep):
                return key, sep, option[len(key) + 1 :]
    for key in ("resource", "file"):
        if option.startswith(key + "="):
            return key, "=", option[len(key) + 1 :]
    return None, "", ""


def _entry_warnings(
    entry: Entry, options: list[str], where: str, deprecated: set[str]
) -> list[str]:
    warnings: list[str] = []
    if not entry.reason.strip():
        warnings.append(
            f'{where}: {entry.id} has no reason; add reason="why this risk is accepted"'
        )
    has_expiry = any(o.startswith(("exp:", "exp=")) for o in options)
    if not has_expiry and not entry.scoped and not entry.is_fingerprint:
        warnings.append(
            f"{where}: {entry.id} is a global entry (no fingerprint and no resource= or file= "
            "scope) with no expiry; add exp:YYYY-MM-DD or narrow it"
        )
    if entry.id.casefold() in deprecated:
        warnings.append(
            f"{where}: {entry.id} names a rule that was removed or renamed (it is listed in a "
            "rule file's deprecated_ids), so this entry no longer suppresses anything; "
            "update or delete it"
        )
    return warnings


# ── Matching ──────────────────────────────────────────────────────────


def _glob_matches(glob: str, value: str) -> bool:
    return value == glob or fnmatchcase(value, glob)


def _keys(threat: Threat) -> set[str]:
    values = [threat.rule_id, threat.id, threat.fingerprint, *threat.aliases]
    # A trust boundary finding has no rule id of its own; the kind of crossing it reports
    # (BOUNDARY_GENERIC_FLOW) is the key the text report prints in its RULE column
    boundary_rule = threat.metadata.get("boundary_rule")
    if isinstance(boundary_rule, str):
        values.append(boundary_rule)
    return {v.casefold() for v in values if v}


def _threat_matches(entry: Entry, keys: set[str], threat: Threat) -> bool:
    if entry.id.casefold() not in keys:
        return False
    if entry.resource and not _glob_matches(entry.resource, threat.resource_address):
        return False
    if entry.file:
        location = threat.location_file.replace("\\", "/")
        if not location or not _glob_matches(entry.file, location):
            return False
    return True


def _path_matches(entry: Entry, path: AttackPath) -> bool:
    if entry.id.casefold() != path.id.casefold():
        return False
    if entry.file:
        return False
    if entry.resource:
        nodes = {path.entry, path.target, *path.node_ids}
        return any(_glob_matches(entry.resource, node) for node in nodes if node)
    return True


def apply(
    threats: Iterable[Threat],
    ignore: IgnoreFile | None,
    *,
    attack_paths: Iterable[AttackPath] | None = None,
) -> SuppressionResult:
    """Split ``threats`` (and ``attack_paths``) into what is kept and what ``ignore`` suppresses.

    Which entries are expired was decided when the file was loaded.
    """
    result = SuppressionResult()
    paths = list(attack_paths) if attack_paths is not None else []
    if ignore is None:
        result.kept = list(threats)
        result.kept_paths = paths
        return result
    result.ignore_file = ignore.path
    active = [e for e in ignore.entries if not e.expired]
    result.expired = [e for e in ignore.entries if e.expired]
    counts = [0] * len(active)
    for threat in threats:
        keys = _keys(threat)
        matched = False
        for index, entry in enumerate(active):
            if _threat_matches(entry, keys, threat):
                counts[index] += 1
                matched = True
        (result.suppressed if matched else result.kept).append(threat)
    for path in paths:
        matched = False
        for index, entry in enumerate(active):
            if _path_matches(entry, path):
                counts[index] += 1
                matched = True
        (result.suppressed_paths if matched else result.kept_paths).append(path)
    result.matches = [(entry, counts[i]) for i, entry in enumerate(active)]
    result.unmatched = [entry for entry, count in result.matches if count == 0]
    result.notices.extend(ignore.notices)
    for entry in result.expired:
        when = f" on {entry.expires.isoformat()}" if entry.expires else ""
        result.notices.append(
            f"{ignore.path}:{entry.line}: {entry.id} expired{when}; it suppresses nothing"
        )
    for entry in result.unmatched:
        result.notices.append(
            f"{ignore.path}:{entry.line}: {entry.id} matched no finding or attack path"
        )
    return result


# ── Baselines ─────────────────────────────────────────────────────────


def baseline_document(
    threats: Iterable[Threat], attack_paths: Iterable[AttackPath] = ()
) -> dict[str, Any]:
    """The baseline of ``threats`` and ``attack_paths``: sorted, one entry per fingerprint or id.

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
    paths: dict[str, dict[str, str]] = {}
    for path in attack_paths:
        paths.setdefault(
            path.id,
            {
                "id": path.id,
                "entry": path.entry,
                "target": path.target,
                "severity": path.severity.value,
            },
        )
    ordered_paths = sorted(paths.values(), key=lambda p: p["id"])
    return {"schema": BASELINE_SCHEMA, "entries": ordered, "attack_paths": ordered_paths}


def write_baseline(
    path: Path, threats: Iterable[Threat], attack_paths: Iterable[AttackPath] = ()
) -> Path:
    """Write the baseline of ``threats`` and ``attack_paths`` to ``path``; return the path.

    Raises:
        ThreatCodeError: ``path`` is a directory or cannot be written.
    """
    from threatcode.formatters import write_text_file

    text = json.dumps(baseline_document(threats, attack_paths), indent=2) + "\n"
    return write_text_file(path, text)


def load_baseline(path: Path) -> Baseline:
    """The fingerprints (and attack path ids) a baseline file lists.

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
    paths = data.get("attack_paths", []) if isinstance(data, dict) else None
    if (
        not isinstance(data, dict)
        or data.get("schema") != BASELINE_SCHEMA
        or not isinstance(entries, list)
        or not isinstance(paths, list)
    ):
        raise ConfigError(
            f"{path} is not a ThreatCode baseline (expected schema '{BASELINE_SCHEMA}'); "
            "write one with --write-baseline"
        )
    fingerprints = {
        str(e["fingerprint"]) for e in entries if isinstance(e, dict) and e.get("fingerprint")
    }
    path_ids = {str(p["id"]) for p in paths if isinstance(p, dict) and p.get("id")}
    return Baseline(fingerprints, path_ids)


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


def apply_baseline_paths(
    attack_paths: Iterable[AttackPath], baseline: frozenset[str]
) -> tuple[list[AttackPath], list[AttackPath]]:
    """Split ``attack_paths`` into ``(kept, baselined)``.

    A plain ``frozenset`` (not a ``Baseline`` from ``load_baseline``) lists no paths, so every
    path is kept.
    """
    known: frozenset[str] = getattr(baseline, "path_ids", frozenset())
    kept: list[AttackPath] = []
    baselined: list[AttackPath] = []
    for path in attack_paths:
        (baselined if path.id in known else kept).append(path)
    return kept, baselined
