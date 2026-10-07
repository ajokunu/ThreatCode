"""Shared helpers for the formatters.

Text in a report that comes from the scanned input (resource names, rule descriptions, model
output) is untrusted: it can carry Markdown, HTML, @-mentions and newlines meant to break out of
the line it is printed on.
``md_inline`` and ``md_code`` are the two ways untrusted text enters Markdown, so a hostile
resource name stays inert in a pull request comment.

The vocabulary the formats share lives here too: the STRIDE order and labels, the severity labels
and the one-line verdict, so Markdown, the terminal report and Bitbucket never disagree.
"""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import quote

from threatcode.engine.stride import StrideCategory
from threatcode.models.report import threat_severity
from threatcode.models.threat import Severity, Threat

if TYPE_CHECKING:
    from threatcode.models.attack_path import AttackPath
    from threatcode.models.report import ThreatReport

__all__ = [
    "attack_path_phrase",
    "SEVERITY_ORDER",
    "STRIDE_ORDER",
    "collapse_whitespace",
    "md_code",
    "md_inline",
    "plural",
    "repo_path",
    "root_prefix",
    "severity_counts",
    "severity_label",
    "source_uri",
    "stride_label",
    "technique_url",
    "truncate",
    "verdict_line",
]

SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

# Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of
# privilege: the order STRIDE is named in, which is how a reader looks for a category.
STRIDE_ORDER: tuple[str, ...] = tuple(category.value for category in StrideCategory)

_STRIDE_LABELS: dict[str, str] = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Information Disclosure",
    "denial_of_service": "Denial of Service",
    "elevation_of_privilege": "Elevation of Privilege",
}

ZERO_WIDTH_JOINER = "‍"

_WHITESPACE = re.compile(r"\s+")
# Control characters other than tab and newline, which collapse to spaces with the rest.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
# Characters that start a block when they open a line: headings, lists, quotes, tables, fences,
# setext underlines, thematic breaks and ordered-list numbers.
_LEADING_BLOCK = re.compile(
    r"^(?:#{1,6}(?=\s|$)|>+|\|+|[-+*](?=\s|$)|[-*_=]{3,}|={2,}|\d{1,9}[.)](?=\s|$)|`{3,}|~{3,})\s*"
)
# Characters with a meaning inside a line of Markdown.
_INLINE_SPECIAL = re.compile(r"([\\`*\[\]<|~&])")
# An underscore inside a word (snake_case) is literal; one at a word edge can start emphasis.
_EDGE_UNDERSCORE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")
_URL_SCHEME = re.compile(r"(?i)\b(https?|ftp)://")
_MENTION = re.compile(r"(?<![A-Za-z0-9])@(?=[A-Za-z0-9_])")
_ISSUE_REF = re.compile(r"#(?=\d)")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")


def collapse_whitespace(text: str) -> str:
    """One line: control characters and every whitespace run, newlines included, become a space."""
    return _WHITESPACE.sub(" ", _CONTROL.sub(" ", text)).strip()


def truncate(text: str, limit: int) -> str:
    """``text`` cut to ``limit`` characters with ``...`` when it was longer."""
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[: max(limit, 0)]
    return text[: limit - 3].rstrip() + "..."


def md_inline(text: str, *, limit: int | None = None) -> str:
    """Untrusted ``text`` as one line of inline Markdown that renders as the plain words.

    Newlines and runs of whitespace collapse to single spaces, so the text cannot start a new
    block (a heading, a list item, a table row, a quote) or end the paragraph it sits in.
    Block markers at the start are dropped.
    The characters Markdown treats as syntax inside a line are backslash-escaped, so
    ``<script>``, ``[label](url)``, ``*bold*``, ``|`` and the like show literally.
    A zero-width joiner after ``@`` and ``#`` before a digit stops GitHub from notifying a user or
    team and from linking an issue, and one inside ``://`` stops a bare URL from becoming a link.
    ``->`` and parentheses stay readable.
    ``limit`` caps the length of the plain text before escaping.
    """
    flat = collapse_whitespace(text)
    previous = None
    while previous != flat:
        previous = flat
        flat = _LEADING_BLOCK.sub("", flat, count=1)
    if limit is not None:
        flat = truncate(flat, limit)
    escaped = _INLINE_SPECIAL.sub(r"\\\1", flat)
    escaped = _EDGE_UNDERSCORE.sub(r"\\_", escaped)
    escaped = _URL_SCHEME.sub(lambda m: f"{m.group(1)}:{ZERO_WIDTH_JOINER}//", escaped)
    escaped = _MENTION.sub(f"@{ZERO_WIDTH_JOINER}", escaped)
    return _ISSUE_REF.sub(f"#{ZERO_WIDTH_JOINER}", escaped)


def md_code(text: str, *, table: bool = False) -> str:
    """``text`` as an inline code span that shows it exactly, whatever it contains.

    The fence is one backtick longer than the longest run of backticks in the text, and the text
    is padded with a space when it starts or ends with a backtick, so nothing inside can close the
    span early.
    Nothing is escaped inside, so ``module.net.aws_instance.web["a"][0]`` renders literally.
    Inside a table cell (``table=True``) a ``|`` is written ``\\|``, which GFM requires even in a
    code span.
    Newlines collapse to spaces, so the span stays on one line.
    """
    flat = collapse_whitespace(text)
    if not flat:
        return ""
    if table:
        flat = flat.replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", flat)), default=0)
    fence = "`" * (longest + 1)
    padded = f" {flat} " if flat.startswith("`") or flat.endswith("`") else flat
    return f"{fence}{padded}{fence}"


def stride_label(category: str) -> str:
    """Readable STRIDE category: ``information_disclosure`` is ``Information Disclosure``."""
    label = _STRIDE_LABELS.get(category)
    if label is not None:
        return label
    words = category.replace("_", " ").split()
    return " ".join(w if w in ("of", "and") else w.capitalize() for w in words)


def severity_label(severity: Severity | str) -> str:
    """``[HIGH]``: the plain-text severity marker used in place of emoji."""
    value = severity.value if isinstance(severity, Severity) else str(severity)
    return f"[{value.upper()}]"


def plural(count: int, noun: str, plural_form: str | None = None) -> str:
    """``1 finding`` or ``2 findings``."""
    word = noun if count == 1 else (plural_form or f"{noun}s")
    return f"{count} {word}"


def severity_counts(threats: Iterable[Threat]) -> dict[str, int]:
    """Findings per effective severity, in severity order, zero counts left out."""
    counts = {name: 0 for name in SEVERITY_ORDER}
    for threat in threats:
        counts[threat_severity(threat).value] += 1
    return {name: n for name, n in counts.items() if n}


def technique_url(technique_id: str) -> str:
    """The attack.mitre.org page of a technique, or ``""`` for an id that is not a technique id."""
    if not _TECHNIQUE_ID.match(technique_id):
        return ""
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def _zone_phrase(zones: Sequence[str]) -> str:
    named = ["the internet" if z == "internet" else z for z in zones]
    if len(named) <= 1:
        return "".join(named)
    return ", ".join(named[:-1]) + " and " + named[-1]


def attack_path_phrase(paths: Sequence[AttackPath]) -> str:
    """``2 attack paths from the internet to data``, or ``""`` when there are none."""
    if not paths:
        return ""
    entries = sorted({p.hops[0].zone for p in paths if p.hops and p.hops[0].zone})
    targets = sorted({p.hops[-1].zone for p in paths if p.hops and p.hops[-1].zone})
    phrase = plural(len(paths), "attack path")
    if entries and targets:
        return f"{phrase} from {_zone_phrase(entries)} to {_zone_phrase(targets)}"
    return phrase


def verdict_line(report: ThreatReport) -> str:
    """One line that says where the scan landed: ``3 critical, 14 high, 2 attack paths from ...``.

    Severities are the effective ones the gate uses.
    A scan with nothing to report says so.
    """
    parts = [f"{n} {name}" for name, n in severity_counts(report.threats).items()]
    paths = attack_path_phrase(report.attack_paths)
    if paths:
        parts.append(paths)
    return ", ".join(parts) if parts else "no findings"


# ── paths ─────────────────────────────────────────────────────────────


def repo_path(path: str, prefix: str = "") -> str:
    """A repository-relative POSIX path for ``path``; never absolute, never ``..``.

    Backslashes become slashes, ``.`` and empty segments disappear and ``..`` removes the segment
    before it (or is dropped when there is none), so the result cannot point outside the checkout.
    An absolute path is made relative to the current directory when it is inside it, and reduced
    to its file name when it is not.
    ``prefix`` is put in front of a relative path; it is the scan root's place inside the
    repository when the scan was not run from the repository root.
    A path with nothing left names the repository root, ``.``.
    """
    text = path.replace("\\", "/")
    if text.startswith("/") or _WINDOWS_ABSOLUTE.match(text):
        text = _relative_to_cwd(text)
    elif prefix:
        text = f"{prefix}/{text}"
    segments: list[str] = []
    for segment in text.split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return "/".join(segments) or "."


def source_uri(path: str, prefix: str = "") -> str:
    """``repo_path`` percent-encoded as a URI reference: space, ``@``, ``:``, ``%`` and the like."""
    return quote(repo_path(path, prefix), safe="/")


def _relative_to_cwd(text: str) -> str:
    """An absolute path relative to the current directory, or its file name when it is outside."""
    if _WINDOWS_ABSOLUTE.match(text):
        return PurePosixPath(text).name
    try:
        relative = PurePosixPath(os.path.relpath(text)).as_posix()
    except ValueError:
        return PurePosixPath(text).name
    return PurePosixPath(text).name if relative.startswith("..") else relative


def root_prefix(source_root: str | os.PathLike[str] | None) -> str:
    """Where the scan root sits inside the current directory, as a POSIX path, or ``""``."""
    if source_root is None:
        return ""
    root = Path(os.path.abspath(source_root))
    cwd = Path(os.path.abspath(Path.cwd()))
    try:
        relative = root.relative_to(cwd)
    except ValueError:
        return ""
    return "" if str(relative) == "." else relative.as_posix()
