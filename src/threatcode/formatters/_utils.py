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
from collections import Counter
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING
from urllib.parse import quote

from threatcode.engine.stride import StrideCategory
from threatcode.models.report import threat_severity
from threatcode.models.threat import Severity, Threat

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.attack_path import AttackPath
    from threatcode.models.report import ThreatReport

__all__ = [
    "ELLIPSIS",
    "attack_path_phrase",
    "display_path",
    "input_summary",
    "join_verdict",
    "join_words",
    "rule_label",
    "set_aside_phrase",
    "threat_source",
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
    "terminal_safe",
    "truncate",
    "verdict_items",
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

# What the text report puts where it cut something; a single character, so it cannot be mistaken
# for the ``...`` that a name may contain.
ELLIPSIS = "…"

ZERO_WIDTH_JOINER = "\u200d"

_WHITESPACE = re.compile(r"\s+")
# Control characters other than tab and newline, which collapse to spaces with the rest.
# C0, DEL and C1: the 8-bit forms of CSI (0x9b) and OSC (0x9d) are controls on some terminals.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
# What must never reach a terminal as itself: every C0 control, DEL, every C1 control, the line and
# paragraph separators, and the bidirectional controls that reorder what is printed around them.
# Tab, newline and carriage return are in the set too; `terminal_safe` decides what they become.
_TERMINAL_UNSAFE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)
_LINE_BREAKS = frozenset("\t\n\r")
# Characters that start a block when they open a line: headings, lists, quotes, tables, fences,
# setext underlines, thematic breaks and ordered-list numbers.
_LEADING_BLOCK = re.compile(
    r"^(?:#{1,6}(?=\s|$)|>+|\|+|[-+*](?=\s|$)|[-*_=]{3,}|={2,}|\d{1,9}[.)](?=\s|$)|`{3,}|~{3,})\s*"
)
# Characters with a meaning inside a line of Markdown.
_INLINE_SPECIAL = re.compile(r"([\\`*\[\]<|~&])")
# An underscore inside a word (snake_case) is literal; one at a word edge can start emphasis.
_EDGE_UNDERSCORE = re.compile(r"(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")
# What GitHub turns into a link or a notification when it sits in running text: a web address up
# to the first character that ends it (a code span), and an ``@user`` handle or an issue number
# (defused with a zero-width joiner).
_URL = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>\"'`|]+")
_URL_TRAILING = ".,;:!?)]}"
_MENTION = re.compile(r"(?<![A-Za-z0-9])@(?=[A-Za-z0-9_])")
_ISSUE_REF = re.compile(r"#(?=\d)")
# Where a code span is put back after the escaping: private-use characters nothing else writes.
_SLOT_MARK = "\ue000{}\ue001"
_SLOT = re.compile("\ue000(\\d+)\ue001")
_PRIVATE_USE = re.compile("[\ue000-\uf8ff]")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_WINDOWS_ABSOLUTE = re.compile(r"^[A-Za-z]:/")


def collapse_whitespace(text: str) -> str:
    """One line: control characters and every whitespace run, newlines included, become a space."""
    return _WHITESPACE.sub(" ", _CONTROL.sub(" ", text)).strip()


def _visible(match: re.Match[str]) -> str:
    code = ord(match.group())
    return f"\\x{code:02x}" if code <= 0xFF else f"\\u{code:04x}"


def terminal_safe(text: str, *, keep_lines: bool = False) -> str:
    """``text`` made safe to print on a terminal: no control character reaches it as itself.

    Text from the scanned input is hostile: a resource name, a server key or a file name can carry
    ESC, BEL or a C1 control that clears the screen, moves the cursor, retitles the window or
    overwrites what was printed before it.
    Every C0 control, DEL, C1 control, line and paragraph separator and bidirectional control is
    replaced by a visible escape, ``\\x1b`` or ``\\u202e``, so the reader sees that something was
    there and nothing is executed.
    Tab, newline and carriage return become a single space, as in ``collapse_whitespace``, unless
    ``keep_lines`` is set: a message that is printed as it is keeps its own line breaks and tabs
    and loses a carriage return, which would overwrite the line.
    """
    if keep_lines:
        text = text.replace("\r\n", "\n").replace("\r", " ")
        return _TERMINAL_UNSAFE.sub(
            lambda m: m.group() if m.group() in ("\t", "\n") else _visible(m), text
        )
    flat = _TERMINAL_UNSAFE.sub(lambda m: " " if m.group() in _LINE_BREAKS else _visible(m), text)
    return _WHITESPACE.sub(" ", flat).strip()


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
    A web address is written as a code span, which GitHub does not link and which copies exactly.
    A zero-width joiner after ``@`` and ``#`` before a digit stops GitHub from notifying a user or
    team and from linking an issue.
    ``->`` and parentheses stay readable.
    ``limit`` caps the length of the plain text before escaping.
    """
    flat = collapse_whitespace(_PRIVATE_USE.sub("", text))
    previous = None
    while previous != flat:
        previous = flat
        flat = _LEADING_BLOCK.sub("", flat, count=1)
    if limit is not None:
        flat = truncate(flat, limit)
    spans: list[str] = []

    def slot(match: re.Match[str]) -> str:
        found = match.group(0)
        tail = ""
        while found and found[-1] in _URL_TRAILING:
            tail = found[-1] + tail
            found = found[:-1]
        if not found:
            return match.group(0)
        spans.append(found)
        return _SLOT_MARK.format(len(spans) - 1) + tail

    marked = _URL.sub(slot, flat)
    escaped = _INLINE_SPECIAL.sub(r"\\\1", marked)
    escaped = _EDGE_UNDERSCORE.sub(r"\\_", escaped)
    escaped = _MENTION.sub(f"@{ZERO_WIDTH_JOINER}", escaped)
    escaped = _ISSUE_REF.sub(f"#{ZERO_WIDTH_JOINER}", escaped)
    return _SLOT.sub(lambda m: md_code(spans[int(m.group(1))]), escaped)


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
    counts = dict.fromkeys(SEVERITY_ORDER, 0)
    for threat in threats:
        counts[threat_severity(threat).value] += 1
    return {name: n for name, n in counts.items() if n}


def technique_url(technique_id: str) -> str:
    """The attack.mitre.org page of a technique, or ``""`` for an id that is not a technique id."""
    if not _TECHNIQUE_ID.match(technique_id):
        return ""
    return f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"


def join_words(words: Sequence[str]) -> str:
    """``a``, ``a and b`` or ``a, b and c``."""
    if len(words) <= 1:
        return "".join(words)
    return ", ".join(words[:-1]) + " and " + words[-1]


# What a path ends at, by the kind the engine gives its target: how one such target reads and how
# several do.
_TARGET_NOUNS: dict[str, tuple[str, str]] = {
    "data store": ("a data store", "data stores"),
    "secret store": ("a secret store", "secret stores"),
    "administrator identity": ("an administrator identity", "administrator identities"),
    "cluster-admin grant": ("a cluster-admin grant", "cluster-admin grants"),
    "private data": ("private data", "private data"),
}
# What the last hop of a path with no target kind (one built by hand) sits in, and where a path
# starts. The zone is where the target is, not what it is, so the phrase is deliberately vague.
_ZONE_NOUNS: dict[str, str] = {
    "internet": "the internet",
    "dmz": "the DMZ",
    "private": "private workloads",
    "data": "data",
    "management": "management resources",
}
# A verdict is one line of fixed words: a kind or a zone the tables do not know is never echoed,
# because Markdown prints the verdict as it is.
_UNKNOWN_TARGET = "sensitive targets"
_UNKNOWN_ENTRY = "an exposed entry point"


def _target_noun(path: AttackPath, *, single: bool) -> str:
    """What ``path`` ends at, in words: ``a data store``, ``secret stores``, ``data``."""
    nouns = _TARGET_NOUNS.get(path.target_kind)
    if nouns is not None:
        return nouns[0] if single else nouns[1]
    zone = path.hops[-1].zone if path.hops else ""
    return _ZONE_NOUNS.get(zone, _UNKNOWN_TARGET)


def attack_path_phrase(paths: Sequence[AttackPath]) -> str:
    """``2 attack paths from the internet to data stores, worst critical``, or ``""`` for none.

    The targets are named by what they are (a data store, a secret store, an administrator
    identity), not by the trust zone the last hop sits in, and the phrase says how bad the worst
    path is, so a critical path is not hidden behind a verdict that counts only findings.
    A path built by hand, with no target kind, falls back to a noun for its zone.
    """
    if not paths:
        return ""
    entries = sorted({_ZONE_NOUNS.get(p.hops[0].zone, _UNKNOWN_ENTRY) for p in paths if p.hops})
    single = len(paths) == 1
    nouns = Counter(_target_noun(p, single=single) for p in paths)
    ordered = sorted(nouns.items(), key=lambda item: (-item[1], item[0]))
    phrase = plural(len(paths), "attack path")
    if entries:
        phrase += f" from {join_words(entries)} to {join_words([noun for noun, _ in ordered])}"
    worst = max(p.severity for p in paths).value
    return f"{phrase} ({worst})" if single else f"{phrase}, worst {worst}"


def rule_label(threat: Threat) -> str:
    """The key a finding is suppressed and reported by: its rule id, else the kind of boundary.

    A trust boundary finding has no rule of the rule engine; the kind of crossing it reports
    (``BOUNDARY_GENERIC_FLOW``) is the id the suppressions file accepts for it.
    A finding with neither is named by its source (``llm``).
    """
    if threat.rule_id:
        return threat.rule_id
    boundary = threat.metadata.get("boundary_rule")
    if isinstance(boundary, str) and boundary:
        return boundary
    return threat.source.value


def verdict_items(report: ThreatReport) -> list[tuple[str, str]]:
    """The verdict as phrases, each with the severity that colors it (``""`` for none).

    Severities are the effective ones the gate uses.
    A scan that could not read part of its input says so (``incomplete``), because a verdict
    of ``no findings`` over a scan that failed reads as clean.
    A scan with nothing left says why: nothing was found, the baseline accepted it or
    ``--min-severity`` hid it.
    """
    cov = report.coverage
    items = [(f"{n} {name}", name) for name, n in severity_counts(report.threats).items()]
    paths = attack_path_phrase(report.attack_paths)
    if paths:
        items.append((paths, max(p.severity for p in report.attack_paths).value))
    if cov.errors:
        problem = plural(len(cov.errors), "input error")
        if cov.units_parsed == 0:
            return [(f"no result ({problem}; nothing was analysed)", "high")]
        return [
            (f"incomplete ({problem}); in the rest:", "high"),
            *(items or [("no findings", "")]),
        ]
    return items or [(_nothing_left(report), "")]


def join_verdict(items: Sequence[tuple[str, str]]) -> str:
    """The phrases of a verdict as one line: comma separated, a colon introduces the rest."""
    line = ""
    for text, _style in items:
        if not line:
            line = text
        elif line.endswith((":", ";")):
            line += f" {text}"
        else:
            line += f", {text}"
    return line


def verdict_line(report: ThreatReport) -> str:
    """One line that says where the scan landed: ``3 critical, 14 high, 2 attack paths from ...``.

    Markdown, the terminal report and Bitbucket all print this one, so they never disagree.
    """
    return join_verdict(verdict_items(report))


def set_aside_phrase(findings: int, paths: int) -> str:
    """``6 findings and 2 attack paths``; ``findings`` and ``paths`` are counts."""
    return join_words(
        [
            *([plural(findings, "finding")] if findings else []),
            *([plural(paths, "attack path")] if paths else []),
        ]
    )


def _nothing_left(report: ThreatReport) -> str:
    cov = report.coverage
    baselined = set_aside_phrase(cov.baselined - cov.baselined_paths, cov.baselined_paths)
    if baselined:
        return f"no new findings ({baselined} baselined)"
    if cov.hidden_findings or cov.hidden_paths:
        hidden = set_aside_phrase(cov.hidden_findings, cov.hidden_paths)
        return f"no findings at or above {cov.min_severity} ({hidden} hidden by --min-severity)"
    return "no findings"


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


def display_path(
    raw: str,
    *,
    cwd: str | os.PathLike[str] | None = None,
    root: str | os.PathLike[str] | None = None,
) -> str:
    """``raw`` as a report names a scanned path: the way it was typed, never absolute, never ``.``.

    A relative path is normalised (``./infra/`` is ``infra``) and kept as typed, so the directory
    a file sits in is not lost.
    An absolute path inside the current directory becomes relative to it, so a report made on one
    machine does not carry the home directory of the person who ran it.
    One outside it is shown relative to ``root`` (the common parent of everything scanned) when
    that is given and the path is inside it, and is otherwise reduced to its own name.
    The current directory itself, and a path that is only ``..``, is named by its directory name,
    because ``.`` says nothing about what was scanned.
    """
    base = os.path.abspath(cwd) if cwd is not None else os.getcwd()
    absolute = os.path.abspath(os.path.join(base, raw))
    text = os.path.normpath(raw).replace(os.sep, "/")
    if os.path.isabs(raw):
        text = _inside(absolute, base)
        if not text and root is not None:
            anchor = os.path.abspath(root)
            text = _inside(absolute, anchor)
            if text == ".":
                return PurePosixPath(anchor.replace(os.sep, "/")).name or "/"
    if text in ("", ".", ".."):
        return PurePosixPath(absolute.replace(os.sep, "/")).name or "/"
    return text


def _inside(absolute: str, base: str) -> str:
    """``absolute`` relative to ``base`` as a POSIX path, or ``""`` when it is not inside."""
    try:
        relative = os.path.relpath(absolute, base).replace(os.sep, "/")
    except ValueError:  # another drive on Windows
        return ""
    return "" if relative == ".." or relative.startswith("../") else relative


def input_summary(label: str, *, limit: int = 60) -> str:
    """The inputs of a scan in a few words: ``infra``, ``a.tf and b.tf`` or ``a.tf and 2 more``.

    ``label`` is ``ThreatReport.input_file``, the inputs joined with ``, ``.
    One input that is longer than ``limit`` keeps its end, because that is the part that names it.
    """
    parts = [part for part in label.split(", ") if part]
    if len(parts) == 2 and len(label) <= limit:
        return f"{parts[0]} and {parts[1]}"
    if len(parts) > 1:
        return f"{_keep_end(parts[0], limit - 12)} and {len(parts) - 1} more"
    return _keep_end(parts[0], limit) if parts else ""


def _keep_end(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return ELLIPSIS + text[len(text) - max(limit - 1, 1) :]


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


def threat_source(
    threat: Threat, graph: InfraGraph | None = None
) -> tuple[str, int | None, int | None]:
    """The file and lines a finding sits on: its own location, else the node it is about.

    Returns ``("", None, None)`` when neither knows.
    """
    if threat.location_file:
        return threat.location_file, threat.location_start_line, threat.location_end_line
    node = graph.get_node(threat.resource_address) if graph is not None else None
    if node is not None and node.source_file:
        return node.source_file, node.start_line, node.end_line
    return "", None, None
