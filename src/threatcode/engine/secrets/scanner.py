"""The secret detector core: text in, matches out.

``SecretScanner.scan_text`` runs the rules over the text of one file and returns where each
secret is, never what it is.
It does not walk directories or open files: the scan pipeline reads files through its discovery
units (``engine.secrets.iac``), which is what keeps a symlink or a device file from ever being
opened by a detector.

Properties worth knowing:

* Lines are split on ``\\n`` only (a trailing ``\\r`` is dropped), so a form feed or a Unicode line
  separator inside a line does not shift the line numbers of everything after it.
* The keyword prefilter compares lower-cased text with keywords lower-cased at rule construction.
* A match is the ``secret`` group of the rule's regex.
  Allow-lists, placeholders and templates are judged on that value alone.
* A rule marked ``multiline`` (a PEM block) runs over the whole text instead of line by line, and
  its finding sits on the line where the block starts.
* In a templated file (a Helm template) a generic ``key = value`` match inside a ``{{ }}``
  action is template code, not a literal, and is dropped.
* When two rules match overlapping text on one line, the more specific rule wins: a provider
  token over a credential in a URL or header over a generic ``key = value``.
* The preview of a match is ``[REDACTED <rule id> len=<n>]``: it holds no character of the secret.
* Findings are capped per file and per rule, and the outcome says when it truncated.
"""

from __future__ import annotations

import bisect
import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Literal

from threatcode.engine.secrets.builtin import entropy_rule, get_builtin_rules
from threatcode.engine.secrets.config import MAX_PATTERN_LENGTH, ExtraRule, SecretScanConfig
from threatcode.engine.secrets.rules import KIND_PRIORITY, SecretRule

__all__ = [
    "ScanOutcome",
    "SecretMatch",
    "SecretScanner",
    "decode_secret_text",
    "redact",
]

logger = logging.getLogger(__name__)

# Binary file detection: a NUL in the first 8 KB means binary, unless the file is UTF-16 text
_BINARY_CHECK_SIZE = 8192

_BOMS: tuple[tuple[bytes, str], ...] = (
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)

# A template action, which can span lines: {{ ... }} with the trim markers of Go templates
_TEMPLATE_ACTION = re.compile(r"\{\{.{0,4096}?\}\}", re.DOTALL)

_KEY_BEFORE = re.compile(
    r"""([A-Za-z0-9_.\-\[\]]{1,128})["']?[ \t]{0,32}(?::=|=>|[=:])[ \t]{0,32}["']?\Z"""
)


def redact(rule_id: str, length: int) -> str:
    """The only form in which a secret appears in a report: its rule and its length."""
    return f"[REDACTED {rule_id} len={length}]"


def decode_secret_text(raw: bytes) -> str | None:
    """Decode file bytes to text for scanning; None for binary data.

    A byte order mark selects the codec; UTF-16 without a mark (every other byte NUL, as
    PowerShell redirection writes it) is recognised by that pattern; anything else is UTF-8 with
    invalid bytes replaced.
    """
    for bom, codec in _BOMS:
        if raw.startswith(bom):
            return raw.decode(codec, errors="replace")
    head = raw[:_BINARY_CHECK_SIZE]
    if b"\x00" in head:
        even = head[0::2].count(0)
        odd = head[1::2].count(0)
        pairs = max(len(head) // 2, 1)
        if odd > pairs * 0.3 and even < pairs * 0.1:
            return raw.decode("utf-16-le", errors="replace")
        if even > pairs * 0.3 and odd < pairs * 0.1:
            return raw.decode("utf-16-be", errors="replace")
        return None
    return raw.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class SecretMatch:
    """One secret found in a text: where it is and how to describe it, never its characters.

    ``value`` is kept for the caller's in-memory work (finding the property it sits in,
    collapsing repeats) and is excluded from ``repr`` and comparisons so it is not printed by
    accident.
    """

    rule: SecretRule
    line: int
    column: int
    length: int
    attribute: str
    preview: str
    masked_line: str = field(repr=False, compare=False, default="")
    value: str = field(repr=False, compare=False, default="")


@dataclass
class ScanOutcome:
    """The matches of one text and whether a cap dropped some."""

    matches: list[SecretMatch] = field(default_factory=list)
    truncated: bool = False
    dropped: int = 0


@dataclass
class _Candidate:
    rule: SecretRule
    line: int
    start: int
    end: int
    value: str
    text: str


class SecretScanner:
    """Find hardcoded secrets in text."""

    def __init__(
        self,
        config: SecretScanConfig | None = None,
        extra_rules: Iterable[SecretRule] | None = None,
    ) -> None:
        self.config = config or SecretScanConfig()
        disabled = set(self.config.disabled_rules)
        rules = [r for r in get_builtin_rules() if r.id not in disabled]
        if self.config.entropy_threshold:
            rules.append(entropy_rule(self.config.entropy_threshold))
        for extra in self.config.extra_rules:
            built = _build_extra(extra)
            if built is not None:
                rules.append(built)
        if extra_rules:
            rules.extend(extra_rules)
        self.rules = rules

        self._global_allow: list[re.Pattern[str]] = []
        for pattern in self.config.allow_patterns:
            if len(pattern) > MAX_PATTERN_LENGTH:
                logger.warning("Allow pattern too long (%d chars), skipping", len(pattern))
                continue
            try:
                self._global_allow.append(re.compile(pattern))
            except re.error:
                logger.warning("Invalid allow pattern: %s", pattern)

    def scan_text(self, text: str, *, path: str = "", templated: bool = False) -> ScanOutcome:
        """Scan the text of one file.

        ``path`` is used only for the rules' path filters.
        ``templated`` says the file is a template whose ``{{ }}`` actions are code: a generic
        match inside one is dropped, because ``$secret := .Values.x`` is not a secret.
        """
        lowered = text.lower()
        active = [
            rule
            for rule in self.rules
            if rule.matches_path(path)
            and (not rule.keywords or any(kw in lowered for kw in rule.keywords))
            and (rule.requires is None or rule.requires.search(text))
        ]
        if not active:
            return ScanOutcome()

        lines = text.split("\n")
        lower_lines = lowered.split("\n")
        if len(lower_lines) != len(lines):  # lower() never changes the line count; stay safe
            lower_lines = [line.lower() for line in lines]
        actions = _template_actions(text) if templated else []
        starts = _line_starts(lines) if actions else []
        candidates: list[_Candidate] = []
        # Stop collecting once a rule has far more candidates than can be reported, so a file of
        # repeated matches costs a bounded amount of work instead of a quadratic one.
        limit = 2 * max(self.config.max_findings_per_file, self.config.max_findings_per_rule)
        flooded = False
        for rule in active:
            collected = 0
            if rule.multiline:
                found = self._multiline_candidates(rule, text, lines, limit)
                collected = len(found)
                candidates.extend(found)
                flooded = flooded or collected >= limit
                continue
            for index, raw in enumerate(lines):
                if collected >= limit:
                    flooded = True
                    break
                if rule.keywords and not any(kw in lower_lines[index] for kw in rule.keywords):
                    continue
                line = raw[:-1] if raw.endswith("\r") else raw
                for match in rule.regex.finditer(line):
                    value, start, end = rule.secret_of(match)
                    quoted = "q" in match.re.groupindex and match.group("q") is not None
                    host = match.group("host") if "host" in match.re.groupindex else ""
                    if not rule.accepts(value, quoted=quoted, host=host or ""):
                        continue
                    if any(allow.search(value) for allow in self._global_allow):
                        continue
                    if (
                        actions
                        and rule.kind == "generic"
                        and _in_action(actions, starts[index] + start)
                    ):
                        continue
                    candidates.append(_Candidate(rule, index + 1, start, end, value, line))
                    collected += 1
                    if collected >= limit:
                        flooded = True
                        break
        outcome = self._finish(candidates)
        if flooded:
            outcome.truncated = True
            outcome.dropped = max(outcome.dropped, 1)
        return outcome

    def _multiline_candidates(
        self, rule: SecretRule, text: str, lines: Sequence[str], limit: int
    ) -> list[_Candidate]:
        """The matches of a rule that spans lines, each placed on the line where it starts."""
        found: list[_Candidate] = []
        starts: list[int] | None = None
        for match in rule.regex.finditer(text):
            if rule.verify is not None and not rule.verify(match):
                continue
            value, begin, _end = rule.secret_of(match)
            if not rule.accepts(value, quoted=True):
                continue
            if any(allow.search(value) for allow in self._global_allow):
                continue
            if starts is None:
                starts = _line_starts(lines)
            index = bisect.bisect_right(starts, begin) - 1
            raw = lines[index]
            line = raw[:-1] if raw.endswith("\r") else raw
            column = begin - starts[index]
            found.append(_Candidate(rule, index + 1, column, len(line), value, line))
            if len(found) >= limit:
                break
        return found

    # -- selection -----------------------------------------------------------------------------

    def _finish(self, candidates: Sequence[_Candidate]) -> ScanOutcome:
        """Drop overlapping matches (the more specific rule wins), then apply the caps."""
        ordered = sorted(
            candidates,
            key=lambda c: (c.line, KIND_PRIORITY[c.rule.kind], c.start, c.rule.id),
        )
        kept: list[_Candidate] = []
        spans: dict[int, list[tuple[int, int]]] = {}
        for cand in ordered:
            taken = spans.setdefault(cand.line, [])
            if any(cand.start < end and start < cand.end for start, end in taken):
                continue
            taken.append((cand.start, cand.end))
            kept.append(cand)
        kept.sort(key=lambda c: (c.line, c.start, c.rule.id))

        outcome = ScanOutcome()
        per_rule: dict[str, int] = {}
        for cand in kept:
            seen = per_rule.get(cand.rule.id, 0)
            if (
                len(outcome.matches) >= self.config.max_findings_per_file
                or seen >= self.config.max_findings_per_rule
            ):
                outcome.truncated = True
                outcome.dropped += 1
                continue
            per_rule[cand.rule.id] = seen + 1
            outcome.matches.append(_to_match(cand))
        return outcome


def _line_starts(lines: Sequence[str]) -> list[int]:
    """The offset of the first character of each line of a text split on newlines."""
    starts: list[int] = []
    offset = 0
    for line in lines:
        starts.append(offset)
        offset += len(line) + 1
    return starts


def _template_actions(text: str) -> list[tuple[int, int]]:
    """The spans of the ``{{ }}`` actions of a template, in order."""
    return [match.span() for match in _TEMPLATE_ACTION.finditer(text)]


def _in_action(actions: Sequence[tuple[int, int]], offset: int) -> bool:
    """Whether a character offset sits inside one of the (sorted, disjoint) action spans."""
    where = bisect.bisect_right(actions, (offset, offset)) - 1
    return where >= 0 and actions[where][0] <= offset < actions[where][1]


def _to_match(cand: _Candidate) -> SecretMatch:
    length = len(cand.value)
    return SecretMatch(
        rule=cand.rule,
        line=cand.line,
        column=cand.start + 1,
        length=length,
        attribute=_attribute(cand),
        preview=redact(cand.rule.id, length),
        masked_line=_mask_line(cand),
        value=cand.value,
    )


def _attribute(cand: _Candidate) -> str:
    """The key the secret is assigned to, when the text says (``MasterUserPassword``)."""
    if not cand.rule.keyed:
        return ""
    found = _KEY_BEFORE.search(cand.text[max(0, cand.start - 192) : cand.start])
    return found.group(1).strip(".") if found else ""


def _mask_line(cand: _Candidate) -> str:
    """The line with the secret replaced, so it can be hashed without holding the secret."""
    masked = cand.text[: cand.start] + "*" + cand.text[cand.end :]
    return " ".join(masked.split())[:400]


def _build_extra(extra: ExtraRule) -> SecretRule | None:
    try:
        regex = re.compile(extra.regex)
    except re.error:
        return None
    rule_id = extra.id if extra.id.startswith("SECRET_") else f"SECRET_{extra.id}"
    levels: dict[str, Literal["critical", "high", "medium", "low"]] = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
    }
    severity = levels.get(extra.severity, "high")
    return SecretRule(
        id=rule_id,
        category="custom",
        title=extra.title or rule_id,
        severity=severity,
        regex=regex,
        keywords=list(extra.keywords),
        kind="provider",
    )
