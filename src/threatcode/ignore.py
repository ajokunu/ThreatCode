""".threatcodeignore file parser."""

from __future__ import annotations

import logging
from datetime import date
from pathlib import Path

logger = logging.getLogger(__name__)


def load_ignore_ids(
    search_dir: Path | None = None,
    ignore_path: Path | None = None,
) -> frozenset[str]:
    """Load suppressed finding IDs from a .threatcodeignore file.

    The file format is one ID per line:
      - Lines starting with ``#`` are comments
      - Blank lines are skipped
      - An optional ``exp:YYYY-MM-DD`` suffix sets an expiration date
      - After the expiration date, the ID is no longer suppressed

    Example .threatcodeignore::

        # Suppress a CVE that has been accepted
        CVE-2023-12345
        # Suppress a rule with an expiration
        TC-DOCKER-001  exp:2026-06-01
        # Secret rule suppression
        SECRET-aws-access-key  exp:2026-12-31

    Args:
        search_dir: Directory to search for ``.threatcodeignore`` (defaults to cwd).
        ignore_path: Explicit path to the ignore file. Overrides search_dir.

    Returns:
        Frozen set of active (non-expired) IDs to suppress.
    """
    if ignore_path is None:
        base = search_dir or Path.cwd()
        ignore_path = base / ".threatcodeignore"

    if not ignore_path.is_file():
        return frozenset()

    today = date.today()
    ids: set[str] = set()

    try:
        content = ignore_path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("Could not read %s: %s", ignore_path, e)
        return frozenset()

    for line_num, raw_line in enumerate(content.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        rule_id = parts[0]

        # Check for expiration
        expired = False
        for part in parts[1:]:
            if part.startswith("exp:"):
                try:
                    exp_date = date.fromisoformat(part[4:])
                    if today > exp_date:
                        expired = True
                        logger.debug(
                            "%s:%d — %s expired on %s, not suppressing",
                            ignore_path,
                            line_num,
                            rule_id,
                            exp_date,
                        )
                except ValueError:
                    logger.warning(
                        "%s:%d — invalid expiration date: %s",
                        ignore_path,
                        line_num,
                        part,
                    )

        if not expired:
            ids.add(rule_id)

    if ids:
        logger.debug("Loaded %d ignore rules from %s", len(ids), ignore_path)

    return frozenset(ids)


def apply_ignore(
    findings: list[dict[str, object]],
    ignore_ids: frozenset[str],
    id_key: str = "id",
) -> list[dict[str, object]]:
    """Remove findings whose ID is in the ignore set.

    Args:
        findings: List of finding dicts.
        ignore_ids: Set of IDs to suppress.
        id_key: Key in each finding dict that holds the ID.

    Returns:
        Filtered list with suppressed findings removed.
    """
    if not ignore_ids:
        return findings
    return [f for f in findings if str(f.get(id_key, "")) not in ignore_ids]
