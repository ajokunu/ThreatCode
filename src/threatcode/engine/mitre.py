"""MITRE ATT&CK reference data and lookups.

The data lives in the generated module ``mitre_data`` (built from the official enterprise-attack
STIX bundle by ``scripts/gen_mitre_db.py``).
This module is the stable API over it.
Revoked and deprecated techniques stay in ``TECHNIQUE_DB`` with their flags, so rules and user
input that still carry an old ID keep resolving; ``normalize_technique`` maps them to the
current ID.
"""

from __future__ import annotations

from threatcode.engine.mitre_data import (
    ATTACK_SOURCE_URL,
    ATTACK_VERSION,
    REVOKED_ALIASES,
    TACTICS,
    TECHNIQUES,
    TacticEntry,
    TechniqueEntry,
)

__all__ = [
    "ATTACK_SOURCE_URL",
    "ATTACK_VERSION",
    "BOUNDARY_TACTICS",
    "BOUNDARY_TECHNIQUES",
    "REVOKED_ALIASES",
    "TACTIC_DB",
    "TACTIC_SHORTNAME",
    "TECHNIQUE_DB",
    "TacticEntry",
    "TechniqueEntry",
    "is_deprecated",
    "is_revoked",
    "lookup_tactic",
    "lookup_technique",
    "normalize_technique",
    "tactic_shortname",
    "tactics_for_techniques",
]

# ATT&CK tactics keyed by TA id: {name, shortname, url}.
TACTIC_DB: dict[str, TacticEntry] = TACTICS

# Every enterprise technique and sub-technique, including revoked and deprecated entries:
# {name, tactic_ids, url, platforms, deprecated, revoked, revoked_by}.
TECHNIQUE_DB: dict[str, TechniqueEntry] = TECHNIQUES

# TA id -> ATT&CK Navigator tactic shortname (for example "TA0001" -> "initial-access").
TACTIC_SHORTNAME: dict[str, str] = {ta_id: t["shortname"] for ta_id, t in TACTICS.items()}

# Default MITRE techniques for trust boundary crossings.
# Their redesign belongs to the boundary work, so the values stay as they were.
BOUNDARY_TECHNIQUES: list[str] = ["T1040", "T1557"]
BOUNDARY_TACTICS: list[str] = ["TA0006", "TA0009"]


def lookup_technique(technique_id: str) -> TechniqueEntry | None:
    """Look up a technique by ID. Returns None if not found."""
    return TECHNIQUE_DB.get(technique_id)


def lookup_tactic(tactic_id: str) -> TacticEntry | None:
    """Look up a tactic by ID. Returns None if not found."""
    return TACTIC_DB.get(tactic_id)


def tactic_shortname(tactic_id: str) -> str | None:
    """Navigator shortname for a TA id, or None for an unknown tactic."""
    return TACTIC_SHORTNAME.get(tactic_id)


def normalize_technique(technique_id: str) -> str:
    """Map a revoked technique ID to the ID that replaced it.

    Follows revoked-by chains to the current ID.
    IDs that are current, deprecated without a replacement or unknown come back unchanged.
    """
    seen = {technique_id}
    current = technique_id
    while current in REVOKED_ALIASES:
        current = REVOKED_ALIASES[current]
        if current in seen:  # defensive: a cycle in the data must not hang the caller
            break
        seen.add(current)
    return current


def is_revoked(technique_id: str) -> bool:
    """True when ATT&CK has revoked this technique ID (it was replaced or folded in)."""
    tech = TECHNIQUE_DB.get(technique_id)
    return bool(tech and tech["revoked"])


def is_deprecated(technique_id: str) -> bool:
    """True when ATT&CK has deprecated this technique ID without a replacement."""
    tech = TECHNIQUE_DB.get(technique_id)
    return bool(tech and tech["deprecated"])


def tactics_for_techniques(technique_ids: list[str]) -> list[str]:
    """Derive unique tactic IDs from a list of technique IDs."""
    tactics: set[str] = set()
    for tid in technique_ids:
        tech = TECHNIQUE_DB.get(tid)
        if tech:
            tactics.update(tech["tactic_ids"])
    return sorted(tactics)
