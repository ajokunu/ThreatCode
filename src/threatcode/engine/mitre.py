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
    "PATH_TECHNIQUES",
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
# Boundary threats no longer read them: `engine.boundaries` derives the techniques of a crossing
# from its zone pair and from what the flow declares. They stay because the mitre tests pin them.
BOUNDARY_TECHNIQUES: list[str] = ["T1040", "T1557"]
BOUNDARY_TACTICS: list[str] = ["TA0006", "TA0009"]


# The ATT&CK techniques the steps of an attack path use, by the kind of step.
# Every value is validated against TECHNIQUE_DB by the tests
PATH_TECHNIQUES: dict[str, str] = {
    # The first hop reaches an exposed application, or an exposed remote administration service
    "exposed_application": "T1190",
    "exposed_remote_service": "T1133",
    # A hop whose instance still answers the session-less metadata service (EC2_IMDSV1)
    "instance_metadata": "T1552.005",
    # A hop that assumes a role
    "role_assumption": "T1078.004",
    # A hop that reads a bucket or another cloud storage
    "cloud_storage_data": "T1530",
    # A hop that reads a Kubernetes Secret through the API or a mount
    "container_secret": "T1552.007",
    # A privileged container, which can leave its container for the host
    "container_escape": "T1611",
    # Untrusted content reaches an AI agent through one of its servers
    "content_injection": "T1659",
    # An MCP server that reads files of the local system, and credentials among them
    "local_data": "T1005",
    "credentials_in_files": "T1552.001",
}


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
