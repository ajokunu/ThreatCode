"""Stable fingerprints: the identity of a finding across runs, machines and rewordings.

A fingerprint is the first 16 hex characters of a SHA-256 over four parts:

1. the kind of finding (``Threat.source``: rule, boundary, secret, scanner or llm);
2. the rule id, or for a finding without one the boundary key (``metadata['boundary_key']`` when a
   producer sets it, else the threat id, which for a boundary finding already names the two
   resources it connects);
3. the resource address, or ``metadata['fingerprint_hint']`` when the producer sets one (the secret
   detectors use it so a moved secret keeps its identity);
4. the root-relative POSIX path of the source file (on Windows, a file on another drive than the
   root is named by the drive and its place under the inputs on that drive, never by an
   absolute path).

Property values are not part of it, so editing a resource's settings does not change which finding
it is, which is what makes baselines and ``diff`` useful.
Threat ids are unchanged and keep their own meaning.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import TYPE_CHECKING

from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

__all__ = ["FINGERPRINT_LENGTH", "assign_fingerprints", "compute_fingerprint"]

FINGERPRINT_LENGTH = 16
_SEPARATOR = "\x1f"


def compute_fingerprint(threat: Threat, source_file: str = "") -> str:
    """Fingerprint of ``threat``; ``source_file`` defaults to the threat's own location."""
    kind = threat.source.value
    key = threat.rule_id or str(threat.metadata.get("boundary_key") or "") or threat.id
    hint = threat.metadata.get("fingerprint_hint")
    address = str(hint) if hint else threat.resource_address
    path = (source_file or threat.location_file).replace("\\", "/")
    digest = hashlib.sha256(_SEPARATOR.join((kind, key, address, path)).encode()).hexdigest()
    return digest[:FINGERPRINT_LENGTH]


def assign_fingerprints(threats: Iterable[Threat], graph: InfraGraph | None = None) -> None:
    """Set ``fingerprint`` on every threat, in place.

    The source file comes from the threat's own location, else from the graph node at its
    resource address.
    """
    for threat in threats:
        source_file = threat.location_file
        if not source_file and graph is not None:
            node = graph.get_node(threat.resource_address)
            source_file = node.source_file if node is not None else ""
        threat.fingerprint = compute_fingerprint(threat, source_file)
