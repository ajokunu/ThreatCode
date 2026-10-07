"""CVSS v3 base scores from vector strings.

OSV advisories often carry only the vector (``CVSS:3.1/AV:N/AC:L/...``), so the score that maps to
a severity has to be computed.
Only CVSS v3.0 and v3.1 are supported; a vector of another version, or a malformed one, has no score
here and the caller falls back to the advisory's own severity label.
"""

from __future__ import annotations

import math

__all__ = ["cvss3_base_score"]

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 Roundup: the smallest number with one decimal that is not below ``value``."""
    scaled = round(value * 100000)
    if scaled % 10000 == 0:
        return scaled / 100000.0
    return (math.floor(scaled / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """The base score of a CVSS v3.0 or v3.1 vector, or ``None`` when it cannot be computed."""
    parts = vector.strip().split("/")
    if not parts or parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")
        if not sep or key in metrics:
            return None
        metrics[key] = value
    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
    except KeyError:
        return None
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    if impact <= 0:
        return 0.0
    total = impact + exploitability
    return _roundup(min(1.08 * total if scope_changed else total, 10.0))
