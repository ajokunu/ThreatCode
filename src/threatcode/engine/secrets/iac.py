"""Secret findings placed on the resources of a scan.

``find_secrets(units, graph)`` is the call the scan pipeline makes once per scan, after the graph is
built.
``units`` are the ``ScanUnit`` objects of ``threatcode.discovery``: each carries the absolute
``path`` to read, the root-relative POSIX ``relpath``, its ``kind`` and, once parsed, the
``ParsedOutput`` in ``parsed``.
Files are read only through these units, so a symlinked or special file the walker skipped is never
opened.
Findings are ``Threat`` objects with ``source`` set to ``ThreatSource.SECRET``, a root-relative
``location_file`` and the address of the resource that holds the secret.

The detectors arrive with the secrets package; until then no findings are produced.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.discovery import ScanUnit
    from threatcode.ir.graph import InfraGraph

__all__ = ["find_secrets"]


def find_secrets(units: Sequence[ScanUnit], graph: InfraGraph) -> list[Threat]:
    """Return the secret findings in the text of the modeled files of ``units``."""
    return []
