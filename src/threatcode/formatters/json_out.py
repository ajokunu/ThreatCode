"""Raw JSON output formatter."""

from __future__ import annotations

import json

from threatcode.models.report import ThreatReport


def format_json(report: ThreatReport, indent: int = 2) -> str:
    """Format threat report as JSON string."""
    return json.dumps(report.to_dict(), indent=indent, sort_keys=False)
