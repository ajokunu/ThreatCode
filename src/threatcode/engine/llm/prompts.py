"""System prompt and analysis prompt builder for LLM threat analysis."""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """You are an expert cloud security architect performing STRIDE threat modeling.
You analyze infrastructure graphs and identify security threats that rule-based scanning might miss.

STRIDE categories:
- Spoofing: Authentication threats, identity forgery
- Tampering: Unauthorized data/code modification
- Repudiation: Inability to trace actions, missing audit trails
- Information Disclosure: Data exposure, confidentiality breaches
- Denial of Service: Availability degradation
- Elevation of Privilege: Unauthorized capability gain

Guidelines:
1. Focus on architectural threats, not just misconfiguration (rules already catch those).
2. Look for: implicit trust relationships, missing defense-in-depth, attack paths across resources.
3. Consider the BLAST RADIUS of each threat — how far can an attacker move laterally?
4. Assign severity based on impact and exploitability.
5. Provide actionable, specific mitigations.

IMPORTANT: Resource addresses may contain redacted values (REDACTED_*). This is intentional.
Do NOT attempt to guess or reconstruct redacted values.

Respond ONLY with valid JSON in this exact format:
{
  "threats": [
    {
      "title": "Brief threat title",
      "description": "Detailed description of the threat scenario",
      "stride_category": "spoofing|tampering|repudiation|...|elevation_of_privilege",
      "severity": "critical|high|medium|low|info",
      "resource_type": "aws_resource_type",
      "resource_address": "resource.address.from.graph",
      "mitigation": "Specific remediation steps",
      "confidence": 0.0-1.0
    }
  ]
}"""


def build_analysis_prompt(
    graph_data: dict[str, Any],
    existing_rule_ids: set[str],
) -> str:
    """Build the analysis prompt with graph context."""
    graph_json = json.dumps(graph_data, indent=2)

    existing_note = ""
    if existing_rule_ids:
        existing_note = (
            f"\n\nThe following rule-based threats have already been identified: "
            f"{', '.join(sorted(existing_rule_ids))}. "
            f"Focus on architectural and cross-resource threats that rules cannot detect."
        )

    return f"""Analyze this infrastructure graph for STRIDE threats.{existing_note}

Infrastructure Graph:
```json
{graph_json}
```

Identify threats that require architectural analysis — implicit trust, missing segmentation,
lateral movement paths, data exposure through service interactions, etc.
Do NOT duplicate threats that simple property-checking rules would already catch."""
