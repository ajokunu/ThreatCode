"""MITRE ATT&CK Cloud Matrix reference data and lookups."""

from __future__ import annotations

# ATT&CK Tactic definitions (Cloud Matrix)
TACTIC_DB: dict[str, dict[str, str]] = {
    "TA0001": {"name": "Initial Access", "url": "https://attack.mitre.org/tactics/TA0001/"},
    "TA0002": {"name": "Execution", "url": "https://attack.mitre.org/tactics/TA0002/"},
    "TA0003": {"name": "Persistence", "url": "https://attack.mitre.org/tactics/TA0003/"},
    "TA0004": {"name": "Privilege Escalation", "url": "https://attack.mitre.org/tactics/TA0004/"},
    "TA0005": {"name": "Defense Evasion", "url": "https://attack.mitre.org/tactics/TA0005/"},
    "TA0006": {"name": "Credential Access", "url": "https://attack.mitre.org/tactics/TA0006/"},
    "TA0007": {"name": "Discovery", "url": "https://attack.mitre.org/tactics/TA0007/"},
    "TA0008": {"name": "Lateral Movement", "url": "https://attack.mitre.org/tactics/TA0008/"},
    "TA0009": {"name": "Collection", "url": "https://attack.mitre.org/tactics/TA0009/"},
    "TA0010": {"name": "Exfiltration", "url": "https://attack.mitre.org/tactics/TA0010/"},
    "TA0011": {"name": "Command and Control", "url": "https://attack.mitre.org/tactics/TA0011/"},
    "TA0040": {"name": "Impact", "url": "https://attack.mitre.org/tactics/TA0040/"},
}

# ATT&CK Technique definitions relevant to cloud IaC threats
TECHNIQUE_DB: dict[str, dict[str, str | list[str]]] = {
    "T1040": {
        "name": "Network Sniffing",
        "tactic_ids": ["TA0006", "TA0007"],
        "url": "https://attack.mitre.org/techniques/T1040/",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic_ids": ["TA0007"],
        "url": "https://attack.mitre.org/techniques/T1046/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "T1078.004": {
        "name": "Valid Accounts: Cloud Accounts",
        "tactic_ids": ["TA0001", "TA0003", "TA0004", "TA0005"],
        "url": "https://attack.mitre.org/techniques/T1078/004/",
    },
    "T1098": {
        "name": "Account Manipulation",
        "tactic_ids": ["TA0003", "TA0004"],
        "url": "https://attack.mitre.org/techniques/T1098/",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic_ids": ["TA0001"],
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1485": {
        "name": "Data Destruction",
        "tactic_ids": ["TA0040"],
        "url": "https://attack.mitre.org/techniques/T1485/",
    },
    "T1499": {
        "name": "Endpoint Denial of Service",
        "tactic_ids": ["TA0040"],
        "url": "https://attack.mitre.org/techniques/T1499/",
    },
    "T1530": {
        "name": "Data from Cloud Storage",
        "tactic_ids": ["TA0009"],
        "url": "https://attack.mitre.org/techniques/T1530/",
    },
    "T1537": {
        "name": "Transfer Data to Cloud Account",
        "tactic_ids": ["TA0010"],
        "url": "https://attack.mitre.org/techniques/T1537/",
    },
    "T1557": {
        "name": "Adversary-in-the-Middle",
        "tactic_ids": ["TA0006", "TA0009"],
        "url": "https://attack.mitre.org/techniques/T1557/",
    },
    "T1562.008": {
        "name": "Impair Defenses: Disable or Modify Cloud Logs",
        "tactic_ids": ["TA0005"],
        "url": "https://attack.mitre.org/techniques/T1562/008/",
    },
    "T1580": {
        "name": "Cloud Infrastructure Discovery",
        "tactic_ids": ["TA0007"],
        "url": "https://attack.mitre.org/techniques/T1580/",
    },
}

# STRIDE category -> default ATT&CK tactic IDs
STRIDE_TO_TACTICS: dict[str, list[str]] = {
    "spoofing": ["TA0001", "TA0006"],
    "tampering": ["TA0040"],
    "repudiation": ["TA0005"],
    "information_disclosure": ["TA0009", "TA0010"],
    "denial_of_service": ["TA0040"],
    "elevation_of_privilege": ["TA0004"],
}

# Default MITRE techniques for trust boundary crossings
BOUNDARY_TECHNIQUES: list[str] = ["T1040", "T1557"]
BOUNDARY_TACTICS: list[str] = ["TA0006", "TA0009"]


def lookup_technique(technique_id: str) -> dict[str, str | list[str]] | None:
    """Look up a technique by ID. Returns None if not found."""
    return TECHNIQUE_DB.get(technique_id)


def lookup_tactic(tactic_id: str) -> dict[str, str] | None:
    """Look up a tactic by ID. Returns None if not found."""
    return TACTIC_DB.get(tactic_id)


def tactics_for_techniques(technique_ids: list[str]) -> list[str]:
    """Derive unique tactic IDs from a list of technique IDs."""
    tactics: set[str] = set()
    for tid in technique_ids:
        tech = TECHNIQUE_DB.get(tid)
        if tech:
            tactic_ids = tech.get("tactic_ids", [])
            if isinstance(tactic_ids, list):
                tactics.update(tactic_ids)
    return sorted(tactics)
