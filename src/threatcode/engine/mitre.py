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
    "T1611": {
        "name": "Escape to Host",
        "tactic_ids": ["TA0004"],
        "url": "https://attack.mitre.org/techniques/T1611/",
    },
    "T1610": {
        "name": "Deploy Container",
        "tactic_ids": ["TA0002", "TA0005"],
        "url": "https://attack.mitre.org/techniques/T1610/",
    },
    "T1552.001": {
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic_ids": ["TA0006"],
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
    "T1195.002": {
        "name": "Supply Chain Compromise: Compromise Software Supply Chain",
        "tactic_ids": ["TA0001"],
        "url": "https://attack.mitre.org/techniques/T1195/002/",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic_ids": ["TA0008"],
        "url": "https://attack.mitre.org/techniques/T1021/",
    },
    "T1528": {
        "name": "Steal Application Access Token",
        "tactic_ids": ["TA0006"],
        "url": "https://attack.mitre.org/techniques/T1528/",
    },
    "T1565.001": {
        "name": "Data Manipulation: Stored Data Manipulation",
        "tactic_ids": ["TA0040"],
        "url": "https://attack.mitre.org/techniques/T1565/001/",
    },
    "T1613": {
        "name": "Container and Resource Discovery",
        "tactic_ids": ["TA0007"],
        "url": "https://attack.mitre.org/techniques/T1613/",
    },
    "T1609": {
        "name": "Container Administration Command",
        "tactic_ids": ["TA0002"],
        "url": "https://attack.mitre.org/techniques/T1609/",
    },
    "T1552": {
        "name": "Unsecured Credentials",
        "tactic_ids": ["TA0006"],
        "url": "https://attack.mitre.org/techniques/T1552/",
    },
    "T1195": {
        "name": "Supply Chain Compromise",
        "tactic_ids": ["TA0001"],
        "url": "https://attack.mitre.org/techniques/T1195/",
    },
    "T1565": {
        "name": "Data Manipulation",
        "tactic_ids": ["TA0040"],
        "url": "https://attack.mitre.org/techniques/T1565/",
    },
    "T1548": {
        "name": "Abuse Elevation Control Mechanism",
        "tactic_ids": ["TA0004", "TA0005"],
        "url": "https://attack.mitre.org/techniques/T1548/",
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic_ids": ["TA0002", "TA0003", "TA0004"],
        "url": "https://attack.mitre.org/techniques/T1053/",
    },
    "T1068": {
        "name": "Exploitation for Privilege Escalation",
        "tactic_ids": ["TA0004"],
        "url": "https://attack.mitre.org/techniques/T1068/",
    },
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
