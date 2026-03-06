# MITRE ATT&CK Integration

ThreatCode maps every finding to the [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/), giving every threat a globally recognized technique and tactic ID.

---

## Coverage

ThreatCode covers **25 ATT&CK techniques** across **12 tactics**:

| Tactic | ID | Techniques Covered |
|--------|----|--------------------|
| Initial Access | TA0001 | T1078, T1078.004, T1190, T1195, T1195.002 |
| Execution | TA0002 | T1609, T1610 |
| Persistence | TA0003 | T1078, T1098 |
| Privilege Escalation | TA0004 | T1068, T1548, T1078.004, T1611 |
| Defense Evasion | TA0005 | T1562.008 |
| Credential Access | TA0006 | T1552, T1552.001 |
| Discovery | TA0007 | T1046, T1580, T1613 |
| Lateral Movement | TA0008 | T1021 |
| Collection | TA0009 | T1530, T1528, T1565, T1565.001 |
| Exfiltration | TA0010 | T1537 |
| Command & Control | TA0011 | T1021 |
| Impact | TA0040 | T1485, T1499 |

---

## STRIDE → ATT&CK Mapping

| STRIDE Category | ATT&CK Tactics |
|-----------------|---------------|
| Spoofing | TA0001 (Initial Access), TA0006 (Credential Access) |
| Tampering | TA0040 (Impact) |
| Repudiation | TA0005 (Defense Evasion) |
| Information Disclosure | TA0009 (Collection), TA0010 (Exfiltration) |
| Denial of Service | TA0040 (Impact) |
| Elevation of Privilege | TA0004 (Privilege Escalation) |

---

## How Technique IDs Are Assigned

**1. Built-in rule metadata** — Every built-in rule specifies techniques and tactics directly:

```yaml
metadata:
  mitre:
    techniques: ["T1530"]
    tactics: ["TA0009"]
```

**2. Trust boundary crossing detection** — Boundary crossing findings get default techniques T1040 (Network Sniffing) and T1557 (Adversary-in-the-Middle).

**3. LLM-generated threats** — The LLM is prompted to return MITRE technique IDs. All IDs are validated against `TECHNIQUE_DB` and `TACTIC_DB` before being included in findings — invalid IDs are rejected.

**4. STRIDE fallback** — If no explicit techniques are specified, the STRIDE-to-tactic mapping above is used to populate `mitre_tactics`.

---

## ATT&CK Navigator Export

Export a layer JSON file for visualization in the MITRE ATT&CK Navigator:

```bash
threatcode scan tfplan.json --no-llm --format matrix -o layer.json
```

Load `layer.json` at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).

### Layer format

```json
{
  "name": "ThreatCode Threat Model",
  "versions": {"attack": "16", "navigator": "5.1", "layer": "4.5"},
  "domain": "enterprise-attack",
  "techniques": [
    {
      "techniqueID": "T1530",
      "score": 75,
      "color": "#ff6600",
      "comment": "3 finding(s): S3 no encryption, S3 public access, ...",
      "metadata": [{"name": "findings", "value": "3"}]
    }
  ]
}
```

### Severity → color mapping

| Severity | Score | Color |
|----------|-------|-------|
| Critical | 100 | `#ff0000` (red) |
| High | 75 | `#ff6600` (orange) |
| Medium | 50 | `#ffcc00` (yellow) |
| Low | 25 | `#66ccff` (blue) |
| Info | 10 | `#cccccc` (gray) |

When multiple findings map to the same technique, the highest severity determines the color. The score reflects the highest severity finding.

---

## Technique Reference

Selected techniques frequently detected by ThreatCode:

| ID | Name | Detected By |
|----|------|-------------|
| T1530 | Data from Cloud Storage | S3/Blob without encryption or public access rules |
| T1537 | Transfer Data to Cloud Account | CloudTrail disabled, no logging |
| T1580 | Cloud Infrastructure Discovery | Overly permissive IAM with `*:*` actions |
| T1078.004 | Valid Accounts: Cloud Accounts | IAM without MFA, overly broad assume-role |
| T1190 | Exploit Public-Facing Application | RDS/Elasticsearch publicly accessible |
| T1562.008 | Disable Cloud Logs | CloudTrail/CloudWatch disabled |
| T1611 | Escape to Host | Kubernetes privileged container |
| T1610 | Deploy Container | Kubernetes missing securityContext |
| T1552.001 | Credentials in Files | Secrets in ENV variables, Dockerfiles |
| T1195.002 | Supply Chain Compromise: Software | Outdated/vulnerable dependencies |
| T1068 | Exploitation for Privilege Escalation | Kernel-level capabilities (SYS_ADMIN, etc.) |
| T1548 | Abuse Elevation Control | Privilege escalation allowed in containers |
| T1040 | Network Sniffing | Trust boundary crossing (DMZ → Data) |
| T1557 | Adversary-in-the-Middle | Trust boundary crossing (Internet → Private) |
