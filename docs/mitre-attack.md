# MITRE ATT&CK Integration

ThreatCode maps every threat finding to the [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/), linking infrastructure misconfigurations and architectural weaknesses to real-world adversary techniques.

## How Technique IDs Are Mapped

Each built-in YAML rule includes a `metadata.mitre` block that specifies the relevant ATT&CK technique IDs and tactic IDs. When a rule matches a resource, those IDs are carried through to the output.

For trust boundary crossing findings (`source: boundary`), ThreatCode assigns default techniques: **T1040** (Network Sniffing) and **T1557** (Adversary-in-the-Middle).

For LLM-generated findings, the LLM is prompted to include MITRE technique and tactic IDs when applicable. If the LLM provides technique IDs but omits tactic IDs, ThreatCode automatically derives the tactics from its built-in technique database.

---

## Rule-to-ATT&CK Mapping Table

| Rule ID | Rule Title | Techniques | Tactics |
|---------|-----------|------------|---------|
| `S3_NO_ENCRYPTION` | S3 bucket without server-side encryption | T1530 | TA0009 (Collection) |
| `S3_PUBLIC_ACCESS` | S3 bucket allows public access | T1530, T1190 | TA0009 (Collection), TA0001 (Initial Access) |
| `S3_NO_VERSIONING` | S3 bucket without versioning | T1485 | TA0040 (Impact) |
| `S3_NO_LOGGING` | S3 bucket without access logging | T1562.008 | TA0005 (Defense Evasion) |
| `IAM_WILDCARD_ACTION` | IAM policy with wildcard actions | T1078.004 | TA0001, TA0003, TA0004, TA0005 |
| `IAM_NO_MFA` | IAM user without MFA requirement | T1078.004 | TA0001, TA0003, TA0004, TA0005 |
| `IAM_OVERPERMISSIVE_ROLE` | IAM role with overly broad assume role policy | T1078.004, T1098 | TA0001, TA0003, TA0004 |
| `EC2_PUBLIC_IP` | EC2 instance with public IP address | T1190 | TA0001 (Initial Access) |
| `EC2_NO_MONITORING` | EC2 instance without detailed monitoring | T1562.008 | TA0005 (Defense Evasion) |
| `EC2_UNENCRYPTED_EBS` | EC2 instance with unencrypted root volume | T1530 | TA0009 (Collection) |
| `VPC_DEFAULT_SG_OPEN` | Default security group allows traffic | T1190 | TA0001 (Initial Access) |
| `SG_UNRESTRICTED_INGRESS` | Security group allows unrestricted ingress | T1190, T1046 | TA0001 (Initial Access), TA0007 (Discovery) |
| `VPC_NO_FLOW_LOGS` | VPC without flow logs enabled | T1562.008 | TA0005 (Defense Evasion) |
| `RDS_PUBLIC_ACCESS` | RDS instance is publicly accessible | T1190 | TA0001 (Initial Access) |
| `RDS_NO_ENCRYPTION` | RDS instance without encryption at rest | T1530 | TA0009 (Collection) |
| `RDS_NO_BACKUP` | RDS instance without automated backups | T1485 | TA0040 (Impact) |
| `LAMBDA_NO_VPC` | Lambda function not attached to VPC | T1190 | TA0001 (Initial Access) |
| `LAMBDA_OVERPERMISSIVE_ROLE` | Lambda function with broad execution role | T1078.004 | TA0001, TA0003, TA0004, TA0005 |
| `LAMBDA_NO_DLQ` | Lambda function without dead letter queue | T1499 | TA0040 (Impact) |

---

## ATT&CK Navigator Export

Generate an ATT&CK Navigator layer file using the `--format matrix` flag:

```bash
threatcode scan tfplan.json --no-llm --format matrix -o threatcode-layer.json
```

This produces a JSON file compatible with [ATT&CK Navigator v5.1](https://mitre-attack.github.io/attack-navigator/).

### Loading the Layer

1. Open [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
2. Click **Open Existing Layer**
3. Select **Upload from local** and choose the generated `threatcode-layer.json`
4. The matrix will highlight techniques found in your scan, color-coded by severity:

| Color | Severity |
|-------|----------|
| Red (`#ff0000`) | Critical |
| Orange (`#ff6600`) | High |
| Yellow (`#ffcc00`) | Medium |
| Blue (`#66ccff`) | Low |
| Gray (`#cccccc`) | Info |

Each highlighted technique includes metadata showing the number of findings and their titles.

!!! tip "CI/CD artifact"
    In CI/CD pipelines, save the Navigator layer as a build artifact so security teams can review the ATT&CK coverage of each deployment. See the [CI/CD Integration](cicd.md) page for examples.

---

## STRIDE-to-ATT&CK Tactic Mapping

ThreatCode maintains a default mapping from STRIDE categories to ATT&CK tactics:

| STRIDE Category | Default ATT&CK Tactics |
|----------------|----------------------|
| Spoofing | TA0001 (Initial Access), TA0006 (Credential Access) |
| Tampering | TA0040 (Impact) |
| Repudiation | TA0005 (Defense Evasion) |
| Information Disclosure | TA0009 (Collection), TA0010 (Exfiltration) |
| Denial of Service | TA0040 (Impact) |
| Elevation of Privilege | TA0004 (Privilege Escalation) |

This mapping is used as a fallback when a rule or LLM finding does not specify explicit tactic IDs.

---

## LLM Responses and MITRE Fields

When LLM augmentation is enabled, the system prompt instructs the LLM to include MITRE ATT&CK technique IDs in its response. The LLM is asked to use ATT&CK Cloud Matrix IDs (e.g., `T1530` for Data from Cloud Storage) and to omit the fields rather than guess if unsure.

LLM-generated MITRE mappings are carried through to all output formats, including SARIF (as tags) and the ATT&CK Navigator layer.
