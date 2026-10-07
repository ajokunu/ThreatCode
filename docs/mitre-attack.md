# MITRE ATT&CK Integration

Every rule-based and boundary finding carries [MITRE ATT&CK](https://attack.mitre.org/) technique and tactic IDs.

---

## ATT&CK Data

ThreatCode pins **ATT&CK Enterprise v19.2**.
The data is not written by hand.
`src/threatcode/engine/mitre_data.py` is generated from the official enterprise-attack STIX 2.1 bundle in the [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) releases.
The pinned bundle is `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json`.

The generated module holds:

- `ATTACK_VERSION`, the pinned release (also exported from `threatcode.engine.mitre`).
- `TACTICS`, all 15 enterprise tactics with `name`, `shortname` (the ATT&CK Navigator tactic name) and `url`.
- `TECHNIQUES`, every enterprise technique and sub-technique with `name`, `tactic_ids`, `url`, `platforms`, `deprecated`, `revoked` and `revoked_by`.
- `REVOKED_ALIASES`, a map from each revoked technique ID to the ID that replaced it, built from the bundle's `revoked-by` relationships.

Sub-technique names carry the parent name, for example `Valid Accounts: Cloud Accounts`.

`threatcode.engine.mitre` is the API over that data:

| Name | Purpose |
|------|---------|
| `TECHNIQUE_DB`, `TACTIC_DB` | The generated tables. |
| `ATTACK_VERSION` | The pinned release, for outputs that must state a version. |
| `TACTIC_SHORTNAME` and `tactic_shortname(ta_id)` | Navigator tactic names such as `initial-access` or `defense-impairment`. |
| `tactics_for_techniques(ids)` | The sorted set of tactic IDs that ATT&CK assigns to the techniques. |
| `normalize_technique(id)` | Maps a revoked ID to the current one, following chains. Current and unknown IDs come back unchanged. |
| `is_revoked(id)`, `is_deprecated(id)` | The ATT&CK status flags. |

Revoked and deprecated techniques stay in `TECHNIQUE_DB` with their flags.
That keeps rules and user input that still carry an old ID resolvable.
Callers that need a current ID call `normalize_technique`.

### Regenerating the data

```bash
python scripts/gen_mitre_db.py                       # download the pinned bundle and rewrite the module
python scripts/gen_mitre_db.py --check               # exit 1 if the committed module is stale
python scripts/gen_mitre_db.py --version 19.3        # move the pin to a new release
python scripts/gen_mitre_db.py --stix bundle.json    # offline, using a bundle you already have
```

The script uses only the standard library.
`--check` never writes.
It exits 0 when the committed module equals what the bundle produces, 1 when it differs, and 2 on an input error such as an unreadable file or a malformed bundle.
Without `--stix` the pinned version is the `ATTACK_VERSION` already in the module, so a plain `--check` always verifies the module against its own release.
To move to a new release, run the script with `--version`, review the diff, and update this page.
`tests/fixtures/stix/` holds a small excerpt of the bundle that the offline generator tests use.

### Changes in the v19 line that matter here

These were checked against the v19.2 bundle.

- TA0005 is named **Stealth** (shortname `stealth`).
  It was Defense Evasion in earlier releases.
- TA0112 **Defense Impairment** exists (shortname `defense-impairment`).
- TA0043 **Reconnaissance** is in the matrix and is now in `TACTIC_DB`.
- T1562.008 is **revoked** and replaced by T1685.002 (Disable or Modify Cloud Log, tactic TA0112).
  The parent T1562 is revoked in favor of T1685.
- T1610 (Deploy Container) belongs to Execution only.
  It no longer lists Defense Evasion.
- T1548 (Abuse Elevation Control Mechanism) belongs to Privilege Escalation only.
  It no longer lists Defense Evasion.

The builtin rules still carry T1562.008 and the older tactic lists.
Each rule package remaps its own rule files against this database.
The technique and tactic tests report rules that still use revoked techniques as a warning until then.

---

## Coverage

Across the builtin rules and the boundary analysis, ThreatCode maps to **26 ATT&CK techniques** in **12 tactics**.
The table lists each technique under every tactic ATT&CK assigns it to, so some techniques appear more than once.

| Tactic | ID | Techniques Covered |
|--------|----|--------------------|
| Initial Access | TA0001 | T1078, T1078.004, T1189, T1190, T1195.002 |
| Execution | TA0002 | T1059, T1609 |
| Persistence | TA0003 | T1078, T1078.004, T1098 |
| Privilege Escalation | TA0004 | T1068, T1078, T1078.004, T1098, T1611 |
| Stealth (was Defense Evasion) | TA0005 | T1078, T1078.004, T1562.008 |
| Credential Access | TA0006 | T1040, T1528, T1552.001, T1557 |
| Discovery | TA0007 | T1040, T1046, T1580, T1613 |
| Lateral Movement | TA0008 | T1021 |
| Collection | TA0009 | T1005, T1530, T1557 |
| Exfiltration | TA0010 | T1048 |
| Impact | TA0040 | T1485, T1499, T1565.001 |
| Resource Development | TA0042 | T1587.001 |

Each rule names its own techniques and tactics, so there is no fixed STRIDE-to-tactic mapping.

---

## How Technique IDs Are Assigned

**1. Built-in rule metadata** - Every built-in rule specifies techniques and tactics directly:

```yaml
metadata:
  mitre:
    techniques: ["T1530"]
    tactics: ["TA0009"]
```

**2. Trust boundary crossing detection** - Boundary crossing findings get default techniques T1040 (Network Sniffing) and T1557 (Adversary-in-the-Middle).

**3. LLM-generated threats** - The LLM is prompted to return MITRE technique IDs. All IDs are validated against `TECHNIQUE_DB` and `TACTIC_DB` before being included in findings - invalid IDs are rejected.

**4. STRIDE fallback** - If no explicit techniques are specified, the STRIDE-to-tactic mapping above is used to populate `mitre_tactics`.

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
| T1562.008 | Disable or Modify Cloud Logs (revoked in v19, now T1685.002) | CloudTrail/CloudWatch disabled |
| T1611 | Escape to Host | Kubernetes privileged container |
| T1610 | Deploy Container | Kubernetes missing securityContext |
| T1552.001 | Credentials in Files | Secrets in ENV variables, Dockerfiles |
| T1195.002 | Supply Chain Compromise: Software | Outdated/vulnerable dependencies |
| T1068 | Exploitation for Privilege Escalation | Kernel-level capabilities (SYS_ADMIN, etc.) |
| T1548 | Abuse Elevation Control | Privilege escalation allowed in containers |
| T1040 | Network Sniffing | Trust boundary crossing (DMZ → Data) |
| T1557 | Adversary-in-the-Middle | Trust boundary crossing (Internet → Private) |
