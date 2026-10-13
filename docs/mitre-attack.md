# MITRE ATT&CK integration

Every rule finding, boundary crossing, secret finding and attack path hop carries [MITRE ATT&CK](https://attack.mitre.org/) technique and tactic ids.
The mapping follows what a weakness enables for an attacker, so a rule that only reports a missing control (no flow logs, no access logs) claims no technique at all.

## ATT&CK data

ThreatCode pins **ATT&CK Enterprise v19.2<!-- count:attack_version -->**.
The data is generated, not written by hand.
`src/threatcode/engine/mitre_data.py` is built from the official enterprise-attack STIX 2.1 bundle in the [mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data) releases, which has 858<!-- count:attack_techniques --> techniques and sub-techniques and 15<!-- count:attack_tactics --> tactics.
The pinned bundle is `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v19.2/enterprise-attack/enterprise-attack-19.2.json`.

The generated module holds:

- `ATTACK_VERSION`, the pinned release.
- `TACTICS`, every enterprise tactic with `name`, `shortname` (the ATT&CK Navigator tactic name) and `url`.
- `TECHNIQUES`, every technique and sub-technique with `name`, `tactic_ids`, `url`, `platforms`, `deprecated`, `revoked` and `revoked_by`.
- `REVOKED_ALIASES`, each revoked technique id mapped to the id that replaced it.

`threatcode.engine.mitre` is the API over that data:

| Name | Purpose |
|------|---------|
| `TECHNIQUE_DB`, `TACTIC_DB` | The generated tables. |
| `ATTACK_VERSION` | The pinned release, for outputs that must state a version. |
| `TACTIC_SHORTNAME`, `tactic_shortname(ta_id)` | Navigator tactic names such as `initial-access` or `defense-impairment`. |
| `tactics_for_techniques(ids)` | The sorted tactic ids that ATT&CK assigns to the techniques. |
| `normalize_technique(id)` | Maps a revoked id to the current one, following chains. Current and unknown ids come back unchanged. |
| `is_revoked(id)`, `is_deprecated(id)` | The ATT&CK status flags. |
| `PATH_TECHNIQUES` | The technique of each kind of attack path step. |

Revoked and deprecated techniques stay in `TECHNIQUE_DB` with their flags, so a rule or an LLM reply that carries an old id still resolves.
Callers that need a current id call `normalize_technique`, which is also what the LLM reply parser does: an aliased `T1562.008` becomes `T1685.002`.

### Regenerating the data

```bash
python scripts/gen_mitre_db.py                       # download the pinned bundle and rewrite the module
python scripts/gen_mitre_db.py --check               # exit 1 if the committed module is stale
python scripts/gen_mitre_db.py --version 19.3        # move the pin to a new release
python scripts/gen_mitre_db.py --stix bundle.json    # offline, using a bundle you already have
```

The script uses only the standard library.
`--check` never writes: it exits 0 when the committed module equals what the bundle produces, 1 when it differs, and 2 on an input error.
A weekly CI job compares the committed tables with the pinned release and with the newest published one, and reports drift without blocking a pull request.
To move to a new release, run the script with `--version`, review the diff, and regenerate this page with `python scripts/gen_docs_counts.py --write`.

### Changes in the v19 line that matter here

- TA0005 is named **Stealth** (shortname `stealth`); it was Defense Evasion before v19.
- TA0112 **Defense Impairment** exists (shortname `defense-impairment`), and TA0043 **Reconnaissance** is in `TACTIC_DB`.
- T1562.008 is **revoked** and replaced by T1685.002 (Disable or Modify Cloud Log, tactic TA0112).
  No built-in rule uses it: a missing logging control is not an adversary technique, so those rules claim none.
- T1610 (Deploy Container) belongs to Execution only, and T1548 (Abuse Elevation Control Mechanism) to Privilege Escalation only.

## How techniques are assigned

1. **Rules.**
   Each rule lists its techniques in `metadata.mitre.techniques`.
   Its tactics are *derived* from the techniques with `tactics_for_techniques`, never written by hand, so the two cannot disagree.
   A rule loader check rejects a malformed technique id, and a test checks that every technique in every built-in rule exists in ATT&CK v19.2 and is not revoked.

   ```yaml
   metadata:
     mitre:
       techniques: ["T1530"]
   ```

2. **Trust boundary crossings.**
   The techniques follow the flow and the zones it joins.
   A flow declared unauthenticated is spoofing (T1557), one declared unencrypted is information disclosure (T1040), and any other is tampering with a flow in transit (T1565.002).
   A flow from the internet into the DMZ adds T1190, into the data zone T1530, and into the management zone T1078.
   The tactics are derived from the techniques.
   The text report shows the kind of crossing in its RULE column and the JSON report in `metadata.boundary_rule`, as one of: `BOUNDARY_UNAUTHENTICATED_FLOW` (spoofing), `BOUNDARY_UNENCRYPTED_FLOW` (information disclosure), `BOUNDARY_UNVALIDATED_FLOW` (a flow declared not validated) and `BOUNDARY_GENERIC_FLOW` (tampering).
   These are not rules, since no rule file defines them, but an ignore entry can name one, and it then hides every crossing of that kind.

3. **Attack paths.**
   Each hop lists the technique of the step that reaches it, and the path lists their union and the tactics that follow:
   T1190 for an exposed application, T1133 for an exposed remote administration port, T1552.005 where the instance allows IMDSv1, T1078.004 for a role assumed, T1530 for cloud storage read, T1552.007 for a Kubernetes Secret read, T1611 for a privileged container, T1659 for untrusted content that reaches an agent, and T1005 and T1552.001 for an MCP server that reads files and credential paths.

4. **Secret findings** map to T1552.001 (Credentials In Files).

5. **LLM findings** carry the ids the model returned, after normalizing revoked ids and dropping unknown ones.

There is no fixed STRIDE-to-tactic table, and nothing fills in a tactic for a finding that has no technique.

## Coverage

<!-- gen:techniques -->
Built-in rules map to 34 techniques in 12 tactics.
Counting the techniques the engine assigns to attack paths, boundary crossings and secret findings, ThreatCode references 36 techniques in 12 tactics of ATT&CK v19.2.

| Technique | Name | Tactics | Used by |
| --- | --- | --- | --- |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | TA0009 | `MCP_BROAD_FILESYSTEM`, `MCP_SENSITIVE_PATHS`; attack paths |
| [T1021](https://attack.mitre.org/techniques/T1021/) | Remote Services | TA0008 | `GCP_VM_SERIAL_PORT` |
| [T1021.001](https://attack.mitre.org/techniques/T1021/001/) | Remote Services: Remote Desktop Protocol | TA0008 | `AZURE_NSG_RDP_OPEN` |
| [T1021.004](https://attack.mitre.org/techniques/T1021/004/) | Remote Services: SSH | TA0008 | `AZURE_NSG_SSH_OPEN`, `DOCKER_EXPOSED_SSH`, `EKS_SSH_ACCESS_NODES` |
| [T1040](https://attack.mitre.org/techniques/T1040/) | Network Sniffing | TA0006, TA0007 | 4 rules; boundary crossings |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Network Service Discovery | TA0007 | `GKE_NO_NETWORK_POLICY`, `K8S_NO_NETWORK_POLICY` |
| [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration Over Alternative Protocol | TA0010 | `K8S_DEFAULT_ALLOW_EGRESS` |
| [T1059](https://attack.mitre.org/techniques/T1059/) | Command and Scripting Interpreter | TA0002 | `MCP_SHELL_EXEC` |
| [T1078](https://attack.mitre.org/techniques/T1078/) | Valid Accounts | TA0001, TA0003, TA0004, TA0005 | 12 rules; boundary crossings |
| [T1078.001](https://attack.mitre.org/techniques/T1078/001/) | Valid Accounts: Default Accounts | TA0001, TA0003, TA0004, TA0005 | `K8S_DEFAULT_SERVICE_ACCOUNT` |
| [T1078.004](https://attack.mitre.org/techniques/T1078/004/) | Valid Accounts: Cloud Accounts | TA0001, TA0003, TA0004, TA0005 | 17 rules; attack paths |
| [T1098.006](https://attack.mitre.org/techniques/T1098/006/) | Account Manipulation: Additional Container Cluster Roles | TA0003, TA0004 | `K8S_RBAC_ESCALATION_VERBS` |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | TA0011 | `ECS_NO_READONLY_FS`, `K8S_WRITABLE_ROOT_FS` |
| [T1110](https://attack.mitre.org/techniques/T1110/) | Brute Force | TA0006 | `AZURE_VM_PASSWORD_AUTH` |
| [T1133](https://attack.mitre.org/techniques/T1133/) | External Remote Services | TA0001, TA0003 | 7 rules; attack paths |
| [T1190](https://attack.mitre.org/techniques/T1190/) | Exploit Public-Facing Application | TA0001 | 40 rules; attack paths; boundary crossings |
| [T1195.002](https://attack.mitre.org/techniques/T1195/002/) | Supply Chain Compromise: Compromise Software Supply Chain | TA0001 | 6 rules |
| [T1485](https://attack.mitre.org/techniques/T1485/) | Data Destruction | TA0040 | 9 rules |
| [T1498](https://attack.mitre.org/techniques/T1498/) | Network Denial of Service | TA0040 | `AZURE_VNET_NO_DDOS` |
| [T1499](https://attack.mitre.org/techniques/T1499/) | Endpoint Denial of Service | TA0040 | 5 rules |
| [T1525](https://attack.mitre.org/techniques/T1525/) | Implant Internal Image | TA0003 | `ECR_MUTABLE_TAGS` |
| [T1528](https://attack.mitre.org/techniques/T1528/) | Steal Application Access Token | TA0006 | `GCP_IAM_SA_KEY`, `K8S_AUTOMOUNT_DEFAULT`, `K8S_AUTOMOUNT_SA_TOKEN` |
| [T1530](https://attack.mitre.org/techniques/T1530/) | Data from Cloud Storage | TA0009 | 25 rules; attack paths; boundary crossings |
| [T1542.003](https://attack.mitre.org/techniques/T1542/003/) | Pre-OS Boot: Bootkit | TA0003, TA0005 | `GCP_VM_NO_SHIELDED`, `GKE_NO_SHIELDED_NODES` |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Abuse Elevation Control Mechanism | TA0004 | `K8S_ALLOW_PRIVILEGE_ESCALATION`, `SAGEMAKER_NOTEBOOK_ROOT_ACCESS` |
| [T1548.003](https://attack.mitre.org/techniques/T1548/003/) | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | TA0004 | `DOCKER_RUN_SUDO` |
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | TA0006 | 8 rules; attack paths; secret findings |
| [T1552.005](https://attack.mitre.org/techniques/T1552/005/) | Unsecured Credentials: Cloud Instance Metadata API | TA0006 | `EC2_IMDSV1`, `EKS_NO_IRSA`, `GKE_NO_WORKLOAD_IDENTITY`; attack paths |
| [T1552.007](https://attack.mitre.org/techniques/T1552/007/) | Unsecured Credentials: Container API | TA0006 | `K8S_RBAC_SECRETS_READ`; attack paths |
| [T1555.006](https://attack.mitre.org/techniques/T1555/006/) | Credentials from Password Stores: Cloud Secrets Management Stores | TA0006 | 6 rules |
| [T1557](https://attack.mitre.org/techniques/T1557/) | Adversary-in-the-Middle | TA0006, TA0009 | 16 rules; boundary crossings |
| [T1565.002](https://attack.mitre.org/techniques/T1565/002/) | Data Manipulation: Transmitted Data Manipulation | TA0040 | boundary crossings |
| [T1567](https://attack.mitre.org/techniques/T1567/) | Exfiltration Over Web Service | TA0010 | `MCP_LETHAL_TRIFECTA`, `SAGEMAKER_NOTEBOOK_DIRECT_INTERNET` |
| [T1609](https://attack.mitre.org/techniques/T1609/) | Container Administration Command | TA0002 | `ECS_EXEC_ENABLED`, `K8S_RBAC_POD_EXEC` |
| [T1611](https://attack.mitre.org/techniques/T1611/) | Escape to Host | TA0004 | 15 rules; attack paths |
| [T1659](https://attack.mitre.org/techniques/T1659/) | Content Injection | TA0001, TA0011 | attack paths |
<!-- /gen:techniques -->

The [rule catalog](rules.md) lists the techniques of every rule, and has a table of the rules for each technique.

## ATT&CK Navigator export

```bash
threatcode scan infra/ -f navigator -o layer.json
```

Load `layer.json` at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).

A layer has one entry per (technique, tactic), written with the tactic's Navigator shortname, so an entry never has an empty tactic.
There is no platform filter, so Docker, Kubernetes and MCP techniques are visible.
`versions.attack` is the bundled ATT&CK release, the Navigator version is a full semantic version, a revoked technique id is mapped to its replacement, and an id ATT&CK does not know is kept with a warning and listed in the layer metadata instead of being dropped.

A technique that ATT&CK files under several tactics goes in the tactic the finding names.
An attack path does not name one, so the layer picks the tactic the step plays: initial access for the entry step, and for a later step the tactic that moves the attacker closest to the target.
Painting a technique in every column of the matrix would claim that one step does four things.
In the sample below `T1078.004` (Valid Accounts: Cloud Accounts) belongs to four tactics in ATT&CK, and the layer draws it once, under privilege escalation, because the step is a role assumption.
Techniques of attack paths are in the layer with their own comment, a score from the worst path that uses them and the number of paths.

The first entry of the layer for `examples/aws-webapp`:

<!-- gen:navigator-sample -->
```json
{
  "name": "ThreatCode Threat Model",
  "versions": {
    "attack": "19.2",
    "navigator": "5.1.0",
    "layer": "4.5"
  },
  "domain": "enterprise-attack",
  "layout": {
    "layout": "side",
    "aggregateFunction": "max",
    "showID": true,
    "showName": true,
    "showAggregateScores": true,
    "countUnscored": false,
    "expandedSubtechniques": "annotated"
  },
  "techniques": [
    {
      "techniqueID": "T1078.004",
      "tactic": "privilege-escalation",
      "score": 100,
      "color": "#ff0000",
      "comment": "2 attack path(s): internet to aws_s3_bucket.customer_data; internet to aws_secretsmanager_secret.db_credentials",
      "enabled": true,
      "metadata": [
        {
          "name": "findings",
          "value": "0"
        },
        {
          "name": "attack_paths",
          "value": "2"
        },
        {
          "name": "max_severity",
          "value": "critical"
        }
      ]
    }
  ]
}
```
<!-- /gen:navigator-sample -->

### Severity and color

Each technique takes the highest effective severity of the findings that map to it.

<!-- gen:navigator-colors -->
| Severity | Score | Color |
| --- | --- | --- |
| critical | 100 | `#ff0000` |
| high | 75 | `#ff6600` |
| medium | 50 | `#ffcc00` |
| low | 25 | `#66ccff` |
| info | 10 | `#cccccc` |
<!-- /gen:navigator-colors -->
