# Writing Rules

ThreatCode uses declarative YAML rules to detect security issues. Rules are evaluated against every node in the infrastructure graph using a safe condition evaluator — no `eval()` is ever used.

---

## Rule File Structure

```yaml
rules:
  - id: RULE_ID
    title: "Short human-readable name"
    description: >
      Detailed explanation of the threat and its impact.
    stride_category: information_disclosure
    severity: high
    resource_type: aws_s3_bucket
    condition:
      # ... condition structure (see below) ...
    mitigation: >
      Specific remediation steps.
    metadata:
      mitre:
        techniques: ["T1530"]
        tactics: ["TA0009"]
```

---

## Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier. Must be globally unique across all loaded files. |
| `title` | string | Short, clear threat name |
| `description` | string | Full threat description with context and impact |
| `stride_category` | string | One of the 6 STRIDE categories (see below) |
| `severity` | string | `critical`, `high`, `medium`, `low`, or `info` |
| `resource_type` | string | Resource type prefix to match against (supports prefix matching) |
| `condition` | dict | Condition structure (see Condition Operators) |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `mitigation` | string | Specific remediation steps |
| `metadata.mitre.techniques` | list[string] | MITRE ATT&CK technique IDs, e.g. `["T1530"]` or `["T1078.004"]` |
| `metadata.mitre.tactics` | list[string] | MITRE ATT&CK tactic IDs, e.g. `["TA0009"]` |

---

## STRIDE Categories

| Value | Threat Type | Example |
|-------|------------|---------|
| `spoofing` | Authentication | Overly broad IAM assume-role |
| `tampering` | Integrity | S3 bucket without versioning |
| `repudiation` | Audit trails | S3 bucket without access logging |
| `information_disclosure` | Confidentiality | Publicly accessible RDS instance |
| `denial_of_service` | Availability | Lambda without dead letter queue |
| `elevation_of_privilege` | Authorization | Wildcard IAM actions |

---

## Condition Operators

### Property operators

These operators check a specific property key on the resource:

```yaml
# Property does not exist
condition:
  server_side_encryption_configuration:
    not_exists: true

# Exact equality
condition:
  publicly_accessible:
    equals: true

# Not equal
condition:
  engine:
    not_equals: "aurora"

# Contains (substring in string, or item in list/dict)
condition:
  policy:
    contains: '"Principal":"*"'

# Not contains
condition:
  acl:
    not_contains: "private"

# One of a set of values
condition:
  acl:
    matches_any: ["public-read", "public-read-write"]

# Numeric comparisons
condition:
  backup_retention_period:
    less_than: 7

condition:
  min_tls_version:
    greater_than: 1.1

# Truthy check
condition:
  enabled:
    is_true: false      # fails if enabled is falsy

# Empty check (None, "", [], {})
condition:
  versioning:
    is_empty: true

# Nested path existence
condition:
  logging.0.target_bucket:
    not_exists: true    # checks if nested path exists
```

### Logical operators

```yaml
# ALL conditions must match
condition:
  all_of:
    - publicly_accessible:
        equals: true
    - deletion_protection:
        equals: false

# AT LEAST ONE condition must match
condition:
  any_of:
    - server_side_encryption_configuration:
        not_exists: true
    - server_side_encryption_configuration:
        is_empty: true

# NONE of the conditions can match
condition:
  none_of:
    - storage_encrypted:
        equals: true

# Negation
condition:
  not:
    multi_az:
      equals: true
```

### Nested path access

Use dot-separated keys with list indices to navigate nested properties:

```yaml
# Checks versioning[0]["enabled"]
condition:
  versioning.0.enabled:
    equals: false
```

### Implicit equality

Direct key-value is shorthand for `equals`:

```yaml
condition:
  engine: "mysql"
  # Equivalent to:
  # engine:
  #   equals: "mysql"
```

---

## Resource Type Matching

The `resource_type` field uses **prefix matching**. A rule with `resource_type: aws_s3_bucket` matches any resource whose type starts with `aws_s3_bucket`.

This means:
- `aws_s3_bucket` — matches exactly `aws_s3_bucket`
- `aws_s3` — matches `aws_s3_bucket`, `aws_s3_bucket_policy`, etc.
- `aws_` — matches all AWS resources

Examples:
```yaml
resource_type: aws_s3_bucket              # Terraform S3 bucket
resource_type: aws_db_instance            # Terraform RDS instance
resource_type: azurerm_storage_account    # Azure Storage
resource_type: google_compute_instance    # GCP Compute
resource_type: kubernetes_pod             # Kubernetes Pod
resource_type: dockerfile_image           # Dockerfile (synthetic summary)
```

---

## Complete Example Rules

### S3 public access

```yaml
rules:
  - id: S3_PUBLIC_ACCESS
    title: S3 bucket allows public access
    description: >
      The S3 bucket ACL or policy allows public read or write access.
      Exposed data can be accessed without authentication.
    stride_category: information_disclosure
    severity: critical
    resource_type: aws_s3_bucket
    condition:
      any_of:
        - acl:
            matches_any: ["public-read", "public-read-write", "authenticated-read"]
        - policy:
            contains: '"Effect":"Allow","Principal":"*"'
    mitigation: >
      Set ACL to 'private' and use aws_s3_bucket_public_access_block
      to enforce public access restrictions at the bucket level.
    metadata:
      mitre:
        techniques: ["T1530"]
        tactics: ["TA0009"]
```

### RDS encryption

```yaml
  - id: RDS_NO_ENCRYPTION
    title: RDS instance without encryption at rest
    description: >
      The RDS database instance does not have storage encryption enabled.
      Unencrypted data is at risk if storage media is compromised.
    stride_category: information_disclosure
    severity: high
    resource_type: aws_db_instance
    condition:
      any_of:
        - storage_encrypted:
            not_exists: true
        - storage_encrypted:
            is_true: false
    mitigation: >
      Set storage_encrypted = true. Existing unencrypted instances must be
      snapshotted and restored to a new encrypted instance.
    metadata:
      mitre:
        techniques: ["T1530"]
        tactics: ["TA0009"]
```

### Kubernetes privileged container

```yaml
  - id: K8S_PRIVILEGED_CONTAINER
    title: Kubernetes container running in privileged mode
    description: >
      A container is running with full root capabilities, bypassing all
      Linux security controls. A compromised privileged container can
      escape to the host node.
    stride_category: elevation_of_privilege
    severity: critical
    resource_type: kubernetes_deployment
    condition:
      privileged:
        equals: true
    mitigation: >
      Remove privileged: true from the container security context.
      Use specific capability grants (capabilities.add) only for what
      the container actually needs.
    metadata:
      mitre:
        techniques: ["T1611"]
        tactics: ["TA0004"]
```

---

## Loading Custom Rules

```bash
# Load additional rule files via CLI
threatcode scan tfplan.json --rules my_rules.yml --rules compliance.yml

# Via config file
```

```yaml
# .threatcode.yml
extra_rule_paths:
  - rules/my_org_rules.yml
  - rules/compliance.yml
```

```python
# Via Python API
from threatcode import scan
report = scan("tfplan.json", extra_rule_paths=["my_rules.yml"])
```

---

## Constraints

| Limit | Value |
|-------|-------|
| Max rules per file | 100 |
| Max total rules | 1000 |
| Max rule file size | 1 MB |
| Rule ID uniqueness | Global (across all loaded files) |
| Symlinks in extra_rule_paths | Blocked |
| Max recursion depth | 10 |

---

## Rule ID Conventions

Built-in rules follow this pattern: `{PROVIDER}_{SERVICE}_{ISSUE}`, e.g.:
- `S3_NO_ENCRYPTION`
- `K8S_PRIVILEGED_CONTAINER`
- `DOCKER_NO_USER`

For custom rules, use a namespace prefix to avoid conflicts:
- `MYORG_REQUIRE_TAGGING`
- `COMPLIANCE_SOC2_LOGGING`
