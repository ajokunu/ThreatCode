# Rule Writing Guide

ThreatCode uses declarative YAML rules to detect threats. Rules are evaluated against every node in the infrastructure graph using a safe condition evaluator -- no `eval()` is ever used.

## Rule Schema

Each rule file contains a top-level `rules` key with a list of rule definitions:

```yaml
rules:
  - id: UNIQUE_RULE_ID
    title: Short human-readable title
    description: >
      Detailed description of the threat scenario.
    stride_category: information_disclosure
    severity: high
    resource_type: aws_s3_bucket
    condition:
      # condition operators (see below)
    mitigation: >
      Specific remediation steps.
    metadata:
      mitre:
        techniques: ["T1530"]
        tactics: ["TA0009"]
```

### Required Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `str` | Unique rule identifier (e.g., `S3_NO_ENCRYPTION`) |
| `title` | `str` | Short threat title |
| `description` | `str` | Detailed threat explanation |
| `stride_category` | `str` | One of: `spoofing`, `tampering`, `repudiation`, `information_disclosure`, `denial_of_service`, `elevation_of_privilege` |
| `severity` | `str` | One of: `critical`, `high`, `medium`, `low`, `info` |
| `resource_type` | `str` | Terraform resource type to match (prefix matching is used, so `aws_s3` matches `aws_s3_bucket` and `aws_s3_bucket_policy`) |
| `condition` | `dict` | Condition tree to evaluate against node properties |

### Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `mitigation` | `str` | Remediation guidance |
| `metadata` | `dict` | Arbitrary metadata; use `metadata.mitre` for ATT&CK mapping |

---

## Condition Operators

Conditions operate on resource properties from the infrastructure graph. Properties are accessed by dot-separated paths (e.g., `server_side_encryption_configuration` or `root_block_device.0.encrypted`).

### Property Operators

| Operator | Description | Example |
|----------|-------------|---------|
| `equals` | Value must equal the expected value | `publicly_accessible: { equals: true }` |
| `not_equals` | Value must not equal the expected value | `engine: { not_equals: "aurora" }` |
| `contains` | String/list/dict must contain the value | `policy: { contains: '"Action":"*"' }` |
| `not_contains` | String/list/dict must not contain the value | `acl: { not_contains: "public" }` |
| `exists` | Property must exist (not `null`) | `vpc_config: { exists: true }` |
| `not_exists` | Property must not exist (must be `null`) | `logging: { not_exists: true }` |
| `matches_any` | Value must be one of the listed values | `acl: { matches_any: ["public-read", "public-read-write"] }` |
| `greater_than` | Numeric value must be greater than | `retention: { greater_than: 0 }` |
| `less_than` | Numeric value must be less than | `backup_retention_period: { less_than: 7 }` |
| `is_true` | Boolean truthiness check | `enabled: { is_true: true }` |
| `is_empty` | Value is `null`, `""`, `[]`, or `{}` | `encryption_configuration: { is_empty: true }` |
| `property_path` | Checks that a nested path exists in the data | `config: { property_path: "logging.bucket" }` |

### Dot-Path Resolution

Property paths use dot notation to traverse nested data structures. Array indices are supported:

```yaml
# Check a nested property
server_side_encryption_configuration.rule.0.apply_server_side_encryption_by_default.sse_algorithm:
  equals: "aws:kms"

# Check an array element
root_block_device.0.encrypted:
  equals: false
```

### Logical Operators

Logical operators combine multiple conditions:

#### `all_of` -- All conditions must match (AND)

```yaml
condition:
  all_of:
    - publicly_accessible:
        equals: true
    - storage_encrypted:
        equals: false
```

#### `any_of` -- At least one condition must match (OR)

```yaml
condition:
  any_of:
    - acl:
        matches_any: ["public-read", "public-read-write", "authenticated-read"]
    - policy:
        contains: '"Effect":"Allow","Principal":"*"'
```

#### `none_of` -- No condition must match (NOR)

```yaml
condition:
  none_of:
    - vpc_config:
        exists: true
    - tags.vpc_attached:
        equals: "true"
```

#### `not` -- Negates a single condition

```yaml
condition:
  not:
    storage_encrypted:
      equals: true
```

### Implicit AND

When a condition dict has multiple keys without a logical operator, they are evaluated as implicit AND -- all must match:

```yaml
condition:
  publicly_accessible:
    equals: true
  storage_encrypted:
    not_exists: true
```

---

## Adding MITRE ATT&CK Metadata

Include a `mitre` block inside `metadata` to map the rule to ATT&CK techniques and tactics:

```yaml
metadata:
  mitre:
    techniques: ["T1530", "T1190"]
    tactics: ["TA0009", "TA0001"]
```

!!! tip "Auto-deriving tactics"
    If you provide `techniques` but omit `tactics`, ThreatCode will automatically derive the tactic IDs from its built-in technique database. You only need to specify `tactics` explicitly if you want to override the defaults.

---

## Full Example Rule

```yaml
rules:
  - id: S3_PUBLIC_ACCESS
    title: S3 bucket allows public access
    description: >
      The S3 bucket ACL or policy allows public read or write access.
      This can lead to data exposure or unauthorized data modification.
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
      to block all public access at the bucket level.
    metadata:
      mitre:
        techniques: ["T1530", "T1190"]
        tactics: ["TA0009", "TA0001"]
```

---

## Testing Custom Rules

Pass your rule files using the `--rules` flag on the CLI or `extra_rule_paths` in the Python API:

```bash
# CLI
threatcode scan tfplan.json --no-llm --rules path/to/custom_rules.yml

# Multiple rule files
threatcode scan tfplan.json --no-llm --rules org_rules.yml --rules team_rules.yml
```

```python
# Python API
from threatcode import scan

report = scan(
    "tfplan.json",
    extra_rule_paths=["path/to/custom_rules.yml"],
)
```

Custom rules are loaded alongside the 19 built-in rules. They follow the exact same schema and are evaluated in the same pass.

!!! warning "Unknown operators fail closed"
    If a condition contains an operator that ThreatCode does not recognize, the condition evaluates to `False` (fail closed). This prevents accidentally matching resources due to typos in operator names.
