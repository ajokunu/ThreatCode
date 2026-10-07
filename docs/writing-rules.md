# Writing Rules

ThreatCode uses declarative YAML rules to detect security issues.
Rules are evaluated against every node in the infrastructure graph using a safe condition evaluator, and no `eval()` is ever used.
A rule file is checked completely when it is loaded, so a typo is a loud error that names the file, the rule and the key path instead of a rule that quietly never fires.

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

# Optional: IDs of rules that used to live in this file and were removed
deprecated_ids: [OLD_RULE_ID]
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
| `resource_type` or `resource_types` | string or list | The resource types the rule applies to. Set exactly one of the two (see Resource Type Matching). |
| `condition` | dict | Condition structure (see Condition Operators) |

## Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `mitigation` | string | Specific remediation steps |
| `confidence` | string | How the condition was established: `definitive` (the configuration proves it, the default), `heuristic` (inferred from names or partial data) or `absence` (it fires because something is missing) |
| `root_cause` | string | What actually has to change when several findings share one underlying cause |
| `metadata.mitre.techniques` | list[string] | MITRE ATT&CK technique IDs, e.g. `["T1530"]` or `["T1078.004"]` |
| `metadata.mitre.tactics` | list[string] | MITRE ATT&CK tactic IDs, e.g. `["TA0009"]` |

Loaded rules are immutable.
`rule.metadata` and `rule.condition` are read-only containers, so copy them with `copy.deepcopy()` before changing them.

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

## Resource Type Matching

A rule applies to a node only when the node's resource type is one the rule names.
Matching is exact: `resource_type: aws_s3_bucket` matches `aws_s3_bucket` and nothing else, so it never fires on the sibling resources `aws_s3_bucket_versioning`, `aws_s3_bucket_policy` or `aws_s3_bucket_public_access_block`.
Data sources never match a rule.

There are three ways to name types.

```yaml
# One exact type
resource_type: aws_s3_bucket

# Several exact types
resource_types: [aws_s3_bucket, aws_s3_bucket_acl]

# A family: one trailing * makes a prefix glob
resource_type: "aws_s3_bucket*"
```

Set exactly one of `resource_type` and `resource_types`.
The only wildcard is a single `*` at the end of an entry after a non-empty prefix.
`aws_*_bucket`, `aws_s3_bucket**` and a bare `*` are load errors.

### Named groups

A name that starts with `@` expands to a list of types, in either field.
Quote the value, because `@` cannot start a plain YAML scalar.

```yaml
resource_type: "@kubernetes_pod_workloads"
resource_types: ["@kubernetes_long_running", kubernetes_job]
```

| Group | Types |
|-------|-------|
| `@kubernetes_pod_workloads` | `kubernetes_pod`, `kubernetes_deployment`, `kubernetes_daemon_set`, `kubernetes_stateful_set`, `kubernetes_replica_set`, `kubernetes_job`, `kubernetes_cron_job` |
| `@kubernetes_long_running` | the same without `kubernetes_job` and `kubernetes_cron_job` |
| `@kubernetes_controllers` | the same without `kubernetes_pod` |

Use `@kubernetes_pod_workloads` for anything that reads the pod template, `@kubernetes_long_running` for checks that make no sense for batch jobs such as liveness probes, and an explicit list when only some kinds apply.
An unknown group is a load error that lists the known ones.

Examples:

```yaml
resource_type: aws_db_instance            # Terraform RDS instance
resource_type: azurerm_storage_account    # Azure Storage
resource_type: google_compute_instance    # GCP Compute
resource_type: kubernetes_pod             # Kubernetes Pod
resource_type: dockerfile_image           # Dockerfile (synthetic summary)
```

---

## Condition Structure

A condition is one of two things.

1. A mapping of property paths to checks.
   Every property in the mapping must pass (implicit AND).
2. A single logical operator (`all_of`, `any_of`, `none_of`, `not`) and nothing else.

A mapping that mixes a logical operator with property keys is a load error, and so is a mapping with two logical operators.
Nest them instead.

### Property operators

These operators check one property:

```yaml
# Property is absent (None, "", [] and {} count as absent; False and 0 do not)
condition:
  server_side_encryption_configuration:
    not_exists: true

# Property is present
condition:
  kms_key_id:
    exists: true

# Exact equality: booleans are strict, so true does not equal 1
condition:
  publicly_accessible:
    equals: true

# Not equal
condition:
  engine:
    not_equals: "aurora"

# Equality that ignores case (a boolean true compares as "true")
condition:
  metadata.serial-port-enable:
    equals_ci: "true"

# Substring of a string, element of a list, key of a mapping
condition:
  policy:
    contains: '"Principal":"*"'

# Not contains
condition:
  acl:
    not_contains: "private"

# The value is one of a set
condition:
  acl:
    matches_any: ["public-read", "public-read-write"]

# Numeric comparisons: numeric strings count, booleans never do
condition:
  backup_retention_period:
    less_than: 7

condition:
  rate_limit:
    greater_than: 2000

# Truthiness: true, or the strings "true", "1" and "yes" in any case
condition:
  enabled:
    is_true: false

# Empty check (the same set as not_exists: None, "", [] and {})
condition:
  versioning:
    is_empty: true

# The value, or any element of a list, is open to the world
condition:
  cidr_blocks:
    is_world_cidr: true
```

Details that matter:

- `equals` and `not_equals` do not coerce: `3` is not `"3"` and `True` is not `1`.
- `is_true` reads the string `"false"` as false.
- `greater_than` and `less_than` accept numeric strings such as `"120"` (CloudFormation writes numbers that way) and reject booleans.
- `contains` on a string needs a string argument; any other argument is simply not contained, it never raises.
- `contains` on a list tests element equality, so it cannot look inside a list of objects.
  Use a quantifier for that (below).
- `contains` on a mapping tests its keys.
- `matches_any` means "the value is in this list".
- `not_equals`, `not_contains` and `not_exists` are the exact negations of their positive forms.
- `is_world_cidr` is true for `0.0.0.0/0`, `::/0`, any network with prefix length 0, and `*`, `internet` and `any` in any case.
- `exists: false` is `not_exists: true`.

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

`all_of`, `any_of` and `none_of` take a non-empty list of conditions and `not` takes one condition.
Nesting is limited to 10 levels, counting quantifiers, and a deeper rule is rejected at load time.

### Querying lists of objects: any_item, all_items, none_items

Terraform stores repeated blocks such as `ingress` as a list of objects.
The quantifiers take a condition and evaluate it against each element as if the element were a resource of its own.
Every property operator and logical operator works inside.

```yaml
# Some ingress rule is open to the world on an admin port
condition:
  ingress:
    any_item:
      cidr_blocks:
        is_world_cidr: true
      port_overlaps: [22, 3389]

# Every statement is an Allow
condition:
  statement:
    all_items:
      effect:
        equals: Allow

# No ingress rule is open to the world
condition:
  ingress:
    none_items:
      cidr_blocks:
        is_world_cidr: true
```

- `any_item` is false on an empty or absent list, `all_items` is true on one, and `none_items` is the negation of `any_item`.
- A mapping element supplies its keys as properties.
  A scalar element is bound to the key `_value`, so `any_item: {_value: {equals: "b"}}` tests a list of strings.
- A single object or scalar is treated as a list of one.
- Quantifiers nest.

### Network checks: is_world_cidr and port_overlaps

`is_world_cidr` is a property operator, shown above.

`port_overlaps` is a key, not an operator: it checks the mapping the condition is evaluated against, which is a resource or, inside a quantifier, one list element.
Its argument is a non-empty list of ports and `"lo-hi"` ranges (and `"*"` for every port) and it is true when the element's ports overlap any of them.
It reads the element in this order:

1. `port`, `port_range`, `destination_port_range` (a port, a range, `"*"`) or `destination_port_ranges` (a list of those).
   These are what Azure and similar resources use.
   The protocol `"*"` means any protocol there, not any port.
2. Otherwise, a protocol of `-1`, `all` or `*` (key `protocol` or `ip_protocol`) means every port.
3. Otherwise `from_port` and `to_port` give an inclusive range.
   ICMP has no ports.

```yaml
# Azure style
condition:
  all_of:
    - direction: {equals: Inbound}
    - port_overlaps: [22, 3389]
```

Port numbers outside 0 to 65535 and malformed ranges are load errors.

### Nested path access

A property key is a path.
Segments are separated by dots, and the resolver follows the shapes Terraform produces.

```yaml
# Checks versioning[0]["enabled"]
condition:
  versioning.0.enabled:
    equals: false

# The same property, without the index: a one-element list of blocks is entered implicitly
condition:
  versioning.enabled:
    equals: false
```

| Path form | Meaning |
|-----------|---------|
| `a.b.c` | Nested mappings. |
| `a.0.b` or `a[0].b` | An integer step indexes a list. |
| `a.b` where `a` is a list | A one-element list of objects is entered; a longer list fans out and the check is true if it holds for any element (any element equals, any element contains); an empty list has nothing to find. |
| `a.*.b` or `a[*].b` | Fan out over every list element or mapping value. |
| `labels.pod-security.kubernetes.io/enforce` | At each mapping the longest remaining dotted key that exists literally is tried first, so keys that contain dots resolve without quoting. |
| `labels['a.b']` or `labels["a.b"]` | A bracketed, quoted key is taken literally and is never split, indexed or treated as a wildcard. |
| `labels.a\.b` | A backslash escapes a dot (`\.`), a bracket (`\[`, `\]`) or a backslash (`\\`). |

A path may have at most 16 segments, and empty segments are errors.

### Absent values

None, the empty string, the empty list and the empty mapping are absent, so `not_exists` and `exists` treat them alike.
`False`, `0` and the string `"false"` are present.
This makes Terraform plan JSON, which stores an unset block as `[]`, agree with HCL, where the key is missing.

### Implicit equality

Direct key-value is shorthand for `equals`:

```yaml
condition:
  engine: "mysql"
  # Equivalent to:
  # engine:
  #   equals: "mysql"
```

A condition value of `null` is a load error; use `not_exists: true`.

---

## Unknown values and design evidence

Every check has three outcomes: TRUE, FALSE and UNKNOWN.
A rule fires only when its condition is TRUE.

A check is UNKNOWN when:

- the value is an `Unknown`, which a parser places where a value exists but cannot be resolved by a static scan (a Terraform attribute known only after apply, an unresolved reference or variable, an unresolvable CloudFormation intrinsic), or an `Unknown` sits anywhere above the path;
- the property is missing on a node whose evidence is `design`.
  A resource that comes from a diagram or a threat model has only the properties its author wrote, so a missing property is a question, not a fact.
  A resource that comes from deployable configuration (`config` evidence, the default) keeps definite semantics: a missing property is absent.

Every operator returns UNKNOWN for an UNKNOWN value, so an unresolved value never produces a finding and never counts as a pass.
`kms_key_id: {not_exists: true}` does not fire on a trail whose key is `aws_kms_key.logs.arn` and still fires on a trail with no `kms_key_id`.

When a path fans out over several values, `equals`, `contains` and `matches_any` are TRUE if any value matches, and their negative forms are TRUE only if none does.
If no value matches and one is UNKNOWN, the result is UNKNOWN.

### Truth tables

The logical operators follow Kleene's three-valued logic.

| `all_of` | TRUE | FALSE | UNKNOWN |
|----------|------|-------|---------|
| TRUE | TRUE | FALSE | UNKNOWN |
| FALSE | FALSE | FALSE | FALSE |
| UNKNOWN | UNKNOWN | FALSE | UNKNOWN |

| `any_of` | TRUE | FALSE | UNKNOWN |
|----------|------|-------|---------|
| TRUE | TRUE | TRUE | TRUE |
| FALSE | TRUE | FALSE | UNKNOWN |
| UNKNOWN | TRUE | UNKNOWN | UNKNOWN |

| value | `not` | `none_of` of that one condition |
|-------|-------|--------------------------------|
| TRUE | FALSE | FALSE |
| FALSE | TRUE | TRUE |
| UNKNOWN | UNKNOWN | UNKNOWN |

`none_of` is `not` of `any_of`.
The properties of a flat condition are combined with `all_of` semantics.

Because UNKNOWN stays UNKNOWN under negation, nothing can turn a failure to evaluate into a match.
A condition nested deeper than 10 levels, a malformed condition or an unknown operator evaluates to UNKNOWN at match time, and the loader rejects all of them before that.

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
    resource_types: [aws_s3_bucket, aws_s3_bucket_acl]
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

### Security group open to the world on an admin port

```yaml
  - id: MYORG_SG_ADMIN_OPEN
    title: Security group exposes an admin port to the internet
    description: >
      An ingress rule allows SSH or RDP from anywhere.
    stride_category: elevation_of_privilege
    severity: high
    confidence: definitive
    resource_type: aws_security_group
    condition:
      ingress:
        any_item:
          cidr_blocks:
            is_world_cidr: true
          port_overlaps: [22, 3389]
    mitigation: >
      Restrict the source to a bastion or VPN range.
    metadata:
      mitre:
        techniques: ["T1190"]
        tactics: ["TA0001"]
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
    resource_type: "@kubernetes_pod_workloads"
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

## Validation Errors

Every rule is validated when its file is loaded.
An error is a `RuleLoadError` that names the rule, the file and the path of the offending key inside the condition.

```text
Rule MY_TYPO in rules.yml: condition.bucket.eqauls: Unknown operator 'eqauls' (did you mean 'equals'?). Valid operators: all_items, all_of, any_item, ...
Rule MY_RULE in rules.yml: condition: mixes the logical operator 'all_of' with property keys ['bucket']; put the properties inside the operator
Rule MY_RULE in rules.yml: condition.all_of[1].port.less_than: 'less_than' takes a number, got '5'
Rule MY_RULE in rules.yml: invalid resource type 'aws_*_bucket'; use an exact type or one trailing '*' after a prefix (for example 'aws_s3_bucket*'), with no other wildcard
Rule MY_RULE in rules.yml: unknown resource type group '@kubernetes_everything'. Known groups: @kubernetes_controllers, ...
```

What is checked:

- Operator names (with a close-match suggestion), and that logical operators stay out of property position and property operators out of logical position.
- That a condition holds exactly one logical operator and no property keys beside it.
- Argument types: `exists`, `not_exists`, `is_true`, `is_empty` and `is_world_cidr` take true or false, `matches_any` a non-empty list of values, `greater_than` and `less_than` a number, `equals_ci` a string, `contains` and `not_contains` a string, number or boolean, quantifiers a condition, and `port_overlaps` a non-empty list of valid ports.
- Property paths (empty segments, unterminated brackets, more than 16 segments).
- Nesting depth, at most 10.
- That `metadata.mitre.techniques` and `metadata.mitre.tactics` are lists of strings.
- `resource_type`, `resource_types` and group names, and that `confidence` is one of the three levels.
- Duplicate keys in the YAML itself, because YAML would silently keep the last one.

Unknown MITRE technique IDs only log a warning.

---

## Deprecated rule IDs

When a rule is removed, list its ID in the file it lived in:

```yaml
rules:
  - id: STILL_HERE
    # ...
deprecated_ids: [REMOVED_RULE]
```

`deprecated_rule_ids()` in `threatcode.engine.rules.loader` returns the IDs listed by the built-in files (and by extra files when you pass their paths), so a suppression that names a removed rule can warn that the rule no longer exists.
Listing an ID that is still defined in the same file is a load error.

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

Rules loaded from a custom file get the source group `custom__<file stem>`.

---

## Constraints

| Limit | Value |
|-------|-------|
| Max rules per file | 100 |
| Max total rules | 1000 |
| Max rule file size | 1 MB |
| Rule ID uniqueness | Global (across all loaded files) |
| Symlinks in extra_rule_paths | Blocked |
| Max condition nesting depth | 10 |
| Max property path segments | 16 |

---

## Rule ID Conventions

Built-in rules follow this pattern: `{PROVIDER}_{SERVICE}_{ISSUE}`, e.g.:
- `S3_NO_ENCRYPTION`
- `K8S_PRIVILEGED_CONTAINER`
- `DOCKER_NO_USER`

For custom rules, use a namespace prefix to avoid conflicts:
- `MYORG_REQUIRE_TAGGING`
- `COMPLIANCE_SOC2_LOGGING`
