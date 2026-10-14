# Writing Rules

ThreatCode uses declarative YAML rules to detect security issues.
Rules are evaluated against every node in the infrastructure graph using a safe condition evaluator, and no `eval()` is ever used.
A rule file is checked completely when it is loaded, so a typo is a loud error that names the file, the rule and the key path instead of a rule that quietly never fires.

The 256<!-- count:rules --> built-in rules are listed in the [rule catalog](rules.md).
Your own rules go in a file you pass with `--rules`, next to them.
Every example on this page that is a complete rule file is loaded by the test suite, so it works as written.

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
    confidence: definitive
    mitigation: >
      Specific remediation steps.
    metadata:
      mitre:
        techniques: ["T1530"]

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
| `metadata.mitre.techniques` | list[string] | MITRE ATT&CK technique IDs, e.g. `["T1530"]` or `["T1078.004"]`. Leave it out when no adversary technique honestly applies. |
| `metadata.mitre.tactics` | list[string] | Optional. The tactics are derived from the techniques, so write them only to override the derivation. Built-in rules never do. |

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

## Confidence and severity

Every built-in rule declares how it knows, and its severity respects that.

| Confidence | Meaning | Severity cap |
|------------|---------|--------------|
| `definitive` | The configuration proves the condition. | none; `critical` is reserved for definitive, direct exposure of data or control: a public data store, an admin wildcard, a world-open trust policy |
| `heuristic` | Inferred from names, a default or partial data. | `high` |
| `absence` | It fires because something is missing. | `medium` |

A test keeps the built-in rules inside those caps.
Use the same convention for your own rules: a rule that says "no flow logs" is an absence rule at low or medium, and a rule that fires on a literal `0.0.0.0/0` to port 22 is definitive.

Rules that share one fix declare the same `root_cause`, and the Markdown and text reports show them as one entry with a line each.

A rule sets the base severity.
The engine may add an effective severity with a reason when context changes it, for example one level up for a weakness on a resource the internet reaches.
Your rule does not need to know about that.

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

### Exposure: the `_exposure` pseudo-property

A condition can ask whether the internet can reach the resource.
`_exposure` is not a property of the resource: it reads the exposure that the graph worked out from the reachability edges, and it is one of `internet`, `internal` or unknown when the graph could not decide.
It takes the same checks as any property.

<!-- rules-file -->

```yaml
rules:
  - id: EXAMPLE_INTERNET_FACING_LB
    title: Load balancer reachable from the internet
    description: >
      The load balancer takes traffic from the internet, so everything
      behind it is exposed to whatever the internet sends.
    stride_category: tampering
    severity: medium
    confidence: heuristic
    resource_type: aws_lb
    condition:
      _exposure: internet
    mitigation: >
      Put a web application firewall in front of the load balancer.
```

Because the value is unknown when the graph cannot tell, a rule that says `_exposure: internet` never fires on a resource that merely might be exposed, and `not: {_exposure: internet}` does not fire on it either.
No built-in rule uses `_exposure` yet, because the engine already raises the effective severity of a finding on a resource the internet reaches (see [Severity](architecture.md#severity)); use it for a check that should exist only for exposed resources.

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

Each block below is a complete rule file.
The ids start with `EXAMPLE_` because a custom id that equals a built-in id is a load error (`Duplicate rule ID`).
Use your own prefix, see [Rule ID conventions](#rule-id-conventions).

### Public bucket ACL

<!-- rules-file -->

```yaml
rules:
  - id: EXAMPLE_S3_PUBLIC_ACL
    title: S3 bucket ACL allows public access
    description: >
      The bucket ACL grants read or write access to everyone.
      Exposed data can be read without authentication.
    stride_category: information_disclosure
    severity: critical
    confidence: definitive
    resource_type: aws_s3_bucket
    condition:
      acl:
        matches_any: ["public-read", "public-read-write", "authenticated-read"]
    mitigation: >
      Set the ACL to private and use aws_s3_bucket_public_access_block
      to enforce public access restrictions at the bucket level.
    metadata:
      mitre:
        techniques: ["T1530"]
```

### Database without encryption

<!-- rules-file -->

```yaml
rules:
  - id: EXAMPLE_RDS_UNENCRYPTED
    title: RDS instance without encryption at rest
    description: >
      The RDS database instance does not have storage encryption enabled.
      Unencrypted data is at risk if storage media is compromised.
    stride_category: information_disclosure
    severity: high
    confidence: definitive
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
```

### Security group open to the world on an admin port

<!-- rules-file -->

```yaml
rules:
  - id: MYORG_SG_ADMIN_OPEN
    title: Security group exposes an admin port to the internet
    description: >
      An ingress rule allows SSH or RDP from anywhere.
    stride_category: elevation_of_privilege
    severity: high
    confidence: definitive
    resource_type: aws_security_group
    condition:
      derived.ingress:
        any_item:
          cidr_blocks:
            is_world_cidr: true
          port_overlaps: [22, 3389]
    mitigation: >
      Restrict the source to a bastion or VPN range.
    metadata:
      mitre:
        techniques: ["T1133"]
```

`derived.ingress` is a fact the engine computes, see [Facts the engine computes](#facts-the-engine-computes).

### Kubernetes privileged container

<!-- rules-file -->

```yaml
rules:
  - id: EXAMPLE_K8S_PRIVILEGED
    title: Kubernetes container running in privileged mode
    description: >
      A container is running with full root capabilities, bypassing all
      Linux security controls. A compromised privileged container can
      escape to the host node.
    stride_category: elevation_of_privilege
    severity: critical
    confidence: definitive
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
```

---

## Built-in rules as shipped

The built-in rules are written exactly like yours.
Three of them, copied from the rule files by the documentation generator, so they are the real thing:

<!-- gen:shown-rules -->
### `S3_PUBLIC_ACCESS`

From `builtin/aws/s3.yml`:

```yaml
  - id: S3_PUBLIC_ACCESS
    title: S3 bucket allows public access
    description: >
      The bucket is readable or writable by anyone.
      Either its ACL is public-read, public-read-write or authenticated-read (any AWS account
      holder) and the public access block does not ignore public ACLs, or a bucket policy
      allows every principal with no condition that limits the caller (aws:PrincipalOrgID,
      aws:SourceVpce, aws:SourceVpc, aws:SourceArn, aws:SourceAccount or aws:PrincipalArn)
      and the public access block does not stop public policies.
      Public buckets are how most cloud data breaches start.
    stride_category: information_disclosure
    severity: critical
    confidence: definitive
    root_cause: s3-public-access
    resource_type: aws_s3_bucket
    condition:
      any_of:
        - all_of:
            - derived.acl:
                matches_any: ["public-read", "public-read-write", "authenticated-read"]
            - derived.public_access_block.block_public_acls:
                not_equals: true
            - derived.public_access_block.ignore_public_acls:
                not_equals: true
        - all_of:
            - derived.allows_any_principal:
                equals: true
            - derived.public_access_block.block_public_policy:
                not_equals: true
            - derived.public_access_block.restrict_public_buckets:
                not_equals: true
    mitigation: >
      Set the ACL to private, remove statements that name every principal from the bucket
      policy or narrow them with aws:PrincipalOrgID, aws:SourceVpce or aws:SourceArn, and turn on
      all four settings of aws_s3_bucket_public_access_block.
    metadata:
      mitre:
        techniques: ["T1530"]
```

### `RDS_NO_ENCRYPTION`

From `builtin/aws/rds.yml`:

```yaml
  - id: RDS_NO_ENCRYPTION
    title: RDS database without encryption at rest
    description: >
      The database instance or Aurora cluster does not have storage encryption enabled.
      Its storage, snapshots and automated backups are unencrypted, so anyone who obtains a
      snapshot or the underlying volume can read the data.
      Encryption can only be chosen when the database is created.
      A database restored from a snapshot or created as a replica inherits the source's setting
      and is not reported, and neither is an instance that belongs to a cluster, which inherits
      the cluster's, or a serverless Aurora cluster, which is always encrypted.
    stride_category: information_disclosure
    severity: high
    confidence: definitive
    root_cause: rds-storage-unencrypted
    resource_types: [aws_db_instance, aws_rds_cluster]
    condition:
      all_of:
        - any_of:
            - storage_encrypted:
                equals: false
            - storage_encrypted:
                not_exists: true
        - snapshot_identifier:
            not_exists: true
        - replicate_source_db:
            not_exists: true
        - replication_source_identifier:
            not_exists: true
        - db_cluster_identifier:
            not_exists: true
        - engine_mode:
            not_equals: serverless
    mitigation: >
      Set storage_encrypted to true, with a customer-managed kms_key_id where key control matters.
      To encrypt an existing database, copy a snapshot with encryption and restore from it.
    metadata:
      mitre:
        techniques: ["T1530"]
```

### `K8S_PRIVILEGED_CONTAINER`

From `builtin/kubernetes/workloads.yml`:

```yaml
  - id: K8S_PRIVILEGED_CONTAINER
    title: Container running in privileged mode
    description: >
      A container is configured with privileged: true, giving it full access to the host.
      This effectively disables all container isolation.
      It applies to regular, init and ephemeral containers alike.
    stride_category: elevation_of_privilege
    severity: critical
    confidence: definitive
    resource_type: "@kubernetes_pod_workloads"
    condition:
      privileged:
        equals: true
    mitigation: >
      Remove privileged: true from the container securityContext.
      Use specific capabilities instead.
    metadata:
      mitre:
        techniques: ["T1611"]
```
<!-- /gen:shown-rules -->

Note `confidence` and `root_cause`, a technique and no tactic, and conditions that read `derived.*` facts.
A built-in id cannot be reused, so to start from one, copy it and give it your own prefix.

---

## Facts the engine computes

Some questions cannot be asked of one attribute.
Whether a bucket is versioned depends on `aws_s3_bucket_versioning`, a different resource.
Whether a security group is open depends on inline `ingress` blocks, `aws_security_group_rule` and `aws_vpc_security_group_ingress_rule` taken together.
After the graph is built, an enrichment pass folds companion resources into their parent and writes the answers under `derived.*`, where a rule reads them like any other property.

- `derived.ingress` and `derived.egress` hold the rules of a security group in one canonical shape, whatever resources declared them.
- `derived.versioning_enabled`, `derived.logging_enabled`, `derived.sse_algorithm` and `derived.public_access_block` hold the effective settings of a bucket.
- `derived.has_flow_log` says whether a flow log targets a VPC, and `derived.has_diagnostic_settings` whether a diagnostic setting targets an Azure resource.
- `derived.policy_statements`, `derived.assume_role_statements` and `derived.inline_policy_statements` hold parsed policy statements (effect, actions, resources, principals, condition keys) for IAM, KMS, S3, SQS and SNS.
- `derived.role_attached_policy_arns` and `derived.role_policy_statements` hold what the role of a Lambda function, instance or task allows.

A companion whose parent cannot be resolved (a variable, a value known only after apply, an ambiguous name) makes the same facts `Unknown` on every candidate parent, so a rule never reports "unconfigured" for something it could not see.
The namespace is reserved: an input that carries its own `derived` attribute has it replaced.
Each enrichment module documents the keys it writes in its docstring (`src/threatcode/ir/enrichment/`).

Kubernetes workloads carry one property shape whatever the kind, so a rule written once applies to every pod-bearing kind.
`privileged`, `host_network`, `host_pid` and `host_ipc` are workload-wide flags, and `container_findings` maps a property to the containers that make it unsafe (`{"privileged": ["log-shipper"]}`).
`seccomp_profile_type`, `has_seccomp_profile`, `has_cpu_limit`, `has_memory_limit` and `has_ephemeral_storage_limit` give the effective settings (a container value wins over the pod value), `effective_automount_sa_token` settles token mounting across the pod and its ServiceAccount, and `ingress_policy_covered` and `egress_policy_covered` say whether a NetworkPolicy of the same scan input selects the workload.
Roles carry `has_wildcard_api_groups`, `has_escalation_verbs`, `has_secrets_read` and `has_pod_exec`, bindings carry `binds_unauthenticated_group` and `binds_authenticated_group`, and an Ingress carries `has_tls`.

An MCP config is read into one `mcp_server` per entry and one `mcp_agent` per config scope.
The agent holds the union of what its enabled servers can do as three booleans, `reads_private_data`, `ingests_untrusted_content` and `can_exfiltrate_or_act`, and a rule written for `resource_type: mcp_agent` combines them (`MCP_LETHAL_TRIFECTA` requires all three).
Each server gets its capability tags from one reviewed table of known packages and images and from facts its own entry proves, never by starting it; a server missing from the table adds nothing and is reported as `mcp.unknown_capability`.

Provider defaults work the other way round.
A Terraform file or CloudFormation template leaves out values that a plan prints, so a module may declare `DEFAULTS` that fill an absent attribute in place, for HCL and CloudFormation input only, never for a plan or a design.
The filled paths are listed in `derived.defaults_applied`.

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

Pass a rule file with `--rules`, as many times as you like:

<!-- runnable -->

```bash
cat > my_rules.yml <<'EOF'
rules:
  - id: EXAMPLE_INSTANCE_WITHOUT_OWNER_TAG
    title: Instance without an owner tag
    description: Every instance needs an owner tag so incidents have somebody to call.
    stride_category: repudiation
    severity: low
    confidence: absence
    resource_type: aws_instance
    condition:
      tags.owner:
        not_exists: true
    mitigation: Add an owner tag.
EOF
threatcode scan examples/aws-webapp --rules my_rules.yml -f json -o report.json --fail-on none
grep -q EXAMPLE_INSTANCE_WITHOUT_OWNER_TAG report.json
```

A custom rule file decides what is reported, so it comes only from you:

- `--rules FILE` on the command line, repeatable.
- `rules` in a config file that you name with `--config`.
  An auto-discovered `.threatcode.yml` cannot load rules, because it belongs to the repository being scanned.
- `extra_rule_paths=[...]` in the Python API.

```yaml
# rules.yml, used with: threatcode scan infra/ --config rules.yml
rules:
  - rules/my_org_rules.yml
  - rules/compliance.yml
```

Relative paths in `rules` resolve against the directory of the config file.

```python
from threatcode import scan

report = scan("tfplan.json", extra_rule_paths=["my_rules.yml"])
```

Rules loaded from a custom file get the source group `custom__<file stem>`.
A finding from one of your rules is a normal finding: it can be suppressed, baselined, gated on and exported like any other.

---

## Constraints

| Limit | Value |
|-------|-------|
| Max rules per file | 100 |
| Max total rules | 1000 |
| Max rule file size | 1 MB |
| Rule ID uniqueness | Global (across all loaded files) |
| Symlinks in `--rules` and `rules` | Blocked |
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
