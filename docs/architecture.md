# Architecture

ThreatCode follows a four-stage pipeline architecture:

```
IaC Files --> Parser Layer --> IR Graph --> Hybrid Engine --> Formatter
                              (NetworkX)   |-- Rules (YAML)    |-- SARIF 2.1.0
                                           |-- Boundaries      |-- JSON
                                           '-- LLM             |-- Markdown
                                                               |-- Bitbucket
                                                               |-- ATT&CK Navigator
```

---

## Parser Layer

**Location:** `src/threatcode/parsers/`

The parser layer auto-detects the input format and normalizes it into a common `ParsedOutput` structure.

### Supported Formats

| Format | Parser | Detection |
|--------|--------|-----------|
| Terraform plan JSON | `TerraformPlanParser` | `.json` with `planned_values` or `format_version` key |
| Terraform HCL | `TerraformHCLParser` | `.tf` file extension |
| CloudFormation | `CloudFormationParser` | `.json`/`.yml`/`.yaml` with `AWSTemplateFormatVersion` or `Resources` key |

### `ParsedOutput` Structure

```python
@dataclass
class ParsedOutput:
    resources: list[ParsedResource]
    source_path: str
    format_type: str
    metadata: dict[str, Any]

@dataclass
class ParsedResource:
    resource_type: str          # e.g., "aws_s3_bucket"
    address: str                # e.g., "aws_s3_bucket.data"
    name: str                   # e.g., "data"
    provider: str               # e.g., "registry.terraform.io/hashicorp/aws"
    properties: dict[str, Any]  # raw resource config
    dependencies: list[str]     # explicit dependency references
    module: str                 # module path (if nested)
    source_location: str        # file location hint
```

The entry point is `detect_and_parse(path)`, which dispatches to the correct parser based on file extension and content inspection.

---

## IR Layer (Intermediate Representation)

**Location:** `src/threatcode/ir/`

The IR layer builds a cloud-agnostic directed graph using [NetworkX](https://networkx.org/). This graph is the single source of truth for all downstream analysis.

### Graph Construction

`InfraGraph.from_parsed(parsed)` performs the following steps:

1. **Create nodes** -- Each `ParsedResource` becomes an `InfraNode` with an inferred `NodeCategory` and `TrustZone`.
2. **Infer edges** -- Three types of edges are inferred from resource properties:
    - **Dependencies** -- Explicit Terraform dependency references
    - **Containment** -- VPC/subnet/security group relationships inferred from `vpc_id`, `subnet_id`, `security_groups` properties
    - **IAM bindings** -- Role attachments and instance profile links
3. **Mark trust boundaries** -- Edges connecting nodes in different trust zones are flagged with `crosses_trust_boundary = True`.

### Node Categories

| Category | Example Resources | STRIDE Element |
|----------|------------------|----------------|
| `compute` | EC2 instances, launch templates | Process |
| `storage` | S3 buckets, EBS volumes | Data Store |
| `network` | VPCs, subnets, security groups, load balancers | Data Flow |
| `database` | RDS instances, DynamoDB tables | Data Store |
| `iam` | IAM roles, policies, users | External Entity |
| `serverless` | Lambda functions | Process |
| `cdn` | CloudFront distributions | Data Flow |
| `dns` | Route53 records | Data Flow |
| `monitoring` | CloudWatch resources | Process |
| `messaging` | SNS topics, SQS queues | Data Flow |
| `container` | ECS/EKS resources | Process |

### Trust Zones

Nodes are classified into trust zones based on resource type and properties:

| Zone | Resources | Condition |
|------|-----------|-----------|
| `internet` | Internet gateways | -- |
| `dmz` | Load balancers, CloudFront; also any resource with `publicly_accessible=true` or `associate_public_ip_address=true` | Public-facing |
| `private` | EC2 instances, Lambda, ECS | Default for compute |
| `data` | RDS, DynamoDB, S3, ElastiCache | Data stores |
| `management` | IAM, CloudWatch | Control plane |

### Edge Types

| Type | Meaning | Inference |
|------|---------|-----------|
| `dependency` | Terraform dependency reference | Explicit `depends_on` / reference |
| `containment` | Parent-child relationship | `vpc_id`, `subnet_id` properties |
| `network_flow` | Network-level connection | Security group attachments |
| `iam_binding` | Permission relationship | Role policy attachments, instance profiles |
| `data_flow` | Data transfer path | Inferred from service relationships |

---

## Engine Layer

**Location:** `src/threatcode/engine/`

The `HybridEngine` orchestrates three analysis phases:

### Phase 1: Rule-Based Analysis

Evaluates all YAML rules (19 built-in + any custom rules) against every node in the graph. For each node, the engine checks whether the node's `resource_type` matches the rule's `resource_type` (using prefix matching) and then evaluates the condition tree against the node's properties.

Rule matching uses a safe declarative condition evaluator. See the [Rule Writing Guide](writing-rules.md) for the condition language.

### Phase 2: Trust Boundary Analysis

Iterates over all edges in the graph that cross trust zone boundaries. For each boundary crossing, it generates a `Threat` with:

- STRIDE category: `tampering`
- Severity based on the zone pair (e.g., `internet -> data` is `high`, `private -> data` is `medium`)
- MITRE techniques: T1040 (Network Sniffing), T1557 (Adversary-in-the-Middle)

### Phase 3: LLM-Augmented Analysis

If an LLM client is provided (and `no_llm` is not set):

1. The infrastructure graph is serialized to a dictionary
2. The `Redactor` strips sensitive values (ARNs, account IDs, IPs, emails)
3. A prompt is constructed with the redacted graph and the list of rule IDs already matched (to avoid duplicates)
4. The LLM response is parsed for structured threat objects
5. Resource addresses in the response are unredacted back to their original values
6. MITRE tactic IDs are auto-derived from technique IDs if the LLM omitted them

---

## Formatter Layer

**Location:** `src/threatcode/formatters/`

Formatters convert a `ThreatReport` into output strings:

| Formatter | Output | Use Case |
|-----------|--------|----------|
| `format_json` | JSON object | Default, machine-readable |
| `format_sarif` | SARIF 2.1.0 JSON | GitHub Code Scanning integration |
| `format_markdown` | Markdown tables | PR comments, human review |
| `format_bitbucket` | Bitbucket Code Insights JSON | Bitbucket pipeline integration |
| `format_attack_navigator` | ATT&CK Navigator layer JSON | MITRE ATT&CK visualization |

The `diff` module (`formatters/diff.py`) compares two JSON reports and outputs added/removed/changed threats.

---

## Design Decisions

### Why declarative rules?

YAML rules with structured operators (`equals`, `contains`, `not_exists`, etc.) are auditable, version-controllable, and safe to evaluate. Security teams can review and modify rules without writing code.

### Why no `eval()`?

The condition evaluator never uses `eval()`, `exec()`, `compile()`, or any form of dynamic code execution. All operators are implemented as explicit Python functions with well-defined behavior. Unknown operators fail closed (return `False`). This makes ThreatCode safe to run in enterprise environments where arbitrary code execution in security tooling is unacceptable.

### Why a hybrid approach?

Deterministic rules are fast, reliable, and auditable -- but they can only catch known patterns. Architectural threats (implicit trust relationships, missing defense-in-depth, lateral movement paths) require reasoning about the *relationships* between resources, which is where LLM augmentation adds value. The hybrid approach gives teams deterministic results they can rely on, with optional AI-powered depth.

### Why NetworkX?

NetworkX provides a mature, well-tested graph library with efficient traversal algorithms. The infrastructure graph naturally maps to a directed graph where resources are nodes and relationships are edges. NetworkX makes it straightforward to implement trust boundary detection, neighbor analysis, and path finding.
