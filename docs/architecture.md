# Architecture

ThreatCode turns infrastructure code into a graph, decides which parts of the graph an attacker can reach, and reports the weaknesses on the way.
This page follows one scan from the command line to the report.

## Pipeline

```text
paths ──> discovery ──> parsers ──> graph ──> enrichment ──> exposure ──> reachability
                                                                              │
reports <── formatters <── suppressions <── [ rules ─ context ─ boundaries ─ severity ─ paths ─ LLM ]
```

`threatcode.pipeline.run_scan` runs the whole sequence, and the command line, `threatcode.scan` and `threatcode.analyze` all call it, so they cannot disagree.

1. **Discovery** (`threatcode.discovery`) walks the named paths and groups what it finds into *units*: a Terraform module directory, a plan, a Helm chart, a template, a manifest, a Dockerfile, an MCP config.
   It reads only regular files, never follows a symlink out of the tree, and counts what it skipped.
2. **Parsers** (`threatcode.parsers`) turn each unit into a `ParsedOutput`: resources, the references between them, source lines and diagnostics.
3. **The graph** (`threatcode.ir.graph.InfraGraph`) joins every unit into one graph.
   It turns references into typed edges, gives each node a category and a trust zone, and qualifies addresses that two units share.
4. **Enrichment** (`threatcode.ir.enrich`) folds companion resources into their parents, so a bucket's versioning, encryption and public access block become facts under `derived.*` that a rule can read.
5. **Exposure** decides, for every node, whether the configuration puts it within reach of the internet, keeps it off the internet, or says nothing.
6. **Reachability** (`threatcode.ir.reachability`) adds the directed edges an attacker follows, starting from a synthetic `internet` node.
7. **The engine** (`threatcode.engine.hybrid.HybridEngine`) runs its phases in order: rules, secret and scanner findings, boundary crossings, contextual severity, attack paths and the optional LLM review.
8. **Suppressions and the baseline** remove accepted findings before the gate is computed.
9. **Formatters** render the result.

## Parsers

A parser is registered with a detector and a factory.
The registry asks each detector in priority order, lowest first, and the first that claims a file parses it.
A file that a parser claims but cannot parse is an input error and exit 2, never a silent skip.

<!-- gen:parsers -->
| Parser | Priority | File extensions |
| --- | --- | --- |
| `helm` | 8 | `.yaml`, `.yml` |
| `terraform_plan` | 10 | `.json` |
| `mcp_config` | 15 | `.json` |
| `cloudformation` | 20 | `.cfn`, `.json`, `.template`, `.yaml`, `.yml` |
| `kubernetes` | 22 | `.json`, `.yaml`, `.yml` |
| `dockerfile` | 25 | by content |
| `terraform_hcl` | 30 | `.json`, `.tf`, `.tofu` |
<!-- /gen:parsers -->

Every parser produces `ParsedResource` objects with the same fields, so the graph does not care where a resource came from:

| Field | Meaning |
|-------|---------|
| `resource_type`, `address`, `name`, `provider` | What it is and how it is addressed (`aws_s3_bucket.logs`). |
| `properties` | Attribute names and values as the rules read them. A value the parser cannot determine is `values.Unknown`, never absent and never text. |
| `references` | Attribute path to the raw reference strings written there, for example `ingress[].security_groups`. The graph resolves them to typed edges. |
| `dependencies` | Explicit dependencies such as `depends_on`. |
| `start_line`, `end_line`, `source_location` | Where the block is, so a finding points at it. |
| `mode` | `managed` for a resource the input creates, `data` for one it looks up (context only, rules never run on it). |
| `meta` | Bookkeeping such as `count`, `for_each` and the module instance, invisible to rules. |
| `trust_zone`, `boundary`, `evidence` | A zone or boundary the input declares, and whether the properties come from configuration (a missing property is a fact) or from a design (a missing property is unknown). |

A parser reports what it could not analyse as `Diagnostic` objects with a code from a closed registry (`hcl.module_call_skipped`, `helm.fallback_render`, `cfn.unresolved_intrinsic`).
Warnings become coverage gaps.

To add a parser, see [API reference](api-reference.md#register-a-custom-parser).

## The graph

Nodes carry a category, a trust zone and an exposure.

- **Categories:** compute, storage, network, database, iam, serverless, cdn, dns, monitoring, messaging, container, secret, api and unknown.
  A data store, a secret store (keys, secrets, parameters, certificates, Kubernetes Secrets) and an API are separate categories because they play different roles on a path.
- **Trust zones:** internet, dmz, private, data and management.
  The zone follows the category, with property overrides: a data store stays in `data` even when it is public, and gains `exposure: internet` instead, so it can be the end of an attack path rather than an entry.
- **Exposure:** `internet`, `internal` or `unknown`.
  Only a flag the configuration states as true counts; `(known after apply)`, a variable and the string `"false"` do not.

Provider defaults that a plan materialises but HCL and CloudFormation leave out (for example an EKS cluster's public endpoint) are filled in only for HCL and CloudFormation input, never for a plan or a design.

### Edges

| Type | Meaning |
|------|---------|
| `containment` | The source is placed in the target (instance in subnet, subnet in VPC). |
| `dependency` | The source references the target. `relation` says how: `security_group`, `encrypts_with`, `references`. A security group attachment is wiring, not traffic. |
| `network_flow` | The source can send traffic to the target. |
| `data_flow` | A flow of data that the input declares. |
| `iam_binding` | The source assumes or uses the target's permissions: `assumes`, `instance_profile`, `attaches`, `has_policy`, `can_assume`, `resource_policy`, `permission`. |

**An edge exists only because the input names its target.**
There is no "first VPC" guess and no matching on names.
A literal that names nothing makes no edge, and a literal `vpc_id` binds only when the input has exactly one VPC.
Ambiguity is a diagnostic, not a guess.

*Structural* edges (containment, dependency) say how things are wired.
*Reachability* edges (network flow, data flow, IAM binding) say what an attacker who controls the source can reach.
Attack paths follow reachability edges only, so a VPC that merely contains two subnets never joins them.
Reachability edges carry `source` (where the fact came from), `via` (the nodes that enable it), `protocol`, `ports`, `world_open` and `definite`.
Two facts about one pair merge into one edge.

Reachability is modeled for:

- **AWS:** security group rules between groups and from the internet, load balancer listeners and target groups, CloudFront origins, API Gateway integrations and Lambda permissions, Lambda function URLs, public buckets and public EKS endpoints, Auto Scaling groups and ECS services, and IAM: instance profiles, trust policies, attached and inline policies, and resource policies.
- **Kubernetes:** Ingress to Service to workload, the Secrets a workload reads, the ServiceAccount it runs as, and the Roles and ClusterRoles a binding grants, including across files.
- **MCP agent configs:** an enabled server that ingests untrusted content or is remote is entered from the internet, and content flows through the agent to the servers that read private data.

**Azure and GCP resources are not modeled for reachability.**
They get rule findings, severities and ATT&CK mappings, but no exposure, no reachability edges and no attack paths.

## The engine

`HybridEngine.analyze` runs six phases, each in its own module:

| Phase | Module | What it does |
|-------|--------|--------------|
| Rules | `engine.hybrid` | Every rule against every node of its resource type. A rule that raises is recorded in `coverage.rule_errors` and the scan continues. |
| Context | `engine.context` | Secret findings and ingested scanner findings join the threat list. |
| Boundaries | `engine.boundaries` | One finding per pair of resources whose traffic crosses a trust zone, from the flow edges only. |
| Severity | `engine.severity` | Adds `effective_severity` and `severity_reason` when context changes a finding. The base severity is never touched. |
| Paths | `engine.paths` | Searches for attack paths and tags the enabling findings with the path id. |
| LLM | `engine.llm.phase` | The optional review. Its findings are advisory. |

### Rules

A rule is a YAML condition over a node's properties, written once and applied to every node of its resource type.
Conditions are evaluated three-valued: true, false or unknown, and a rule fires only on true.
A value the parser marked `Unknown` makes every operator unknown, so an unresolved value never produces a finding and never counts as a pass, and on a design input a missing property is unknown instead of absent.
Rule files are checked when they load: an unknown operator, a malformed path or a duplicate key stops the load with an error that names the file and the rule.

### Severity

A finding keeps the base severity its rule assigns.
The engine raises it one level for a weakness on a resource that the internet reaches over network flows (unless the finding states the exposure itself), and for any finding on a data store tagged with a sensitive classification.
It lowers it one level for exposure marked intentional with a `Public=true`, `Intent=public` or `threatcode:intent=public` tag.
The gate, SARIF `security-severity` and the reports use the effective severity.

### Attack paths

An attack path runs from the `internet` node over reachability edges to a crown jewel: a data store, a secret store, an identity that may do everything, a Kubernetes Secret or cluster-admin grant, or an MCP server that reads private data.
It ends at the first crown jewel it reaches, runs through at most 8 edges and visits no node twice.
Monitoring nodes, networks, namespaces and companion resources are never targets and never part of a path.

Each hop lists the findings that enable it (`enabled_by`), the edge to the next hop (`via`) and the ATT&CK techniques of the step.
A path is kept only when some finding enables a hop or the target.
Its severity is the worst effective severity of the enabling findings, one level higher when the target is a tagged data store, and never above `high` unless every edge on it is definite.
Routes that differ only by the instance of a counted resource are one path with `alternatives` counting the others.
At most 5 routes per target and 100 paths are kept, and the search is bounded and says so when it stops early.

### Limits

The graph limits nodes, edges and the fan-out of each reachability rule (`--max-nodes`, `--max-edges`, `THREATCODE_MAX_FANOUT`), and every limit that cuts a result is a coverage gap that says so.
See [security model](security-model.md) for the resource limits that protect the scan itself.

## Formatters

`threatcode.formatters.FORMATTERS` is the one registry the command line, the config and the Python API read.
Each formatter takes an `AnalysisResult` (the graph, the report, the scan root and the ingested sources) and returns text.
SARIF and Bitbucket annotations use the scan root to write repository-relative paths.

## LLM review

The model sees a pseudonymized, allowlisted copy of the graph, never the input files, and its findings are validated, attributed to a resource of the scan and tagged as advisory.
A finding that names no resource of the scan is quarantined in `llm.unattributed`.
See [security](security.md).
