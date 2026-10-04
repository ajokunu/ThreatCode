# Architecture

ThreatCode is a multi-scanner security analysis pipeline. Input flows through auto-detection, parsing, graph construction, and parallel scanning engines before being serialized to one of eight output formats.

---

## Pipeline Overview

```
Input Files / Container Images
         │
         ▼
┌─────────────────────────────────────────────────────────┐
│                  Auto-Detection Layer                    │
│  Priority-ordered parser registry detects format        │
│  from filename, extension, and content heuristics       │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                    Parser Layer                          │
│  Terraform Plan JSON  ▸  HCL  ▸  CloudFormation        │
│  Dockerfile  ▸  Kubernetes  ▸  Lockfiles (10 formats)  │
│  OCI Registry Client  ▸  Layer Extractor                │
│                                                          │
│  Output: ParsedOutput { resources: ParsedResource[] }   │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│           Infrastructure Graph (NetworkX)                │
│                                                          │
│  InfraNode:                                              │
│    resource_type, category (NodeCategory enum)          │
│    trust_zone (TrustZone enum), properties, provider    │
│                                                          │
│  Edges: DEPENDENCY, CONTAINMENT, NETWORK_FLOW,          │
│         IAM_BINDING, DATA_FLOW                          │
│                                                          │
│  Trust zones: internet → dmz → private → data → mgmt    │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  Scanning Engines                        │
│                                                          │
│  ① HybridEngine (threat modeling)                       │
│     - YAML rule matching (228 built-in rules)           │
│     - Trust boundary crossing detection                  │
│     - Optional LLM architectural analysis               │
│                                                          │
│  ② SecretScanner                                        │
│     - 24 regex patterns + keyword pre-filter            │
│     - Binary detection, allow-list, redaction           │
│                                                          │
│  ③ VulnerabilityScanner                                 │
│     - SQLite offline DB (OSV bulk data)                 │
│     - semver / PEP 440 / RPM version comparison        │
│                                                          │
│  ④ ImageScanner                                         │
│     - OS detection + APK/DPKG/RPM package parsing      │
│     - OS advisory matching                              │
│     - Application lockfile detection in images         │
│                                                          │
│  ⑤ LicenseScanner                                      │
│     - SPDX classification                               │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│                  Output Formatters                       │
│                                                          │
│  JSON  ▸  SARIF 2.1.0  ▸  Markdown  ▸  Bitbucket       │
│  ATT&CK Navigator  ▸  SVG Diagram  ▸  CycloneDX 1.5    │
│  Table (image)  ▸  Diff                                 │
└─────────────────────────────────────────────────────────┘
```

---

## Parser Layer

### Auto-Detection Registry

Parsers are registered with a priority value. Lower priority = tried first.

| Priority | Parser | Detection |
|----------|--------|-----------|
| 5 | LockfileParser | Filename matches known lockfile names |
| 10 | TerraformPlanParser | JSON with `planned_values` or `format_version` |
| 20 | CloudFormationParser | YAML/JSON with `AWSTemplateFormatVersion` or `Resources` + descriptor |
| 22 | KubernetesParser | YAML with `apiVersion` AND `kind` |
| 25 | DockerfileParser | Filename `Dockerfile`, `Dockerfile.*`, `*.dockerfile` |
| 30 | TerraformHCLParser | `.tf` extension |

Register custom parsers:

```python
from threatcode.parsers import register_parser
register_parser(
    name="my_format",
    detector=my_detect_fn,   # (path, content, parsed_data) -> bool
    factory=MyParser,        # returns a BaseParser
    extensions={".myext"},
    priority=50,             # lower is checked first; built-ins use 5-30
)
```

### ParsedResource Structure

Every parser normalizes resources into `ParsedResource`:

```python
@dataclass
class ParsedResource:
    resource_type: str       # e.g. "aws_s3_bucket", "kubernetes_pod"
    address: str             # Unique address within the file
    name: str                # Human-readable name
    provider: str            # "aws", "docker", "kubernetes", "npm", ...
    properties: dict         # All resource attributes
    dependencies: list[str]  # Addresses of resources this depends on
    module: str              # Terraform module path (if applicable)
    source_location: str     # "file.tf:42"
    trust_zone: str | None   # zone declared by the input; None infers it
    boundary: str            # declared boundary id, finer than the zone
    evidence: str            # "config" (IaC) or "design" (diagram, threat model)
```

A parser can also state edges directly in `ParsedOutput.edges`, as `ParsedEdge(source, target, edge_type="data_flow", metadata={})`.
Design inputs use this for data flows, which configuration only implies.

`evidence` records where a resource's properties came from.
In configuration a missing property is a fact, because a Terraform plan lists every attribute.
In a design a missing property is unknown, and the engine treats it that way.

---

## Infrastructure Graph (InfraGraph)

The graph is a NetworkX `DiGraph`. Each node is an `InfraNode`:

### NodeCategory Enum

| Value | Maps to (DFD) | Example Resources |
|-------|--------------|-------------------|
| `compute` | Process | EC2, VM, Lambda, Pod, ECS |
| `storage` | Data Store | S3, Blob, GCS bucket |
| `network` | Data Flow | VPC, Subnet, Load Balancer, SG |
| `database` | Data Store | RDS, DynamoDB, CosmosDB, Cloud SQL |
| `iam` | External Entity | IAM Role, Service Account, RBAC |
| `serverless` | Process | Lambda, Azure Functions, Cloud Functions |
| `cdn` | Data Flow | CloudFront, Azure CDN |
| `dns` | Data Flow | Route53, Azure DNS |
| `monitoring` | Process | CloudWatch, Azure Monitor |
| `messaging` | Data Flow | SNS, SQS, Pub/Sub, Service Bus |
| `container` | Process | EKS, AKS, GKE, K8s workloads |
| `unknown` | Process | Unclassified resources |

### TrustZone Enum

| Zone | Description |
|------|-------------|
| `internet` | Untrusted — externally reachable, no auth |
| `dmz` | Semi-trusted — edge services, load balancers, public APIs |
| `private` | Trusted — internal services, private subnets |
| `data` | Sensitive — databases, file storage, data warehouses |
| `management` | Administrative — IAM, monitoring, bastion hosts |

### Edge Inference

The graph engine automatically infers edges from resource properties:

- **Containment**: VPC → Subnet → EC2 (from `vpc_id`, `subnet_id` properties)
- **IAM Binding**: Lambda → IAM Role (from `role`, `execution_role_arn` properties)
- **Network Flow**: EC2 → RDS when both are in the same security group
- **Dependency**: Explicit `depends_on` references in Terraform
- **Declared**: Edges a parser states in `ParsedOutput.edges`, such as data flows in a design; a declared edge that repeats an inferred one adds its metadata to it

### Trust Boundary Crossing Detection

An edge crosses a trust boundary when its two nodes are in different trust zones, or when both nodes declare a `boundary` and the boundaries differ (two private subnets in a design are separate boundaries in the same zone).
Each crossing produces one Tampering threat.
Crossings between internet and private, internet and data, internet and management, or dmz and data are rated high in either direction; every other crossing is rated medium.

---

## Hybrid Engine

The `HybridEngine` runs three analysis phases in sequence:

**Phase 1 — Rule-based analysis**

Each node's `properties` dict is evaluated against every loaded rule. Rules use a safe condition evaluator (`all_of`, `any_of`, `not_exists`, `equals`, `matches_any`, etc.) — no `eval()`.

**Phase 2 — Boundary analysis**

Every edge that crosses a trust boundary (see above) generates a Tampering threat, rated high or medium by the pair of zones it connects.

**Phase 3 — LLM analysis (optional)**

A redacted representation of the graph is sent to the configured LLM for architectural threat identification. The LLM is prompted to return structured JSON (STRIDE category, severity, MITRE technique, affected resource, mitigation). All output is validated against the known schema before being included.

---

## Container Image Pipeline

```
Image Reference
     │
     ▼
ImageReference.parse()           — full Docker reference grammar
     │
     ▼
RegistryClient.pull_manifest()   — bearer token auth, platform selection
RegistryClient.pull_blob()       — SHA-256 verified download
     │
     ▼
LayerExtractor.extract_from_blobs()
     — decompress (gzip/zstd)
     — apply layers in order
     — whiteout handling (.wh. and .wh..wh..opq)
     — path traversal protection
     │
     ▼
ExtractedImage (temp filesystem)
     │
     ├─ OSDetector.detect()       — /etc/os-release + fallbacks
     │
     ├─ parse_os_packages()       — APK / DPKG / RPM header binary
     │
     ├─ find_app_dependencies()   — lockfiles + site-packages METADATA
     │
     ├─ ImageScanner._scan_os_packages()  — OS advisory DB lookup
     │
     ├─ VulnerabilityScanner      — ecosystem vuln DB lookup
     │
     ├─ SecretScanner (optional)  — pattern matching on image filesystem
     │
     └─ check_image_config()      — OCI config best-practice checks
```

---

## Security Architecture

- **No `eval()` anywhere** — rule conditions use explicit Python comparison functions
- **YAML `safe_load` only** — no arbitrary Python object deserialization
- **Sandboxed rule loading** — symlinks blocked, 1 MB size limit, 1000 rule cap
- **SSRF protection** - all HTTP calls (LLM, registry) validate resolved IPs against private/loopback ranges (the `ollama` and `local` LLM providers can opt in to local addresses with `llm.allow_local_network`)
- **Redaction pipeline** — sensitive values stripped before LLM calls; reversible mapping maintained
- **Path traversal protection** — OCI layer extraction rejects `..` path components before normalization
- **Digest verification** — all downloaded blobs are SHA-256 verified before extraction
