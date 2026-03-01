# ThreatCode

**Threat Model as Code — automated threat modeling derived from your actual infrastructure.**

```python
from threatcode import scan

report = scan("tfplan.json")

for threat in report["threats"]:
    print(f"[{threat['severity'].upper()}] {threat['title']}")
    print(f"  Resource: {threat['resource_address']}")
    print(f"  MITRE:    {threat['mitre_techniques']}")
    print(f"  Fix:      {threat['mitigation']}")
```

ThreatCode turns your Infrastructure-as-Code into a living threat model. Every `terraform plan` produces an up-to-date, MITRE ATT&CK-mapped threat analysis — no separate diagrams, no manual translation, no drift. It bridges a critical gap in the DevSecOps pipeline: tools like Checkov, tfsec, and Trivy catch *misconfigurations* — ThreatCode performs actual *threat modeling*, identifying how an attacker could exploit your infrastructure's architecture, trust relationships, and data flows.

## Install

```bash
pip install threatcode
```

## Library API

The primary interface is the `scan()` function, which accepts any supported IaC file and returns a structured threat report:

```python
from threatcode import scan

# Basic scan — rules only, no LLM
report = scan("tfplan.json", no_llm=True)

# Filter by severity
report = scan("tfplan.json", min_severity="high")

# With custom rules
report = scan("tfplan.json", extra_rule_paths=["my_rules.yml"])

# With config file
report = scan("tfplan.json", config_path=".threatcode.yml")
```

The return value is a dict:

```python
{
    "version": "0.2.1",
    "timestamp": "2026-02-28T15:26:24Z",
    "scanned_resources": 7,
    "total_threats": 12,
    "summary": {"critical": 3, "high": 4, "medium": 5},
    "threats": [
        {
            "id": "8ec379e733ff",
            "title": "S3 bucket without server-side encryption",
            "description": "The S3 bucket does not have server-side encryption...",
            "stride_category": "information_disclosure",
            "severity": "high",
            "source": "rule",                           # "rule", "boundary", or "llm"
            "resource_type": "aws_s3_bucket",
            "resource_address": "aws_s3_bucket.data",
            "mitigation": "Enable SSE-S3 or SSE-KMS...",
            "rule_id": "S3_NO_ENCRYPTION",
            "confidence": 1.0,
            "mitre_techniques": ["T1530"],              # ATT&CK technique IDs
            "mitre_tactics": ["TA0009"],                # ATT&CK tactic IDs
        },
        # ...
    ],
}
```

### Programmatic Access to Internals

For deeper integration, you can use the component APIs directly:

```python
from threatcode.parsers import detect_and_parse
from threatcode.ir.graph import InfraGraph
from threatcode.engine.hybrid import HybridEngine
from threatcode.formatters.sarif import format_sarif

# Parse any supported format (auto-detected)
parsed = detect_and_parse("tfplan.json")

# Build the infrastructure graph
graph = InfraGraph.from_parsed(parsed)

# Inspect the graph
for node_id, node in graph.nodes.items():
    print(f"{node_id}: {node.category.value} in {node.trust_zone.value} zone")

for edge in graph.get_boundary_crossing_edges():
    print(f"Boundary crossing: {edge.source} -> {edge.target}")

# Run the threat engine
engine = HybridEngine()
report = engine.analyze(graph)

# Output as SARIF
sarif_json = format_sarif(report)
```

## Why Threat Model as Code

Traditional threat modeling lives in diagrams that drift out of date the moment infrastructure changes. ThreatCode eliminates that gap: your threat model is derived directly from what you're deploying, regenerated on every `terraform plan`, and embedded in your CI/CD pipeline.

### The Gap ThreatCode Fills

| Tool | What it does | What it misses |
|------|-------------|----------------|
| Checkov / tfsec / Trivy | Linting — flags misconfigurations (public S3, no encryption) | Architectural threats, trust boundary crossings, lateral movement paths |
| Threagile | Threat modeling from custom YAML DSL | Requires manual translation of your IaC into its own format |
| IriusRisk | Commercial threat modeling | Shallow IaC integration, expensive, vendor lock-in |
| **ThreatCode** | **Threat Model as Code — automated from your actual IaC** | — |

### What Organizations Get

1. **Threat models that never drift** — Derived from live IaC, not a separate diagram. Every `terraform plan` produces an up-to-date threat model with MITRE ATT&CK technique mappings.

2. **CI/CD native** — Plugs into GitHub Actions (SARIF upload to Code Scanning) and Bitbucket Pipelines (Code Insights API). Threats appear as annotations on pull requests, right next to the code that introduces them.

3. **MITRE ATT&CK mapped** — All findings map to ATT&CK Cloud Matrix techniques. Export Navigator layer JSON for threat matrix visualization. Speak the same language as your SOC and red team.

4. **Hybrid analysis engine** — Deterministic YAML rules catch known patterns (public buckets, wildcard IAM, unencrypted databases). An optional LLM layer identifies architectural threats that rules can't: implicit trust relationships, missing defense-in-depth, lateral movement attack paths.

5. **Enterprise-grade redaction** — Before any data reaches an external LLM, ThreatCode strips AWS account IDs, ARNs, IP addresses, tags, and other sensitive fields using configurable placeholder or hash strategies. For zero-trust environments, point it at a local LLM (Ollama, vLLM) — no data leaves your network.

6. **Actionable output** — Every threat includes a STRIDE classification, ATT&CK technique, severity ranking, the specific resource affected, and a concrete mitigation. No vague "consider improving security" — you get `Set publicly_accessible = false on aws_db_instance.main and place it in a private subnet.`

## How It Works

```
IaC Files ─► Parser Layer ─► Cloud-Agnostic IR ─► Hybrid Threat Engine ─► Output Formatters
                              (NetworkX Graph)    ├─ Rule-based (YAML)     ├─ SARIF 2.1.0
                                                  ├─ Boundary analysis     ├─ JSON
                                                  └─ LLM-augmented        ├─ Markdown
                                                                          ├─ ATT&CK Navigator
                                                                          ├─ Bitbucket
                                                                          └─ Diff
```

1. **Parse** — Reads `terraform show -json` output (resolves all modules, variables, conditionals), raw `.tf` files, or CloudFormation YAML/JSON.
2. **Build IR** — Constructs a directed graph of infrastructure nodes (compute, storage, network, IAM, etc.) with edges representing dependencies, containment, network flows, and IAM bindings. Each node is classified into a trust zone (internet, DMZ, private, data, management).
3. **Analyze** — Evaluates 19 built-in YAML rules across 6 AWS services, all mapped to MITRE ATT&CK techniques. Detects trust boundary crossings (e.g., DMZ to data zone flows). Optionally sends a redacted graph to an LLM for architectural threat identification.
4. **Report** — Outputs threats in SARIF (GitHub Code Scanning), ATT&CK Navigator layer JSON, Markdown (PR comments), JSON, Bitbucket Code Insights, or diff format. Each threat includes STRIDE category, ATT&CK techniques, severity, affected resource, and mitigation.

## Built-in Rules

| Service | Rules | Covers |
|---------|-------|--------|
| S3 | 4 | Missing encryption, public access, no versioning, no logging |
| IAM | 3 | Wildcard actions, no MFA, overpermissive assume-role |
| EC2 | 3 | Public IP exposure, no monitoring, unencrypted EBS |
| VPC | 3 | Default SG open, unrestricted ingress, no flow logs |
| RDS | 3 | Public access, no encryption, no backups |
| Lambda | 3 | No VPC attachment, overpermissive role, no DLQ |

Rules are declarative YAML with structured operators (`not_exists`, `equals`, `contains`, `matches_any`, `all_of`, `any_of`, `none_of`). No `eval()` — enterprise-safe. Add custom rules:

```python
report = scan("tfplan.json", extra_rule_paths=["my_org_rules.yml"])
```

## STRIDE Categories

Every threat is classified into one of the six STRIDE categories:

| Category | Threatens | Example |
|----------|-----------|---------|
| **S**poofing | Authentication | IAM role with overly broad assume-role policy |
| **T**ampering | Integrity | S3 bucket without versioning |
| **R**epudiation | Audit trails | S3 bucket without access logging |
| **I**nformation Disclosure | Confidentiality | RDS instance publicly accessible |
| **D**enial of Service | Availability | Lambda without dead letter queue |
| **E**levation of Privilege | Authorization | IAM policy with wildcard actions |

## LLM Integration

ThreatCode's hybrid engine optionally uses an LLM to identify architectural threats that deterministic rules cannot catch — cross-resource attack paths, implicit trust assumptions, missing segmentation.

```python
# Claude API
report = scan("tfplan.json", no_llm=False, config_path=".threatcode.yml")

# Dry run — see what would be sent to the LLM without calling it
report = scan("tfplan.json")  # configure dry_run: true in .threatcode.yml
```

### Redaction

All infrastructure data is redacted before reaching any external LLM:

- AWS account IDs, ARNs, IP addresses, email addresses are replaced with placeholders
- Tags and sensitive metadata are stripped
- Configurable strategy: `placeholder` (default) or `hash`
- For full air-gap: use a local LLM via OpenAI-compatible API (Ollama, vLLM, llama.cpp)

### Configuration

```yaml
# .threatcode.yml
llm:
  provider: anthropic          # or "ollama", "openai", "local"
  model: claude-sonnet-4-20250514
  base_url: ""                 # Required for local LLMs
  max_tokens: 4096

redaction:
  enabled: true
  strategy: placeholder        # or "hash"
  fields: [arn, account_id, tags, ip_address]

min_severity: info
no_llm: false
```

## CLI (Included)

ThreatCode ships with a CLI for quick scans and CI/CD integration:

```bash
# Rules-only scan, JSON output
threatcode scan tfplan.json --no-llm --format json

# SARIF for GitHub Code Scanning
threatcode scan tfplan.json --no-llm --format sarif -o results.sarif

# Markdown for PR comments
threatcode scan tfplan.json --no-llm --format markdown

# Diff between two runs
threatcode diff baseline.json current.json --format markdown

# LLM dry run
threatcode scan tfplan.json --dry-run
```

### GitHub Actions

```yaml
- name: ThreatCode Scan
  uses: ./.github/actions/threatcode
  with:
    input-file: tfplan.json
    format: sarif
    no-llm: 'true'
    min-severity: medium
```

Uploads SARIF results to GitHub Code Scanning — threats appear as security alerts on PRs.

## Architecture

- **Parser layer** — Pluggable parsers for Terraform plan JSON, raw HCL, and CloudFormation. Auto-detection based on file extension and content.
- **Intermediate Representation** — NetworkX directed graph. Nodes have categories (compute, storage, IAM, etc.) and trust zones. Edges represent dependencies, containment, network flows, and IAM bindings.
- **Rule engine** — Declarative YAML rules with structured operators. No `eval()` — enterprise-safe.
- **LLM integration** — Anthropic Claude API, OpenAI-compatible (Ollama, vLLM, llama.cpp), or dry-run mode. All data is redacted before leaving your environment.
- **Output formatters** — SARIF 2.1.0 (GitHub), ATT&CK Navigator layer JSON, Bitbucket Code Insights, Markdown, JSON, and diff.

## License

MIT
