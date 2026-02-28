# ThreatCode

**STRIDE threat model generator from Infrastructure-as-Code definitions.**

ThreatCode automatically generates [STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats) threat models from your Terraform plans, HCL files, and CloudFormation templates. It bridges a critical gap in the DevSecOps pipeline: while tools like Checkov, tfsec, and Trivy catch *misconfigurations*, none of them perform actual *threat modeling* — identifying how an attacker could exploit your infrastructure's architecture, trust relationships, and data flows.

## Why This Matters for Organizations

### The Gap ThreatCode Fills

| Tool | What it does | What it misses |
|------|-------------|----------------|
| Checkov / tfsec / Trivy | Linting — flags misconfigurations (public S3, no encryption) | Architectural threats, trust boundary crossings, lateral movement paths |
| Threagile | Threat modeling from custom YAML DSL | Requires manual translation of your IaC into its own format |
| IriusRisk | Commercial threat modeling | Shallow IaC integration, expensive, vendor lock-in |
| **ThreatCode** | **STRIDE threat modeling from your actual IaC** | — |

### What Organizations Get

1. **Threat-models-as-code** — Your threat model is derived from what you're actually deploying, not a separate diagram that drifts out of date. Every `terraform plan` produces an up-to-date threat model.

2. **CI/CD native** — Runs in GitHub Actions (SARIF upload to Code Scanning) and Bitbucket Pipelines (Code Insights API). Threats appear as annotations on your pull requests, right next to the code that introduces them.

3. **Hybrid analysis engine** — Deterministic YAML rules catch known patterns (public buckets, wildcard IAM, unencrypted databases). An optional LLM layer (Claude API, or any OpenAI-compatible local model) identifies architectural threats that rules can't: implicit trust relationships, missing defense-in-depth, lateral movement attack paths.

4. **Enterprise-grade redaction** — Before any data reaches an external LLM, ThreatCode strips AWS account IDs, ARNs, IP addresses, tags, and other sensitive fields using configurable placeholder or hash strategies. Supports PCI-DSS and SOC 2 compliance requirements. For zero-trust environments, point it at a local LLM (Ollama, vLLM) and no data leaves your network.

5. **Actionable output** — Every threat includes a STRIDE classification, severity ranking, the specific resource affected, and a concrete mitigation. No vague "consider improving security" — you get "Set `publicly_accessible = false` on `aws_db_instance.main` and place it in a private subnet."

## How It Works

```
IaC Files ─► Parser Layer ─► Cloud-Agnostic IR ─► Hybrid Threat Engine ─► Output Formatters
                              (NetworkX Graph)    ├─ Rule-based (YAML)     ├─ SARIF 2.1.0
                                                  ├─ Boundary analysis     ├─ JSON
                                                  └─ LLM-augmented        ├─ Markdown
                                                                          ├─ Bitbucket
                                                                          └─ Diff
```

1. **Parse** — Reads `terraform show -json` output (resolves all modules, variables, conditionals), raw `.tf` files, or CloudFormation YAML/JSON.
2. **Build IR** — Constructs a directed graph of infrastructure nodes (compute, storage, network, IAM, etc.) with edges representing dependencies, containment, network flows, and IAM bindings. Each node is classified into a trust zone (internet, DMZ, private, data, management).
3. **Analyze** — Evaluates 19 built-in YAML rules across 6 AWS services. Detects trust boundary crossings (e.g., DMZ→data zone flows). Optionally sends a redacted graph to an LLM for architectural threat identification.
4. **Report** — Outputs threats in SARIF (GitHub Code Scanning), JSON, Markdown (PR comments), or Bitbucket Code Insights format. Each threat includes STRIDE category, severity, affected resource, and mitigation.

## Quick Start

```bash
pip install threatcode
```

### Basic Scan (Rules Only)

```bash
# Generate a Terraform plan
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json

# Scan it
threatcode scan tfplan.json --no-llm --format json
```

### SARIF Output (GitHub Code Scanning)

```bash
threatcode scan tfplan.json --no-llm --format sarif -o results.sarif
```

### LLM-Augmented Analysis

```bash
# With Claude API
ANTHROPIC_API_KEY=sk-... threatcode scan tfplan.json

# With local LLM (Ollama)
threatcode scan tfplan.json --config .threatcode.yml
# .threatcode.yml:
#   llm:
#     provider: ollama
#     base_url: http://localhost:11434
#     model: llama3
```

### Dry Run (See What Gets Sent to LLM)

```bash
threatcode scan tfplan.json --dry-run
```

### Diff Between Runs

```bash
threatcode diff baseline.json current.json --format markdown
```

## GitHub Actions Integration

```yaml
- name: ThreatCode Scan
  uses: ./.github/actions/threatcode
  with:
    input-file: tfplan.json
    format: sarif
    no-llm: 'true'
    min-severity: medium
```

This uploads SARIF results directly to GitHub Code Scanning, where threats appear as security alerts on pull requests.

## Built-in Rules

| Service | Rules | Covers |
|---------|-------|--------|
| S3 | 4 | Missing encryption, public access, no versioning, no logging |
| IAM | 3 | Wildcard actions, no MFA, overpermissive assume-role |
| EC2 | 3 | Public IP exposure, no monitoring, unencrypted EBS |
| VPC | 3 | Default SG open, unrestricted ingress, no flow logs |
| RDS | 3 | Public access, no encryption, no backups |
| Lambda | 3 | No VPC attachment, overpermissive role, no DLQ |

Rules are YAML files with structured dict operators (no `eval()` — safe for enterprise use). Add custom rules by pointing `--rules` at your own YAML files.

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

## Configuration

Create a `.threatcode.yml` in your project root:

```yaml
llm:
  provider: anthropic          # or "ollama", "openai", "local"
  model: claude-sonnet-4-20250514
  base_url: ""                 # Required for local LLMs
  max_tokens: 4096

redaction:
  enabled: true
  strategy: placeholder        # or "hash"
  fields:
    - arn
    - account_id
    - tags
    - ip_address

min_severity: info
output_format: json
no_llm: false
```

## Library API

```python
from threatcode import scan

report = scan(
    "tfplan.json",
    no_llm=True,
    min_severity="medium",
)

for threat in report["threats"]:
    print(f"[{threat['severity'].upper()}] {threat['title']}")
    print(f"  Resource: {threat['resource_address']}")
    print(f"  STRIDE: {threat['stride_category']}")
    print(f"  Mitigation: {threat['mitigation']}")
```

## Architecture

- **Parser layer** — Pluggable parsers for Terraform plan JSON, raw HCL, and CloudFormation. Auto-detection based on file extension and content.
- **Intermediate Representation** — NetworkX directed graph. Nodes have categories (compute, storage, IAM, etc.) and trust zones. Edges represent dependencies, containment, network flows, and IAM bindings.
- **Rule engine** — Declarative YAML rules with structured operators (`not_exists`, `equals`, `contains`, `matches_any`, `all_of`, `any_of`, `none_of`). No `eval()` — enterprise-safe.
- **LLM integration** — Anthropic Claude API, OpenAI-compatible (Ollama, vLLM, llama.cpp), or dry-run mode. All data is redacted before leaving your environment.
- **Output formatters** — SARIF 2.1.0 (GitHub), Bitbucket Code Insights, Markdown, JSON, and diff.

## License

MIT
