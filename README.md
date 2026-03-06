# ThreatCode

**Automated security scanning and threat modeling from Infrastructure-as-Code.**

```bash
pip install threatcode
```

```python
from threatcode import scan

report = scan("tfplan.json", no_llm=True)
for t in report["threats"]:
    print(f"[{t['severity'].upper()}] {t['title']} — {t['resource_address']}")
    print(f"  MITRE: {t['mitre_techniques']}  Fix: {t['mitigation']}")
```

ThreatCode is a Python security scanning library and CLI that works across the full DevSecOps stack:

- **STRIDE threat modeling** from Terraform, CloudFormation, Dockerfile, and Kubernetes — with MITRE ATT&CK mapping
- **Secret detection** across codebases and IaC files — 24 built-in patterns
- **Vulnerability scanning** from lockfiles — 10 package ecosystems, offline SQLite DB from OSV
- **Container image scanning** — pull from any OCI registry, scan OS packages and app dependencies
- **SBOM generation** in CycloneDX 1.5 format
- **License compliance** scanning with SPDX classification

---

## Install

```bash
pip install threatcode
```

**Requirements:** Python 3.10 or newer.

---

## Quick Start

### Threat modeling (IaC)

```bash
# Scan a Terraform plan
terraform show -json > tfplan.json
threatcode scan tfplan.json --no-llm --format sarif -o results.sarif

# Scan a Kubernetes manifest
threatcode scan deployment.yaml --no-llm --format json

# Scan a Dockerfile
threatcode scan Dockerfile --no-llm --format markdown

# Run all scanners at once
threatcode scan tfplan.json --scanners misconfig,secret,vuln --no-llm
```

### Secret scanning

```bash
threatcode secret ./src/
```

### Vulnerability scanning

```bash
threatcode db update                          # one-time DB download (~few hundred MB)
threatcode vuln package-lock.json
threatcode vuln requirements.txt --ignore-unfixed
```

### Container image scanning

```bash
threatcode db update --os                     # also download OS advisories
threatcode image nginx:latest
threatcode image ghcr.io/owner/repo:v1.2.3 --format table
threatcode image python:3.12-slim --scanners vuln,secret,misconfig
```

### SBOM and license compliance

```bash
threatcode sbom package-lock.json -o sbom.json     # CycloneDX 1.5
threatcode license requirements.txt
```

---

## Supported Input Formats

| Format | File Detection | What's Parsed |
|--------|---------------|---------------|
| Terraform plan JSON | `planned_values` or `format_version` key | All resources, modules, variables fully resolved |
| Terraform HCL | `.tf` extension | Resource blocks, variable references |
| CloudFormation | `AWSTemplateFormatVersion` or `Resources` + descriptor key | All resources and properties |
| Dockerfile | `Dockerfile`, `Dockerfile.*`, `*.dockerfile` | All instructions (FROM, USER, RUN, COPY, ADD, EXPOSE, ENV, HEALTHCHECK, WORKDIR) |
| Kubernetes | YAML with `apiVersion` + `kind` | Deployments, DaemonSets, StatefulSets, Jobs, CronJobs, Pods, Services, Ingresses, RBAC, NetworkPolicies |
| package-lock.json | Filename match | npm dependencies (v1/v2/v3 format) |
| yarn.lock | Filename match | npm dependencies |
| pnpm-lock.yaml | Filename match | npm dependencies |
| requirements.txt | Filename match | PyPI dependencies |
| Pipfile.lock | Filename match | PyPI dependencies |
| poetry.lock | Filename match | PyPI dependencies |
| go.sum | Filename match | Go module dependencies |
| Cargo.lock | Filename match | Rust crate dependencies |
| Gemfile.lock | Filename match | RubyGems dependencies |
| composer.lock | Filename match | PHP Packagist dependencies |

Maximum input size: 50 MB.

---

## CLI Reference

### `threatcode scan`

Scan IaC files for security threats and misconfigurations.

```
threatcode scan INPUT_FILE [OPTIONS]

Options:
  -f, --format    json | sarif | markdown | bitbucket | matrix | diagram
                  Default: json
  -o, --output    Write output to file instead of stdout
  --no-llm        Rules-only mode (skip LLM analysis)
  --dry-run       Show what would be sent to LLM, don't call it
  --min-severity  critical | high | medium | low | info   Default: info
  -c, --config    Path to .threatcode.yml config file
  -r, --rules     Additional rule YAML files (can repeat)
  -s, --scanners  Comma-separated: misconfig,secret,vuln,license
                  Default: misconfig
  --ignore-unfixed  Skip vulnerabilities without a fix (for vuln scanner)
```

**Output formats:**

| Format | Use case |
|--------|----------|
| `json` | Programmatic consumption, CI artifacts |
| `sarif` | GitHub Code Scanning upload |
| `markdown` | PR comments, Slack notifications |
| `bitbucket` | Bitbucket Code Insights |
| `matrix` | MITRE ATT&CK Navigator layer JSON |
| `diagram` | Interactive SVG data flow diagram |

### `threatcode image`

Pull a container image from any OCI registry and scan for vulnerabilities, secrets, and misconfigurations.

```
threatcode image IMAGE_REF [OPTIONS]

Options:
  -f, --format    json | sarif | table   Default: json
  -o, --output    Write output to file
  --severity      Minimum severity to report   Default: info
  --ignore-unfixed  Skip unfixed vulnerabilities
  --platform      Target platform for multi-arch images   Default: linux/amd64
  -s, --scanners  vuln,secret,misconfig   Default: vuln
  --insecure      Allow HTTP (non-TLS) registries
```

**Supported image references:**

```bash
threatcode image nginx                                  # Docker Hub official
threatcode image myuser/myapp:v2                        # Docker Hub user image
threatcode image ghcr.io/owner/repo:tag                 # GitHub Container Registry
threatcode image gcr.io/project/image:sha               # Google Container Registry
threatcode image 123456.dkr.ecr.us-east-1.amazonaws.com/app:prod  # AWS ECR
threatcode image nginx@sha256:a3f...                    # Digest-pinned
```

Registry credentials are read automatically from `~/.docker/config.json`, including credential helpers (`docker-credential-ecr-login`, `docker-credential-gcloud`, etc.).

### `threatcode secret`

Scan files and directories for hardcoded secrets.

```
threatcode secret PATH [OPTIONS]

Options:
  -f, --format    json | sarif | markdown   Default: json
  -o, --output    Write output to file
```

### `threatcode vuln`

Scan a lockfile for known vulnerabilities against the offline OSV database.

```
threatcode vuln PATH [OPTIONS]

Options:
  -f, --format      json | sarif | markdown   Default: json
  -o, --output      Write output to file
  --ignore-unfixed  Skip vulnerabilities without a fix version
```

### `threatcode sbom`

Generate a Software Bill of Materials from a lockfile.

```
threatcode sbom PATH [OPTIONS]

Options:
  -f, --format    cyclonedx   Default: cyclonedx
  -o, --output    Write output to file
```

Produces CycloneDX 1.5 JSON with Package URL (PURL) identifiers for all 6 supported ecosystems.

### `threatcode license`

Scan dependencies for license compliance issues.

```
threatcode license PATH [OPTIONS]

Options:
  -f, --format    json   Default: json
  -o, --output    Write output to file
```

Classifies every dependency's license into: **permissive**, **weakly copyleft**, **copyleft**, **restrictive**, or **unknown**.

### `threatcode diff`

Compare two threat report JSON files.

```
threatcode diff BASELINE CURRENT [OPTIONS]

Options:
  -f, --format    json | markdown   Default: json
```

### `threatcode db`

Manage the offline vulnerability database (powered by OSV).

```
threatcode db status             # Show DB path, size, entry count
threatcode db update             # Download ecosystem vuln data (npm, PyPI, Go, Cargo, Ruby, PHP)
threatcode db update --os        # Also download OS advisory data (Alpine, Debian, Amazon Linux)
```

---

## Python API

### `scan()` — IaC threat modeling

```python
from threatcode import scan

report = scan(
    "tfplan.json",
    no_llm=True,                      # Skip LLM, rules only
    min_severity="high",              # Filter to high+ threats
    extra_rule_paths=["my_rules.yml"],
    config_path=".threatcode.yml",
)

# Return shape:
# {
#   "version": "0.7.0",
#   "timestamp": "2026-03-05T...",
#   "scanned_resources": 14,
#   "total_threats": 6,
#   "summary": {"critical": 1, "high": 3, "medium": 2, "low": 0, "info": 0},
#   "threats": [
#     {
#       "id": "abc123",
#       "title": "S3 bucket without server-side encryption",
#       "description": "...",
#       "stride_category": "information_disclosure",
#       "severity": "high",
#       "source": "rule",          # "rule", "boundary", or "llm"
#       "resource_type": "aws_s3_bucket",
#       "resource_address": "aws_s3_bucket.data",
#       "mitigation": "Enable SSE-S3 or SSE-KMS...",
#       "rule_id": "S3_NO_ENCRYPTION",
#       "confidence": 1.0,
#       "mitre_techniques": ["T1530"],
#       "mitre_tactics": ["TA0009"],
#     }
#   ]
# }
```

### `analyze()` — Returns graph + report

```python
from threatcode import analyze

result = analyze("tfplan.json", no_llm=True)

# result.graph — InfraGraph (NetworkX-backed)
for node_id, node in result.graph.nodes.items():
    print(f"{node_id}: {node.category.value} / {node.trust_zone.value}")

for edge in result.graph.get_boundary_crossing_edges():
    print(f"Trust boundary: {edge.source} → {edge.target}")

# result.report — ThreatReport
print(result.report.to_dict())
```

### `scan_secrets()` — Secret detection

```python
from threatcode import scan_secrets

result = scan_secrets("./src/")

# {
#   "total_secrets": 3,
#   "findings": [
#     {
#       "id": "SECRET-a1b2c3d4",
#       "finding_type": "secret",
#       "title": "AWS Access Key ID",
#       "severity": "critical",
#       "file_path": "src/config.py",
#       "line_number": 14,
#       "secret_type": "aws",
#       "match": "AKIA****XWYZ",
#       "rule_id": "SECRET_AWS_ACCESS_KEY",
#     }
#   ]
# }
```

### `scan_vulnerabilities()` — Lockfile vuln scanning

```python
from threatcode import scan_vulnerabilities

result = scan_vulnerabilities("requirements.txt", ignore_unfixed=False)

# {
#   "total_vulnerabilities": 2,
#   "dependencies_scanned": 47,
#   "findings": [
#     {
#       "id": "VULN-1234abcd",
#       "finding_type": "vulnerability",
#       "title": "Remote code execution in package X",
#       "severity": "critical",
#       "package_name": "requests",
#       "package_version": "2.28.0",
#       "ecosystem": "pypi",
#       "cve_id": "CVE-2023-12345",
#       "fixed_version": "2.31.0",
#       "cvss_score": 9.8,
#     }
#   ]
# }
```

### `scan_all()` — Unified multi-scanner

```python
from threatcode import scan_all

result = scan_all(
    "tfplan.json",
    scanners=("misconfig", "secret", "vuln", "license"),
    no_llm=True,
    min_severity="medium",
)

# {
#   "scanners": ["misconfig", "secret", "vuln", "license"],
#   "misconfig": { ...ThreatReport... },
#   "secret": { "total_secrets": 0, "findings": [] },
#   "vuln": { "total_vulnerabilities": 2, ... },
#   "license": { "total_issues": 1, ... },
# }
```

### `scan_image()` — Container image scanning

```python
from threatcode import scan_image

result = scan_image(
    "nginx:latest",
    platform="linux/amd64",
    ignore_unfixed=False,
    scan_secrets=False,
    scan_misconfig=True,
)

# {
#   "image": "nginx:latest",
#   "os": {"family": "debian", "name": "Debian GNU/Linux", "version": "12"},
#   "metadata": {"architecture": "amd64", "user": "nginx", ...},
#   "summary": {
#     "os_packages": 142,
#     "os_vulnerabilities": 12,
#     "app_dependencies": 0,
#     "app_vulnerabilities": 0,
#     "misconfigs": 1,
#     "total_vulnerabilities": 12,
#   },
#   "os_vulnerabilities": [...VulnerabilityFinding dicts...],
#   "app_vulnerabilities": [...],
#   "misconfigs": [...],
# }
```

---

## Built-in Security Rules

### IaC Misconfiguration Rules (131 total)

| Provider | Rules | Services Covered |
|----------|-------|-----------------|
| **AWS** | 57 | S3, IAM, EC2, VPC, RDS, Lambda, KMS, CloudTrail, ECS, EKS, CloudFront, ElastiCache, Elasticsearch, ELB, SNS, SQS, DynamoDB |
| **Azure** | 19 | Compute, Storage, Network, Database, AKS |
| **GCP** | 17 | Compute, Storage, Network, GKE, IAM |
| **Dockerfile** | 15 | Image security, instruction best practices |
| **Kubernetes** | 21 | Workloads, RBAC, networking |

Every rule is declarative YAML — no `eval()`, no code execution. Add custom rules:

```bash
threatcode scan tfplan.json --rules my_org_rules.yml
```

Rule file format:

```yaml
rules:
  - id: MY_CUSTOM_RULE
    title: "RDS instance in public subnet"
    description: >
      RDS instance is accessible from the public internet.
    stride_category: information_disclosure
    severity: critical
    resource_type: aws_db_instance
    condition:
      publicly_accessible:
        equals: true
    mitigation: >
      Set publicly_accessible = false and place the instance in a private subnet.
    metadata:
      mitre:
        techniques: ["T1190"]
        tactics: ["TA0001"]
```

**Condition operators:** `equals`, `not_equals`, `contains`, `not_contains`, `exists`, `not_exists`, `matches_any`, `greater_than`, `less_than`, `is_true`, `is_empty`, `all_of`, `any_of`, `none_of`, `not`

### Secret Detection (24 patterns)

| Category | Rules |
|----------|-------|
| AWS | Access key ID, secret access key |
| GitHub | PAT (classic), fine-grained token |
| GitLab | Personal access token |
| Slack | API token |
| Cryptography | Private keys (RSA, EC, DSA, OPENSSH, PGP) |
| Authentication | JSON Web Token |
| Database | Connection strings (postgres, mysql, mongodb, redis) |
| Cloud | Azure client secret, GCP service account key |
| Payments | Stripe, Square |
| Communication | Twilio, SendGrid |
| Package managers | NPM token |
| Services | Heroku, Mailgun, Shopify, Databricks, Linear |
| Generic | Password, API key, secret assignments |

All secrets are redacted in output (first/last 4 characters shown: `AKIA****WXYZ`).

### Container Image Checks

| Check ID | Severity | Description |
|----------|----------|-------------|
| `IMG_ROOT_USER` | HIGH | Image runs as root — no USER instruction set |
| `IMG_NO_HEALTHCHECK` | MEDIUM | No HEALTHCHECK defined |
| `IMG_SECRET_IN_ENV` | CRITICAL | Secret-like value in ENV variable |
| `IMG_PRIVILEGED_PORT` | LOW | Port below 1024 exposed |
| `IMG_NO_MAINTAINER` | INFO | Missing maintainer/author label |

---

## MITRE ATT&CK Integration

All findings map to [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/) technique and tactic IDs. ThreatCode covers **25 techniques** across **12 tactics**.

Export an ATT&CK Navigator layer for visualization:

```bash
threatcode scan tfplan.json --no-llm --format matrix -o layer.json
```

Load `layer.json` at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/). Findings appear as color-coded technique cells (red = critical, orange = high, yellow = medium, blue = low, gray = info).

**STRIDE → ATT&CK tactic mapping:**

| STRIDE | ATT&CK Tactics |
|--------|---------------|
| Spoofing | TA0001 (Initial Access), TA0006 (Credential Access) |
| Tampering | TA0040 (Impact) |
| Repudiation | TA0005 (Defense Evasion) |
| Information Disclosure | TA0009 (Collection), TA0010 (Exfiltration) |
| Denial of Service | TA0040 (Impact) |
| Elevation of Privilege | TA0004 (Privilege Escalation) |

---

## LLM-Augmented Analysis

In addition to deterministic rules, ThreatCode can use an LLM to identify architectural threats — cross-service attack paths, implicit trust assumptions, missing network segmentation — that rules can't catch.

```yaml
# .threatcode.yml
llm:
  provider: anthropic             # or "openai", "ollama", "local"
  model: claude-sonnet-4-20250514
  api_key: ""                     # Set ANTHROPIC_API_KEY env var instead

min_severity: info
no_llm: false
```

Before any data reaches an external API, ThreatCode **redacts all sensitive values**: AWS account IDs, ARNs, IP addresses, email addresses, tags, and any field named `secret`, `password`, `token`, `api_key`, etc. The redacted placeholder mapping is reversed on the way out, so findings still reference real resource addresses.

For **air-gapped environments**, point at a local LLM:

```yaml
llm:
  provider: ollama
  base_url: http://localhost:11434
  model: llama3.2
```

---

## Configuration

Create `.threatcode.yml` in your project root:

```yaml
llm:
  provider: anthropic                # anthropic | openai | ollama | local
  model: claude-sonnet-4-20250514
  api_key: ""                        # Use ANTHROPIC_API_KEY env var
  base_url: ""                       # Required for local/Ollama endpoints
  max_tokens: 4096
  temperature: 0.2

redaction:
  strategy: placeholder              # placeholder | hash
  fields: [arn, account_id, tags, ip_address]

min_severity: info                   # critical | high | medium | low | info
no_llm: false
dry_run: false
extra_rule_paths: []
output_format: json
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  threatcode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate Terraform plan
        run: terraform show -json > tfplan.json

      # STRIDE threat model → SARIF → GitHub Code Scanning
      - name: ThreatCode scan
        uses: ./.github/actions/threatcode
        with:
          input-file: tfplan.json
          format: sarif
          no-llm: 'true'
          min-severity: medium

      # Secret scan (fails build on findings)
      - name: Secret scan
        run: pip install threatcode && threatcode secret ./
```

### GitLab CI

```yaml
threatcode:
  image: python:3.12
  script:
    - pip install threatcode
    - terraform show -json > tfplan.json
    - threatcode scan tfplan.json --no-llm --format sarif -o gl-sast-report.json
    - threatcode secret . || true
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Generic CI

```bash
pip install threatcode

# Fail on high+ threats
threatcode scan tfplan.json --no-llm --min-severity high
# Exit code 0 = clean, 1 = findings

# Fail on any secrets
threatcode secret ./src/

# Fail on unfixed high+ vulnerabilities
threatcode vuln package-lock.json --min-severity high --ignore-unfixed
```

---

## SVG Diagram

```bash
threatcode scan tfplan.json --no-llm --format diagram -o threat-model.svg
```

The generated SVG includes:

- **Trust zone swim lanes** (Internet → DMZ → Private → Data → Management)
- **Infrastructure nodes** with DFD-standard shapes (process, data store, data flow, external entity)
- **Interactive tooltips** on nodes (resource type, zone, all threats) and edges (edge type, endpoints)
- **Attack path visualization** — traced routes from internet-facing entry points to critical backend assets
- **Threat findings table** with severity badges, STRIDE category, ATT&CK technique IDs, and mitigations
- **Summary bar** with color-coded severity counts

---

## Security Model

- No `eval()`, `exec()`, `pickle`, `marshal`, or `compile()` anywhere in the codebase
- All YAML loading uses `yaml.safe_load()` exclusively
- Rule files are sandboxed: blocked symlinks, 1 MB size limit, 100 rules/file, 1000 total rules
- LLM output is parsed as JSON only — never executed
- SSRF protection: registry and LLM base URLs are validated against DNS resolution + ipaddress module (blocks loopback, private, link-local, reserved ranges)
- Bidi character stripping in prompts (prevents prompt injection via Unicode override characters)
- Dependency audit: run `pip-audit` against all dependencies

---

## Architecture

```
IaC / Lockfile / Dockerfile / Image
         │
         ▼
   ┌─────────────────────────────────────────────────┐
   │              Parser Layer (auto-detect)          │
   │  Terraform Plan │ HCL │ CloudFormation           │
   │  Dockerfile │ Kubernetes │ Lockfiles             │
   │  OCI Registry Client + Layer Extractor          │
   └──────────────────┬──────────────────────────────┘
                      │ ParsedOutput
                      ▼
   ┌─────────────────────────────────────────────────┐
   │         Infrastructure Graph (NetworkX)          │
   │  Nodes: category + trust zone + properties      │
   │  Edges: dependency, containment, network, IAM   │
   └──────────────────┬──────────────────────────────┘
                      │ InfraGraph
                      ▼
   ┌─────────────────────────────────────────────────┐
   │                Hybrid Engine                     │
   │  ① YAML rule matching (131 built-in rules)      │
   │  ② Trust boundary crossing detection            │
   │  ③ LLM architectural analysis (optional)        │
   │  ④ Secret scanner (24 regex patterns)           │
   │  ⑤ Vulnerability scanner (OSV DB)               │
   │  ⑥ Image OS package scanner                     │
   └──────────────────┬──────────────────────────────┘
                      │ ThreatReport / Findings
                      ▼
   ┌─────────────────────────────────────────────────┐
   │              Output Formatters                   │
   │  JSON │ SARIF │ Markdown │ Bitbucket            │
   │  ATT&CK Navigator │ SVG Diagram │ CycloneDX     │
   │  Table │ Diff                                    │
   └─────────────────────────────────────────────────┘
```

---

## What's in v0.7.0

| Version | Highlights |
|---------|-----------|
| **0.7.0** | Container image scanning — OCI registry client, Alpine/Debian/RPM package DB parsers, OS advisory DB, image config checks |
| **0.6.0** | Dockerfile scanner (16 rules), Kubernetes scanner (22 rules), secret scanning (24 patterns), vulnerability scanning (10 lockfile formats), SBOM/CycloneDX, license compliance, 76 new cloud rules |
| **0.5.x** | SVG diagram with attack paths, interactive tooltips, threat table, MITRE technique columns |
| **0.4.x** | Security audit: SSRF rewrite, prompt injection hardening, redaction improvements, CI hardening |
| **0.3.x** | Pluggable parser registry, GitHub Actions CI, MkDocs documentation |
| **0.2.x** | MITRE ATT&CK Cloud Matrix integration, ATT&CK Navigator export |
| **0.1.0** | Initial release: Terraform threat modeling, SARIF/JSON/Markdown output, LLM augmentation |

Full history in [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT
