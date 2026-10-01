# ThreatCode

**STRIDE threat models with MITRE ATT&CK mappings, generated from your Infrastructure-as-Code.**

ThreatCode reads Terraform plans and `.tf` files, CloudFormation templates, Dockerfiles, Kubernetes manifests and Helm charts.
It also reads the MCP server configs that AI coding agents load, so agent tooling shows up in the same threat model as the infrastructure.
It turns them into a graph of resources, puts each resource in a trust zone (internet, DMZ, private, data or management), and reports the threats that architecture allows.
Each rule and boundary finding names its STRIDE category and the ATT&CK techniques and tactics it enables, with a mitigation attached.

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
threatcode scan tfplan.json --no-llm
```

Here is trimmed output from the insecure test fixture in this repository (`tests/fixtures/terraform/multi_service_insecure.plan.json`):

```json
{
  "scanned_resources": 22,
  "total_threats": 42,
  "summary": {"critical": 3, "high": 14, "medium": 19, "low": 6},
  "threats": [
    {
      "title": "RDS instance is publicly accessible",
      "stride_category": "information_disclosure",
      "severity": "critical",
      "source": "rule",
      "resource_address": "aws_db_instance.public_db",
      "rule_id": "RDS_PUBLIC_ACCESS",
      "mitre_techniques": ["T1190"],
      "mitre_tactics": ["TA0001"]
    },
    {
      "title": "Trust boundary crossing: dmz -> private",
      "stride_category": "tampering",
      "severity": "medium",
      "source": "boundary",
      "resource_address": "aws_db_instance.public_db",
      "mitre_techniques": ["T1040", "T1557"],
      "mitre_tactics": ["TA0006", "TA0009"]
    }
  ]
}
```

## Where the threats come from

- **Rules.** 228 declarative YAML rules cover AWS, Azure, GCP, Dockerfiles, Kubernetes and MCP server configs, and each rule carries its own STRIDE category and ATT&CK mapping.
- **Trust boundaries.** Each graph edge that crosses from one trust zone into another, such as DMZ to private, becomes a Tampering threat.
  These findings are still generic, with the same description pattern and mitigation for every crossing.
- **LLM review, if you turn it on.** With a provider configured, ThreatCode sends a redacted copy of the graph to the model and asks for cross-resource threats the rules miss, such as implicit trust between services.
  `--no-llm` skips this step.

The same findings can come out as SARIF for GitHub code scanning, Markdown for pull request comments, an ATT&CK Navigator layer, or an SVG data-flow diagram.
The diagram draws the trust zones as swim lanes and traces attack paths from internet-facing resources to the data and management resources behind them.

## ThreatCode, Trivy and Checkov

Trivy and Checkov check each resource against a large catalog of misconfiguration policies, and Trivy also scans for vulnerabilities, secrets and container image issues.
Both are mature projects with far more checks than ThreatCode, so if you run them today, keep running them.
ThreatCode's rules exist to feed a threat model, which is why each one carries STRIDE and ATT&CK tags, and the graph adds trust-boundary threats and attack paths that neither tool produces.
Run it beside them when you want to know what an attacker could reach through your architecture, on top of which settings are wrong.

ThreatCode also ships secret, vulnerability, SBOM, license and container image scanners.
They are handy for a single-tool CI job on a small project, but with 24 secret patterns and OSV data for 8 package ecosystems they cover far less than Trivy, Grype, OSV-Scanner or Gitleaks.

## MCP server configs

AI coding agents launch MCP servers from config files that usually sit in the repository next to the infrastructure code.
ThreatCode parses those files offline, without starting or contacting any server, and turns each configured server into an `mcp_server` resource with its own rules.

| Client | File | Shape |
|--------|------|-------|
| Claude Code | `.mcp.json` (project), `~/.claude.json` (user and per-project) | `mcpServers` |
| Claude Desktop | `claude_desktop_config.json` | `mcpServers` |
| Cursor | `.cursor/mcp.json` | `mcpServers` |
| VS Code | `.vscode/mcp.json`, comments allowed | `servers` |
| VS Code and Copilot portable format | `.mcp.json`, `~/.copilot/mcp-config.json` | `mcpServers` |
| Windsurf (now Devin Desktop) | `mcp_config.json` | `mcpServers`, remote servers use `serverUrl` |

File names and shapes were checked against each client's documentation on 2026-10-01.
`threatcode fs` picks up `.cursor/mcp.json` and `.vscode/mcp.json` even though it skips other dot-directories, so one run covers the agent configs and the IaC.

| Rule | Flags | STRIDE | OWASP MCP Top 10 | OWASP Agentic Top 10 |
|------|-------|--------|------------------|----------------------|
| `MCP_SECRET_IN_CONFIG` | A literal credential in `env`, `headers` or the URL query, instead of `${VAR}`, `${env:VAR}` or `${input:id}` | Information disclosure | MCP01 | ASI03 |
| `MCP_PLAINTEXT_TRANSPORT` | A remote server reached over `http://` or `ws://` on a non-loopback host | Information disclosure | MCP01, MCP07 | ASI03 |
| `MCP_REMOTE_NO_AUTH` | A remote server with no auth header, OAuth block or header helper (low severity, since OAuth can be negotiated at connect time) | Spoofing | MCP07 | ASI03 |
| `MCP_UNPINNED_PACKAGE` | `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `uvx`, `docker` or `podman` launching a package or image without a fixed version | Tampering | MCP04 | ASI04 |
| `MCP_BROAD_FILESYSTEM` | A filesystem server rooted at `/`, a home directory or a whole drive | Elevation of privilege | MCP02 | ASI02, ASI03 |
| `MCP_SHELL_EXEC` | A server that exists to run shell commands for the agent | Elevation of privilege | MCP05 | ASI05, ASI02 |
| `MCP_CONTAINER_PRIVILEGED` | A containerized server started with `--privileged`, host namespaces, dangerous capabilities or a mount of `/` or the Docker socket | Elevation of privilege | MCP02, MCP05 | ASI05 |

The OWASP IDs appear in each finding's `metadata.owasp` in JSON output and as `owasp-mcp-top-10/...` and `owasp-agentic-top-10/...` tags in SARIF.
The MCP Top 10 (2025) was still in beta when these mappings were written.
ThreatCode stores only the names of environment variables and headers, never their values.

---

## Install

```bash
pip install threatcode
```

Release 0.9.1 is the first one published to PyPI.
To run the current `main` branch instead:

```bash
pip install "git+https://github.com/ajokunu/ThreatCode.git"
```

**Requirements:** Python 3.10 or newer.

---

## Quick Start

### Threat modeling (IaC)

```bash
# Scan a Terraform plan and write SARIF for GitHub code scanning
terraform show -json tfplan > tfplan.json
threatcode scan tfplan.json --no-llm --format sarif -o results.sarif

# Draw the threat model as an SVG data-flow diagram with attack paths
threatcode scan tfplan.json --no-llm --format diagram -o threat-model.svg

# Scan a Kubernetes manifest
threatcode scan deployment.yaml --no-llm --format json

# Scan a Dockerfile
threatcode scan Dockerfile --no-llm --format markdown

# Add the secret and vulnerability scanners to the same run
threatcode scan tfplan.json --scanners misconfig,secret,vuln --no-llm
```

### Filesystem scanning

```bash
# Scan a project directory with every scanner
threatcode fs ./my-project

# Scan with specific scanners
threatcode fs ./my-project --scanners vuln,secret

# Scan and suppress known findings
echo "CVE-2023-12345" > .threatcodeignore
threatcode fs ./my-project
```

### Repository scanning

```bash
# Scan a remote Git repo
threatcode repo https://github.com/org/repo.git

# Scan a specific branch
threatcode repo https://github.com/org/repo.git --branch develop --scanners vuln,secret
```

### Secret scanning

```bash
threatcode secret ./src/
```

### Vulnerability scanning

```bash
threatcode db update                          # one-time download of OSV data
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
| MCP client config | `mcpServers` key in any `.json` file, `servers` key in `mcp.json`, `projects.*.mcpServers` in `.claude.json` | One `mcp_server` resource per configured server |
| Helm chart | `Chart.yaml` | Templates rendered with `helm template` when the Helm CLI is installed, otherwise scanned raw, then parsed as Kubernetes |
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
| mix.lock | Filename match | Elixir Hex dependencies |
| pubspec.lock | Filename match | Dart Pub dependencies |
| conan.lock | Filename match | C/C++ Conan dependencies (no OSV vulnerability data) |

Maximum input size: 50 MB.

---

## CLI Reference

### `threatcode fs`

Scan a filesystem directory for vulnerabilities, secrets, misconfigurations, and license issues.

```
threatcode fs PATH [OPTIONS]

Options:
  -f, --format      json   Default: json
  -o, --output      Write output to file
  -s, --scanners    Comma-separated: vuln,secret,misconfig,license
                    Default: vuln,secret,misconfig,license
  --severity        Minimum severity to report   Default: info
  --ignore-unfixed  Skip unfixed vulnerabilities
  --no-llm          Disable LLM analysis for misconfig scanner
  -c, --config      Path to .threatcode.yml config file
  --ignorefile      Path to .threatcodeignore file (auto-detected in target dir)
```

Discovers lockfiles, Terraform files, CloudFormation templates, Dockerfiles, Kubernetes manifests, Helm charts and MCP client configs, then runs the selected scanners against them.
Skips `.git`, `node_modules`, `vendor`, `__pycache__`, `.venv`, every other directory whose name starts with a dot, and other common non-source directories.
The one exception is `mcp.json` inside `.cursor/` and `.vscode/`, which is collected so agent configs are scanned in the same run.

### `threatcode repo`

Clone a Git repository and scan it.

```
threatcode repo URL [OPTIONS]

Options:
  -f, --format      json   Default: json
  -o, --output      Write output to file
  -b, --branch      Branch to clone (default: repo default branch)
  -s, --scanners    Comma-separated: vuln,secret,misconfig,license
                    Default: vuln,secret,misconfig,license
  --severity        Minimum severity to report   Default: info
  --ignore-unfixed  Skip unfixed vulnerabilities
  --no-llm          Disable LLM analysis for misconfig scanner
  -c, --config      Path to .threatcode.yml config file
```

Performs a shallow clone (depth=1) into a temporary directory, runs the filesystem scanner, then cleans up. Supports HTTPS (`https://`), SSH (`git@`), and `ssh://` URLs.

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

Produces CycloneDX 1.5 JSON with a Package URL (PURL) for every dependency.

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
threatcode db update             # OSV data: npm, PyPI, Go, crates.io, RubyGems, Packagist, Hex, Pub
threatcode db update --os        # Also OS advisories: Alpine, Debian, Ubuntu, Amazon Linux, RHEL
```

---

## `.threatcodeignore`

Create a `.threatcodeignore` file in your project root to suppress known findings:

```
# Suppress a CVE that has been risk-accepted
CVE-2023-12345

# Suppress a misconfig rule
S3_NO_ENCRYPTION

# Suppress with an expiration date (re-enables after this date)
CVE-2024-9999  exp:2026-06-01

# Suppress a secret detection rule
SECRET_AWS_ACCESS_KEY  exp:2026-12-31
```

Rules:
- One ID per line (CVE IDs, rule IDs, or secret rule IDs)
- Lines starting with `#` are comments
- Optional `exp:YYYY-MM-DD` suffix sets an expiration, after which the finding is no longer suppressed
- Auto-detected in the target directory for `threatcode fs`, or specify with `--ignorefile`

---

## Python API

### `scan_filesystem()`: Directory scanning

```python
from threatcode import scan_filesystem

result = scan_filesystem(
    "./my-project",
    scanners=("vuln", "secret", "misconfig", "license"),
    ignore_unfixed=True,
    min_severity="medium",
    ignore_path=".threatcodeignore",
)

# {
#   "target": "/path/to/my-project",
#   "scanners": ["vuln", "secret", "misconfig", "license"],
#   "files_scanned": 234,
#   "lockfiles_found": 3,
#   "iac_files_found": 12,
#   "vuln": { "total_vulnerabilities": 5, "findings": [...] },
#   "secret": { "total_secrets": 1, "findings": [...] },
#   "misconfig": { "total_threats": 18, "findings": [...] },
#   "license": { "total_issues": 2, "findings": [...] },
#   "has_issues": true,
# }
```

### `scan_repository()`: Git repo scanning

```python
from threatcode import scan_repository

result = scan_repository(
    "https://github.com/org/repo.git",
    branch="main",
    scanners=("vuln", "secret"),
)

# Same shape as scan_filesystem(), plus:
# "repository": "https://github.com/org/repo.git",
# "branch": "main",
```

### `scan()`: IaC threat modeling

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
#   "version": "0.9.1",
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

### `analyze()`: Returns graph + report

```python
from threatcode import analyze

result = analyze("tfplan.json", no_llm=True)

# result.graph: InfraGraph (NetworkX-backed)
for node_id, node in result.graph.nodes.items():
    print(f"{node_id}: {node.category.value} / {node.trust_zone.value}")

for edge in result.graph.get_boundary_crossing_edges():
    print(f"Trust boundary: {edge.source} → {edge.target}")

# result.report: ThreatReport
print(result.report.to_dict())
```

### `scan_secrets()`: Secret detection

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

### `scan_vulnerabilities()`: Lockfile vuln scanning

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

### `scan_all()`: Unified multi-scanner

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

### `scan_image()`: Container image scanning

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

### Misconfiguration Rules (228 total)

| Provider | Rules | Services Covered |
|----------|-------|-----------------|
| **AWS** | 90 | S3, IAM, EC2, VPC, RDS, Lambda, KMS, CloudTrail, ECS, EKS, CloudFront, ElastiCache, Elasticsearch, ELB, SNS, SQS, DynamoDB, WAF, WAFv2, Secrets Manager, GuardDuty, Config, SSM Parameter Store |
| **Azure** | 45 | Compute, Storage, Network, Database, AKS, Key Vault, App Service, Functions, SQL Database, Cosmos DB, Monitor |
| **GCP** | 35 | Compute, Storage, Network, GKE, IAM, Cloud SQL, Cloud Functions, BigQuery, Pub/Sub, Cloud Run |
| **Dockerfile** | 20 | Image security, instruction best practices |
| **Kubernetes** | 31 | Workloads, RBAC, networking |
| **MCP server configs** | 7 | Secrets, transport, pinning, filesystem scope, shell access, container privileges ([details](#mcp-server-configs)) |

Every rule is declarative YAML, evaluated by a fixed set of operators with no `eval()` or code execution.
Add custom rules:

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
| `IMG_ROOT_USER` | HIGH | Image runs as root because no USER instruction is set |
| `IMG_NO_HEALTHCHECK` | MEDIUM | No HEALTHCHECK defined |
| `IMG_SECRET_IN_ENV` | CRITICAL | Secret-like value in ENV variable |
| `IMG_PRIVILEGED_PORT` | LOW | Port below 1024 exposed |
| `IMG_NO_MAINTAINER` | INFO | Missing maintainer/author label |

---

## MITRE ATT&CK Integration

Every rule-based and boundary finding carries [MITRE ATT&CK](https://attack.mitre.org/) technique and tactic IDs.
Across the builtin rules and the boundary analysis, ThreatCode maps to **26 techniques** in **12 tactics**.
Each rule names its own techniques and tactics, so the mapping follows what the misconfiguration enables rather than a fixed STRIDE-to-tactic table.

Export an ATT&CK Navigator layer for visualization:

```bash
threatcode scan tfplan.json --no-llm --format matrix -o layer.json
```

Load `layer.json` at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/).
Findings appear as color-coded technique cells (red = critical, orange = high, yellow = medium, blue = low, gray = info).

--------|---------------|
| Spoofing | TA0001 (Initial Access), TA0006 (Credential Access) |
| Tampering | TA0040 (Impact) |
| Repudiation | TA0005 (Defense Evasion) |
| Information Disclosure | TA0009 (Collection), TA0010 (Exfiltration) |
| Denial of Service | TA0040 (Impact) |
| Elevation of Privilege | TA0004 (Privilege Escalation) |

---

## LLM-Augmented Analysis

Rules look at one resource at a time.
With an LLM configured, ThreatCode also sends the infrastructure graph and the IDs of the rules that already fired, and asks the model for threats that span resources: cross-service attack paths, implicit trust between services and missing network segmentation.

```yaml
# .threatcode.yml
llm:
  provider: anthropic             # or "openai" for an OpenAI-compatible HTTPS endpoint
  model: claude-sonnet-4-20250514
  api_key: ""                     # Set ANTHROPIC_API_KEY env var instead

min_severity: info
no_llm: false
```

Before any data leaves the machine, ThreatCode redacts sensitive values: AWS account IDs, ARNs, IP addresses, email addresses, tags, and any field named `secret`, `password`, `token`, `api_key` or similar.
It reverses the placeholder mapping on the way back, so findings still reference real resource addresses.
`--dry-run` builds the payload and reports its size without calling the API.

**Known limitation:** the SSRF guard on `base_url` accepts only HTTPS URLs that resolve to public addresses.
A local model server such as Ollama on `http://localhost:11434` is rejected, so the `ollama` and `local` providers do not work yet.
Use `--no-llm` for air-gapped runs.

---

## Configuration

Create `.threatcode.yml` in your project root:

```yaml
llm:
  provider: anthropic                # anthropic | openai
  model: claude-sonnet-4-20250514
  api_key: ""                        # Use ANTHROPIC_API_KEY env var
  base_url: ""                       # HTTPS endpoint for the openai provider
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

The composite action in this repository installs ThreatCode, scans one file and uploads the SARIF to GitHub code scanning.

```yaml
name: Security Scan
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # needed for the SARIF upload

jobs:
  threatcode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: hashicorp/setup-terraform@v3
      - name: Generate Terraform plan
        run: |
          terraform init
          terraform plan -out tfplan
          terraform show -json tfplan > tfplan.json

      - name: ThreatCode threat model
        uses: ajokunu/ThreatCode/.github/actions/threatcode@v0.9.1
        with:
          input-file: tfplan.json
          format: sarif
          no-llm: 'true'
          min-severity: medium

      # Secret scan (fails the build on findings)
      - name: Secret scan
        run: pip install threatcode && threatcode secret ./
```

### GitLab CI

```yaml
threatcode:
  image: python:3.12
  script:
    - pip install threatcode
    - threatcode scan tfplan.json --no-llm --format sarif -o threatcode.sarif
    - threatcode secret . || true
  artifacts:
    when: always
    paths:
      - threatcode.sarif
```

The job assumes an earlier stage wrote `tfplan.json`.
ThreatCode writes SARIF, not GitLab's own SAST report schema, so keep the file as a plain artifact rather than under `artifacts:reports:sast`.

### Generic CI

```bash
pip install threatcode

# Scan the whole project with every scanner
threatcode fs . --severity high --ignore-unfixed

# Or scan a remote repo directly
threatcode repo https://github.com/org/repo.git --scanners vuln,secret

# Fail on high+ threats (IaC only)
threatcode scan tfplan.json --no-llm --min-severity high
# Exit code 0 means no findings; 1 means findings or an error

# Fail on any secrets
threatcode secret ./src/

# Fail on unfixed high+ vulnerabilities
threatcode vuln package-lock.json --ignore-unfixed
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
- **Attack paths** traced from internet-facing and DMZ resources to data and management resources, where both ends have findings
- **Threat findings table** with severity badges, STRIDE category, ATT&CK technique IDs, and mitigations
- **Summary bar** with color-coded severity counts

---

## Security Model

- No `eval()`, `exec()`, `pickle`, `marshal`, or `compile()` anywhere in the codebase
- All YAML loading uses `yaml.safe_load()` exclusively
- Rule files are sandboxed: blocked symlinks, 1 MB size limit, 100 rules/file, 1000 total rules
- LLM output is parsed as JSON and never executed
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
   │              Parser Layer (auto-detect)         │
   │  Terraform Plan │ HCL │ CloudFormation          │
   │  Dockerfile │ Kubernetes │ Helm │ Lockfiles     │
   │  MCP client configs                             │
   │  OCI Registry Client + Layer Extractor          │
   └──────────────────┬──────────────────────────────┘
                      │ ParsedOutput
                      ▼
   ┌─────────────────────────────────────────────────┐
   │         Infrastructure Graph (NetworkX)         │
   │  Nodes: category + trust zone + properties      │
   │  Edges: dependency, containment, network, IAM   │
   └──────────────────┬──────────────────────────────┘
                      │ InfraGraph
                      ▼
   ┌─────────────────────────────────────────────────┐
   │                Hybrid Engine                    │
   │  ① YAML rule matching (228 built-in rules)      │
   │  ② Trust boundary crossing detection            │
   │  ③ LLM architectural analysis (optional)        │
   │  ④ Secret scanner (24 regex patterns)           │
   │  ⑤ Vulnerability scanner (OSV DB)               │
   │  ⑥ Image OS package scanner                     │
   └──────────────────┬──────────────────────────────┘
                      │ ThreatReport / Findings
                      ▼
   ┌─────────────────────────────────────────────────┐
   │              Output Formatters                  │
   │  JSON │ SARIF │ Markdown │ Bitbucket            │
   │  ATT&CK Navigator │ SVG Diagram │ CycloneDX     │
   │  Table │ Diff                                   │
   └─────────────────────────────────────────────────┘
```

---

## Version History

| Version | Highlights |
|---------|-----------|
| **0.9.1** | MIT LICENSE file, CI check that installs the built wheel and scans a fixture, trusted-publishing workflow for PyPI, fix for wheels that shipped without rule files |
| **0.9.0** | 221 misconfig rules (up from 131), Ubuntu, Amazon Linux and RHEL advisories, `mix.lock`, `pubspec.lock` and `conan.lock` parsers, Helm chart scanning |
| **0.8.0** | Filesystem scanning (`threatcode fs`), repository scanning (`threatcode repo`), `.threatcodeignore` with expiration dates |
| **0.7.2** | Security hardening: SSRF fixes, symlink traversal, ReDoS, ENV redaction, type safety, dead code cleanup |
| **0.7.0** | Container image scanning: OCI registry client, Alpine/Debian/RPM package DB parsers, OS advisory DB, image config checks |
| **0.6.0** | Dockerfile scanner (16 rules), Kubernetes scanner (22 rules), secret scanning (24 patterns), vulnerability scanning (10 lockfile formats), SBOM/CycloneDX, license compliance, 76 new cloud rules |
| **0.5.x** | SVG diagram with attack paths, interactive tooltips, threat table, MITRE technique columns |
| **0.4.x** | Security audit: SSRF rewrite, prompt injection hardening, redaction improvements, CI hardening |
| **0.3.x** | Pluggable parser registry, GitHub Actions CI, MkDocs documentation |
| **0.2.x** | MITRE ATT&CK Cloud Matrix integration, ATT&CK Navigator export |
| **0.1.0** | Initial release: Terraform threat modeling, SARIF/JSON/Markdown output, LLM augmentation |

Full history in [CHANGELOG.md](CHANGELOG.md).

---

## License

MIT. See [LICENSE](LICENSE).
