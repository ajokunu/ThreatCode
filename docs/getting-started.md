# Getting Started

## Installation

```bash
pip install threatcode
```

**Requirements:** Python 3.10 or newer.

---

## Your First Scan

### Terraform / CloudFormation

```bash
# Generate a Terraform plan
terraform show -json > tfplan.json

# Rules-only threat model (no API key needed)
threatcode scan tfplan.json --no-llm

# SARIF output for GitHub Code Scanning
threatcode scan tfplan.json --no-llm --format sarif -o results.sarif

# Interactive SVG threat model diagram
threatcode scan tfplan.json --no-llm --format diagram -o threat-model.svg
```

### Kubernetes

```bash
threatcode scan deployment.yaml --no-llm
threatcode scan k8s/ --no-llm --format markdown
```

### Dockerfile

```bash
threatcode scan Dockerfile --no-llm
```

### Secret scanning

```bash
threatcode secret ./src/
threatcode secret . --format json -o secrets.json
```

### Vulnerability scanning

```bash
# One-time DB download (powered by OSV)
threatcode db update
threatcode db status

threatcode vuln package-lock.json
threatcode vuln requirements.txt --ignore-unfixed
threatcode vuln Cargo.lock
```

### Container image scanning

```bash
# Download OS advisories too (Alpine, Debian, Amazon Linux)
threatcode db update --os

threatcode image nginx:latest
threatcode image ghcr.io/owner/repo:v1 --format table --severity high
threatcode image python:3.12-slim --scanners vuln,secret,misconfig
```

### SBOM and license compliance

```bash
threatcode sbom package-lock.json -o sbom.cyclonedx.json
threatcode license requirements.txt
```

---

## Understanding Threat Report Output

```json
{
  "version": "0.7.0",
  "timestamp": "2026-03-05T12:00:00Z",
  "scanned_resources": 14,
  "total_threats": 3,
  "summary": {"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0},
  "threats": [
    {
      "id": "8ec379e733ff",
      "title": "S3 bucket without server-side encryption",
      "description": "The S3 bucket does not have server-side encryption configured...",
      "stride_category": "information_disclosure",
      "severity": "high",
      "source": "rule",
      "resource_type": "aws_s3_bucket",
      "resource_address": "aws_s3_bucket.data",
      "rule_id": "S3_NO_ENCRYPTION",
      "confidence": 1.0,
      "mitigation": "Enable SSE-S3 or SSE-KMS encryption.",
      "mitre_techniques": ["T1530"],
      "mitre_tactics": ["TA0009"]
    }
  ]
}
```

**`source` values:** `rule` (matched YAML rule) | `boundary` (trust boundary crossing) | `llm` (LLM analysis)

**`stride_category` values:** `spoofing` | `tampering` | `repudiation` | `information_disclosure` | `denial_of_service` | `elevation_of_privilege`

---

## Exit Codes

- `0` — No findings at or above the threshold
- `1` — Findings found, or error

Use `--min-severity` as a quality gate:

```bash
# Only fail on critical / high
threatcode scan tfplan.json --no-llm --min-severity high
```

---

## Common Workflows

### Multi-scanner (IaC + secrets + vulns)

```bash
threatcode scan . --no-llm --scanners misconfig,secret,vuln -o full-scan.json
```

### Compare scans across PRs (diff)

```bash
threatcode diff baseline.json current.json --format markdown
```

### ATT&CK Navigator layer

```bash
threatcode scan tfplan.json --no-llm --format matrix -o layer.json
# Load layer.json at https://mitre-attack.github.io/attack-navigator/
```

---

## Next Steps

- [API Reference](api-reference.md) — Full Python library API
- [Writing Rules](writing-rules.md) — Custom detection rules
- [CI/CD Integration](cicd.md) — GitHub Actions, GitLab CI
- [MITRE ATT&CK](mitre-attack.md) — ATT&CK mapping and Navigator export
- [Configuration](configuration.md) — LLM, redaction, all settings
- [Architecture](architecture.md) — How the pipeline works
- [Security](security.md) — Security model
