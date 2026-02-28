# Getting Started

## Installation

### From PyPI

```bash
pip install threatcode
```

### From Source

```bash
git clone https://github.com/ajokunu/ThreatCode.git
cd ThreatCode
pip install -e ".[dev]"
```

## First Scan

Generate a Terraform plan JSON and scan it:

```bash
terraform plan -out=tfplan
terraform show -json tfplan > tfplan.json
threatcode scan tfplan.json --no-llm
```

The `--no-llm` flag runs rules-only analysis, requiring no API keys. ThreatCode exits with code `1` if any threats are found and `0` if none are found, making it suitable for CI/CD gating.

## Reading Output

By default, ThreatCode outputs JSON. The structure looks like this:

```json
{
  "version": "0.1.1",
  "timestamp": "2026-02-28T15:26:24+00:00",
  "input_file": "tfplan.json",
  "scanned_resources": 7,
  "total_threats": 12,
  "summary": {
    "critical": 3,
    "high": 4,
    "medium": 5
  },
  "threats": [
    {
      "id": "8ec379e733ff",
      "title": "S3 bucket without server-side encryption",
      "description": "The S3 bucket does not have server-side encryption...",
      "stride_category": "information_disclosure",
      "severity": "high",
      "source": "rule",
      "resource_type": "aws_s3_bucket",
      "resource_address": "aws_s3_bucket.data",
      "mitigation": "Enable SSE-S3 or SSE-KMS...",
      "rule_id": "S3_NO_ENCRYPTION",
      "confidence": 1.0,
      "mitre_techniques": ["T1530"],
      "mitre_tactics": ["TA0009"]
    }
  ]
}
```

Each threat includes:

| Field | Description |
|-------|-------------|
| `id` | Deterministic SHA-256 hash (stable across runs for the same rule + resource) |
| `title` | Human-readable threat title |
| `description` | Detailed explanation of the threat scenario |
| `stride_category` | One of: `spoofing`, `tampering`, `repudiation`, `information_disclosure`, `denial_of_service`, `elevation_of_privilege` |
| `severity` | `critical`, `high`, `medium`, `low`, or `info` |
| `source` | `rule` (YAML rules), `boundary` (trust boundary analysis), or `llm` (LLM-identified) |
| `resource_type` | Terraform resource type (e.g., `aws_s3_bucket`) |
| `resource_address` | Full resource address from the plan |
| `mitigation` | Actionable remediation steps |
| `mitre_techniques` | MITRE ATT&CK technique IDs (e.g., `T1530`) |
| `mitre_tactics` | MITRE ATT&CK tactic IDs (e.g., `TA0009`) |

## Common Options

```bash
# Output as SARIF for GitHub Code Scanning
threatcode scan tfplan.json --no-llm --format sarif -o results.sarif

# Output as Markdown (useful for PR comments)
threatcode scan tfplan.json --no-llm --format markdown

# Output as ATT&CK Navigator layer
threatcode scan tfplan.json --no-llm --format matrix -o layer.json

# Filter by minimum severity
threatcode scan tfplan.json --no-llm --min-severity high

# Load custom rules
threatcode scan tfplan.json --no-llm --rules my_org_rules.yml

# Use a config file
threatcode scan tfplan.json --config .threatcode.yml

# Dry run -- see what would be sent to the LLM
threatcode scan tfplan.json --dry-run

# Compare two reports
threatcode diff baseline.json current.json --format markdown
```

All available output formats:

| Format | Flag | Use Case |
|--------|------|----------|
| JSON | `--format json` | Default, machine-readable |
| SARIF | `--format sarif` | GitHub Code Scanning upload |
| Markdown | `--format markdown` | PR comments, human review |
| Bitbucket | `--format bitbucket` | Bitbucket Code Insights API |
| ATT&CK Navigator | `--format matrix` | MITRE ATT&CK Navigator layer |

## Using the Python API

For programmatic access, use the `scan()` function directly:

```python
from threatcode import scan

# Basic rules-only scan
report = scan("tfplan.json", no_llm=True)

# Filter by severity
report = scan("tfplan.json", min_severity="high")

# With custom rules
report = scan("tfplan.json", extra_rule_paths=["my_rules.yml"])

# With config file
report = scan("tfplan.json", config_path=".threatcode.yml")
```

The return value is a plain Python dictionary with the same structure shown above.

!!! note "LLM mode"
    By default, `scan()` sets `no_llm=True`. To enable LLM analysis, pass `no_llm=False` and ensure an API key is configured via `.threatcode.yml` or the `ANTHROPIC_API_KEY` environment variable. See the [Configuration](configuration.md) page for details.
