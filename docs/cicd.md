# CI/CD Integration

ThreatCode exits with code `1` when findings exist (above the severity threshold) and `0` when the scan is clean, making it a natural quality gate in any CI pipeline.

---

## GitHub Actions

### Using the composite action

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  threatcode:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write    # Required for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init
        run: terraform init

      - name: Generate plan
        run: terraform show -json > tfplan.json
        env:
          TF_VAR_environment: staging

      - name: ThreatCode scan
        uses: ./.github/actions/threatcode
        with:
          input-file: tfplan.json
          format: sarif
          no-llm: 'true'
          min-severity: medium
```

### Composite action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `input-file` | required | Path to the IaC file to scan |
| `format` | `sarif` | Output format: `sarif`, `json`, `markdown` |
| `min-severity` | `info` | Minimum severity to report |
| `no-llm` | `true` | Disable LLM analysis |
| `config-file` | — | Path to `.threatcode.yml` |
| `extra-rules` | — | Comma-separated additional rule file paths |
| `python-version` | `3.11` | Python version to use |

### Composite action outputs

| Output | Description |
|--------|-------------|
| `sarif-file` | Path to the generated SARIF file |
| `threat-count` | Total number of threats found |

### Manual workflow (full pipeline)

```yaml
name: Full Security Pipeline
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install ThreatCode
        run: pip install threatcode

      # --- Threat modeling ---
      - name: Generate Terraform plan
        run: terraform show -json > tfplan.json

      - name: IaC threat model
        run: threatcode scan tfplan.json --no-llm --format sarif -o iac.sarif

      - name: Upload IaC SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: iac.sarif

      # --- Kubernetes scan ---
      - name: Kubernetes scan
        run: threatcode scan k8s/ --no-llm --format sarif -o k8s.sarif

      - name: Upload K8s SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: k8s.sarif

      # --- Secret detection ---
      - name: Secret scan
        run: threatcode secret ./

      # --- Vulnerability scan ---
      - name: Download vulnerability DB
        run: threatcode db update

      - name: Vulnerability scan
        run: threatcode vuln package-lock.json --ignore-unfixed

      # --- ATT&CK Navigator layer ---
      - name: ATT&CK Navigator layer
        run: threatcode scan tfplan.json --no-llm --format matrix -o layer.json

      - name: Upload Navigator layer
        uses: actions/upload-artifact@v4
        with:
          name: attack-navigator-layer
          path: layer.json
```

---

## GitLab CI

```yaml
threatcode:
  stage: security
  image: python:3.12-slim
  before_script:
    - pip install threatcode
  script:
    # IaC threat model → SARIF
    - terraform show -json > tfplan.json
    - threatcode scan tfplan.json --no-llm --format sarif -o gl-sast-report.json

    # Kubernetes
    - threatcode scan k8s/ --no-llm --format sarif -o k8s-report.json

    # Secrets (non-blocking — informational)
    - threatcode secret ./ || true

    # Vulnerabilities (fail on high+)
    - threatcode db update
    - threatcode vuln package-lock.json --min-severity high
  artifacts:
    reports:
      sast:
        - gl-sast-report.json
        - k8s-report.json
    expire_in: 1 week
```

---

## Bitbucket Pipelines

```yaml
pipelines:
  default:
    - step:
        name: Security Scan
        image: python:3.12
        script:
          - pip install threatcode
          - terraform show -json > tfplan.json
          - threatcode scan tfplan.json --no-llm --format bitbucket -o report.json
          # Bitbucket Code Insights upload
          - |
            curl -X POST \
              "https://api.bitbucket.org/2.0/repositories/$BITBUCKET_WORKSPACE/$BITBUCKET_REPO_SLUG/commit/$BITBUCKET_COMMIT/reports/threatcode" \
              -H "Authorization: Bearer $BITBUCKET_TOKEN" \
              -H "Content-Type: application/json" \
              -d @report.json
```

---

## Generic CI / Shell

```bash
pip install threatcode

# Quality gate — fail on medium+ threats
threatcode scan tfplan.json --no-llm --min-severity medium
# Exit code 1 if findings >= medium

# Non-blocking scan (informational only)
threatcode scan tfplan.json --no-llm || true

# Secret scan (fail on any secrets found)
threatcode secret ./src/

# Vulnerability gate (only unfixed high+ vulns)
threatcode db update
threatcode vuln package-lock.json --min-severity high --ignore-unfixed

# Container image (fail on critical vulns)
threatcode db update --os
threatcode image myapp:$TAG --severity critical
```

---

## PR Diff Workflow

Track new threats introduced in each PR:

```bash
# Save baseline from main branch
git checkout main
threatcode scan tfplan.json --no-llm -o baseline.json

# Check PR branch
git checkout feature-branch
threatcode scan tfplan.json --no-llm -o current.json

# Compare
threatcode diff baseline.json current.json --format markdown > diff.md
```

---

## Cost Management (LLM mode)

When running with LLM analysis enabled:

- **Use `--no-llm` in CI** unless you specifically need architectural threat detection
- Rule-based scanning is free and covers 131 built-in patterns
- LLM analysis adds architectural threat discovery (cross-resource attack paths, implicit trust assumptions)
- Use `--dry-run` to preview what would be sent to the LLM before paying for API calls
- Token budget is configurable: `llm.max_tokens: 4096` (default)

```bash
# Preview LLM call without executing
threatcode scan tfplan.json --dry-run 2>&1 | head -50
```
