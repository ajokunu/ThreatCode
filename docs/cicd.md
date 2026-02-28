# CI/CD Integration

ThreatCode is designed for CI/CD pipelines. It exits with code `1` when threats are found and code `0` when none are found, making it a natural quality gate.

## GitHub Actions

### Full Workflow with SARIF Upload

```yaml
name: Threat Model

on:
  pull_request:
    paths:
      - '**.tf'
      - '**.json'

permissions:
  security-events: write
  contents: read

jobs:
  threatcode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Terraform Init & Plan
        run: |
          terraform init
          terraform plan -out=tfplan
          terraform show -json tfplan > tfplan.json

      - name: ThreatCode Scan
        uses: ./.github/actions/threatcode
        with:
          input-file: tfplan.json
          format: sarif
          no-llm: 'true'
          min-severity: medium
```

The bundled composite action installs ThreatCode, runs the scan, and uploads the SARIF file to GitHub Code Scanning automatically. Threats appear as security alerts on the pull request.

### Manual Workflow (Without Composite Action)

```yaml
name: Threat Model

on: [pull_request]

permissions:
  security-events: write

jobs:
  threatcode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install ThreatCode
        run: pip install threatcode

      - name: Run scan
        run: threatcode scan tfplan.json --no-llm --format sarif -o results.sarif || true

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
          category: threatcode

      - name: Save ATT&CK Navigator layer
        run: threatcode scan tfplan.json --no-llm --format matrix -o threatcode-layer.json || true

      - name: Upload Navigator layer artifact
        uses: actions/upload-artifact@v4
        with:
          name: attack-navigator-layer
          path: threatcode-layer.json
```

!!! note "Exit code handling"
    ThreatCode exits with `1` when findings exist. Use `|| true` if you want the pipeline to continue past the scan step (e.g., to still upload SARIF results). Alternatively, use `--min-severity` to control which findings cause a non-zero exit.

---

## Bitbucket Pipelines

```yaml
pipelines:
  pull-requests:
    '**':
      - step:
          name: Threat Model
          image: python:3.11
          script:
            - pip install threatcode
            - terraform init
            - terraform plan -out=tfplan
            - terraform show -json tfplan > tfplan.json
            - threatcode scan tfplan.json --format bitbucket --no-llm -o threatcode-report.json || true
            - |
              # Upload to Bitbucket Code Insights
              REPORT=$(cat threatcode-report.json | python -c "import sys,json; print(json.dumps(json.load(sys.stdin)['report']))")
              ANNOTATIONS=$(cat threatcode-report.json | python -c "import sys,json; print(json.dumps(json.load(sys.stdin)['annotations']))")
              COMMIT=${BITBUCKET_COMMIT}
              REPO=${BITBUCKET_REPO_FULL_NAME}

              # Create report
              curl -X PUT \
                "https://api.bitbucket.org/2.0/repositories/${REPO}/commit/${COMMIT}/reports/threatcode" \
                -H "Content-Type: application/json" \
                -H "Authorization: Bearer ${BB_AUTH_TOKEN}" \
                -d "${REPORT}"

              # Create annotations
              for row in $(echo "${ANNOTATIONS}" | python -c "import sys,json; [print(json.dumps(a)) for a in json.load(sys.stdin)]"); do
                curl -X POST \
                  "https://api.bitbucket.org/2.0/repositories/${REPO}/commit/${COMMIT}/reports/threatcode/annotations" \
                  -H "Content-Type: application/json" \
                  -H "Authorization: Bearer ${BB_AUTH_TOKEN}" \
                  -d "${row}"
              done
```

The `--format bitbucket` output is structured for the Bitbucket Code Insights API, with a `report` object and `annotations` array ready for upload.

---

## Generic CI

For any CI system, ThreatCode works as a standard CLI tool:

```bash
pip install threatcode

# Run scan, exit 1 on findings
threatcode scan tfplan.json --no-llm --format json -o results.json

# Use as quality gate with severity threshold
threatcode scan tfplan.json --no-llm --min-severity high
```

The exit code behavior:

| Exit Code | Meaning |
|-----------|---------|
| `0` | No threats found (at or above the minimum severity) |
| `1` | One or more threats found |

---

## ATT&CK Navigator Layer as Build Artifact

Save the Navigator layer alongside your scan results for security review:

```bash
# Generate the layer
threatcode scan tfplan.json --no-llm --format matrix -o threatcode-layer.json

# In GitHub Actions, upload as artifact
# In other CI, archive the file with your build outputs
```

Security teams can load the layer into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to visualize which ATT&CK techniques are covered by your infrastructure's threat model.

---

## Using `--min-severity` as Quality Gate

Control which findings block the pipeline:

```bash
# Block on critical and high only
threatcode scan tfplan.json --no-llm --min-severity high

# Block on medium and above
threatcode scan tfplan.json --no-llm --min-severity medium

# Report everything but never block
threatcode scan tfplan.json --no-llm --min-severity info || true
```

!!! tip "Recommended approach"
    Start with `--min-severity high` to avoid alert fatigue, then progressively lower the threshold as your team addresses findings. Use `--min-severity medium` once the high-severity backlog is clear.

---

## LLM Mode in CI

LLM augmentation can be enabled in CI by providing an API key and omitting the `--no-llm` flag:

```yaml
- name: ThreatCode Scan (with LLM)
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: |
    threatcode scan tfplan.json --format sarif -o results.sarif || true
```

!!! warning "Cost considerations"
    Each LLM-augmented scan sends the infrastructure graph to the configured LLM provider. For large plans, this can consume significant tokens. Consider:

    - Using `--no-llm` for PR-level scans and LLM mode only for release branches
    - Using a local LLM (Ollama) in CI for cost-free analysis
    - Setting `max_tokens` in `.threatcode.yml` to limit response size
    - Using `--dry-run` to preview token usage before enabling LLM in production pipelines
