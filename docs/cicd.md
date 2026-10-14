# CI/CD integration

ThreatCode fits a pipeline in two steps: produce a report, and gate on the exit code.
The exit code carries the contract, so a pipeline can tell the three outcomes apart:

| Exit code | Meaning | What a pipeline should do |
|-----------|---------|---------------------------|
| 0 | Clean at the chosen `--fail-on`. | Continue. |
| 1 | A finding or attack path at or above `--fail-on` remains. | Fail the check, and show the report. |
| 2 | The scan cannot be trusted: an unreadable path, a file that failed to parse, nothing to scan, a bad option, or a coverage gap under `--strict`. | Fail the job and show stderr. Never treat it as "no findings". |

Install from Git until the package is published to PyPI (see [releasing](releasing.md)):

```bash
pip install "git+https://github.com/ajokunu/ThreatCode.git"
```

Plan files in every recipe below come from `terraform plan -out tfplan` followed by `terraform show -json tfplan > tfplan.json`.
Never run `terraform show -json` without naming the plan file: it prints state, which ThreatCode rejects.

## GitHub Actions

### The composite action

```yaml
name: threat-model
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning
  pull-requests: write     # only when comment is true

jobs:
  threatcode:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ajokunu/ThreatCode/.github/actions/threatcode@main
        with:
          path: infra/
          fail-on: high
          comment: true
```

Pin `@main` to a release tag or a commit SHA once you have chosen one.
The action installs the code at the ref it was called with, so the action at a ref always runs the code at that ref.
The optional `version` input installs `threatcode==VERSION` from PyPI instead, which works only after the package is published.

What the action does:

- It runs `threatcode scan` and writes the report next to your checkout.
- Exit 2 fails the job at once, and the annotation carries the message from stderr.
- Exit 1 does not stop the action: the report is written, the SARIF upload runs (`if: always()`), and the last step of the action fails the job.
- `fail-on` defaults to `none`, so adopting the action reports without breaking a build until you set `fail-on: high`, which matches the CLI default.
- With `comment: true` on a `pull_request` event it posts the Markdown report as one comment, found by the hidden marker `<!-- threatcode-report -->` on its second line, and updates it on later pushes.
  Fork pull requests, read-only tokens and other events skip the comment with a notice.

Inputs:

<!-- gen:action-inputs -->
| Input | Default | What it does |
| --- | --- | --- |
| `path` | empty | What to scan: a file (Terraform plan JSON, .tf, CloudFormation, Kubernetes, Dockerfile, MCP config) or a directory of them. Several paths go on separate lines. |
| `input-file` | empty | Deprecated alias of path, kept so existing workflows keep working. |
| `format` | `sarif` | Output format (sarif, json, markdown, bitbucket, navigator, mermaid, diagram, text) |
| `fail-on` | `none` | Fail the job when a finding or attack path at or above this severity remains after suppressions and the baseline (critical, high, medium, low, info). none never fails on findings, which is the default so that adopting the action does not break a build. |
| `min-severity` | empty | Hide findings below this severity (critical, high, medium, low, info). Display only: it does not change the gate. Empty means the CLI default. |
| `config-file` | empty | Path to a .threatcode.yml config file. Only an explicit config can set fail_on. |
| `extra-rules` | empty | Additional rule files, one per line (commas also separate) |
| `ingest` | empty | Scanner results to join to the graph (Trivy JSON, Grype JSON, OSV-Scanner JSON or SARIF), one file per line. |
| `baseline` | empty | Baseline file: findings already in it are hidden from the gate and the report |
| `comment` | `false` | Post the Markdown report as a sticky pull request comment (needs pull-requests: write). Skipped with a notice on forks, read-only tokens and events other than pull_request. |
| `github-token` | `${{ github.token }}` | Token used to post the comment |
| `upload` | `true` | Upload the SARIF file to GitHub Code Scanning (needs security-events: write) |
| `version` | empty | Install this released version from PyPI (threatcode==VERSION) instead of the code at the ref the action was called with. |
| `python-version` | `3.12` | Python version to use |
<!-- /gen:action-inputs -->

Outputs:

<!-- gen:action-outputs -->
| Output | Meaning |
| --- | --- |
| `exit-code` | Exit code of the scan: 0 clean, 1 gate tripped, 2 or more an error |
| `threat-count` | Number of findings in the report, whatever the format |
| `path-count` | Number of attack paths in the report, whatever the format |
| `report-file` | Path of the written report, relative to the workspace |
| `sarif-file` | Path of the SARIF report when format is sarif, else empty |
<!-- /gen:action-outputs -->

`format` takes any `threatcode scan -f` value.
The SARIF upload runs only for `format: sarif`, and needs `security-events: write`; set `upload: false` for a job without it.

### Baselines and scanner results

Adopt the gate on an existing codebase by committing a baseline, then fail only on what a pull request adds:

```bash
threatcode scan infra/ --write-baseline .threatcode-baseline.json
```

```yaml
      - uses: ajokunu/ThreatCode/.github/actions/threatcode@main
        with:
          path: infra/
          fail-on: high
          baseline: .threatcode-baseline.json
          ingest: |
            trivy.json
            gitleaks.sarif
```

The baseline records every attack path as well as every finding, so a path that was already there stops failing the job and a new path, or a known path that gained or lost a hop, fails it.
A baseline written by an older version lists no path and hides none, so write it again once.

### Without the action

```yaml
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install "git+https://github.com/ajokunu/ThreatCode.git"
      - run: threatcode scan infra/ -f sarif -o threatcode.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: threatcode.sarif
      - run: threatcode scan infra/ --fail-on high -f text
```

The first scan reports without failing so the upload step always has a file; the last scan is the gate.
Run the scan from the repository root so the SARIF locations are repository-relative, which is what code scanning needs to place an alert on a line.

### What the SARIF file contains

SARIF paths are relative to the top of the git checkout that holds the scan root, wherever the scan was started, because that is what GitHub resolves them against.
A checkout without a `.git` directory (an exported archive) needs `--source-root DIR` with the repository root.
When GitHub could not place the alerts, the run carries a warning notification: `sarif.paths.unanchored` when the scanned path is in no checkout, and `sarif.paths.outside_repository` for files outside the repository root.

A finding whose effective severity differs from its rule's belongs to a variant rule `<id>/<severity>` (`EC2_IMDSV1/high`), because GitHub ranks an alert by the severity of its rule, and the bare id is the rule's highest base severity.
The first scan after upgrading may close an alert and open its variant once.
The run also says what the file leaves out and what it joined, in note-level notifications: `suppressions.applied`, `baseline.applied`, `min_severity.hidden`, `ingest.source` and `llm.ran`.
They never fail the invocation, and they keep a smaller report from reading as a safer one.
[The CLI reference](cli.md#format-details) lists them.

The Bitbucket report's `result` follows the gate: `--fail-on none` is never `FAILED`.

## GitLab CI

GitLab does not read SARIF as a SAST report (its format is a different schema), so keep the report as a job artifact instead of registering it under `reports: sast`.

<!-- ci-script only=threatcode exit=1 creates=threatcode-report.md -->

```yaml
threatcode:
  image: python:3.12
  stage: test
  script:
    - pip install "git+https://github.com/ajokunu/ThreatCode.git"
    - threatcode scan infra/ -f markdown -o threatcode-report.md --fail-on high
  artifacts:
    when: always
    paths:
      - threatcode-report.md
```

The report is written before the exit code is decided, and `when: always` keeps the artifact when the gate fails the job.
To keep a SARIF copy for other tools, add `-f sarif -o threatcode.sarif` to a second scan and list the file under `paths`.

## Bitbucket Pipelines

`-f bitbucket` writes one JSON document with three keys: `report`, the Code Insights report; `annotations`, every annotation; and `annotation_batches`, the same annotations in lists of at most 100, because the bulk endpoint takes 100 at a time.
Bitbucket wants the report with `PUT` and the annotations with `POST`, so the document cannot be sent as it is.
Save this helper in your repository as `scripts/bitbucket_upload.py`:

<!-- bitbucket-upload -->

```python
"""Publish a ThreatCode Bitbucket document as a Code Insights report with annotations."""

import json
import os
import urllib.request

API = os.environ.get("BITBUCKET_API", "http://api.bitbucket.org/2.0")
PROXY = os.environ.get("BITBUCKET_PROXY", "http://localhost:29418")
REPORT_ID = os.environ.get("REPORT_ID", "threatcode")
URL = (
    f"{API}/repositories/{os.environ['BITBUCKET_REPO_FULL_NAME']}"
    f"/commit/{os.environ['BITBUCKET_COMMIT']}/reports/{REPORT_ID}"
)

with open(os.environ.get("INSIGHTS_FILE", "insights.json"), encoding="utf-8") as handle:
    document = json.load(handle)

# Inside Pipelines a proxy on localhost:29418 adds the credentials to the request.
handlers = [urllib.request.ProxyHandler({"http": PROXY} if PROXY else {})]
opener = urllib.request.build_opener(*handlers)


def send(method, url, body):
    request = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method=method,
        headers={"Content-Type": "application/json"},
    )
    with opener.open(request, timeout=60) as response:
        return response.status


print("report:", send("PUT", URL, document["report"]))
for batch in document["annotation_batches"]:
    print("annotations:", len(batch), send("POST", f"{URL}/annotations", batch))
```

Then the pipeline scans without failing, publishes, and gates last:

<!-- ci-script only=threatcode exit=1 creates=insights.json -->

```yaml
pipelines:
  default:
    - step:
        name: ThreatCode
        image: python:3.12
        script:
          - pip install "git+https://github.com/ajokunu/ThreatCode.git"
          - threatcode scan infra/ -f bitbucket -o insights.json --fail-on none
          - python scripts/bitbucket_upload.py
          - threatcode scan infra/ --fail-on high -f text
```

Inside a pipeline the request goes through the authenticating proxy on `localhost:29418`, as the [Code Insights documentation](https://support.atlassian.com/bitbucket-cloud/docs/code-insights/) describes, so no credentials are needed.
Set `BITBUCKET_PROXY=` (empty) and `BITBUCKET_API` to send to another host.
Annotations carry the file and line of the resource, or the input file and line 1, never a resource address, and the document holds at most 1000 of them, most severe first.

## pre-commit

```yaml
repos:
  - repo: https://github.com/ajokunu/ThreatCode
    rev: main
    hooks:
      - id: threatcode
```

The hook runs `threatcode scan . --fail-on high --format text` over the whole repository, because an attack path can cross files and the list of changed files would hide half of it.
It runs when a commit touches a file type that can hold infrastructure code.
Add `args: ["--fail-on", "critical"]` to change the gate.
Replace `main` with a release tag once you have chosen one; the header of `.pre-commit-hooks.yaml` says the same.

## Any other CI system

Run the scan, keep the exit code, and treat 2 as an error:

```bash
set +e
threatcode scan infra/ -f sarif -o threatcode.sarif --fail-on high
status=$?
set -e
if [ "$status" -ge 2 ]; then
  echo "ThreatCode could not analyse the input" >&2
  exit "$status"
fi
exit "$status"
```

Use `--strict` where a coverage gap should fail the build too.
Use `-q` to hide progress; errors and coverage gaps still print.

## Pull request diffs

Compare the report of the base branch with the report of the change, and fail only on what the change made worse:

```bash
git worktree add ../base "$BASE_SHA"
threatcode scan ../base/infra -f json -o base.json --fail-on none
threatcode scan infra -f json -o current.json --fail-on none
threatcode diff base.json current.json -f markdown -o diff.md --fail-on-new high
```

Paths in a report are relative to the scan root, so the same file has the same fingerprint in both scans.
`diff` lists attack paths that appeared or closed before findings, and `--fail-on-new` also fails on a new attack path at or above the severity.

## Keep the ignore file out of reach

A `.threatcodeignore` or a baseline inside the repository can be edited by a pull request, and the edit suppresses its own findings.
When the `CI` variable is set and the ignore file lives inside the scanned tree, ThreatCode prints a notice that says so.
Keep the file where the pull request cannot change it (a protected branch, a separate repository checked out beside the code, `CODEOWNERS` on the file) and name it with `--ignore-file`.
The same holds for `--config`: `fail_on` is read only from a config you name, so a pull request cannot turn off the gate by adding a `.threatcode.yml`.

## The model review in CI

The LLM review is off in CI unless you turn it on.
To see what a run would send without sending it, add `--dry-run`: the exact request is written to stderr, or to the file named by `--dry-run-output`, and no connection is opened.
Findings from the model are advisory and never fail the gate.
See [security](security.md) for what is redacted.
