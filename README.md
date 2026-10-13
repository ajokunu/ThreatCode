# ThreatCode

**Attack paths from the internet to your data, found in the infrastructure code you already have.**

ThreatCode reads the infrastructure code and AI-agent configs a team already has: Terraform plans and HCL directories, CloudFormation and SAM templates, Kubernetes manifests, Helm charts, Dockerfiles and MCP client configs.
It builds one graph of what is exposed to what, puts every resource in a trust zone, and walks that graph from the internet to the data stores, secret stores and admin identities behind it.
What comes out is a STRIDE threat model with MITRE ATT&CK mappings and a list of attack paths, each hop naming the finding that makes it possible.

It does not try to out-scan Trivy, Checkov, Grype, OSV-Scanner or Gitleaks.
You run them as you do today, and `--ingest` joins their results to the graph, so a critical CVE in the image of a workload that the internet can reach shows up as a step in a path instead of a line in a list.

## See it work

The repository ships a demo stack in [`examples/aws-webapp`](https://github.com/ajokunu/ThreatCode/tree/main/examples/aws-webapp): a load balancer, two app instances that still allow IMDSv1, a database, a customer data bucket, and a Trivy report with one critical CVE in the app image.
The demo stacks live in the repository and are not part of the pip package, so install ThreatCode from a clone and run the command from its top directory:

```bash
git clone https://github.com/ajokunu/ThreatCode.git
cd ThreatCode
pip install .
```

<!-- runnable exit=1 -->

```bash
threatcode scan examples/aws-webapp --ingest examples/aws-webapp/scanner/trivy-app-image.json
```

On a terminal that prints the text report below, at 100 columns.
Pipe it, or pass `-f json`, and you get the full JSON report instead.

<!-- gen:example-report -->
```text
ThreatCode scan of examples/aws-webapp: 28 resources, 14 findings

Verdict: 2 critical, 5 high, 6 medium, 1 low, 3 attack paths from the internet to data stores and
         secret stores, worst critical

Attack paths (3)
P1  CRITICAL  internet -> aws_s3_bucket.customer_data
    data store, 5 hops, score 9.2; 3 findings enable it, the worst being
    CRITICAL trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same
    resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_s3_bucket.customer_data
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: CRITICAL trivy:CVE-2022-37434,
        HIGH EC2_IMDSV1
    ignore id: 5453d439158d

P2  CRITICAL  internet -> aws_secretsmanager_secret.db_credentials
    secret store, 5 hops, score 9.0; 3 findings enable it, the worst being
    CRITICAL trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same
    resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_secretsmanager_secret.db_credentials
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: CRITICAL trivy:CVE-2022-37434,
        HIGH EC2_IMDSV1
    ignore id: 1e87639aaf0e

P3  CRITICAL  internet -> aws_db_instance.orders
    data store, 3 hops, score 9.0; 3 findings enable it, the worst being
    CRITICAL trivy:CVE-2022-37434; plus 1 equivalent route through other instances of the same
    resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_db_instance.orders
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_db_instance.orders on tcp/5432: CRITICAL trivy:CVE-2022-37434,
        HIGH EC2_IMDSV1
    ignore id: e716deafaabc

Findings (14)
SEVERITY  RESOURCE                                  RULE                       PATHS
          FINDING
          LOCATION         ATT&CK           STRIDE
CRITICAL  aws_instance.app[0]                       trivy:CVE-2022-37434       P1,P2+1
          CVE-2022-37434: zlib: heap-based buffer over-read and overflow in inflate() in inflate.c
            via a large gzip header extra field
          tfplan.json:484                   EoP
CRITICAL  aws_instance.app[1]                       trivy:CVE-2022-37434
          CVE-2022-37434: zlib: heap-based buffer over-read and overflow in inflate() in inflate.c
            via a large gzip header extra field
          tfplan.json:532                   EoP
HIGH^     aws_instance.app[0]                       EC2_IMDSV1                 P1,P2+1
          EC2 instance metadata service allows IMDSv1
          tfplan.json:484  T1552.005        EoP
HIGH^     aws_instance.app[1]                       EC2_IMDSV1
          EC2 instance metadata service allows IMDSv1
          tfplan.json:532  T1552.005        EoP
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[0] (tcp/8080)
          tfplan.json:351  T1565.002        Tampering
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[1] (tcp/8080)
          tfplan.json:351  T1565.002        Tampering
HIGH^     aws_s3_bucket.customer_data               S3_NO_VERSIONING
          S3 bucket without versioning
          tfplan.json:660  T1485            DoS
MEDIUM    aws_instance.app[0]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:484  T1530,T1565.002  Tampering
MEDIUM    aws_instance.app[1]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:532  T1530,T1565.002  Tampering
MEDIUM    aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, internet > dmz: from the internet (tcp/443)
          tfplan.json:351  T1190,T1565.002  Tampering
MEDIUM^   aws_s3_bucket.customer_data               S3_NO_LOGGING
          S3 bucket without access logging
          tfplan.json:660                   Repudiation
MEDIUM    aws_secretsmanager_secret.db_credentials  SM_NO_ROTATION
          Secrets Manager secret without rotation
          tfplan.json:721  T1555.006        Info disclosure
MEDIUM    aws_vpc.main                              VPC_NO_FLOW_LOGS
          VPC without flow logs
          tfplan.json:12                    Repudiation
LOW       aws_security_group.alb                    SG_WEB_PORT_OPEN_TO_WORLD  P1,P2+1
          Security group allows the internet to reach a web port
          tfplan.json:219  T1190            Info disclosure

Key: ^ severity raised from the rule's own by context; P1, P2: the attack paths above that the
     finding enables

Coverage: 3 files discovered, 1 unit parsed
  Not infrastructure: expected.yml, scanner/trivy-app-image.json
  No input errors or coverage gaps were recorded.
```
<!-- /gen:example-report -->

Exit code 1 says the gate tripped: at least one finding or attack path is at or above `--fail-on` (default `high`).
Without `--ingest` the same scan shows the same three paths and no scanner finding, and the data bucket path is `critical` because the bucket is tagged as confidential.

## Install

To use ThreatCode on your own code, install it straight from GitHub:

```bash
pip install "git+https://github.com/ajokunu/ThreatCode.git"
```

Add the optional model client with `pip install "threatcode[llm] @ git+https://github.com/ajokunu/ThreatCode.git"`.
Python 3.10 or newer is required.
The package is not published to PyPI yet, so the install line above is the supported one until the release checklist in [docs/releasing.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/releasing.md) is done.

## Quick start

Scan a directory, a file, or several of each.
`scan` finds the infrastructure files itself, never follows a symlink out of the tree, and builds one graph across everything it found, so a path can cross files.

```bash
threatcode scan infra/
threatcode scan main.tf modules/ k8s/ Dockerfile
```

For Terraform, scan the source directory, or scan a plan, which holds the resolved values.
`terraform show -json` prints state unless you name a plan file, and state is rejected with the command that fixes it:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
threatcode scan tfplan.json
```

Pick the output with `-f` and the destination with `-o`.
Without `-f` you get the text report on a terminal and JSON when the output is a file or a pipe.

<!-- runnable -->

```bash
threatcode scan examples/aws-webapp -f sarif -o threatcode.sarif --fail-on none
threatcode scan examples/aws-webapp -f markdown -o report.md --fail-on none
threatcode scan examples/aws-webapp -f mermaid -o paths.mmd --fail-on none
```

<!-- gen:formats -->
| `-f` value | Extension | What it is |
| --- | --- | --- |
| `json` | .json | Machine-readable report with coverage |
| `sarif` | .sarif | SARIF 2.1.0 for GitHub code scanning |
| `markdown` | .md | Markdown for pull request comments |
| `bitbucket` | .json | Bitbucket Code Insights report |
| `navigator` | .json | MITRE ATT&CK Navigator layer |
| `mermaid` | .mmd | Mermaid flowchart by trust zone with attack paths |
| `diagram` | .svg | SVG diagram of the infrastructure |
| `text` | .txt | Human summary for a terminal |
| `matrix` | .json | Deprecated alias of navigator |
<!-- /gen:formats -->

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Clean. Nothing at or above `--fail-on` survived the suppressions and the baseline, or `--fail-on none` was given. |
| 1 | At least one finding or attack path at or above `--fail-on` (default `high`) remains. Findings from the LLM are advisory and never count. |
| 2 | The scan cannot be trusted: an unreadable path, a file that a parser claims but cannot parse, an ingest file that is unreadable or unrecognized, nothing to scan, a bad option, or a coverage gap under `--strict`. |

When more than one applies, 2 wins over 1 and 1 wins over 0.
`--min-severity` only hides findings from the report, so `--min-severity critical --fail-on high` shows critical findings and still exits 1 on a high one.

A scan never reports a clean pass for input it did not analyse.
A remote Terraform module, a Helm chart rendered without `helm`, values known only after apply, unresolved CloudFormation intrinsics and skipped documents are coverage gaps.
They are printed on stderr even with `-q`, listed in the JSON, SARIF, Markdown and text reports, and `--strict` turns any of them into exit 2.

## What it reads

<!-- gen:support-summary -->
| Input | Rules for | Attack paths |
| --- | --- | --- |
| Terraform plan JSON | AWS, Azure, GCP | AWS |
| Terraform and OpenTofu source | AWS, Azure, GCP | AWS |
| CloudFormation and SAM | AWS | AWS |
| Kubernetes manifests | Kubernetes | Kubernetes |
| Helm charts | Kubernetes | Kubernetes |
| Dockerfiles | Dockerfile | none (the image is judged where it runs) |
| MCP client and agent configs | MCP | MCP |
<!-- /gen:support-summary -->

**Attack paths are modeled for AWS, Kubernetes and MCP agent configs.**
Azure and GCP resources get rule findings, severities and ATT&CK mappings, but no topology yet: no exposure, no reachability edges and no attack paths.
A Terraform scan of an Azure or GCP stack therefore reports findings and an empty path list, which means "not modeled", not "no path exists".
[docs/support-matrix.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/support-matrix.md) has the full matrix: versions, Kubernetes kinds, the 142 CloudFormation types and what each input cannot do.

## What it shows

**Attack paths.**
A path is a chain of resources an attacker can follow over directed reachability edges (security group rules, load balancer targets, API Gateway integrations, IAM permissions, Kubernetes Services, Ingresses and RBAC bindings, MCP agent tool edges), from a synthetic `internet` node to a crown jewel: a data store, a secret store, an admin identity, a Kubernetes Secret or cluster-admin grant, or an MCP server that reads private data.
Each hop lists the findings that enable it, the ATT&CK technique of that step, and the port and protocol it rests on.
A path appears only when some finding enables it, so an architecture with nothing wrong on the way to the data has none.

**Findings with context.**
Each of the 256<!-- count:rules --> built-in rules declares a STRIDE category, ATT&CK techniques, a confidence and a mitigation, and keeps the base severity it assigns.
When context changes the severity, the engine adds an effective severity with the reason: one level up for a weakness the internet can reach or on a data store tagged confidential, one level down for exposure tagged as intentional.
The gate, SARIF and the reports use the effective severity.

**Trust boundaries.**
Every traffic flow that crosses from one zone to another (internet, DMZ, private, data, management) is a boundary finding with its protocol, ports and whether the input says the flow is authenticated and encrypted.

**ATT&CK.**
Rules and the engine reference 36<!-- count:techniques --> techniques in 12<!-- count:tactics --> tactics of ATT&CK v19.2<!-- count:attack_version -->, and `-f navigator` writes a layer for the ATT&CK Navigator.

## Use it next to the scanners you run

| Tool | What it finds | How to join it |
|------|---------------|----------------|
| Trivy | CVEs, misconfigurations and secrets in images, filesystems and IaC | `trivy image --format json --output trivy.json IMAGE`, then `--ingest trivy.json` |
| Grype | CVEs in images and SBOMs | `grype IMAGE -o json > grype.json`, then `--ingest grype.json` |
| OSV-Scanner | CVEs in lockfiles | `osv-scanner --format json ... > osv.json`, then `--ingest osv.json` |
| Checkov, Gitleaks, any SARIF 2.1.0 tool | IaC policy failures, committed secrets | write SARIF, then `--ingest results.sarif` |

A finding is placed on the graph by the first key that matches: the container image reference a workload holds, the file and line of a resource, or the directory of a lockfile.
A finding no key can place is kept, counted, and reported as a coverage gap.
Secrets in a scanner result are never copied into the report.

```bash
trivy image --format json --output trivy.json registry.example.com/shop/orders-api:3.2.1
threatcode scan infra/ --ingest trivy.json
```

ThreatCode's own secret detectors run only over the files it models, and attach each finding to the resource that holds the secret.
There is no `repo`, `fs`, `image` or `secret` command: clone the repository and run `threatcode scan` on it.

## In CI

```yaml
- uses: ajokunu/ThreatCode/.github/actions/threatcode@main
  with:
    path: infra/
    fail-on: high
```

The action installs the code at the ref it was called with, uploads SARIF to GitHub code scanning, can post the Markdown report as one pull request comment that later pushes update, and fails the job only when the gate trips.
[docs/cicd.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/cicd.md) has the permissions it needs, baselines, and recipes for GitLab CI, Bitbucket Pipelines and pre-commit.

## Suppress and baseline

A `.threatcodeignore` file in the scan root takes one entry per line:

```text
S3_NO_LOGGING resource=aws_s3_bucket.scratch reason="scratch bucket, no data" exp:2027-01-01
```

An entry names a rule id, a finding id, a fingerprint, a CVE or an attack path id, and can be scoped with `resource=` and `file=` globs.
`--write-baseline FILE` records every current finding and attack path, and `--baseline FILE` hides those from the gate and the listings, so a team can adopt the gate on an existing codebase and fail only on new findings and new attack paths.
A path is recorded by its id, which comes from its route, so a path that gains or loses a hop is a new path and gates again.
A baseline written by an older version lists no paths and hides none, so write it again.

## Configuration

A `.threatcode.yml` that the scan finds on its own, in the scan root or the current directory, belongs to the repository being scanned, so it is auto-discovered and untrusted: only `min_severity` and `format` are read from it, the rest is ignored with a warning, and a note on stderr says which file was used.
That is deliberate: a pull request must not be able to turn off its own gate, load its own rules or point the tool at its own model server.
Everything else, `fail_on`, `rules`, `llm`, `redaction` and the graph limits, is read only from a file you name with `--config`.
Precedence is the flag, then the `THREATCODE_FAIL_ON`, `THREATCODE_MIN_SEVERITY`, `THREATCODE_FORMAT` and `THREATCODE_LLM` variables, then the config file, then the default.
[docs/configuration.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/configuration.md) lists every key.

## The LLM is opt-in

ThreatCode contacts a model only with `--llm`, `THREATCODE_LLM=1` or `llm.enabled: true` in a config you name with `--config`, and only with the `llm` extra installed.
An exported `ANTHROPIC_API_KEY` alone sends nothing.
The payload is pseudonymized (resources are opaque handles), allowlisted and redacted, and `--dry-run` prints exactly what would be sent without opening a connection.
LLM findings are advisory: they are tagged as such and never set exit code 1.
The default model is `claude-sonnet-5-5`.
[docs/security.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/security.md) describes what is redacted and what leaves the machine.

## Python API

<!-- runnable -->

```python
import threatcode

report = threatcode.scan("examples/aws-webapp", fail_on="none")
assert report["attack_paths"], "the demo stack has paths from the internet to data"
for path in report["attack_paths"]:
    print(path["severity"], path["entry"], "->", path["target"])
```

`scan` returns the report as a dict, exactly what `-f json` prints.
`analyze` returns the graph with the report, and `run_scan` returns everything, including the exit code and the coverage.
They raise `ThreatCodeError` when an input could not be analysed, so a caller cannot mistake a partial result for a clean one.
[docs/api-reference.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/api-reference.md) has the details.

## How good is it

On the ten realistic fixtures in the test suite, which plant 39 known issues such as open security groups, wildcard roles, public buckets and IMDSv1, ThreatCode finds 37<!-- count:benchmark_found --> of 39<!-- count:benchmark_total --> and reports no finding on the resources the fixtures harden.
The two it misses are explained in [docs/benchmark.md](https://github.com/ajokunu/ThreatCode/blob/main/docs/benchmark.md), and a ratchet in the test suite keeps the number from falling.
Every command and count in this README is executed or computed by `tests/test_docs.py`.

## Documentation

- [Getting started](https://github.com/ajokunu/ThreatCode/blob/main/docs/getting-started.md) walks through a first scan.
- [CLI reference](https://github.com/ajokunu/ThreatCode/blob/main/docs/cli.md), [configuration](https://github.com/ajokunu/ThreatCode/blob/main/docs/configuration.md) and [CI/CD](https://github.com/ajokunu/ThreatCode/blob/main/docs/cicd.md).
- [Architecture](https://github.com/ajokunu/ThreatCode/blob/main/docs/architecture.md), [rule catalog](https://github.com/ajokunu/ThreatCode/blob/main/docs/rules.md) and [writing rules](https://github.com/ajokunu/ThreatCode/blob/main/docs/writing-rules.md).
- [MITRE ATT&CK mapping](https://github.com/ajokunu/ThreatCode/blob/main/docs/mitre-attack.md), [security](https://github.com/ajokunu/ThreatCode/blob/main/docs/security.md) and [the security model of the tool itself](https://github.com/ajokunu/ThreatCode/blob/main/docs/security-model.md).
- [Migrating from 0.9](https://github.com/ajokunu/ThreatCode/blob/main/docs/migrating.md) lists the removed commands and what replaces them.
- [Claims and their proof](https://github.com/ajokunu/ThreatCode/blob/main/docs/claims.md) maps every public claim about ThreatCode to a command or a test.
- [Changelog](https://github.com/ajokunu/ThreatCode/blob/main/CHANGELOG.md).

To report a vulnerability, follow [SECURITY.md](https://github.com/ajokunu/ThreatCode/blob/main/SECURITY.md).

## License

MIT
