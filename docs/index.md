# ThreatCode

**Attack paths from the internet to your data, found in the infrastructure code you already have.**

ThreatCode reads Terraform plans and HCL directories, CloudFormation and SAM templates, Kubernetes manifests, Helm charts, Dockerfiles and the MCP configs that AI coding agents load.
It builds one graph, walks it from the internet to the data stores, secret stores and admin identities behind it, and reports STRIDE threats with MITRE ATT&CK mappings and the attack paths that connect them.
Each hop of a path names the finding that makes it possible.

It does not compete with Trivy, Checkov, Grype, OSV-Scanner or Gitleaks on breadth.
You run them as you do today and pass their results to `--ingest`, so a critical CVE in the image of a workload the internet can reach becomes a step in a path.

## Quick install

```bash
pip install "git+https://github.com/ajokunu/ThreatCode.git"
```

## Quick start

<!-- runnable exit=1 -->

```bash
threatcode scan examples/aws-webapp --ingest examples/aws-webapp/scanner/trivy-app-image.json
```

The scan prints the verdict, the attack paths and the findings, and exits 1 because the gate tripped (the default is `--fail-on high`).
[Getting started](getting-started.md) reads the report line by line.

## Where to go next

| I want to | Page |
|-----------|------|
| Run a first scan and read the report | [Getting started](getting-started.md) |
| Know every option and exit code | [CLI reference](cli.md) |
| Gate a pull request in GitHub, GitLab or Bitbucket | [CI/CD](cicd.md) |
| Know what each input supports, and what it cannot do | [Support matrix](support-matrix.md) |
| Understand how a scan works | [Architecture](architecture.md) |
| See every rule | [Rule catalog](rules.md) |
| Write my own rules | [Writing rules](writing-rules.md) |
| Configure it, and know which config file is trusted | [Configuration](configuration.md) |
| Know what it does with my files | [Security](security.md) and [Security model](security-model.md) |
| See how well it detects planted issues | [Benchmark](benchmark.md) |
| Upgrade from 0.9 | [Migrating](migrating.md) |
| Call it from Python | [API reference](api-reference.md) |

## What it is

- **Offline by default.**
  It makes no network connection unless you turn on the optional model review.
- **Honest about what it did not read.**
  A coverage block in every report lists unanalysed modules, fallback renders, unknown values and skipped files, and `--strict` turns any of them into exit 2.
- **Rules you can read.**
  256<!-- count:rules --> YAML rules, each with a STRIDE category, ATT&CK techniques, a confidence and a mitigation.
- **Attack paths for AWS, Kubernetes and MCP agent configs.**
  Azure and GCP resources get rule findings but no topology yet.
