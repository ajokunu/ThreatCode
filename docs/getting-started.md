# Getting started

This page takes you from an install to a gated build.
Every command on it runs against the demo stacks in `examples/`, and the test suite runs them, so what you read is what happens.

## Install

The demo stacks are in the repository, not in the pip package, so clone it, install from the clone and stay in its top directory for the rest of this page:

```bash
git clone https://github.com/ajokunu/ThreatCode.git
cd ThreatCode
pip install .
```

Python 3.10 or newer is required.
The core install has no model client; add it with `pip install ".[llm]"` only if you want the optional LLM review.
To work on ThreatCode itself, install the development tools with `pip install -e ".[dev]"` instead.

To scan your own code, you do not need the clone: `pip install "git+https://github.com/ajokunu/ThreatCode.git"` puts the `threatcode` command on your path from anywhere, and `pip install "threatcode[llm] @ git+https://github.com/ajokunu/ThreatCode.git"` adds the model client.
The package is not on PyPI yet, so do not run `pip install threatcode`: that name belongs to a different project.

## Your first scan

`examples/aws-webapp` is a Terraform plan for a small web stack: an internet-facing load balancer, two app instances, a database, a customer data bucket and a secret.

<!-- runnable exit=1 -->

```bash
threatcode scan examples/aws-webapp -f text
```

Exit code 1 means the gate tripped, not that the tool failed.
The report looks like this:

<!-- gen:example-report -->
```text
ThreatCode scan of examples/aws-webapp: 28 resources, 12 findings

Verdict: 5 high, 6 medium, 1 low, 3 attack paths from the internet to data stores and secret stores,
         worst critical

Attack paths (3)
P1  CRITICAL  internet -> aws_s3_bucket.customer_data
    data store, 5 hops, score 9.2; 2 findings enable it, the worst being HIGH EC2_IMDSV1; plus 1
    equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_s3_bucket.customer_data
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: HIGH EC2_IMDSV1
    ignore id: 5453d439158d

P2  HIGH      internet -> aws_secretsmanager_secret.db_credentials
    secret store, 5 hops, score 7.5; 2 findings enable it, the worst being HIGH EC2_IMDSV1; plus 1
    equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_iam_instance_profile.app > aws_iam_role.app
    > aws_secretsmanager_secret.db_credentials
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_iam_instance_profile.app: HIGH EC2_IMDSV1
    ignore id: 1e87639aaf0e

P3  HIGH      internet -> aws_db_instance.orders
    data store, 3 hops, score 7.5; 2 findings enable it, the worst being HIGH EC2_IMDSV1; plus 1
    equivalent route through other instances of the same resources.
    internet > aws_lb.front > aws_instance.app[0] > aws_db_instance.orders
    enabled by:
      internet -> aws_lb.front on tcp/443: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_lb.front -> aws_instance.app[0] on tcp/8080: LOW SG_WEB_PORT_OPEN_TO_WORLD
      aws_instance.app[0] -> aws_db_instance.orders on tcp/5432: HIGH EC2_IMDSV1
    ignore id: e716deafaabc

Findings (12)
SEVERITY  RESOURCE                                  RULE                       PATHS
          FINDING  LOCATION  ATT&CK  STRIDE
HIGH^     aws_instance.app[0]                       EC2_IMDSV1                 P1,P2+1
          EC2 instance metadata service allows IMDSv1  tfplan.json:484  T1552.005  EoP
HIGH^     aws_instance.app[1]                       EC2_IMDSV1
          EC2 instance metadata service allows IMDSv1  tfplan.json:532  T1552.005  EoP
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[0] (tcp/8080)  tfplan.json:351
          T1565.002  Tampering
HIGH      aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, dmz > private: to aws_instance.app[1] (tcp/8080)  tfplan.json:351
          T1565.002  Tampering
HIGH^     aws_s3_bucket.customer_data               S3_NO_VERSIONING
          S3 bucket without versioning  tfplan.json:660  T1485  DoS
MEDIUM    aws_instance.app[0]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:484  T1530,T1565.002  Tampering
MEDIUM    aws_instance.app[1]                       BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, private > data: to aws_db_instance.orders (tcp/5432)
          tfplan.json:532  T1530,T1565.002  Tampering
MEDIUM    aws_lb.front                              BOUNDARY_GENERIC_FLOW
          Trust boundary crossing, internet > dmz: from the internet (tcp/443)  tfplan.json:351
          T1190,T1565.002  Tampering
MEDIUM^   aws_s3_bucket.customer_data               S3_NO_LOGGING
          S3 bucket without access logging  tfplan.json:660  Repudiation
MEDIUM    aws_secretsmanager_secret.db_credentials  SM_NO_ROTATION
          Secrets Manager secret without rotation  tfplan.json:721  T1555.006  Info disclosure
MEDIUM    aws_vpc.main                              VPC_NO_FLOW_LOGS
          VPC without flow logs  tfplan.json:12  Repudiation
LOW       aws_security_group.alb                    SG_WEB_PORT_OPEN_TO_WORLD  P1,P2+1
          Security group allows the internet to reach a web port  tfplan.json:219  T1190  Info
          disclosure
Key: ^ severity raised from the rule's own by context; P1, P2: the attack paths above that the
     finding enables

Coverage: 3 files discovered, 1 unit parsed, 2 not infrastructure
  No input errors or coverage gaps were recorded.
```
<!-- /gen:example-report -->

Read it from the top.

- **The verdict line** counts findings by effective severity and says how many attack paths there are and what they reach (data stores, secret stores, admin identities, MCP data readers).
- **An attack path** is a route an attacker can follow from the internet to something worth having.
  `P1`, `P2` and `P3` number the paths, the severity is the worst one on the route, and the chain below it is the route itself, one resource per hop.
  Each hop is followed by the findings that make it possible, worst first, under `enabled by:`.
  A finding that already enabled the hop before it is not repeated, and a path with nothing wrong on a hop prints no line for that hop.
  The same lists are in the JSON report under `hops[].enabled_by`.
  `ignore id` is the 12-hex-digit id you write in a `.threatcodeignore` file to accept the path (see [Accept what is already there](#accept-what-is-already-there)).
  `plus 1 equivalent route` counts routes through other instances of the same resources, such as `aws_instance.app[1]`, which are folded into the path shown.
- **The findings table** lists every finding, most severe first.
  The RULE column is the rule id.
  A trust boundary crossing is a finding like any other and carries a `BOUNDARY_*` id (`BOUNDARY_GENERIC_FLOW`, `BOUNDARY_UNENCRYPTED_FLOW`; the JSON report has it in `metadata.boundary_rule`), and a result ingested from another scanner is prefixed with the tool, such as `trivy:CVE-2022-37434`.
  The PATHS column names the attack paths that finding enables, so you can tell the findings that matter for an attack from the ones that do not.
- **The severity mark** after a severity says that context moved it from the rule's own: `^` raised it, `v` lowered it.
  `HIGH^` on `EC2_IMDSV1` means the rule assigns medium and the instance is reachable from the internet.
  A line under the table spells the marks out whenever one is used.
- **The coverage block** says what was not analysed.
  An empty list of gaps means the scan read everything it was given.
  A skipped Helm template, an unreadable input or any other gap is listed there, and a clean verdict does not mean those files were read.

The JSON report has the same content in a form a program can read:

<!-- runnable -->

```python
import threatcode

report = threatcode.scan("examples/aws-webapp", fail_on="none")
print(report["summary"], len(report["attack_paths"]), "attack paths")

path = report["attack_paths"][0]
print(path["severity"], path["entry"], "->", path["target"])
for hop in path["hops"]:
    print("  ", hop["node_id"], hop["zone"], hop["techniques"])

finding = next(t for t in report["threats"] if t["rule_id"] == "EC2_IMDSV1")
print(
    finding["severity"], "->", finding["effective_severity"], "because", finding["severity_reason"]
)
assert report["coverage"]["errors"] == []
```

A finding keeps the base severity its rule assigns, and the engine adds `effective_severity` and `severity_reason` when context changes it.
Here the IMDSv1 rule says medium, and the instance is reachable from the internet, so the effective severity is high.
The gate, the SARIF `security-severity` and the reports all use the effective severity.

## Scan your own code

Point `scan` at a directory and it finds what it can read.

```bash
threatcode scan infra/
threatcode scan main.tf modules/ k8s/ Dockerfile .mcp.json
```

Each kind of input has a best way to hand it over.

| You have | Hand over | Why |
|----------|-----------|-----|
| Terraform | the source directory, or a plan | A directory is one module with variables, locals and local modules followed. A plan holds the values Terraform resolved, which a directory cannot know. |
| CloudFormation or SAM | the template | Nested stacks are not followed. |
| Kubernetes | the manifests, a `kubectl get -o yaml` dump, or a Helm chart directory | A chart is rendered with `helm` when it is installed. |
| A Dockerfile | the file | The image is judged where it runs, so pair it with the Kubernetes or ECS definition. |
| An AI agent setup | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json`, `claude_desktop_config.json` | Servers are never started or contacted. |

For a Terraform plan, name the plan file in both commands.
`terraform show -json` without a plan file prints state, and state is rejected:

```bash
terraform plan -out tfplan
terraform show -json tfplan > tfplan.json
threatcode scan tfplan.json
```

The same plan can be piped in:

<!-- runnable exit=1 -->

```bash
cat examples/aws-webapp/tfplan.json | threatcode scan - --stdin-name plan.json -o report.json
```

What the scan could not read is never hidden.
A Terraform module from a registry is not downloaded.
A root that only calls registry modules has nothing to model and exits 2, and a root that also declares resources reports the module as a coverage gap that `--strict` turns into exit 2.
Scan `terraform show -json` output when you need the modules resolved.

## Gate a build

The default gate is `--fail-on high`.
Pick the level you want to block on, or `none` to report without failing.

<!-- runnable exit=1 -->

```bash
threatcode scan examples/k8s-platform --fail-on critical -f markdown -o report.md
```

<!-- runnable -->

```bash
threatcode scan examples/k8s-platform --fail-on none -f sarif -o threatcode.sarif
```

| Exit code | Meaning |
|-----------|---------|
| 0 | Nothing at or above `--fail-on` remains. |
| 1 | A finding or attack path at or above `--fail-on` remains. |
| 2 | The scan cannot be trusted: an input error, nothing to scan, a bad option, or a coverage gap under `--strict`. |

Exit 2 matters in CI.
A build that treats every non-zero status as "findings" will miss a parser that crashed.

## Accept what is already there

On an existing codebase, record the current findings and fail only on new ones:

<!-- runnable -->

```bash
threatcode scan examples/k8s-platform --write-baseline baseline.json
threatcode scan examples/k8s-platform --baseline baseline.json --fail-on critical
```

The first command exits 0 whatever it finds, and the second hides every finding and attack path that is in the baseline, so it exits 0 as well.
Commit `baseline.json` so a pull request fails only on what it adds.

To accept one finding for a reason, with an end date, write a `.threatcodeignore` file in the scan root, or name one with `--ignore-file`:

<!-- runnable -->

```bash
printf 'EC2_IMDSV1 resource="aws_instance.app*" reason="fix scheduled for sprint 42" exp:2099-01-01\n' > ignore.txt
threatcode scan examples/aws-webapp --ignore-file ignore.txt --fail-on none -f json -o report.json
python -c "import json; print(json.load(open('report.json'))['coverage']['suppressed'], 'findings suppressed')"
```

The baseline holds the fingerprint of every finding and the id of every attack path, so a path that was already there stops gating and a new path fails the build.
An ignore entry can name an attack path id too, and `resource=` narrows it to a path that crosses a matching resource.
A baseline written before attack paths were recorded lists no path and hides none, so write it again once.

In CI, a pull request can edit the ignore file, so a notice recommends keeping it outside the tree the pull request controls and naming it with `--ignore-file`.

## Join the scanners you already run

Run Trivy, Grype, OSV-Scanner, Checkov or Gitleaks as you do today, and hand the result to `--ingest`.
The demo stack includes a Trivy report with one critical CVE in the image the app instances run:

<!-- runnable -->

```bash
threatcode scan examples/aws-webapp --ingest examples/aws-webapp/scanner/trivy-app-image.json --fail-on none -f json -o report.json
python -c "import json; r = json.load(open('report.json')); print(r['summary']); print(r['ingest'])"
```

The CVE lands on both instances because each holds the image reference in its user data, and the three attack paths through them become critical.
A scanner finding that no key can place on the graph is kept and reported as a coverage gap, never dropped.

## Other outputs

| Need | Command |
|------|---------|
| GitHub code scanning | `-f sarif -o threatcode.sarif` |
| A pull request comment | `-f markdown -o report.md` |
| A diagram in a README or wiki | `-f mermaid -o paths.mmd` |
| An SVG data-flow diagram | `-f diagram -o threat-model.svg` |
| An ATT&CK Navigator layer | `-f navigator -o layer.json`, then load it at [mitre-attack.github.io/attack-navigator](https://mitre-attack.github.io/attack-navigator/) |
| Bitbucket Code Insights | `-f bitbucket -o insights.json` |

You can leave `-f` out when the file name says the format: `-o threatcode.sarif` writes SARIF, `-o report.md` Markdown and `-o paths.mmd` Mermaid.
`-o -` writes the report to standard output.
The Mermaid chart inside the Markdown report draws the hops of the attack paths only, so it fits in a pull request comment, and `-f mermaid` draws every resource an attacker can act through.

## Compare two scans

Save the JSON report from the base branch and from your change, and diff them:

```bash
threatcode scan infra/ -f json -o base.json --fail-on none
threatcode scan infra/ -f json -o current.json --fail-on none
threatcode diff base.json current.json --fail-on-new high
```

`diff` lists attack paths that appeared or were closed first, then findings that were added, resolved or changed, and exits 1 when something at or above `--fail-on-new` was added or got worse.

## Next steps

- [CLI reference](cli.md) lists every option.
- [CI/CD](cicd.md) shows the GitHub Action, GitLab CI, Bitbucket Pipelines and pre-commit.
- [Configuration](configuration.md) explains which config file is trusted.
- [Support matrix](support-matrix.md) says exactly what each input supports.
- [Writing rules](writing-rules.md) adds your own checks.
