# Security

This page documents the security controls of ThreatCode itself and what it does with your files.
[Security model](security-model.md) lists the trust boundaries and resource limits of the tool.
To report a vulnerability, follow [SECURITY.md](https://github.com/ajokunu/ThreatCode/blob/main/SECURITY.md).

## What leaves your machine

By default, nothing.
ThreatCode reads the files you name and writes the report you ask for.
It makes no network connection of its own: no telemetry, no update check, no database download, no registry call.
The only code that opens a connection is the optional model client, and it runs only when you ask for the model review (`--llm`, `THREATCODE_LLM=1`, or `llm.enabled: true` in a config you name with `--config`) and have installed the `llm` extra.
The only program it starts is `helm template`, when `helm` is installed and a chart is scanned, with no shell, a time limit and an output limit.

An exported `ANTHROPIC_API_KEY` alone does not send anything.
If you request the model review without the extra installed, the scan exits 2 and names `pip install "threatcode[llm]"`.

## The model review

When the review runs, the model receives one request: a system prompt and a JSON document describing the graph.
The document is built to say as little as the analysis needs.

- **Resources are opaque handles** such as `aws_s3_bucket.n3`.
  Names, accounts, addresses and values never leave the machine, and the answer is mapped back locally.
- **Each resource carries** its zone, exposure, boundary and evidence level, the ids of the rules that already fired on it, and a small allowlisted set of security properties: ingress and egress CIDRs and ports, IAM effects, actions and principals, encryption and public-access flags, listener protocols, and Kubernetes and MCP flags.
  Every other property is dropped, because the allowlist is deny by default.
- **Each edge carries** its type, the zones it joins, whether it crosses a trust boundary, and the protocol, ports, authentication and encryption the input declares.
- **Source files, file names and line numbers are not sent.**

Whatever the allowlist keeps still goes through the redactor.

### What the redactor does

- Keys are matched by substring, case-insensitively: `db_password`, `aws_secret_access_key`, `user_data`, `client_secret` and anything with *password, passwd, secret, token, key, credential, authorization, connection, private, certificate* or *cookie* in the name.
  The exact names `arn`, `account_id`, `tags`, `ip_address`, `name`, `module` and a few more are sensitive too.
- Values are scanned for secret shapes whatever key they sit under: cloud keys, GitHub, GitLab, Slack, Stripe and Anthropic tokens, JWTs, PEM blocks, webhook URLs and `scheme://user:pass@host` credentials.
- ARNs, 12-digit account ids next to a word that names them, email addresses and IP addresses become placeholders.
  `0.0.0.0/0` and `::/0` stay readable because they matter to the analysis.
- `redaction.fields` adds names that are redacted at any depth, case-insensitively, and win over the allowlist.
- Past 10,000 distinct values redaction fails closed and nothing is sent, instead of giving different values one placeholder.

A placeholder is `REDACTED_<label>_<n>` with the `placeholder` strategy, and `REDACTED_<label>_<16 hex digits>` with the `hash` strategy.
The label is the lowercase key name or the kind of value (`arn`, `email`, `ip_v4`).
The hash is an HMAC keyed with a random per-run key that is never written anywhere, so a provider cannot confirm a guess by hashing it.

Real output of the redactor, produced by running this snippet:

<!-- gen:redaction -->
<!-- runnable -->

```python
import json

from threatcode.engine.llm.redactor import Redactor

resource = {
    "arn": "arn:aws:s3:::acme-prod-data",
    "db_password": "hunter2-hunter2",
    "owner_contact": "ops@example.com",
    "listener_ip": "203.0.113.7",
    "cidr": "0.0.0.0/0",
    "encrypted": True,
}
print(json.dumps(Redactor("placeholder").redact(resource), indent=2))
```

That prints:

```json
{
  "arn": "REDACTED_arn_1",
  "db_password": "REDACTED_db_password_2",
  "owner_contact": "REDACTED_email_3",
  "listener_ip": "REDACTED_ip_v4_4",
  "cidr": "0.0.0.0/0",
  "encrypted": true
}
```
<!-- /gen:redaction -->

Placeholders are written back into a finding only when they were issued for that finding's own resource and name a location (an ARN, an address or an account).
A secret placeholder in model text stays a placeholder.

### See exactly what would be sent

`--dry-run` builds the request and prints it, after pseudonymization and redaction, without opening a connection.
The request goes to stderr (standard output carries the report), or to the file named by `--dry-run-output`, with the sizes and the input token estimate.

```bash
threatcode scan infra/ --dry-run --dry-run-output request.json
```

Read `request.json` before you enable the review on a repository you care about.
Anything you do not want sent can be added to `redaction.fields` in the config you pass with `--config`.

### What comes back

The reply is parsed as JSON and never executed.
Every field is type-checked and each item is validated on its own, so a malformed item costs only that item; a reply cut off mid-array keeps every complete item.
Titles, descriptions and mitigations lose links, code blocks, shell operator runs, control characters and bidirectional override characters, and are length capped.
A finding that names no resource of the scan goes to `llm.unattributed` in the report and is not listed as a finding.
`resource_type` comes from the graph, tactics are derived from the techniques, and a finding that restates a rule, boundary, secret or scanner finding on the same resource is dropped.
Revoked ATT&CK ids map to their successors, and unknown ones are dropped.
Findings from the model are marked as advisory in every format and never set exit code 1.

### Prompt injection

Text in the scanned files can try to instruct the model, through a resource name or a tag.

- Names never reach the model, because resources are handles.
- The data sits inside a delimiter tag with a random per-request suffix, with `<`, `>` and `&` escaped in the JSON, so a label cannot close it.
- The system prompt tells the model to ignore instructions found in the data and to answer only in the JSON format.
- The reply is capped at 512 KB and 100 findings, and every field is validated.

None of this makes a prompt injection impossible.
It limits what one can do: ThreatCode gives the model no tools, and its output is advisory text that is validated, attributed to a known resource and kept out of the gate.

## Secret previews

A secret finding never contains the secret.
Its preview is `[REDACTED <rule id> len=<n>]`, its id is derived from the rule, the root-relative file, the line and the position on the line, and its fingerprint from the rule, file, resource and attribute, never from the value.
The finding lands on the resource that holds the secret, so it joins the graph and the attack paths.

<!-- runnable -->

```python
import threatcode
from pathlib import Path

Path("main.tf").write_text(
    'resource "aws_db_instance" "orders" {\n'
    '  engine   = "postgres"\n'
    '  password = "Tr0ub4dor&3-live-Secret"\n'
    "}\n"
)
report = threatcode.scan("main.tf", fail_on="none")
secrets = [t for t in report["threats"] if t["source"] == "secret"]
assert secrets, "the literal password is a finding"
for finding in secrets:
    print(finding["rule_id"], finding["resource_address"], finding["metadata"]["preview"])
    assert "Tr0ub4dor" not in str(finding)
```

## Outbound connections and SSRF

The model client is the only code that connects anywhere, so the address check applies to it.
An Anthropic or OpenAI-compatible `base_url`, and the `ANTHROPIC_BASE_URL` variable, are validated before any request:

- The hostname is resolved and every address is checked: loopback, private, link-local (including the cloud metadata address `169.254.169.254`), multicast, reserved, unspecified and IPv4-mapped IPv6 addresses are refused.
- By default only HTTPS to a public address is accepted.
- `llm.allow_local_network: true` is the explicit opt-in for a model server on your own network.
  It accepts loopback, private and shared (`100.64.0.0/10`) addresses over plain HTTP or HTTPS.
  Link-local, multicast, reserved and unspecified addresses stay blocked, and plain HTTP to a public address is rejected.
- A redirect to another scheme, host or port is refused, so the API key and the request body are never forwarded.
  A redirect inside the same origin gets the same address check.
- A key is sent only to the endpoint it was configured for.

`allow_local_network` and the rest of the `llm` section are read only from a file named with `--config`.

## Code safety

- There is no `eval()`, `exec()`, `pickle` or `marshal` in the package.
  Rule conditions are plain data evaluated by explicit comparison functions, and an unknown operator is rejected when the rule loads.
- YAML is read with safe loaders only.
  The CloudFormation loader adds the short-form intrinsic tags (`!Ref`, `!GetAtt`, `!Sub`) and still rejects Python object tags.
- HCL, Terraform expressions and Helm templates are evaluated by ThreatCode's own evaluators with size, depth and step limits.
  Nothing is run: no `eval`, no file reads from an expression and no provider calls.
- Rule files are limited to 1 MB, 100 rules per file and 1000 rules in all, rule ids must be unique, symlinks in extra rule paths are refused, and MITRE ids are validated against the ATT&CK data.

## Configuration

A config file found inside the scanned repository is untrusted, and only `min_severity` and `output_format` are read from it.
`fail_on`, `extra_rule_paths`, the whole `llm` section, `redaction` and the graph limits come only from a file named with `--config`.
A note on stderr names every auto-discovered file and the keys used.
The details are in [configuration](configuration.md).

API keys belong in environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or the variable named by `llm.api_key_env`).
A key found in a config file produces a warning that names the variable to use instead.

## Input limits

| Input | Limit |
|-------|-------|
| JSON or YAML file | 50 MB, larger files are set aside as not infrastructure |
| Standard input | 50 MB |
| Graph nodes and edges | 10,000 and 50,000 by default, changed by `--max-nodes` and `--max-edges` |
| Reachability edges per rule | 500, a cut is reported as a coverage gap |
| Model request | `llm.max_input_tokens`, 60,000 by default, never cut |
| Model call | `llm.timeout`, 120 seconds by default |

The other limits (HCL evaluation, Helm rendering, secret scanning) are in the [security model](security-model.md).

## Dependency audit

CI audits ThreatCode's own dependencies on every run and every Monday:

```bash
pip freeze --exclude threatcode > _audit_reqs.txt
pip-audit --strict -r _audit_reqs.txt
```

## Reporting security issues

Use GitHub private vulnerability reporting, described in [SECURITY.md](https://github.com/ajokunu/ThreatCode/blob/main/SECURITY.md).
Do not open a public issue for a vulnerability.
