# Rule examples

Every builtin rule has a vulnerable example it must fire on and a fixed example it must not.
The harness in `harness.py` loads each example, parses it with `detect_and_parse`, builds the graph and evaluates only that rule on every node through `matches_rule`.

## Adding an example

Create `cases/<group>/<RULE_ID>/bad.<ext>` and `good.<ext>`.
The group is the provider directory and file stem of the builtin rule file, joined with `__`, for example `aws__s3` for `builtin/aws/s3.yml`.
The extension picks the parser:

| Extension | Input | Written under the name |
| --- | --- | --- |
| `tf` | Terraform HCL | `main.tf` |
| `plan.json` | `terraform show -json` output | `tfplan.json` |
| `cfn.yaml` | CloudFormation template | `template.yaml` |
| `k8s.yaml` | Kubernetes manifest | `manifest.yaml` |
| `Dockerfile` | Dockerfile | `Dockerfile` |
| `mcp.json` | MCP client config | `.mcp.json` |

Short snippets can live in `cases/<group>/<RULE_ID>.yml` instead, as `cases: [{format, bad, good}]` with format one of `hcl`, `plan`, `cfn`, `k8s`, `docker` or `mcp`.

The good example is the remediation the rule's own mitigation text recommends, written in real provider syntax.
It must still contain a resource of the type the rule fired on, so it cannot pass by leaving the resource out.

## Plan JSON

Terraform is not installed in the environments that built this corpus, so every plan case is hand-built from the documented `terraform show -json` shape (format 1.2).
`plan_shape_problems` in `tests/helpers/plan_shape.py` checks each one for the parts real plans have and hand-shaped fixtures omit.
`scripts/capture_plans.md` describes replacing them with captures from a real run.

## Pending cases

A case can be written before the package that makes it pass.
Add `pending.yml` beside the files, mapping the format to the package and the specific deliverable:

```yaml
hcl:
  package: WP-2-2
  reason: jsonencode policies are normalized to compact JSON text
```

The case is skipped with that reason and does not count as coverage while it is pending.
The named package deletes the entry when it delivers.

## The coverage ratchet

`uncovered/<group>.txt` lists the rules of a group that have no active example yet.
Adding an example for a listed rule fails the gate until you remove the rule from the list.
A rule with no example that is not listed fails the gate, which is what stops a new rule from landing without examples.
Lists only shrink.
The release gate requires every list to be empty.

`PYTHONPATH=src:. python -m tests.test_rules.harness` prints coverage per group.
