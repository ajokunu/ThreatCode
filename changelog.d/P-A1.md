### Fixed
- **A parse failure is an input error everywhere, and a truncated plan can no longer pass.**
  A Terraform file that cannot be parsed made the scan exit 2 when it was named on the command line and exit 0 when it sat in a directory beside another file that parsed, so `threatcode scan infra/` could report 227 failed files and still pass.
  The failure is now an input error in both cases: it is listed under the coverage errors (and no longer also under the gaps), it ends the closing line with "incomplete: N input errors", and the exit code is 2.
  A `plan.json`, `tfplan.json`, `*.tfplan.json` or `plan-*.json` that is not valid JSON, and any JSON or YAML file whose start reads as a Terraform plan, a CloudFormation template or a Kubernetes manifest, is a parse failure instead of "not infrastructure".
  A truncated `terraform show -json` output in CI therefore fails the scan.
  YAML that carries template delimiters (`{{ .Values.x }}`, `{% if %}`) and files that do not look like infrastructure (`tsconfig.json` with comments) are still counted as not infrastructure.
- A directory whose only resource file fails to parse now says so, instead of "1 input(s) were parsed but produced no resources to model".
  The wording of that message for a scan that really finds no resources is now "1 input was parsed" or "2 inputs were parsed".
- **A Rain module is reported as one.**
  A CloudFormation resource whose type is `!Rain::Module <path>` was skipped with "Type must be a string, not a dict" (29 times in one scan of the AWS CloudFormation templates repository).
  It is now skipped with "Rain module not expanded (Type is !Rain::Module <path>; run rain pkg to expand it), so the resources it creates are not analysed", and the template is marked incomplete, like a nested stack.
- **Valid Terraform that python-hcl2 rejected is read, and a Terraform module is no longer parsed once per caller.**
  python-hcl2 4.x, the lower end of the supported range, rejected an object element whose value is an operator expression (`device_index = i == 0 ? 0 : 1` followed by another element), a conditional that breaks its line before `?` inside nested parentheses (what `terraform fmt` leaves), and a `\r\n` inside a block comment (any checkout with Windows line endings).
  python-hcl2 8.x rejected a traversal that continues on the next line.
  The adapter now retries a file that fails with its layout normalized (line breaks inside brackets joined, an operator value wrapped in parentheses, `\r\n` turned into `\n`), and reports the error of the original text, with its line number, when the retry fails too.
  On a scan of cloud-foundation-fabric under python-hcl2 4.3.5 the 90 failing files (227 `parse.failed` entries, 1681 cascading `hcl.unresolved_reference` gaps) read now: 3026 resources and 29 findings became 5088 resources and 41 findings, and python-hcl2 8.x reads one more file than before.
  A failure under 4.x now says how to upgrade python-hcl2.
- **python-hcl2 4.x no longer changes the precedence of a grouped expression.**
  4.x returns `a && (b || c)` as `a && b || c`, so a `count` or a condition with parentheses evaluated to something else.
  On terraform-aws-vpc 4.x modelled 1758 resources and 8.x 1686, because `local.create_public_subnets && (!var.one_nat_gateway_per_az || ...)` lost its group.
  Every grouping parenthesis is now carried through 4.x and put back, a function call is left alone, and 4.x and 8.x agree on the nodes, properties, findings and gaps of cloud-foundation-fabric, terraform-aws-eks, terraform-aws-vpc and terraform-aws-eks-blueprints.
  The lower bound of the dependency is unchanged; raising it to 8.x would be simpler, and it is recorded as a request in the package report because the CI matrix and its test are not part of this change.
- The parsed text of a Terraform file is kept for the rest of the run (8 million characters, oldest dropped first).
  A module directory is read as a unit of its own and again by every caller, and python-hcl2 8.x parses about 2.5 times slower than 4.x, so a scan of cloud-foundation-fabric took 27 seconds and now takes 11, terraform-aws-vpc took 5.8 seconds and now takes 1.7, with the same findings.
- **A resource that a variable default switches off no longer hides a missing companion.**
  `aws_flow_log` with `count = var.enable ? 1 : 0` and `default = false` was kept as present, so `VPC_NO_FLOW_LOGS` never fired: terraform-aws-vpc reported no findings in 1758 resources, even for `examples/simple` that calls the module without any flow log setting.
  A count of 0 or an empty `for_each` now drops the resource whatever it comes from.
  Inside a followed module the caller is in the repository and did not pass the variable, so its default is the value and the resource is dropped with an info note.
  In the module that is scanned itself a value from `-var`, `-var-file` or `TF_VAR_*` could replace the default, so the drop is also one `hcl.default_disabled` warning per module that names the resources left out and the variables, and `--strict` fails on it; a `terraform.tfvars` or `*.auto.tfvars` value settles it.
  terraform-aws-vpc now reports `VPC_NO_FLOW_LOGS` for 10 VPCs, with the same result under python-hcl2 4.x and 8.x.
  A default that enables the resource still keeps it, flagged `count_from_default` in its meta.
- **A Helm chart whose library dependency is not vendored says why its workloads are missing.**
  A Bitnami chart lists the `common` library chart as a dependency and a fresh checkout has no `charts/common`, so every `include "common.names.fullname"` prints a placeholder where a block of YAML belongs, the template renders to invalid YAML and is skipped, and the scan ended with "Verdict: no findings".
  The skipped-template gap now names the includes that no chart defines and the dependency that should have supplied them, a chart-level gap says "dependency common is not vendored in charts/ ... run 'helm dependency build' in the chart, or install helm", and the parse is marked `incomplete` with `skipped_templates` and `missing_dependencies` in its metadata.
  A dependency that is vendored (a directory or a packed `.tgz`) or switched off by its `condition` is not reported.
- **Unresolved Helm names are words.**
  `kubernetes_service.placeholder-templates-svc-yaml-0-2.placeholder-templates-svc-yaml-0-1` is now `kubernetes_service.unresolved-namespace.unresolved-svc`, and a second unresolved document of the same template is `unresolved-svc-1`, so a boundary finding or an attack path through such a service can be read.
- **A Kubernetes grant limited to named objects is not a grant over all of them.**
  `has_secrets_read` and `has_pod_exec` ignored `resourceNames`, so a Role that reads only the Secret `tls-cert`, or execs only into the pod `debug-0`, was reported like one that covers every Secret or pod.
  A rule that names its objects no longer sets either fact; a broad rule next to it still does.
  The wording of `K8S_RBAC_SECRETS_READ`, which says it cannot tell, is in a rule file this change does not own.
- A CloudFormation `AWS::WAFv2::RuleGroup` now reads like the web ACL: its `Rules` is the Terraform `rule` and its `VisibilityConfig` is the `visibility_config` block.
