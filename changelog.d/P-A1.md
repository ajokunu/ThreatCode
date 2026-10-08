### Fixed
- **A file that fails to parse is an input error wherever it sits.**
  A Terraform file that could not be parsed made the scan exit 2 when you named it on the command line and exit 0 when it sat in a directory next to a file that parsed, so `threatcode scan infra/` could report 227 failed files and still pass.
  Both cases now list the failure under the coverage errors, add "incomplete: N input errors" to the closing line, and exit 2.
  The failure is no longer listed a second time under the gaps.
- **A truncated plan fails the scan.**
  A `plan.json`, `tfplan.json`, `*.tfplan.json` or `plan-*.json` that is not valid JSON was counted as "not infrastructure".
  So was any JSON or YAML file whose first lines read as a Terraform plan, a CloudFormation template or a Kubernetes manifest.
  Each is now a parse failure, which means a half-written `terraform show -json` file in CI exits 2.
  YAML with template delimiters (`{{ .Values.x }}`, `{% if %}`) and files that say nothing about infrastructure, such as a `tsconfig.json` with comments, still count as not infrastructure.
- A directory whose only resource file fails to parse reports that failure.
  It used to say "1 input(s) were parsed but produced no resources to model".
  That message now reads "1 input was parsed" or "2 inputs were parsed", and it appears only when a scan finds no resources and nothing failed.
- **A Rain module says what it is.**
  A CloudFormation resource whose type is `!Rain::Module <path>` was skipped with "Type must be a string, not a dict", 29 times in one scan of the AWS CloudFormation templates repository.
  The skip now reads "Rain module not expanded (Type is !Rain::Module <path>; run rain pkg to expand it), so the resources it creates are not analysed", and the template is marked incomplete like one with a nested stack.
- **Valid Terraform that python-hcl2 rejected now parses.**
  python-hcl2 4.x, the low end of the supported range, rejected an object element whose value is an operator expression (`device_index = i == 0 ? 0 : 1` followed by another element) and a conditional that breaks its line before `?` inside nested parentheses, which is how `terraform fmt` leaves them.
  It also rejected a `\r\n` inside a block comment, which describes every file in a checkout with Windows line endings.
  python-hcl2 8.x rejected a traversal that continues on the next line.
  A file that fails is now retried with its layout normalized: line breaks inside brackets become spaces, an operator value gets parentheses, and `\r\n` becomes `\n`.
  If the retry fails too, the error names the line of the original text.
  On cloud-foundation-fabric under python-hcl2 4.3.5, 90 files failed (227 `parse.failed` entries and 1681 cascading `hcl.unresolved_reference` gaps).
  They all parse now, and 3026 resources with 29 findings became 5088 resources with 41 findings.
  Under 8.x one more file parses.
  An error under 4.x ends with the command that upgrades python-hcl2.
- **python-hcl2 4.x keeps the parentheses of a grouped expression.**
  4.x returns `a && (b || c)` as `a && b || c`, which changes the precedence and so changes what a `count` or a condition evaluates to.
  On terraform-aws-vpc, 4.x modelled 1758 resources and 8.x modelled 1686, because `local.create_public_subnets && (!var.one_nat_gateway_per_az || ...)` lost its group.
  Every grouping parenthesis now travels through 4.x as a marker call and comes back, and calls such as `length(x)` are left alone.
  4.x and 8.x now agree on the nodes, properties, findings and gaps of cloud-foundation-fabric, terraform-aws-eks, terraform-aws-vpc and terraform-aws-eks-blueprints.
  The dependency range stays `>=4.3,<9`.
  Raising the floor to 8.x would be simpler, and the package report asks for it because the CI matrix and its test belong to other files.
- Terraform text is parsed once per run.
  A module directory is read as a unit of its own and again by every caller, and python-hcl2 8.x parses about 2.5 times slower than 4.x.
  The parser now keeps the data of recent texts (8 million characters, oldest dropped first), so cloud-foundation-fabric takes 11 seconds where it took 27 and terraform-aws-vpc takes 1.7 where it took 5.8, with the same findings.
- **A variable default that switches a resource off no longer hides a missing companion.**
  `aws_flow_log` with `count = var.enable ? 1 : 0` and `default = false` was kept as present, so `VPC_NO_FLOW_LOGS` never fired.
  terraform-aws-vpc reported no findings in 1758 resources, including `examples/simple`, which calls the module without any flow log setting.
  A count of 0 or an empty `for_each` now drops the resource wherever the value comes from.
  In a followed module the caller sits in the repository and did not pass the variable, so the default is the value and the drop gets an info note.
  In the module you scan itself, a value from `-var`, `-var-file` or `TF_VAR_*` could replace the default.
  There the drop also produces one `hcl.default_disabled` warning per module that names the resources and the variables, and `--strict` fails on it.
  A value in `terraform.tfvars` or a `*.auto.tfvars` file settles the question.
  terraform-aws-vpc now reports `VPC_NO_FLOW_LOGS` for 10 VPCs under both python-hcl2 majors.
  A default that enables the resource keeps it and flags `count_from_default` in its meta.
- **A Helm chart with an unvendored library dependency says why its workloads are missing.**
  A Bitnami chart lists the `common` library chart as a dependency and a fresh checkout has no `charts/common`.
  Every `include "common.names.fullname"` then prints a placeholder where a block of YAML belongs, the template renders to invalid YAML and is skipped, and the scan ended with "Verdict: no findings".
  The gap for a skipped template now names the includes that no chart defines and the dependency that should have supplied them.
  A chart-level gap says "dependency common is not vendored in charts/" and tells you to run `helm dependency build` or install helm.
  The parse is marked `incomplete`, with `skipped_templates` and `missing_dependencies` in its metadata.
  A dependency that sits in `charts/` as a directory or a `.tgz`, or that its `condition` turns off, is not reported.
- **Unresolved Helm names read as words.**
  `kubernetes_service.placeholder-templates-svc-yaml-0-2.placeholder-templates-svc-yaml-0-1` is now `kubernetes_service.unresolved-namespace.unresolved-svc`.
  A second unresolved document of the same template is `unresolved-svc-1`.
  A boundary finding or an attack path through such a service can be read now.
- **A Kubernetes grant limited to named objects is a narrow grant.**
  `has_secrets_read` and `has_pod_exec` ignored `resourceNames`, so a Role that reads only the Secret `tls-cert`, or execs only into the pod `debug-0`, was reported like one that covers every Secret or pod.
  A rule that names its objects sets neither fact, and a broad rule beside it still does.
  The description of `K8S_RBAC_SECRETS_READ` still says the rule cannot tell, and it lives in a rule file outside this change.
  The golden recording of `real_shapes/helm/platform` loses `K8S_RBAC_SECRETS_READ` on `kubernetes_role.default.release-platform-secrets`, a Role whose only rule lists its Secrets in `resourceNames`.
- A CloudFormation `AWS::WAFv2::RuleGroup` reads like the web ACL: `Rules` becomes the Terraform `rule` and `VisibilityConfig` becomes the `visibility_config` block.
- A Terraform plan, a CloudFormation template and a Kubernetes manifest are read from disk once.
  The registry passes the text it decoded to the parser, which finds its line numbers there, and a file that changes between two reads can no longer misalign them.
