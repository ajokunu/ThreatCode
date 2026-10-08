### Fixed
- **A parse failure is an input error everywhere, and a truncated plan can no longer pass.**
  A Terraform file that cannot be parsed made the scan exit 2 when it was named on the command line and exit 0 when it sat in a directory beside another file that parsed, so `threatcode scan infra/` could report 227 failed files and still pass.
  The failure is now an input error in both cases: it is listed under the coverage errors (and no longer also under the gaps), it ends the closing line with "incomplete: N input errors", and the exit code is 2.
  A `plan.json`, `tfplan.json`, `*.tfplan.json` or `plan-*.json` that is not valid JSON, and any JSON or YAML file whose start reads as a Terraform plan, a CloudFormation template or a Kubernetes manifest, is a parse failure instead of "not infrastructure".
  A truncated `terraform show -json` output in CI therefore fails the scan.
  YAML that carries template delimiters (`{{ .Values.x }}`, `{% if %}`) and files that do not look like infrastructure (`tsconfig.json` with comments) are still counted as not infrastructure.
- A directory whose only resource file fails to parse now says so, instead of "1 input(s) were parsed but produced no resources to model".
  The wording of that message for a scan that really finds no resources is now "1 input was parsed" or "2 inputs were parsed".
