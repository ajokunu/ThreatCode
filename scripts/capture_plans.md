# Capturing Terraform plans

Every plan fixture built by hand is marked `source: handbuilt` because the environments that built the real-shape corpus had no `terraform` or `tofu` binary.
This page explains how to replace each one with a capture from a real run, so the fixtures stay faithful to what the tool prints.

## What to replace

| Files | Records |
| --- | --- |
| `tests/fixtures/real_shapes/terraform/plan/*.plan.json` | One capture per module of the same name; the sidecar `README.md` lists what each file demonstrates. |
| `tests/test_rules/cases/**/*.plan.json` | One small module per rule and per side (`bad`, `good`). |
| `tests/test_rules/parity/*.plan.json` | The plan of the module in the sibling `.tf` file. |
| `examples/aws-webapp/tfplan.json` | The module behind the AWS demo. |

## Recipe

Use the same recipe for Terraform and OpenTofu; replace `terraform` with `tofu` for OpenTofu.
The goal is a plan with no credentials and no network access, so unknown values stay unknown, exactly as they are in a real first apply.

```sh
mkdir capture && cd capture
cp /path/to/module/*.tf .
cat > provider_mock.tf <<'HCL'
provider "aws" {
  region                      = "us-east-1"
  access_key                  = "mock"
  secret_key                  = "mock"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  s3_use_path_style           = true
}
HCL
terraform init -backend=false -input=false
terraform plan -refresh=false -lock=false -input=false -out=tfplan
terraform show -json tfplan > module.plan.json
```

Check the result before committing it:

* `format_version` is 1.x, and `resource_changes` and `configuration` are present.
* Create-time ids and ARNs are missing from `planned_values` and listed in `resource_changes[].change.after_unknown`.
* Relationships appear as `references` under `configuration.root_module.resources[].expressions`.
* `terraform_version` and the provider version are recorded in the sidecar `README.md`.

Data sources need a working provider, because Terraform reads them while planning.
Either keep them out of a capture (replace `data.aws_ami` with a literal image id) or add `-target` for the resources under test.
A capture that needs credentials is not reproducible, so it does not belong in the repository.

## After replacing a file

1. Change `source: handbuilt` to `source: captured` in its sidecar, with the Terraform and provider versions.
2. Run `python -m pytest -q tests/test_rules tests/test_ir/test_graph_realistic_plan.py tests/test_examples_paths.py`.
3. A real capture carries attributes the handbuilt file lacks, so some assertions may need new expected values.
   Fix the assertion only after confirming the capture is the correct one.
4. If golden recordings include the file, re-record them with `THREATCODE_UPDATE_GOLDEN=1` and review the diff before committing.

## What the shape check enforces

`tests/helpers/plan_shape.py` rejects a plan that lacks the parts real plans have.
It checks the top-level keys, a `resource_changes` entry with `actions`, `before`, `after` and `after_unknown` for every planned resource, a `configuration` entry for it, and that no attribute marked unknown after apply has a planned value.
It runs over every plan in the corpus and every plan case, so a capture that loses a part fails the same test.
