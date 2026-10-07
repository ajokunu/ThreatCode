# Terraform HCL

Source shape: hand-written configuration as a team commits it, parsed by python-hcl2 4.3.x.
source: handbuilt.

| Path | Contents |
| --- | --- |
| `module_app/` | A multi-file root module: `variables.tf` with defaults, `terraform.tfvars` overrides, `locals` blocks in two files, `data` sources, a `dynamic "ingress"` block, a `jsonencode` IAM policy, `count` driven by a variable, a literal `count = 0` resource, a local module call (`./modules/subnets`) and a remote registry module call (`terraform-aws-modules/s3-bucket/aws`). |
| `module_app/modules/subnets/` | The local module: one counted subnet resource, input variables and an output. |
| `two_vpcs.tf` | Two VPCs with one subnet, security group and instance each, referenced as `aws_vpc.prod.id` and `aws_vpc.dev.id`. |

A directory of `.tf` files is one Terraform module.
Until the directory parser lands, per-file parsing sees each file alone.
