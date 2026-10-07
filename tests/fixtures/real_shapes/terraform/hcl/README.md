# Terraform HCL

Source shape: hand-written configuration as a team commits it, parsed by python-hcl2 4.3.x.
source: handbuilt.

| Path | Contents |
| --- | --- |
| `module_app/` | A multi-file root module: `variables.tf` with defaults, `terraform.tfvars` overrides, `locals` blocks in two files, `data` sources, a `dynamic "ingress"` block, a `jsonencode` IAM policy, `count` driven by a variable, a literal `count = 0` resource, a local module call (`./modules/subnets`) and a remote registry module call (`terraform-aws-modules/s3-bucket/aws`). |
| `module_app/modules/subnets/` | The local module: one counted subnet resource, input variables and an output. |
| `two_vpcs.tf` | Two VPCs with one subnet, security group and instance each, referenced as `aws_vpc.prod.id` and `aws_vpc.dev.id`. |

A directory of `.tf` files is one Terraform module.
Scanning the directory reads the files together, so variables, locals and references resolve across files and the local module is followed.
Scanning one file reads only that file, so a reference to a resource or a variable declared in another file stays unresolved.
The remote registry module in `module_app/modules.tf` is not read; it is reported as skipped and the parse is marked incomplete.
`tests/test_ir/test_graph_realistic_hcl.py` asserts both readings, and the recordings under `tests/fixtures/golden/real_shapes__terraform__hcl__*` hold the one-file reading of each file, because the recording harness takes files as inputs.
