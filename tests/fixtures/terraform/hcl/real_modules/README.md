# Real terraform-aws-modules files

Files copied from the open-source terraform-aws-modules projects, to check that the HCL parser reads what teams really write.
Each file keeps its original text and gains a three-line comment header that names the repository, the tag and the path.
The projects are licensed under the Apache License, Version 2.0; the text is in `LICENSE`.

| File | Repository | Tag | Path in the repository |
| --- | --- | --- | --- |
| `eks_node_groups.tf` | terraform-aws-eks | v21.26.0 | `node_groups.tf` |
| `eks_managed_node_group.tf` | terraform-aws-eks | v21.26.0 | `modules/eks-managed-node-group/main.tf` |
| `lambda_deploy.tf` | terraform-aws-lambda | v8.9.0 | `modules/deploy/main.tf` |
| `lambda_iam.tf` | terraform-aws-lambda | v8.9.0 | `iam.tf` |
| `iam_role.tf` | terraform-aws-iam | v6.8.2 | `modules/iam-role/main.tf` |
| `iam_policy.tf` | terraform-aws-iam | v6.8.2 | `modules/iam-policy/main.tf` |

python-hcl2 4.x cannot parse `eks_node_groups.tf`, `eks_managed_node_group.tf` and `lambda_deploy.tf`.
It fails on a conditional whose condition is a comparison when that conditional is the value of an entry in an object constructor, as in `service_cidr = var.ip_family == "ipv6" ? ... : ...`.
python-hcl2 8.x parses all six, which is why the parser supports both.
`tests/test_parsers/test_terraform_hcl.py` parses the six under 8.x and checks that 4.x reports the three as a `ParseError` that names the file.
