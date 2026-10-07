# Vendored unchanged from https://github.com/terraform-aws-modules/terraform-aws-iam at v6.8.2, file modules/iam-policy/main.tf.
# Licensed under the Apache License, Version 2.0; the license text is in LICENSE in this directory.
# Kept as a parser fixture only. The only change is this comment block.

################################################################################
# IAM Policy
################################################################################

resource "aws_iam_policy" "policy" {
  count = var.create ? 1 : 0

  description = var.description
  name        = var.name
  name_prefix = var.name_prefix
  path        = var.path
  policy      = var.policy

  tags = var.tags
}
