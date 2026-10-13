# An object constructor whose element value is an operator expression, followed by another
# element. python-hcl2 4.x rejects this shape, which terraform-aws-eks writes as
# `device_index = i == 0 ? 0 : 1`.
variable "n" {
  default = 1
}

variable "prefix" {
  default = "app"
}

locals {
  cfg = {
    index = var.n == 0 ? 0 : 1
    name  = "x"
    label = var.prefix != "" ? "${var.prefix}-x" : "x"
    both  = var.n > 0 && var.prefix == "app"
    total = var.n + 2
    last  = var.n >= 1 ? "one" : "none"
  }

  interfaces = [
    for i in range(2) : {
      device_index = i == 0 ? 0 : 1
      card_index   = i
      kind         = var.n == 1 ? "efa" : "plain"
    }
  ]
}

resource "aws_security_group" "open" {
  name        = local.cfg.name
  description = local.cfg.label

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
