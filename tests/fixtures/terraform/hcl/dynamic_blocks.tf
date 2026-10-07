# Dynamic blocks over known and unknown collections.

variable "rules" {
  type = list(any)
}

variable "ssh_ports" {
  default = [22]
}

resource "aws_security_group" "listed" {
  name = "listed"

  dynamic "ingress" {
    for_each = [22, 3389]

    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

resource "aws_security_group" "mapped" {
  name = "mapped"

  dynamic "ingress" {
    for_each = {
      web = 80
      tls = 443
    }
    iterator = rule

    content {
      description = rule.key
      from_port   = rule.value
      to_port     = rule.value
      protocol    = "tcp"
    }
  }
}

resource "aws_security_group" "unknown" {
  name = "unknown"

  dynamic "ingress" {
    for_each = var.rules

    content {
      from_port = ingress.value.port
      to_port   = ingress.value.port
      protocol  = "tcp"
    }
  }
}

resource "aws_security_group" "mixed" {
  name = "mixed"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  dynamic "ingress" {
    for_each = var.ssh_ports

    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = "tcp"
      cidr_blocks = ["0.0.0.0/0"]
    }
  }
}

resource "aws_security_group" "empty" {
  name = "empty"

  dynamic "ingress" {
    for_each = []

    content {
      from_port = 1
      to_port   = 1
      protocol  = "tcp"
    }
  }
}
