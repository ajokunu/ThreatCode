locals {
  app_ports = {
    http  = 8080
    admin = 9090
  }
}

resource "aws_security_group" "lb" {
  name   = "${local.name}-lb"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name   = "${local.name}-app"
  vpc_id = aws_vpc.main.id

  dynamic "ingress" {
    for_each = local.app_ports

    content {
      description     = "App port ${ingress.key} from the load balancer"
      from_port       = ingress.value
      to_port         = ingress.value
      protocol        = "tcp"
      security_groups = [aws_security_group.lb.id]
    }
  }
}

resource "aws_security_group" "db" {
  name   = "${local.name}-db"
  vpc_id = aws_vpc.main.id

  ingress {
    description     = "Postgres from the app tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_security_group" "bastion" {
  count = var.enable_bastion ? 1 : 0

  name   = "${local.name}-bastion"
  vpc_id = aws_vpc.main.id

  ingress {
    description = "SSH from the admin ranges"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidrs
  }
}

# Kept for reference while the migration finishes; disabled with a literal count.
resource "aws_security_group" "legacy" {
  count = 0

  name   = "${local.name}-legacy"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
