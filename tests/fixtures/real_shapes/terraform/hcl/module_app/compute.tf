resource "aws_instance" "app" {
  count = var.app_instance_count

  ami                    = data.aws_ami.al2023.id
  instance_type          = "t3.small"
  subnet_id              = aws_subnet.private[count.index % 2].id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.app.name

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_size = 30
  }

  tags = { Name = "${local.name}-app-${count.index}" }
}

resource "aws_lb" "front" {
  name               = "${local.name}-front"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.lb.id]
  subnets            = aws_subnet.public[*].id
}

resource "aws_db_subnet_group" "db" {
  name       = "${local.name}-db"
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "orders" {
  identifier             = "${local.name}-db"
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  allocated_storage      = 50
  db_subnet_group_name   = aws_db_subnet_group.db.name
  vpc_security_group_ids = [aws_security_group.db.id]
  storage_encrypted      = true
  publicly_accessible    = false
  username               = "orders_admin"
  password               = var.db_password
}
