locals {
  name = "${var.environment}-db"
}

resource "aws_db_instance" "main" {
  identifier          = local.name
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = var.public
}

resource "aws_instance" "bastion" {
  count = var.enable_bastion ? 1 : 0

  ami           = "ami-1"
  instance_type = "t3.micro"
}

resource "aws_cloudtrail" "audit" {
  count = var.enable_audit ? 1 : 0

  name           = "audit"
  s3_bucket_name = "audit-logs"
}
