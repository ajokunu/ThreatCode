# Expressions the evaluator reads, and the ones it must leave unknown.

variable "region" {
  default = "us-east-1"
}

variable "stage" {
  default = "dev"
}

variable "ports" {
  default = [22, 443]
}

variable "tags" {
  default = {
    Owner = "platform"
  }
}

locals {
  name        = "${var.stage}-app"
  is_prod     = var.stage == "prod"
  encrypted   = local.is_prod ? true : false
  port_count  = length(var.ports)
  common_tags = merge(var.tags, { Stage = var.stage })
  from_self   = local.from_self
}

resource "aws_s3_bucket" "logs" {
  bucket = local.name
  tags   = local.common_tags
}

resource "aws_db_instance" "main" {
  identifier        = local.name
  storage_encrypted = local.encrypted
  port              = 5000 + local.port_count
  kms_key_id        = aws_kms_key.main.arn
  name              = var.undeclared
  username          = lookup(var.tags, "Owner", "nobody")
}

resource "aws_kms_key" "main" {
  description = "main"
}

resource "aws_instance" "web" {
  ami           = "ami-1"
  instance_type = var.stage == "prod" ? "m5.large" : "t3.micro"
  monitoring    = var.stage != "prod" && local.is_prod
  user_data     = file("${path.module}/boot.sh")
  tags          = { loop = [for p in var.ports : p * 2] }
}
