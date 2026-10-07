# Exposure flags driven by variables: a default of false must not read as public.

variable "public" {
  type    = bool
  default = false
}

variable "enabled" {
  type = bool
}

resource "aws_subnet" "private" {
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = var.public
}

resource "aws_subnet" "inverted" {
  cidr_block              = "10.0.2.0/24"
  map_public_ip_on_launch = !var.public
}

resource "aws_subnet" "literal_true" {
  cidr_block              = "10.0.3.0/24"
  map_public_ip_on_launch = true
}

resource "aws_subnet" "literal_false_string" {
  cidr_block              = "10.0.4.0/24"
  map_public_ip_on_launch = "false"
}

resource "aws_subnet" "no_value" {
  cidr_block              = "10.0.5.0/24"
  map_public_ip_on_launch = var.enabled
}

resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  publicly_accessible = var.public
  storage_encrypted   = var.public ? false : true
}
