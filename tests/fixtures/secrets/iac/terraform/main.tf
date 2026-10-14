resource "aws_db_instance" "main" {
  identifier        = "orders"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "orders"
  password          = "Zx9fQ2mLp7Tr0ub4"
}

resource "aws_db_instance" "replica" {
  identifier        = "orders-replica"
  engine            = "postgres"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  username          = "orders"
  password          = var.replica_password
}

variable "replica_password" {
  type = string
}
