resource "aws_db_instance" "orders" {
  identifier          = "orders"
  engine              = "postgres"
  instance_class      = "db.t3.medium"
  allocated_storage   = 50
  publicly_accessible = true
}
