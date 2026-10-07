resource "aws_db_instance" "orders" {
  identifier                  = "orders"
  engine                      = "postgres"
  instance_class              = "db.t3.medium"
  allocated_storage           = 50
  username                    = "orders"
  manage_master_user_password = true
  backup_retention_period     = 7
}
