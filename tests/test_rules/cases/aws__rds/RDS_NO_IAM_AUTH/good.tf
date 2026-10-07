resource "aws_rds_cluster" "orders" {
  cluster_identifier                  = "orders"
  engine                              = "aurora-postgresql"
  master_username                     = "orders"
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
}
