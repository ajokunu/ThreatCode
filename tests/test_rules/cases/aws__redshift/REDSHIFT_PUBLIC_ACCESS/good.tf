resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier     = "warehouse"
  node_type              = "dc2.large"
  database_name          = "dev"
  master_username        = "admin"
  manage_master_password = true
  publicly_accessible    = false
}
