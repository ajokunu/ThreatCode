resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier     = "warehouse"
  node_type              = "dc2.large"
  database_name          = "dev"
  master_username        = "admin"
  manage_master_password = true
}

resource "aws_redshift_logging" "warehouse" {
  cluster_identifier   = aws_redshift_cluster.warehouse.id
  log_destination_type = "s3"
  bucket_name          = "acme-redshift-audit-logs"
}
