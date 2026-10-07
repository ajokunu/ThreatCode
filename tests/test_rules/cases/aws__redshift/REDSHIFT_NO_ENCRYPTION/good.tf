resource "aws_redshift_cluster" "warehouse" {
  cluster_identifier     = "warehouse"
  node_type              = "dc2.large"
  database_name          = "dev"
  master_username        = "admin"
  manage_master_password = true
  encrypted              = true
  kms_key_id             = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
