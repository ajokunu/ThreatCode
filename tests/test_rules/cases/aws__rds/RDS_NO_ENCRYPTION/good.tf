resource "aws_db_instance" "orders" {
  identifier                  = "orders"
  engine                      = "postgres"
  instance_class              = "db.t3.medium"
  allocated_storage           = 50
  username                    = "orders"
  manage_master_user_password = true
  storage_encrypted           = true
  kms_key_id                  = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
