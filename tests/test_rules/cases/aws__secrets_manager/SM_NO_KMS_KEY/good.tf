resource "aws_secretsmanager_secret" "db" {
  name       = "prod/db"
  kms_key_id = "alias/secrets"
}
