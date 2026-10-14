resource "aws_secretsmanager_secret" "db" {
  name = "prod/db"
}
