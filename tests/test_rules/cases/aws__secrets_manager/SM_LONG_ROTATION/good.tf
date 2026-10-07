resource "aws_secretsmanager_secret" "db" {
  name = "prod/db"
}

resource "aws_secretsmanager_secret_rotation" "db" {
  secret_id           = aws_secretsmanager_secret.db.id
  rotation_lambda_arn = "arn:aws:lambda:us-east-1:111122223333:function:rotate-db"

  rotation_rules {
    automatically_after_days = 30
  }
}
