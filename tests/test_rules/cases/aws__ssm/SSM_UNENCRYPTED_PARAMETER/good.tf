resource "aws_ssm_parameter" "db_password" {
  name        = "/prod/db/password"
  description = "Database password"
  type        = "SecureString"
  value       = var.db_password
  key_id      = "alias/parameters"
}
