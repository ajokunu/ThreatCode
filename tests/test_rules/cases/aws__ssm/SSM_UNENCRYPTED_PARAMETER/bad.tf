resource "aws_ssm_parameter" "db_password" {
  name        = "/prod/db/password"
  description = "Database password"
  type        = "String"
  value       = var.db_password
}
