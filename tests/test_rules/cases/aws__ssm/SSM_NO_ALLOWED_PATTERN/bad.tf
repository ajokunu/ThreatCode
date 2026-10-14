resource "aws_ssm_parameter" "retries" {
  name        = "/prod/max-retries"
  description = "Retries before giving up"
  type        = "String"
  value       = "3"
}
