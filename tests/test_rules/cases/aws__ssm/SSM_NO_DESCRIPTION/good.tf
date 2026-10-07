resource "aws_ssm_parameter" "region" {
  name        = "/prod/region"
  description = "Region the production stack runs in"
  type        = "String"
  value       = "us-east-1"
}
