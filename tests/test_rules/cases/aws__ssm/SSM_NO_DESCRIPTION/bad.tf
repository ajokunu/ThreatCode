resource "aws_ssm_parameter" "region" {
  name  = "/prod/region"
  type  = "String"
  value = "us-east-1"
}
