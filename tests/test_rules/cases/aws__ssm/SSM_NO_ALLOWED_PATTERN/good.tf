resource "aws_ssm_parameter" "retries" {
  name            = "/prod/max-retries"
  description     = "Retries before giving up"
  type            = "String"
  value           = "3"
  allowed_pattern = "^[0-9]+$"
}
