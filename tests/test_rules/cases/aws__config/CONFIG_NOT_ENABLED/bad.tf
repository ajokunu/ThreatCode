resource "aws_config_configuration_recorder" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::111122223333:role/config"
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = false
}
