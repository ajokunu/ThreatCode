resource "aws_config_configuration_recorder" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::111122223333:role/config"

  recording_group {
    all_supported = false
    resource_types = ["AWS::S3::Bucket"]
  }
}
