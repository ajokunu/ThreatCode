resource "aws_kms_key" "data" {
  description         = "data key"
  enable_key_rotation = true
}
