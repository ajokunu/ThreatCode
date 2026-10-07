resource "aws_kms_key" "assets" {
  description         = "assets bucket key"
  enable_key_rotation = true
}

resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "assets" {
  bucket = aws_s3_bucket.assets.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.assets.arn
    }
    bucket_key_enabled = true
  }
}
