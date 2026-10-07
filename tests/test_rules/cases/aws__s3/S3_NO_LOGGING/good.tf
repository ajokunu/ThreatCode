resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_s3_bucket_logging" "assets" {
  bucket        = aws_s3_bucket.assets.id
  target_bucket = "acme-central-access-logs"
  target_prefix = "assets/"
}
