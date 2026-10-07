resource "aws_s3_bucket" "tofu" {
  bucket = "tofu-assets"
  acl    = "public-read"
}
