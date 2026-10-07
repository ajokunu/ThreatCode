resource "aws_s3_bucket" "public" {
  bucket = "public-assets"
  acl    = "public-read"
}
