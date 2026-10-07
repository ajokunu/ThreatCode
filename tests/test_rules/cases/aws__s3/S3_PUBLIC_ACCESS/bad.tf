resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
  acl    = "public-read"
}
