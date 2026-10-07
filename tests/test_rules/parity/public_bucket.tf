resource "aws_s3_bucket" "assets" {
  bucket = "acme-public-assets"
  acl    = "public-read"
}

resource "aws_s3_bucket" "private" {
  bucket = "acme-private"
  acl    = "private"
}
