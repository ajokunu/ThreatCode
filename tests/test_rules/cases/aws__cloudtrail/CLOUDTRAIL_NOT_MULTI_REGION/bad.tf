resource "aws_cloudtrail" "audit" {
  name           = "audit"
  s3_bucket_name = "acme-audit-trail"
}
