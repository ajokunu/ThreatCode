resource "aws_cloudtrail" "audit" {
  name                  = "audit"
  s3_bucket_name        = "acme-audit-trail"
  is_multi_region_trail = true
}
