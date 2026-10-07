resource "aws_cloudtrail" "audit" {
  name           = "audit"
  s3_bucket_name = "acme-audit-trail"
  kms_key_id     = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
}
