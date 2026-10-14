# A root that only calls registry and git modules: nothing in it is analysed.

module "s3" {
  source = "terraform-aws-modules/s3-bucket/aws"
  acl    = "public-read"
}

module "vpc" {
  source  = "git::https://example.com/org/vpc.git?ref=v1.2.3"
  version = "1.2.3"
}
