module "extra_subnets" {
  source = "./modules/subnets"

  vpc_id = aws_vpc.main.id
  cidrs  = ["10.30.50.0/24", "10.30.51.0/24"]
}

module "logging_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"

  bucket = "${local.name}-access-logs"
}
