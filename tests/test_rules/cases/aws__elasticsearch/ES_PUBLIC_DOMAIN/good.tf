resource "aws_elasticsearch_domain" "search" {
  domain_name           = "search"
  elasticsearch_version = "7.10"

  vpc_options {
    subnet_ids         = ["subnet-0123456789abcdef0"]
    security_group_ids = ["sg-0123456789abcdef0"]
  }
}
