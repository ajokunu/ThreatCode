resource "aws_elasticsearch_domain" "search" {
  domain_name           = "search"
  elasticsearch_version = "7.10"
}
