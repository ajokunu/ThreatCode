resource "aws_opensearch_domain" "search" {
  domain_name    = "search"
  engine_version = "OpenSearch_2.11"

  encrypt_at_rest {
    enabled = true
  }
}
