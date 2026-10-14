resource "aws_wafv2_web_acl" "edge" {
  name  = "edge"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "edge"
    sampled_requests_enabled   = true
  }
}
