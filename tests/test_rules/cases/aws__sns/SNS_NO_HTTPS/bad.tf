resource "aws_sns_topic" "alerts" {
  name = "alerts"
}

resource "aws_sns_topic_subscription" "webhook" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "http"
  endpoint  = "http://hooks.example.com/alerts"
}
