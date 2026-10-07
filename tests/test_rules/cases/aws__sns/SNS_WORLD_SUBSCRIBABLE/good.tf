resource "aws_sns_topic" "alerts" {
  name = "alerts"
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = ["sns:Subscribe", "sns:Receive"]
      Resource  = aws_sns_topic.alerts.arn
      Condition = {
        StringEquals = { "AWS:SourceOwner" = "111122223333" }
      }
    }]
  })
}
