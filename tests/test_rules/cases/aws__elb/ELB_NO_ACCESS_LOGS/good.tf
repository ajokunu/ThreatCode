resource "aws_lb" "front" {
  name = "front"

  access_logs {
    bucket  = "front-alb-logs"
    prefix  = "front"
    enabled = true
  }
}
