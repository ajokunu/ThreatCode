resource "aws_lb" "front" {
  name = "front"
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.front.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = "arn:aws:acm:us-east-1:111122223333:certificate/0123-4567"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/0123456789abcdef"
  }
}
