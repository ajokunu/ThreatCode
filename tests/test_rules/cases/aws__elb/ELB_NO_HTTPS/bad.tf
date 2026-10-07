resource "aws_lb" "front" {
  name = "front"
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.front.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = "arn:aws:elasticloadbalancing:us-east-1:111122223333:targetgroup/app/0123456789abcdef"
  }
}
