resource "aws_security_group" "alb" {
  name   = "alb"
  vpc_id = "vpc-0a1b2c3d4e5f67890"

  ingress {
    description = "HTTPS from the internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
