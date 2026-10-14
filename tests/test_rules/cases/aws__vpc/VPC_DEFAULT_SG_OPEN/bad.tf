resource "aws_default_security_group" "default" {
  vpc_id = "vpc-0a1b2c3d4e5f67890"

  ingress {
    protocol    = -1
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}
