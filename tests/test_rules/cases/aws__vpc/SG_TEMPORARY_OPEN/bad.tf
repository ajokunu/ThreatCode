resource "aws_security_group" "debug" {
  name        = "temp-debug-access"
  description = "remove after the incident"
  vpc_id      = "vpc-0a1b2c3d4e5f67890"

  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
