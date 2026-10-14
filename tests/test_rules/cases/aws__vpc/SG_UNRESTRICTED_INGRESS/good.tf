resource "aws_security_group" "bastion" {
  name        = "bastion"
  description = "SSH access"
  vpc_id      = "vpc-0a1b2c3d4e5f67890"

  ingress {
    description = "SSH from the corporate network"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
