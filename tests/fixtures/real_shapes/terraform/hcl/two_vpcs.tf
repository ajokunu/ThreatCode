resource "aws_vpc" "prod" {
  cidr_block = "10.1.0.0/16"
}

resource "aws_vpc" "dev" {
  cidr_block = "10.2.0.0/16"
}

resource "aws_subnet" "prod" {
  vpc_id     = aws_vpc.prod.id
  cidr_block = "10.1.1.0/24"
}

resource "aws_subnet" "dev" {
  vpc_id     = aws_vpc.dev.id
  cidr_block = "10.2.1.0/24"
}

resource "aws_security_group" "prod" {
  name   = "prod-workloads"
  vpc_id = aws_vpc.prod.id
}

resource "aws_security_group" "dev" {
  name   = "dev-workloads"
  vpc_id = aws_vpc.dev.id
}

resource "aws_instance" "prod" {
  ami                    = "ami-0c101f26f147fa7fd"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.prod.id
  vpc_security_group_ids = [aws_security_group.prod.id]
}

resource "aws_instance" "dev" {
  ami                    = "ami-0c101f26f147fa7fd"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.dev.id
  vpc_security_group_ids = [aws_security_group.dev.id]
}
