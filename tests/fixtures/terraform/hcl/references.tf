# References between resources, in every shape the parser has to find them.

variable "name" {
  default = "demo"
}

variable "extra_groups" {
  default = []
}

variable "use_profile" {
  default = true
}

locals {
  prefix     = "app"
  subnet_ref = aws_subnet.b.id
}

data "aws_ami" "base" {
  most_recent = true
  owners      = ["amazon"]
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "a" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}

resource "aws_subnet" "b" {
  count = 2

  vpc_id     = aws_vpc.main.id
  cidr_block = "10.0.${count.index + 2}.0/24"
}

resource "aws_security_group" "lb" {
  name   = "lb"
  vpc_id = aws_vpc.main.id
}

resource "aws_security_group" "web" {
  name   = "${local.prefix}-web"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.lb.id]
  }
}

resource "aws_iam_role" "web" {
  name = "web"
}

resource "aws_iam_instance_profile" "web" {
  name = "web"
  role = aws_iam_role.web.name
}

resource "aws_s3_bucket" "data" {
  bucket = "demo-data"
}

resource "aws_instance" "web" {
  ami                    = data.aws_ami.base.id
  instance_type          = "t3.micro"
  subnet_id              = local.subnet_ref
  vpc_security_group_ids = concat([aws_security_group.web.id], var.extra_groups)
  iam_instance_profile   = var.use_profile ? aws_iam_instance_profile.web.name : null

  depends_on = [aws_s3_bucket.data]

  tags = {
    Name = var.name
  }
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table_association" "b" {
  count = 2

  subnet_id      = aws_subnet.b[count.index].id
  route_table_id = aws_route_table.main.id
}

resource "aws_lb" "front" {
  name            = "front"
  subnets         = aws_subnet.b[*].id
  security_groups = [for sg in [aws_security_group.lb] : sg.id]
}
