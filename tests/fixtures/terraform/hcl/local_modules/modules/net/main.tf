variable "vpc_id" {
  type = string
}

variable "cidrs" {
  type = list(string)
}

# The same address as the caller's VPC: a reference to it must not bind here.
resource "aws_vpc" "main" {
  cidr_block = "192.168.0.0/16"
}

resource "aws_subnet" "this" {
  count = length(var.cidrs)

  vpc_id     = var.vpc_id
  cidr_block = var.cidrs[count.index]
}

resource "aws_subnet" "local" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "192.168.1.0/24"
}

output "subnet_ids" {
  value = aws_subnet.this[*].id
}

output "first_subnet" {
  value = aws_subnet.this[0].id
}
