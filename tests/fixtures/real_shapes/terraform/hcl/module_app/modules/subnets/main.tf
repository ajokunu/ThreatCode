resource "aws_subnet" "this" {
  count = length(var.cidrs)

  vpc_id     = var.vpc_id
  cidr_block = var.cidrs[count.index]

  tags = { Name = "extra-${count.index}" }
}
