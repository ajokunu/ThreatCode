variable "vpc_id" {
  description = "VPC the subnets belong to"
  type        = string
}

variable "cidrs" {
  description = "CIDR blocks, one subnet each"
  type        = list(string)
}
