output "subnet_ids" {
  description = "Ids of the created subnets"
  value       = aws_subnet.this[*].id
}
