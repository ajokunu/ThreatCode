output "load_balancer_dns" {
  description = "Public DNS name of the load balancer"
  value       = aws_lb.front.dns_name
}

output "database_endpoint" {
  description = "Endpoint of the orders database"
  value       = aws_db_instance.orders.endpoint
}
