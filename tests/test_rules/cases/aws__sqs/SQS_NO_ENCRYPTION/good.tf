resource "aws_sqs_queue" "orders" {
  name                    = "orders"
  sqs_managed_sse_enabled = true
}
