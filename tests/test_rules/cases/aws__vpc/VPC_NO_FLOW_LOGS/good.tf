resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_flow_log" "main" {
  vpc_id               = aws_vpc.main.id
  traffic_type         = "REJECT"
  log_destination_type = "s3"
  log_destination      = "arn:aws:s3:::flow-logs-bucket"
}
