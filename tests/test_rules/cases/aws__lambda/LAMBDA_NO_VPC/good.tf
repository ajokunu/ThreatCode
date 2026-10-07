resource "aws_lambda_function" "worker" {
  function_name = "worker"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "worker.zip"
  role          = "arn:aws:iam::111122223333:role/cluster"

  vpc_config {
    subnet_ids         = ["subnet-0a1b2c3d"]
    security_group_ids = ["sg-0a1b2c3d4e"]
  }
}
