resource "aws_lambda_function" "worker" {
  function_name = "worker"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "worker.zip"
  role          = "arn:aws:iam::111122223333:role/cluster"
}
