resource "aws_iam_role" "worker" {
  name               = "worker-exec"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "worker" {
  role       = aws_iam_role.worker.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

resource "aws_lambda_function" "worker" {
  function_name = "worker"
  handler       = "index.handler"
  runtime       = "python3.12"
  filename      = "worker.zip"
  role          = aws_iam_role.worker.arn
}
