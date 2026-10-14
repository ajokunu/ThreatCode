resource "aws_iam_role" "app" {
  name = "app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
