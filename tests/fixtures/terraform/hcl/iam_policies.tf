# The same administrator policy written four ways, plus one that holds a variable.

variable "bucket" {
  type = string
}

resource "aws_iam_policy" "heredoc" {
  name   = "heredoc"
  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "*", "Resource": "*"}
  ]
}
POLICY
}

resource "aws_iam_policy" "jsonencode" {
  name = "jsonencode"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "escaped" {
  name   = "escaped"
  policy = "{\"Version\": \"2012-10-17\", \"Statement\": [{\"Effect\": \"Allow\", \"Action\": \"*\", \"Resource\": \"*\"}]}"
}

resource "aws_iam_policy" "indented_heredoc" {
  name   = "indented"
  policy = <<-POLICY
    {"Statement": [{"Resource": "*", "Action": "*", "Effect": "Allow"}], "Version": "2012-10-17"}
  POLICY
}

resource "aws_iam_policy" "with_variable" {
  name = "with-variable"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "arn:aws:s3:::${var.bucket}/*"
      }
    ]
  })
}

resource "aws_iam_policy" "scoped_reference" {
  name = "scoped"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = aws_s3_bucket.data.arn
      }
    ]
  })
}

resource "aws_s3_bucket" "data" {
  bucket = "data"
}
