resource "aws_iam_policy" "app" {
  name = "app-access"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::acme-assets/*"
    }]
  })
}
