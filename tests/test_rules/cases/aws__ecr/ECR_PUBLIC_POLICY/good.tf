resource "aws_ecr_repository" "app" {
  name = "app"
}

resource "aws_ecr_repository_policy" "app" {
  repository = aws_ecr_repository.app.name
  policy     = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "pull",
        "Effect": "Allow",
        "Principal": "*",
        "Action": [
          "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage"
        ],
        "Condition": {
          "StringEquals": {
            "aws:PrincipalOrgID": "o-a1b2c3d4e5"
          }
        }
      }
    ]
  })
}
