resource "aws_s3_bucket" "assets" {
  bucket = "acme-assets"
}

resource "aws_iam_role" "task" {
  name = "task-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  user_data     = <<-EOT
    #!/bin/bash
    docker run -d -p 8080:8080 ghcr.io/acme/web:2.0.1
  EOT
}

resource "aws_ecs_task_definition" "svc" {
  family                = "svc"
  task_role_arn         = aws_iam_role.task.arn
  container_definitions = jsonencode([
    {
      name      = "svc"
      image     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/svc:7"
      essential = true
    }
  ])
}

resource "aws_lambda_function" "fn" {
  function_name = "fn"
  package_type  = "Image"
  image_uri     = "123456789012.dkr.ecr.us-east-1.amazonaws.com/fn@sha256:5f3c1d9e7a2b4c6d8e0f1a3b5c7d9e2f4a6b8c0d1e3f5a7b9c2d4e6f8a0b1c3d"
  role          = aws_iam_role.task.arn
}
