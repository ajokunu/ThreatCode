resource "aws_ecs_task_definition" "app" {
  family                   = "app"
  requires_compatibilities = ["EC2"]
  network_mode             = "awsvpc"
  container_definitions    = <<DEFINITION
  [
    {
      "name": "app",
      "image": "111122223333.dkr.ecr.us-east-1.amazonaws.com/app:1.4.2",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "readonlyRootFilesystem": true,
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/app",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "app"
        }
      },
      "privileged": true
    }
  ]
  DEFINITION
}
