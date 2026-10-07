resource "aws_ecs_service" "app" {
  name                   = "app"
  cluster                = aws_ecs_cluster.main.id
  desired_count          = 2
  launch_type            = "EC2"
  enable_execute_command = false
}
