resource "aws_eks_node_group" "workers" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "workers"
  node_role_arn   = aws_iam_role.node.arn
  subnet_ids      = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]

  scaling_config {
    desired_size = 2
    max_size     = 3
    min_size     = 1
  }
}
