resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::111122223333:role/cluster"
  version  = "1.34"
  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  vpc_config {
    subnet_ids = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]
    endpoint_public_access = false
  }
}
