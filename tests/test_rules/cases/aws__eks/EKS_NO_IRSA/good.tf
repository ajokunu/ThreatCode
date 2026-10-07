resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::111122223333:role/cluster"
  version  = "1.34"
  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  vpc_config {
    subnet_ids = ["subnet-0a1b2c3d", "subnet-4e5f6a7b"]
    endpoint_public_access = false
  }

  encryption_config {
    resources = ["secrets"]

    provider {
      key_arn = "arn:aws:kms:us-east-1:111122223333:key/0a1b2c3d-4e5f-6789-abcd-ef0123456789"
    }
  }
}

resource "aws_iam_openid_connect_provider" "main" {
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da2b0ab7280"]
}
