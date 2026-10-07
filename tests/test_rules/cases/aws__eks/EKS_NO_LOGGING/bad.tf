resource "aws_eks_cluster" "main" {
  name     = "main"
  role_arn = "arn:aws:iam::111122223333:role/cluster"
  version  = "1.34"

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
