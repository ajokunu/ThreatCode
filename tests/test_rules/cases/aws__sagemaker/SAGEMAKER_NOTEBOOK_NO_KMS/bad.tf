resource "aws_sagemaker_notebook_instance" "lab" {
  name          = "lab"
  instance_type = "ml.t3.medium"
  role_arn      = "arn:aws:iam::111122223333:role/notebook"
  subnet_id     = "subnet-0a1b2c3d"
  security_groups = ["sg-0a1b2c3d4e"]
  direct_internet_access = "Disabled"
  root_access            = "Disabled"
}
