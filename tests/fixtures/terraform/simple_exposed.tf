resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "private"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  subnet_id     = "subnet-abc123"
}

resource "aws_ssm_parameter" "db_password" {
  name            = "/prod/db/password"
  description     = "Database password kept as a plain string on purpose"
  type            = "String"
  value           = "hunter2"
  allowed_pattern = ".+"
}
