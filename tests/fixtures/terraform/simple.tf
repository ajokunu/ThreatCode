resource "aws_s3_bucket" "test" {
  bucket = "my-test-bucket"
  acl    = "private"
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"
  subnet_id     = "subnet-abc123"
}
