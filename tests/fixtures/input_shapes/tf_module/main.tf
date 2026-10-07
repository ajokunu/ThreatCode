resource "aws_s3_bucket" "logs" {
  bucket = var.logs_bucket
  acl    = "private"
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
}
