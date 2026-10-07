resource "aws_instance" "web" {
  ami                    = "ami-0abcdef1234567890"
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.a.id
  vpc_security_group_ids = [aws_security_group.web.id]

  depends_on = [aws_s3_bucket.data]
}

resource "aws_s3_bucket" "data" {
  bucket = "module-dir-data"
}
