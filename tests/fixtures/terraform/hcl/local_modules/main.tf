resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

module "net" {
  source = "./modules/net"

  vpc_id = aws_vpc.main.id
  cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
}

module "db" {
  source = "./modules/db"

  publicly_accessible = true
  subnet_ids          = module.net.subnet_ids
}

module "registry" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"
}

resource "aws_instance" "app" {
  ami           = "ami-1"
  instance_type = "t3.micro"
  subnet_id     = module.net.first_subnet
}
