variable "publicly_accessible" {
  type    = bool
  default = false
}

variable "subnet_ids" {
  type = list(string)
}

resource "aws_db_subnet_group" "this" {
  name       = "db"
  subnet_ids = var.subnet_ids
}

resource "aws_db_instance" "this" {
  identifier             = "db"
  engine                 = "postgres"
  instance_class         = "db.t3.medium"
  publicly_accessible    = var.publicly_accessible
  db_subnet_group_name   = aws_db_subnet_group.this.name
}
