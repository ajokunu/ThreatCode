variable "region" {
  description = "AWS region for every resource"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "dev"
}

variable "vpc_cidr" {
  description = "CIDR block of the application VPC"
  type        = string
  default     = "10.30.0.0/16"
}

variable "app_instance_count" {
  description = "Number of application instances"
  type        = number
  default     = 1
}

variable "admin_cidrs" {
  description = "CIDR blocks allowed to reach the admin ports"
  type        = list(string)
  default     = ["10.200.0.0/16"]
}

variable "enable_bastion" {
  description = "Create the bastion host"
  type        = bool
  default     = false
}

variable "db_password" {
  description = "Master password of the database"
  type        = string
  sensitive   = true
}
