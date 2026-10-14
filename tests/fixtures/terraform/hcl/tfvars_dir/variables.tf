variable "environment" {
  type    = string
  default = "dev"
}

variable "public" {
  type    = bool
  default = false
}

variable "enable_bastion" {
  type    = bool
  default = false
}

variable "enable_audit" {
  type    = bool
  default = false
}
