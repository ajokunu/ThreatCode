# Conditionals that break their line before `?`, `:` and `||`, nested inside parentheses
# and function arguments, as `terraform fmt` leaves them. python-hcl2 4.x rejects several of
# these; python-hcl2 8.x rejects a traversal that continues on the next line.
variable "a" {
  default = "on"
}

variable "b" {
  default = null
}

locals {
  picked = (
    var.b == null
    ? null
    : (
      startswith(var.b, "o")
      ? "o"
      : "f"
    )
  )

  either = (
    var.a == "on"
    || var.a == "yes"
  )

  merged = merge(
    { base = 1 },
    contains(["on", "yes"], var.a)
    ? { extra = 2 }
    : {}
  )

  continued = try(
    var.b
    .nested
    .value,
    "none"
  )

  mapped = {
    for k, v in { x = 1, y = 2 } :
    k => v == 1
    ? "one"
    : "other"
  }
}

resource "aws_s3_bucket" "wrapped" {
  bucket = local.either ? "wrapped-on" : "wrapped-off"
}
