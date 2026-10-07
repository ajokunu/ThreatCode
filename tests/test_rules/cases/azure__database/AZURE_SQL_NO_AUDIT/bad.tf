variable "sql_admin_password" {
  type      = string
  sensitive = true
}

resource "azurerm_sql_server" "legacy" {
  name                         = "sql-legacy"
  resource_group_name          = "rg-data"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
}
