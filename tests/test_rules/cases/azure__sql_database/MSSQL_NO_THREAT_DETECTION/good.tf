variable "sql_admin_password" {
  type      = string
  sensitive = true
}

resource "azurerm_mssql_server" "sql" {
  name                         = "sql-sql-prod"
  resource_group_name          = "rg-data"
  location                     = "eastus"
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = var.sql_admin_password
  minimum_tls_version          = "1.2"
}

resource "azurerm_mssql_server_security_alert_policy" "sql" {
  resource_group_name = "rg-data"
  server_name         = azurerm_mssql_server.sql.name
  server_id           = azurerm_mssql_server.sql.id
  state               = "Enabled"
}
