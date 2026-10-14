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

resource "azurerm_mssql_server_extended_auditing_policy" "sql" {
  server_id              = azurerm_mssql_server.sql.id
  storage_endpoint       = "https://acmeaudit.blob.core.windows.net/"
  retention_in_days      = 90
  log_monitoring_enabled = true
}
