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
  extended_auditing_policy {
    storage_endpoint           = "https://acmeaudit.blob.core.windows.net/"
    storage_account_access_key = var.audit_key
    retention_in_days          = 90
  }
}

variable "audit_key" {
  type      = string
  sensitive = true
}
