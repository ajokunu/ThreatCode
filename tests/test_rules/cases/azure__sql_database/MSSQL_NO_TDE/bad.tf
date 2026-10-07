resource "azurerm_mssql_database" "orders" {
  name                                = "orders"
  server_id                           = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-data/providers/Microsoft.Sql/servers/sql-prod"
  sku_name                            = "S3"
  transparent_data_encryption_enabled = false
}
