resource "azurerm_storage_container" "assets" {
  name                  = "assets"
  storage_account_name  = "acmedata"
  container_access_type = "private"
}
