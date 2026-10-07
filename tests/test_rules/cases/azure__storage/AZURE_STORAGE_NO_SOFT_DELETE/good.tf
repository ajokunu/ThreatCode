resource "azurerm_storage_account" "data" {
  name                     = "acmedata"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  blob_properties {
    versioning_enabled = true

    delete_retention_policy {
      days = 14
    }
  }
}
