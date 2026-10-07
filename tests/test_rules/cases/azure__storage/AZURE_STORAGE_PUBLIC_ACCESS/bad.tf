resource "azurerm_storage_account" "current" {
  name                     = "acmecurrent"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_nested_items_to_be_public = true
}

resource "azurerm_storage_account" "legacy" {
  name                     = "acmelegacy"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_blob_public_access = true
}
