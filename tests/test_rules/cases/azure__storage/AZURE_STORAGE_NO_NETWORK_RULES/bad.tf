resource "azurerm_storage_account" "open" {
  name                     = "acmeopen"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  allow_nested_items_to_be_public = false
}

resource "azurerm_storage_account" "allow_inline" {
  name                     = "acmeallow_inline"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  network_rules {
    default_action = "Allow"
  }
}
