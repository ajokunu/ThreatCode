resource "azurerm_storage_account" "inline" {
  name                     = "acmeinline"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = ["203.0.113.7"]
  }
}

resource "azurerm_storage_account" "separate" {
  name                     = "acmeseparate"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
}

resource "azurerm_storage_account_network_rules" "separate" {
  storage_account_id = azurerm_storage_account.separate.id
  default_action     = "Deny"
  bypass             = ["AzureServices"]
}

resource "azurerm_storage_account" "private" {
  name                     = "acmeprivate"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  public_network_access_enabled = false
}
