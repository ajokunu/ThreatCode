resource "azurerm_cosmosdb_account" "db" {
  name                = "cosmos-prod"
  location            = "eastus"
  resource_group_name = "rg-data"
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"

  consistency_policy {
    consistency_level = "Session"
  }

  geo_location {
    location          = "eastus"
    failover_priority = 0
  }

  is_virtual_network_filter_enabled = false
}
