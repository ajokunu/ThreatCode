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

  public_network_access_enabled = false
}

resource "azurerm_cosmosdb_account" "filtered" {
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

  public_network_access_enabled = true
  ip_range_filter               = ["203.0.113.7"]
}
