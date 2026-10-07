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

  key_vault_key_id = "https://kv-prod.vault.azure.net/keys/cosmos/0123456789abcdef0123456789abcdef"
}
