resource "azurerm_key_vault" "kv" {
  name                = "kv-kv-prod"
  location            = "eastus"
  resource_group_name = "rg-sec"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  network_acls {
    default_action = "Deny"
    bypass         = "AzureServices"
  }
}

resource "azurerm_key_vault" "closed" {
  name                = "kv-closed-prod"
  location            = "eastus"
  resource_group_name = "rg-sec"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  public_network_access_enabled = false
}
