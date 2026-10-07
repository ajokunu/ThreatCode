resource "azurerm_key_vault" "open" {
  name                = "kv-open-prod"
  location            = "eastus"
  resource_group_name = "rg-sec"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  public_network_access_enabled = true
}

resource "azurerm_key_vault" "allow" {
  name                = "kv-allow-prod"
  location            = "eastus"
  resource_group_name = "rg-sec"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  network_acls {
    default_action = "Allow"
    bypass         = "None"
  }
}
