resource "azurerm_key_vault" "kv" {
  name                = "kv-kv-prod"
  location            = "eastus"
  resource_group_name = "rg-sec"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  soft_delete_retention_days = 90
}
