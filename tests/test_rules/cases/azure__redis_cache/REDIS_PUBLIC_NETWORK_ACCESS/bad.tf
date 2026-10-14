resource "azurerm_redis_cache" "open" {
  name                = "redis-open"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  public_network_access_enabled = true
}
