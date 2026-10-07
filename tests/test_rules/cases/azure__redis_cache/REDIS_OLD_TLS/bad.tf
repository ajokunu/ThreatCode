resource "azurerm_redis_cache" "old" {
  name                = "redis-old"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  minimum_tls_version = "1.0"
}
