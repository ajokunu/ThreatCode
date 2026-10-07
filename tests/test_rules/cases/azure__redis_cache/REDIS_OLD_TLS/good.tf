resource "azurerm_redis_cache" "modern" {
  name                = "redis-modern"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  minimum_tls_version = "1.2"
}
