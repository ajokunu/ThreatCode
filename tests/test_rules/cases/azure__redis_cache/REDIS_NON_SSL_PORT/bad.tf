resource "azurerm_redis_cache" "legacy" {
  name                = "redis-legacy"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  enable_non_ssl_port = true
}

resource "azurerm_redis_cache" "current" {
  name                = "redis-current"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  non_ssl_port_enabled = true
}
