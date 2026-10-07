resource "azurerm_redis_cache" "closed" {
  name                = "redis-closed"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Standard"
  public_network_access_enabled = false
}

resource "azurerm_redis_cache" "injected" {
  name                = "redis-injected"
  location            = "eastus"
  resource_group_name = "rg-app"
  capacity            = 2
  family              = "C"
  sku_name            = "Premium"
  public_network_access_enabled = true
  subnet_id                     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/cache"
}
