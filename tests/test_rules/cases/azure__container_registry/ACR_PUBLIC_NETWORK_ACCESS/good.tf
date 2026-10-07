resource "azurerm_container_registry" "closed" {
  name                = "crclosedprod"
  resource_group_name = "rg-platform"
  location            = "eastus"
  sku                 = "Premium"
  public_network_access_enabled = false
}

resource "azurerm_container_registry" "firewalled" {
  name                = "crfirewalledprod"
  resource_group_name = "rg-platform"
  location            = "eastus"
  sku                 = "Premium"
  public_network_access_enabled = true

  network_rule_set {
    default_action = "Deny"

    ip_rule {
      action   = "Allow"
      ip_range = "203.0.113.0/24"
    }
  }
}
