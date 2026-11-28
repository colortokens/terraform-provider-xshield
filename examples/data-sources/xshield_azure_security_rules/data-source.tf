# A group whose rules are declared inline holds only those, so declare them through this data source.
locals {
  app_rules = [
    {
      name                       = "allow-https-from-vnet"
      priority                   = 300
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_address_prefix      = "VirtualNetwork"
      source_port_range          = "*"
      destination_address_prefix = "*"
      destination_port_range     = "443"
    },
  ]
}

# The group's ID is given as a string: its own id attribute would make the group
# depend on the rules it is given.
data "xshield_azure_security_rules" "app" {
  cloud_account_id          = "00000000-0000-0000-0000-000000000000"
  region                    = "eastus2"
  network_security_group_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/networkSecurityGroups/nsg-app"
  declared_security_rules   = local.app_rules
  current_security_rules    = [for rule in data.azurerm_network_security_group.app.security_rule : { name = rule.name, priority = rule.priority, direction = rule.direction }]
  version                   = data.xshield_azure_enforcement_status.this.applied_version
}

# Keeps Xshield's rules at the priorities the enforcement module gave them.
data "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  resource_group_name = "rg-net"
}

data "xshield_azure_enforcement_status" "this" {
  cloud_account_id = "00000000-0000-0000-0000-000000000000"
  region           = "eastus2"
}

resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  resource_group_name = "rg-net"
  location            = "eastus2"
  security_rule       = data.xshield_azure_security_rules.app.security_rules
}
